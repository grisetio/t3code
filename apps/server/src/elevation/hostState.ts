// @effect-diagnostics nodeBuiltinImport:off -- Reads root-owned files by owner and mode, which Effect's FileSystem does not expose.
/**
 * Unprivileged reads of the installed state (docs/internals/device-approval.md,
 * "Root-owned state" and "Installed state"). Whoever installed it, T3 only
 * checks the result, so nothing here knows about a particular config tool.
 */
import * as NodeCrypto from "node:crypto";
import * as NodeFSP from "node:fs/promises";
import * as NodePath from "node:path";

import {
  ELEVATION_SIGNATURE_CONTEXT,
  ElevationKeyId,
  ElevationSecurityLevel,
  decodeElevationBase64Url,
  type ElevationCheck,
  type ElevationPayload,
  type ElevationSignedResponse,
} from "@t3tools/contracts";
import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";

const PROTOCOL_VERSION = 1;
const MODULE_MARKER = Buffer.from("\0t3-elevation-module protocol=");

export interface HostPaths {
  /** `/etc/t3-elevation`. */
  readonly etcDir: string;
  /** `/etc/pam.d`. */
  readonly pamDir: string;
  /** Where install leaves the root helper, `ELEVATION_HELPER_INSTALL_PATH`. */
  readonly helperPath: string;
  /** Where the helper's ownership walk stops: `/` on a host, a temp dir in tests. */
  readonly helperRoot: string;
  /** The owner every root-owned path must have; tests run as themselves. */
  readonly rootUid: number;
  readonly platform: NodeJS.Platform;
}

export interface UserConfig {
  readonly version: number | undefined;
  readonly enabled: boolean;
  readonly socket: string | undefined;
}

export interface EnrolledKey {
  readonly keyId: ElevationKeyId;
  readonly publicKey: Uint8Array;
  readonly label: string;
  readonly securityLevel: ElevationSecurityLevel;
  readonly enrolledAt: string;
}

const KeyFile = Schema.Struct({
  version: Schema.Literal(1),
  keyId: ElevationKeyId,
  alg: Schema.Literal("es256"),
  publicKey: Schema.String,
  label: Schema.String,
  securityLevel: ElevationSecurityLevel,
  enrolledAt: Schema.String,
});
const decodeKeyFile = Schema.decodeUnknownOption(Schema.fromJsonString(KeyFile));

const lstat = (path: string) => Effect.promise(() => NodeFSP.lstat(path).catch(() => null));
const readText = (path: string) =>
  Effect.promise(() => NodeFSP.readFile(path, "utf8").catch(() => null));

/** The module refuses a path whose components are not root-owned and closed to others. */
const isRootOwned = Effect.fn("ElevationHostState.isRootOwned")(function* (
  paths: HostPaths,
  path: string,
  top: string = paths.etcDir,
) {
  let current = path;
  while (true) {
    const stat = yield* lstat(current);
    if (stat === null || stat.isSymbolicLink()) return false;
    if (stat.uid !== paths.rootUid || (stat.mode & 0o022) !== 0) return false;
    if (current === top) return true;
    const parent = NodePath.dirname(current);
    if (parent === current) return true;
    current = parent;
  }
});

/**
 * Whether the installed helper is safe to run as root: a regular file that
 * only root could have written or replaced, all the way up.
 */
export const isTrustedHelper = Effect.fn("ElevationHostState.isTrustedHelper")(function* (
  paths: HostPaths,
) {
  const stat = yield* lstat(paths.helperPath);
  if (stat === null || !stat.isFile()) return false;
  return yield* isRootOwned(paths, paths.helperPath, paths.helperRoot);
});

/** The subset of TOML the config uses: top-level `key = value` before any table. */
function parseUserConfig(text: string): UserConfig {
  const values = new Map<string, unknown>();
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (line.startsWith("[")) break;
    const match = /^([A-Za-z0-9_-]+)\s*=\s*(.+)$/.exec(line);
    if (match === null) continue;
    const [, key, rest] = match;
    if (key === undefined || rest === undefined) continue;
    const value = rest.replace(/\s+#.*$/, "");
    if (value.startsWith('"')) {
      try {
        const end = value.lastIndexOf('"');
        values.set(key, JSON.parse(value.slice(0, end + 1)));
      } catch {}
    } else if (value === "true" || value === "false") {
      values.set(key, value === "true");
    } else if (/^[+-]?\d+$/.test(value)) {
      values.set(key, Number(value));
    }
  }
  const version = values.get("version");
  const socket = values.get("socket");
  return {
    version: typeof version === "number" ? version : undefined,
    enabled: values.get("enabled") !== false,
    socket: typeof socket === "string" ? socket : undefined,
  };
}

const configPath = (paths: HostPaths, user: string) =>
  NodePath.join(paths.etcDir, "users", `${user}.toml`);
const keysDir = (paths: HostPaths, user: string) => NodePath.join(paths.etcDir, "keys", user);

export const readUserConfig = Effect.fn("ElevationHostState.readUserConfig")(function* (
  paths: HostPaths,
  user: string,
) {
  const text = yield* readText(configPath(paths, user));
  return text === null ? null : parseUserConfig(text);
});

/** Key files the module would accept; others are skipped like the module skips them. */
export const readEnrolledKeys = Effect.fn("ElevationHostState.readEnrolledKeys")(function* (
  paths: HostPaths,
  user: string,
) {
  const directory = keysDir(paths, user);
  const names = yield* Effect.promise(() => NodeFSP.readdir(directory).catch(() => []));
  const keys: Array<EnrolledKey> = [];
  for (const name of names.toSorted()) {
    if (!name.endsWith(".json")) continue;
    const text = yield* readText(NodePath.join(directory, name));
    const file = text === null ? null : decodeKeyFile(text);
    if (file === null || file._tag === "None") continue;
    const publicKey = decodeElevationBase64Url(file.value.publicKey);
    if (publicKey === null || name !== `${file.value.keyId}.json`) continue;
    if (derivedKeyId(publicKey) !== file.value.keyId) continue;
    keys.push({
      keyId: file.value.keyId,
      publicKey,
      label: file.value.label,
      securityLevel: file.value.securityLevel,
      enrolledAt: file.value.enrolledAt,
    });
  }
  return keys;
});

function derivedKeyId(spki: Uint8Array): string {
  return NodeCrypto.createHash("sha256")
    .update(spki)
    .digest()
    .subarray(0, 16)
    .toString("base64url");
}

export type SignatureCheck = "ok" | "unsupported_alg" | "unknown_key" | "bad_signature";

/** The module's check minus the clock, which only the module's own clock decides. */
export function checkSignature(input: {
  readonly payloadBytes: Uint8Array;
  readonly payload: ElevationPayload;
  readonly response: ElevationSignedResponse;
  readonly keys: ReadonlyArray<EnrolledKey>;
}): SignatureCheck {
  if (input.response.alg !== "es256-der") return "unsupported_alg";
  const key = input.keys.find((candidate) => candidate.keyId === input.response.keyId);
  if (key === undefined || !input.payload.keyIds.includes(key.keyId)) return "unknown_key";
  const signature = decodeElevationBase64Url(input.response.signature);
  if (signature === null || signature.length === 0) return "bad_signature";
  try {
    const verified = NodeCrypto.verify(
      "sha256",
      Buffer.concat([Buffer.from(ELEVATION_SIGNATURE_CONTEXT, "latin1"), input.payloadBytes]),
      { key: Buffer.from(key.publicKey), format: "der", type: "spki", dsaEncoding: "der" },
      signature,
    );
    return verified ? "ok" : "bad_signature";
  } catch {
    return "bad_signature";
  }
}

/** Parses `\0t3-elevation-module protocol=N\0` without loading the library. */
export function moduleProtocol(binary: Uint8Array): number | null {
  const bytes = Buffer.from(binary.buffer, binary.byteOffset, binary.byteLength);
  const start = bytes.indexOf(MODULE_MARKER);
  if (start === -1) return null;
  const digitsStart = start + MODULE_MARKER.length;
  const end = bytes.indexOf(0, digitsStart);
  const digits = end === -1 ? "" : bytes.subarray(digitsStart, end).toString("latin1");
  return /^\d{1,6}$/.test(digits) ? Number(digits) : null;
}

const meaningfulLines = (text: string) =>
  text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));

const LINUX_CONTROL = ["default=die", "ignore=ignore", "success=done"].join(" ");

/** The module path the first auth line names, or why it doesn't qualify. */
function linuxPamModulePath(text: string): string | "missing" | "misplaced" {
  const authLines = meaningfulLines(text).filter((line) => /^-?auth\s/.test(line));
  const elevationLine = authLines.findIndex((line) => line.includes("pam_t3_elevation.so"));
  if (elevationLine === -1) return "missing";
  const match = /^auth\s+\[([^\]]*)\]\s+(\/\S*\/pam_t3_elevation\.so)(\s|$)/.exec(
    authLines[0] ?? "",
  );
  if (elevationLine !== 0 || match === null) return "misplaced";
  const control = (match[1] ?? "").split(/\s+/).filter(Boolean).toSorted().join(" ");
  return control === LINUX_CONTROL && match[2] !== undefined ? match[2] : "misplaced";
}

function macPamModulePath(text: string): string | "missing" | "misplaced" {
  const lines = meaningfulLines(text);
  if (!lines.some((line) => line.includes("pam_t3_elevation.so"))) return "missing";
  const first = /^auth\s+sufficient\s+(\/\S*\/pam_t3_elevation\.so)$/.exec(lines[0] ?? "");
  const gate = /^auth\s+requisite\s+(\/\S*\/pam_t3_elevation\.so)\s+mode=gate$/.exec(
    lines[1] ?? "",
  );
  return first?.[1] !== undefined && first[1] === gate?.[1] ? first[1] : "misplaced";
}

const includesSudo = (text: string) =>
  meaningfulLines(text).some((line) =>
    /^(@include\s+sudo|-?auth\s+(include|substack)\s+sudo)$/.test(line),
  );

/** A check plus whether it fails because its `path` is gone, so install could put it back. */
export interface HostCheck extends ElevationCheck {
  readonly missing?: boolean;
}

export interface StaticChecks {
  readonly checks: ReadonlyArray<HostCheck>;
  readonly config: UserConfig | null;
  readonly keys: ReadonlyArray<EnrolledKey>;
}

export const staticChecks = Effect.fn("ElevationHostState.staticChecks")(function* (
  paths: HostPaths,
  input: { readonly user: string; readonly socketPath: string },
) {
  const checks: Array<HostCheck> = [];
  const pass = (id: string, message: string, path?: string) =>
    checks.push({ id, ok: true, message, ...(path === undefined ? {} : { path }) });
  const fail = (id: string, message: string, path?: string, missing = false) =>
    checks.push({
      id,
      ok: false,
      message,
      ...(path === undefined ? {} : { path }),
      ...(missing ? { missing } : {}),
    });

  const pamFiles =
    paths.platform === "darwin"
      ? [{ file: "sudo_local", parse: macPamModulePath }]
      : [{ file: "sudo", parse: linuxPamModulePath }];
  if (paths.platform === "darwin") {
    const sudo = yield* readText(NodePath.join(paths.pamDir, "sudo"));
    const sudoPath = NodePath.join(paths.pamDir, "sudo");
    if (sudo !== null && !/^\s*auth\s+include\s+sudo_local\s*$/m.test(sudo)) {
      fail("pam_include", `${sudoPath} doesn't include sudo_local`, sudoPath);
    }
  } else {
    const sudoI = yield* readText(NodePath.join(paths.pamDir, "sudo-i"));
    if (sudoI !== null && !includesSudo(sudoI)) {
      pamFiles.push({ file: "sudo-i", parse: linuxPamModulePath });
    }
  }
  const modulePaths = new Set<string>();
  for (const { file, parse } of pamFiles) {
    const path = NodePath.join(paths.pamDir, file);
    const text = yield* readText(path);
    const result = text === null ? "missing" : parse(text);
    if (result === "missing") fail(`pam:${file}`, `PAM line missing in ${path}`, path, true);
    else if (result === "misplaced")
      fail(`pam:${file}`, `PAM line in ${path} isn't first or has the wrong control`, path);
    else {
      pass(`pam:${file}`, `PAM line present in ${path}`, path);
      modulePaths.add(result);
    }
  }
  for (const modulePath of modulePaths) {
    const binary = yield* Effect.promise(() => NodeFSP.readFile(modulePath).catch(() => null));
    const protocol = binary === null ? null : moduleProtocol(binary);
    if (binary === null) fail("module", `PAM module missing at ${modulePath}`, modulePath, true);
    else if (protocol !== PROTOCOL_VERSION)
      fail("module", `PAM module at ${modulePath} isn't a compatible version`, modulePath);
    else pass("module", `PAM module at ${modulePath} is compatible`, modulePath);
  }

  const config = yield* readUserConfig(paths, input.user);
  const configFile = configPath(paths, input.user);
  if (config === null) fail("config", `${configFile} is missing`, configFile, true);
  else if (!(yield* isRootOwned(paths, configFile)))
    fail(
      "config",
      `${configFile} or a parent directory isn't root-owned and closed to others`,
      configFile,
    );
  else if (config.version !== 1)
    fail("config", `${configFile} has an unsupported version`, configFile);
  else if (!config.enabled) fail("config", `${configFile} turns device approval off`, configFile);
  else if (config.socket !== input.socketPath)
    fail("config", `${configFile} points at another T3 server`, configFile);
  else pass("config", `${configFile} points at this server`, configFile);

  const keysPath = keysDir(paths, input.user);
  const keysStat = yield* lstat(keysPath);
  if (keysStat === null) fail("keys", `${keysPath} is missing`, keysPath, true);
  else if (!keysStat.isDirectory()) fail("keys", `${keysPath} isn't a directory`, keysPath);
  else if (!(yield* isRootOwned(paths, keysPath)))
    fail(
      "keys",
      `${keysPath} or a parent directory isn't root-owned and closed to others`,
      keysPath,
    );
  else pass("keys", `${keysPath} is root-owned`, keysPath);

  const keys = yield* readEnrolledKeys(paths, input.user);
  if (keys.length === 0) fail("devices", "No device is enrolled");
  else pass("devices", keys.length === 1 ? "1 device enrolled" : `${keys.length} devices enrolled`);

  return { checks, config, keys } satisfies StaticChecks;
});

const MANAGED_PREFIXES = ["/nix/store/", "/etc/static/"];

/**
 * Another tool owns the path, so a rebuild would undo a direct edit: a
 * symlink (nix-darwin and NixOS link `/etc` into `/etc/static`), or a file
 * in the Nix store.
 */
export const isManagedPath = Effect.fn("ElevationHostState.isManagedPath")(function* (
  path: string,
) {
  const stat = yield* lstat(path);
  return stat?.isSymbolicLink() === true || (yield* isNixPath(path));
});

/** In the Nix store, or resolving into it (nix-darwin and NixOS `/etc` links via `/etc/static`). */
const isNixPath = Effect.fn("ElevationHostState.isNixPath")(function* (path: string) {
  if (MANAGED_PREFIXES.some((prefix) => path.startsWith(prefix))) return true;
  const real = yield* Effect.promise(() => NodeFSP.realpath(path).catch(() => path));
  return MANAGED_PREFIXES.some((prefix) => real.startsWith(prefix));
});

export type PathOwner = NonNullable<ElevationCheck["managedBy"]>;

/**
 * Who owns a path that isn't T3's: Nix when it is or resolves into the store, by hand when it
 * exists and `installed-by-t3.json` doesn't record it. Undefined when T3 wrote it or it's gone.
 * A Nix link wins over the record, since a rebuild replaces whatever T3 wrote there.
 */
export const pathOwner = Effect.fn("ElevationHostState.pathOwner")(function* (
  path: string,
  writtenByT3: ReadonlySet<string>,
) {
  if (yield* isNixPath(path)) return "nix" satisfies PathOwner;
  if (writtenByT3.has(path) || (yield* lstat(path)) === null) return undefined;
  return "hand" satisfies PathOwner;
});

const Manifest = Schema.Struct({
  user: Schema.String,
  changes: Schema.Array(Schema.Struct({ path: Schema.String })),
});
const decodeManifest = Schema.decodeUnknownOption(Schema.fromJsonString(Manifest));

/**
 * What `installed-by-t3.json` records: the user T3 installed for, and the paths it wrote. Null
 * when there is none, so T3 didn't install device approval here.
 */
export const readT3Install = Effect.fn("ElevationHostState.readT3Install")(function* (
  paths: HostPaths,
) {
  const text = yield* readText(NodePath.join(paths.etcDir, "installed-by-t3.json"));
  const manifest = text === null ? null : decodeManifest(text);
  if (manifest === null || manifest._tag === "None") return null;
  return {
    user: manifest.value.user,
    written: new Set(manifest.value.changes.map((change) => change.path)),
  };
});

export interface FixContext {
  /** What the helper's install would change; a blocked entry stops install entirely. */
  readonly plannedChanges: ReadonlyArray<{ readonly path: string; readonly summary: string }>;
  readonly writtenByT3: ReadonlySet<string>;
  readonly managed: ReadonlySet<string>;
  /** `pathOwner` of each failing check's path, where it has one. */
  readonly owners: ReadonlyMap<string, PathOwner>;
}

/**
 * T3 repairs a failing part only when it knows the cause, the repair is the
 * install it already runs, and the repair lasts: the part is missing, install
 * would put back exactly that path, nothing else owns the path, and T3 wrote
 * it in the first place. Everything else goes to an agent with the diagnosis.
 * The phone's key is always T3's to add back.
 */
export function withFixBy(check: HostCheck, context: FixContext): ElevationCheck {
  const { missing, ...rest } = check;
  if (check.ok) return rest;
  const managedBy = check.path === undefined ? undefined : context.owners.get(check.path);
  const wire = managedBy === undefined ? rest : { ...rest, managedBy };
  if (check.id === "devices") return { ...wire, fixBy: "t3" };
  const path = missing === true ? check.path : undefined;
  const installCanWrite =
    path !== undefined &&
    context.plannedChanges.some((change) => change.path === path) &&
    !context.plannedChanges.some((change) => change.summary.startsWith("can't change"));
  const t3 = installCanWrite && !context.managed.has(path) && context.writtenByT3.has(path);
  return { ...wire, fixBy: t3 ? "t3" : "agent" };
}
