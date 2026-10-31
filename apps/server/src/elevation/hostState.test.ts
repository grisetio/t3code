// @effect-diagnostics nodeBuiltinImport:off -- Lays out a fake /etc to check owner and mode rules.
import * as NodeFSP from "node:fs/promises";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";

import { describe, expect, it } from "@effect/vitest";
import {
  decodeElevationBase64Url,
  decodeElevationPayload,
  type ElevationKeyId,
  type ElevationSignedResponse,
} from "@t3tools/contracts";
import vectorsJson from "../../../../packages/contracts/test-vectors/device-approval.json" with { type: "json" };
import * as Effect from "effect/Effect";
import * as Result from "effect/Result";

import {
  checkSignature,
  type FixContext,
  isManagedPath,
  isTrustedHelper,
  moduleProtocol,
  pathOwner,
  readT3Install,
  staticChecks,
  withFixBy,
  type HostPaths,
} from "./hostState.ts";

const bytesOf = (text: string) => {
  const bytes = decodeElevationBase64Url(text);
  if (bytes === null) throw new Error("Not base64url");
  return bytes;
};
const enrolled = {
  keyId: vectorsJson.keys.enrolled.keyId as ElevationKeyId,
  publicKey: bytesOf(vectorsJson.keys.enrolled.spkiDer),
  label: "Pixel",
  securityLevel: "strongbox" as const,
  enrolledAt: "2026-10-30T12:00:00Z",
};

describe("checkSignature", () => {
  // The module alone judges expiry against its own clock.
  const vectors = vectorsJson.verify.filter((vector) => vector.expected !== "expired");
  it.each(vectors)("classifies $name as $expected", (vector) => {
    const payloadBytes = bytesOf(vector.payload);
    expect(
      checkSignature({
        payloadBytes,
        payload: Result.getOrThrow(decodeElevationPayload(payloadBytes)),
        response: vector.response as ElevationSignedResponse,
        keys: [enrolled],
      }),
    ).toBe(vector.expected);
  });
});

describe("moduleProtocol", () => {
  it("reads the marker without loading the library", () => {
    const binary = Buffer.from("\x7fELF...\0t3-elevation-module protocol=1\0...");
    expect(moduleProtocol(binary)).toBe(1);
    expect(moduleProtocol(Buffer.from("\0t3-elevation-module protocol=x\0"))).toBeNull();
    expect(moduleProtocol(Buffer.from("pam_unix"))).toBeNull();
  });
});

const layout = Effect.fn("test.layout")(function* (input: {
  readonly platform: NodeJS.Platform;
  readonly pam: Record<string, string>;
  readonly protocol: number;
}) {
  const root = yield* Effect.acquireRelease(
    Effect.promise(() => NodeFSP.mkdtemp(NodePath.join(NodeOS.tmpdir(), "t3-elevation-host-"))),
    (directory) => Effect.promise(() => NodeFSP.rm(directory, { recursive: true, force: true })),
  );
  const paths: HostPaths = {
    etcDir: NodePath.join(root, "t3-elevation"),
    pamDir: NodePath.join(root, "pam.d"),
    helperPath: NodePath.join(root, "lib", "t3-elevation"),
    helperRoot: root,
    rootUid: process.getuid?.() ?? 0,
    platform: input.platform,
  };
  const modulePath = NodePath.join(root, "lib", "pam_t3_elevation.so");
  const socketPath = NodePath.join(root, "state", "elevation.sock");
  yield* Effect.promise(async () => {
    for (const directory of ["lib", "pam.d", "t3-elevation/users", "t3-elevation/keys/me"]) {
      await NodeFSP.mkdir(NodePath.join(root, directory), { recursive: true, mode: 0o755 });
    }
    await NodeFSP.writeFile(modulePath, `ELF\0t3-elevation-module protocol=${input.protocol}\0`);
    for (const [file, text] of Object.entries(input.pam)) {
      await NodeFSP.writeFile(
        NodePath.join(paths.pamDir, file),
        text.replaceAll("MODULE", modulePath),
      );
    }
    await NodeFSP.writeFile(
      NodePath.join(paths.etcDir, "users", "me.toml"),
      `version = 1\nenabled = true\nsocket = ${JSON.stringify(socketPath)} # this server\n`,
    );
    await NodeFSP.writeFile(
      NodePath.join(paths.etcDir, "keys", "me", `${enrolled.keyId}.json`),
      JSON.stringify({
        version: 1,
        keyId: enrolled.keyId,
        alg: "es256",
        publicKey: vectorsJson.keys.enrolled.spkiDer,
        label: "Pixel",
        securityLevel: "strongbox",
        enrolledAt: enrolled.enrolledAt,
      }),
    );
    // A file named for another key is skipped, as the module skips it.
    await NodeFSP.writeFile(
      NodePath.join(paths.etcDir, "keys", "me", `${vectorsJson.keys.other.keyId}.json`),
      JSON.stringify({ version: 1, keyId: enrolled.keyId }),
    );
  });
  return { paths, socketPath };
});

const okIds = (checks: ReadonlyArray<{ readonly id: string; readonly ok: boolean }>) =>
  checks.map((check) => `${check.id}:${check.ok ? "ok" : "fail"}`);

describe("staticChecks", () => {
  it.effect("passes a complete Linux-PAM setup", () =>
    Effect.gen(function* () {
      const { paths, socketPath } = yield* layout({
        platform: "linux",
        pam: {
          sudo: "#%PAM-1.0\nauth [success=done ignore=ignore default=die] MODULE\nauth include system-auth\n",
          "sudo-i": "auth include sudo\n",
        },
        protocol: 1,
      });
      const result = yield* staticChecks(paths, { user: "me", socketPath });
      expect(okIds(result.checks)).toEqual([
        "pam:sudo:ok",
        "module:ok",
        "config:ok",
        "keys:ok",
        "devices:ok",
      ]);
      expect(result.checks.map((check) => check.path)).toEqual([
        NodePath.join(paths.pamDir, "sudo"),
        NodePath.join(NodePath.dirname(paths.helperPath), "pam_t3_elevation.so"),
        NodePath.join(paths.etcDir, "users", "me.toml"),
        NodePath.join(paths.etcDir, "keys", "me"),
        undefined,
      ]);
      expect(result.keys.map((key) => key.keyId)).toEqual([enrolled.keyId]);
    }).pipe(Effect.scoped),
  );

  it.effect("names what is wrong without naming a tool", () =>
    Effect.gen(function* () {
      const { paths } = yield* layout({
        platform: "linux",
        pam: {
          sudo: "auth include system-auth\nauth [success=done ignore=ignore default=die] MODULE\n",
          "sudo-i": "auth [success=done ignore=ignore default=die] MODULE\n",
        },
        protocol: 2,
      });
      const result = yield* staticChecks(paths, {
        user: "me",
        socketPath: "/elsewhere/elevation.sock",
      });
      expect(okIds(result.checks)).toEqual([
        "pam:sudo:fail",
        "pam:sudo-i:ok",
        "module:fail",
        "config:fail",
        "keys:ok",
        "devices:ok",
      ]);
      expect(result.checks.find((check) => check.id === "config")?.message).toContain(
        "points at another T3 server",
      );
      // A misplaced line and an incompatible module aren't missing parts, but still name their file.
      expect(result.checks.filter((check) => check.missing === true)).toEqual([]);
      expect(result.checks.find((check) => check.id === "pam:sudo")?.path).toBe(
        NodePath.join(paths.pamDir, "sudo"),
      );
    }).pipe(Effect.scoped),
  );

  it.effect("checks macOS's sudo_local pair and that sudo includes it", () =>
    Effect.gen(function* () {
      const { paths, socketPath } = yield* layout({
        platform: "darwin",
        pam: {
          sudo: "auth include sudo_local\nauth sufficient pam_smartcard.so\n",
          sudo_local: "auth sufficient MODULE\nauth requisite MODULE mode=gate\n",
        },
        protocol: 1,
      });
      const ready = yield* staticChecks(paths, { user: "me", socketPath });
      expect(ready.checks.every((check) => check.ok)).toBe(true);

      yield* Effect.promise(() =>
        NodeFSP.writeFile(NodePath.join(paths.pamDir, "sudo"), "auth sufficient pam_tid.so\n"),
      );
      const missingInclude = yield* staticChecks(paths, { user: "me", socketPath });
      expect(missingInclude.checks[0]).toMatchObject({
        id: "pam_include",
        ok: false,
        path: NodePath.join(paths.pamDir, "sudo"),
      });

      const local = NodePath.join(paths.pamDir, "sudo_local");
      yield* Effect.promise(() => NodeFSP.writeFile(local, "auth sufficient pam_tid.so\n"));
      const missingLine = yield* staticChecks(paths, { user: "me", socketPath });
      expect(missingLine.checks.find((check) => check.id === "pam:sudo_local")).toMatchObject({
        ok: false,
        path: local,
        missing: true,
      });
    }).pipe(Effect.scoped),
  );
});

describe("isTrustedHelper", () => {
  it.effect("trusts only a regular file nobody but its owner could replace", () =>
    Effect.gen(function* () {
      const { paths } = yield* layout({ platform: "linux", pam: {}, protocol: 1 });
      const lib = NodePath.dirname(paths.helperPath);
      yield* Effect.promise(async () => {
        await NodeFSP.chmod(lib, 0o755);
        await NodeFSP.writeFile(paths.helperPath, "#!/bin/sh\n", { mode: 0o755 });
      });
      expect(yield* isTrustedHelper(paths)).toBe(true);

      yield* Effect.promise(() => NodeFSP.chmod(lib, 0o775));
      expect(yield* isTrustedHelper(paths)).toBe(false);
      yield* Effect.promise(() => NodeFSP.chmod(lib, 0o755));

      const elsewhere = NodePath.join(lib, "real-helper");
      yield* Effect.promise(async () => {
        await NodeFSP.rename(paths.helperPath, elsewhere);
        await NodeFSP.symlink(elsewhere, paths.helperPath);
      });
      expect(yield* isTrustedHelper(paths)).toBe(false);

      yield* Effect.promise(() => NodeFSP.rm(paths.helperPath));
      expect(yield* isTrustedHelper(paths)).toBe(false);
    }).pipe(Effect.scoped),
  );
});

describe("withFixBy", () => {
  const pam = "/etc/pam.d/sudo_local";
  const missingLine = {
    id: "pam:sudo_local",
    ok: false,
    message: `PAM line missing in ${pam}`,
    path: pam,
    missing: true,
  };
  const repairable: FixContext = {
    plannedChanges: [{ path: pam, summary: "add the device approval lines" }],
    writtenByT3: new Set([pam]),
    managed: new Set(),
    owners: new Map(),
  };
  const fixBy = (check: typeof missingLine | object, context: Partial<FixContext> = {}) =>
    withFixBy({ id: "x", ok: false, message: "", ...check }, { ...repairable, ...context }).fixBy;

  it("leaves passing checks without a fixer or owner and keeps `missing` off the wire", () => {
    expect(
      withFixBy({ ...missingLine, ok: true }, { ...repairable, owners: new Map([[pam, "nix"]]) }),
    ).toEqual({
      id: "pam:sudo_local",
      ok: true,
      message: `PAM line missing in ${pam}`,
      path: pam,
    });
  });

  it("names who owns a failing part", () => {
    const owned = (owner: "nix" | "hand") =>
      withFixBy(missingLine, { ...repairable, owners: new Map([[pam, owner]]) }).managedBy;
    expect(owned("nix")).toBe("nix");
    expect(owned("hand")).toBe("hand");
    expect(withFixBy(missingLine, repairable).managedBy).toBeUndefined();
  });

  it("re-adds a missing line T3 wrote on a file nothing else manages", () => {
    expect(fixBy(missingLine)).toBe("t3");
  });

  it("re-adds this phone's key anywhere", () => {
    expect(fixBy({ id: "devices" }, { plannedChanges: [], writtenByT3: new Set() })).toBe("t3");
  });

  it("hands the same line to an agent when Nix manages the file", () => {
    expect(fixBy(missingLine, { managed: new Set([pam]) })).toBe("agent");
  });

  it("hands parts T3 didn't write, or that install can't write, to an agent", () => {
    expect(fixBy(missingLine, { writtenByT3: new Set() })).toBe("agent");
    expect(fixBy(missingLine, { plannedChanges: [] })).toBe("agent");
    // Install refuses to change anything while one path is blocked.
    expect(
      fixBy(missingLine, {
        plannedChanges: [
          ...repairable.plannedChanges,
          { path: "/etc/t3-elevation/users/me.toml", summary: "can't change: points elsewhere" },
        ],
      }),
    ).toBe("agent");
  });

  it("hands a hand-edited stack or an unknown cause to an agent", () => {
    expect(fixBy({ id: "pam:sudo_local", message: "PAM line isn't first" })).toBe("agent");
    expect(fixBy({ id: "pam_include" })).toBe("agent");
  });
});

describe("isManagedPath", () => {
  it.effect("treats symlinks and Nix store paths as managed elsewhere", () =>
    Effect.gen(function* () {
      const { paths } = yield* layout({
        platform: "darwin",
        pam: { sudo_local: "auth sufficient MODULE\n" },
        protocol: 1,
      });
      const local = NodePath.join(paths.pamDir, "sudo_local");
      expect(yield* isManagedPath(local)).toBe(false);
      expect(yield* isManagedPath(NodePath.join(paths.pamDir, "missing"))).toBe(false);
      expect(yield* isManagedPath("/nix/store/abc-t3-elevation/lib/pam_t3_elevation.so")).toBe(
        true,
      );
      const linked = NodePath.join(paths.pamDir, "sudo_linked");
      yield* Effect.promise(() => NodeFSP.symlink(local, linked));
      expect(yield* isManagedPath(linked)).toBe(true);
    }).pipe(Effect.scoped),
  );
});

describe("pathOwner", () => {
  it.effect("says Nix for store paths, by hand for files T3 didn't write, else nobody", () =>
    Effect.gen(function* () {
      const { paths } = yield* layout({
        platform: "darwin",
        pam: { sudo_local: "auth sufficient pam_tid.so\n" },
        protocol: 1,
      });
      const local = NodePath.join(paths.pamDir, "sudo_local");
      const missing = NodePath.join(paths.pamDir, "missing");
      const store = "/nix/store/abc-t3-elevation/lib/pam_t3_elevation.so";
      expect(yield* pathOwner(store, new Set())).toBe("nix");
      // A rebuild replaces it whatever the record says.
      expect(yield* pathOwner(store, new Set([store]))).toBe("nix");
      expect(yield* pathOwner(local, new Set())).toBe("hand");
      expect(yield* pathOwner(local, new Set([local]))).toBeUndefined();
      expect(yield* pathOwner(missing, new Set())).toBeUndefined();
      // A link that doesn't lead into the store is someone's own.
      const linked = NodePath.join(paths.pamDir, "sudo_linked");
      yield* Effect.promise(() => NodeFSP.symlink(local, linked));
      expect(yield* pathOwner(linked, new Set())).toBe("hand");
    }).pipe(Effect.scoped),
  );
});

describe("readT3Install", () => {
  it.effect("reads who installed-by-t3.json installed for and the paths it wrote", () =>
    Effect.gen(function* () {
      const { paths } = yield* layout({ platform: "darwin", pam: {}, protocol: 1 });
      expect(yield* readT3Install(paths)).toBeNull();
      yield* Effect.promise(() =>
        NodeFSP.writeFile(
          NodePath.join(paths.etcDir, "installed-by-t3.json"),
          JSON.stringify({
            version: 1,
            user: "me",
            changes: [{ path: "/etc/pam.d/sudo_local", action: "created" }],
          }),
        ),
      );
      expect(yield* readT3Install(paths)).toEqual({
        user: "me",
        written: new Set(["/etc/pam.d/sudo_local"]),
      });
    }).pipe(Effect.scoped),
  );
});
