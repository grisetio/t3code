import {
  decodeElevationBase64Url,
  decodeElevationPayload,
  elevationKeyIdFromSpkiSha256,
  type DesktopDeviceApprovalState,
  type DesktopTouchIdUnavailable,
  type ElevationPayload,
  type ElevationSignedResponse,
  type EnvironmentId,
} from "@t3tools/contracts";
import * as Cause from "effect/Cause";
import * as Context from "effect/Context";
import * as Crypto from "effect/Crypto";
import * as Effect from "effect/Effect";
import * as Base64Url from "effect/encoding/Base64Url";
import * as Exit from "effect/Exit";
import * as Fiber from "effect/Fiber";
import * as FiberMap from "effect/FiberMap";
import * as FileSystem from "effect/FileSystem";
import * as Layer from "effect/Layer";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import * as Stream from "effect/Stream";
import * as ChildProcess from "effect/process/ChildProcess";
import * as ChildProcessSpawner from "effect/process/ChildProcessSpawner";

import * as DesktopAppIdentity from "./DesktopAppIdentity.ts";
import * as DesktopEnvironment from "./DesktopEnvironment.ts";

// This Mac approves sudo with a Secure Enclave key behind Touch ID, through the bundled Swift
// helper (native/t3-se-sign). The key file stays here; the renderer only names an environment.

export class DesktopDeviceApprovalError extends Schema.TaggedError<DesktopDeviceApprovalError>()(
  "DesktopDeviceApprovalError",
  { message: Schema.String },
) {}

export class DesktopDeviceApproval extends Context.Service<
  DesktopDeviceApproval,
  {
    readonly state: (environmentId: EnvironmentId) => Effect.Effect<DesktopDeviceApprovalState>;
    /** Makes the key and confirms it with Touch ID; null when the sheet was cancelled. */
    readonly createKey: (input: {
      readonly environmentId: EnvironmentId;
      readonly operationId: string;
    }) => Effect.Effect<{ readonly publicKey: string } | null, DesktopDeviceApprovalError>;
    /** Signs exactly the payload bytes the card decoded; null when cancelled or aborted. */
    readonly sign: (input: {
      readonly environmentId: EnvironmentId;
      readonly operationId: string;
      readonly payload: string;
    }) => Effect.Effect<ElevationSignedResponse | null, DesktopDeviceApprovalError>;
    /** Closes the sheet of a running createKey or sign, which then returns null. */
    readonly abort: (operationId: string) => Effect.Effect<void>;
    readonly forget: (
      environmentId: EnvironmentId,
    ) => Effect.Effect<void, DesktopDeviceApprovalError>;
  }
>()("@t3tools/desktop/app/DesktopDeviceApproval") {}

const HelperFailure = Schema.Struct({
  ok: Schema.Literal(false),
  error: Schema.Struct({ code: Schema.String, message: Schema.String }),
});
const HelperStatus = Schema.Struct({
  ok: Schema.Literal(true),
  secureEnclave: Schema.Boolean,
  biometry: Schema.String,
  touchId: Schema.Boolean,
  clamshellClosed: Schema.NullOr(Schema.Boolean),
  key: Schema.Literals(["absent", "valid", "invalidated", "unknown"]),
  productName: Schema.NullOr(Schema.String),
  hwModel: Schema.NullOr(Schema.String),
  computerName: Schema.NullOr(Schema.String),
});
export type TouchIdFacts = typeof HelperStatus.Type;
const decodeStatus = Schema.decodeUnknownEffect(
  Schema.fromJsonString(Schema.Union([HelperStatus, HelperFailure])),
);
const decodeCreate = Schema.decodeUnknownEffect(
  Schema.fromJsonString(
    Schema.Union([
      Schema.Struct({ ok: Schema.Literal(true), publicKey: Schema.String }),
      HelperFailure,
    ]),
  ),
);
const decodeSign = Schema.decodeUnknownEffect(
  Schema.fromJsonString(
    Schema.Union([
      Schema.Struct({ ok: Schema.Literal(true), signature: Schema.String }),
      HelperFailure,
    ]),
  ),
);
const KeyFilePublicKey = Schema.decodeUnknownEffect(
  Schema.fromJsonString(Schema.Struct({ publicKey: Schema.String })),
);

const MODEL_PREFIXES: ReadonlyArray<readonly [string, string]> = [
  ["MacBookPro", "MacBook Pro"],
  ["MacBookAir", "MacBook Air"],
  ["MacBook", "MacBook"],
  ["Macmini", "Mac mini"],
  ["MacPro", "Mac Pro"],
  ["iMac", "iMac"],
];

/**
 * The approver's label: "MacBook Pro" from Apple silicon's "MacBook Pro (14-inch, Nov 2024)",
 * else from an Intel model identifier such as "MacBookPro16,1".
 */
export function macModelName(facts: Pick<TouchIdFacts, "productName" | "hwModel">): string {
  const product = facts.productName?.replace(/\s*\(.*$/, "").trim();
  if (product) return product.slice(0, 64);
  const model = facts.hwModel ?? "";
  return MODEL_PREFIXES.find(([prefix]) => model.startsWith(prefix))?.[1] ?? "Mac";
}

/** Null when Touch ID can sign now. Only a Mac with Touch ID, or a key, offers an approver. */
export function touchIdUnavailable(
  facts: TouchIdFacts,
): DesktopTouchIdUnavailable | null | "unsupported" {
  if (!facts.secureEnclave) return "unsupported";
  if (facts.key === "invalidated") return "needs_fixing";
  const hasKey = facts.key !== "absent";
  switch (facts.biometry) {
    case "available":
      return facts.touchId || hasKey ? null : "unsupported";
    case "lockout":
      return "locked_out";
    case "not_enrolled":
      return "no_fingerprints";
    case "disconnected":
    case "not_paired":
      return "keyboard_away";
    case "not_available":
      // macOS reports a closed lid and a Mac without Touch ID alike.
      if (facts.clamshellClosed === true) return "lid_closed";
      if (!hasKey) return "unsupported";
      return facts.clamshellClosed === null ? "keyboard_away" : "unavailable";
    default:
      return hasKey ? "unavailable" : "unsupported";
  }
}

/** The sheet's reason: removing this Mac is its own revoke; anything else approves a request. */
export function signingPurpose(payload: ElevationPayload, keyId: string): "approve" | "remove" {
  const [program, subcommand, ...rest] = payload.command.argv;
  const keyIndex = rest.indexOf("--key-id");
  return program?.split("/").at(-1) === "t3-elevation" &&
    subcommand === "revoke" &&
    keyIndex !== -1 &&
    rest[keyIndex + 1] === keyId
    ? "remove"
    : "approve";
}

/** @public Service construction is part of the canonical Effect module API. */
export const make = Effect.gen(function* () {
  const environment = yield* DesktopEnvironment.DesktopEnvironment;
  const identity = yield* DesktopAppIdentity.DesktopAppIdentity;
  const fs = yield* FileSystem.FileSystem;
  const crypto = yield* Crypto.Crypto;
  const spawner = yield* ChildProcessSpawner.ChildProcessSpawner;
  const path = environment.path;
  const operations = yield* FiberMap.make<string, unknown, DesktopDeviceApprovalError>();

  const fail = (message: string) => new DesktopDeviceApprovalError({ message });
  const bundleExecutable = path.join("T3 Code.app", "Contents", "MacOS", "T3 Code");
  const helper = environment.isPackaged
    ? path.join(environment.resourcesPath, "t3-elevation", bundleExecutable)
    : path.join(environment.rootDir, "native", "t3-se-sign", "dist", bundleExecutable);
  // Checked per call: a dev build may build the helper while the app runs.
  const helperPresent =
    environment.platform === "darwin"
      ? fs.exists(helper).pipe(Effect.orElseSucceed(() => false))
      : Effect.succeed(false);

  const keyFile = Effect.fn("DesktopDeviceApproval.keyFile")(
    function* (environmentId: EnvironmentId) {
      const directory = path.join(yield* identity.resolveUserDataPath, "device-approval");
      yield* fs.makeDirectory(directory, { recursive: true, mode: 0o700 });
      const name = Base64Url.encode(
        yield* crypto.digest("SHA-256", new TextEncoder().encode(environmentId)),
      );
      return path.join(directory, `${name}.json`);
    },
    Effect.mapError(() => fail("Couldn't open this Mac's approval keys.")),
  );

  const run = Effect.fn("DesktopDeviceApproval.run")(
    function* (args: ReadonlyArray<string>, stdinLine?: string) {
      const handle = yield* spawner.spawn(
        ChildProcess.make(helper, args, {
          // `sign` keeps reading stdin: its end, like SIGTERM when this scope closes, closes
          // the sheet. So the line goes in and stdin stays open.
          stdin:
            stdinLine === undefined
              ? "ignore"
              : Stream.concat(
                  Stream.make(new TextEncoder().encode(`${stdinLine}\n`)),
                  Stream.never,
                ),
          stderr: "ignore",
        }),
      );
      return yield* handle.stdout.pipe(Stream.decodeText(), Stream.mkString);
    },
    Effect.scoped,
    Effect.mapError(() => fail("Couldn't run Touch ID on this Mac.")),
  );

  // The helper's message carries framework error codes; it goes to the log, not the user.
  const helperFailure = (error: { readonly code: string; readonly message: string }) =>
    error.code === "cancelled"
      ? Effect.succeed(null)
      : Effect.logWarning("Touch ID failed", error).pipe(
          Effect.andThen(
            Effect.fail(
              fail(
                error.code === "invalidated"
                  ? "This Mac's key stopped working because its fingerprints changed. Remove it and set it up again."
                  : error.code === "unavailable"
                    ? "Touch ID isn't available right now."
                    : "Touch ID failed.",
              ),
            ),
          ),
        );

  const readKeyId = Effect.fn("DesktopDeviceApproval.readKeyId")(
    function* (file: string) {
      const { publicKey } = yield* KeyFilePublicKey(yield* fs.readFileString(file));
      const spki = decodeElevationBase64Url(publicKey);
      return spki === null
        ? null
        : elevationKeyIdFromSpkiSha256(yield* crypto.digest("SHA-256", spki));
    },
    Effect.orElseSucceed(() => null),
  );

  /** Runs under `operationId` so `abort` can interrupt it; interruption reads as cancelled. */
  const abortable = Effect.fn("DesktopDeviceApproval.abortable")(function* <A>(
    operationId: string,
    effect: Effect.Effect<A | null, DesktopDeviceApprovalError>,
  ) {
    const fiber = yield* FiberMap.run(operations, operationId, effect);
    const exit = yield* Fiber.await(fiber);
    return Exit.isFailure(exit) && Cause.hasInterruptsOnly(exit.cause) ? null : yield* exit;
  });

  const state: DesktopDeviceApproval["Service"]["state"] = Effect.fn("DesktopDeviceApproval.state")(
    function* (environmentId) {
      if (!(yield* helperPresent)) return { supported: false } as const;
      const file = yield* keyFile(environmentId);
      const facts = yield* decodeStatus(yield* run(["status", "--key", file]));
      if (!facts.ok) return { supported: false } as const;
      const unavailable = touchIdUnavailable(facts);
      if (unavailable === "unsupported") return { supported: false } as const;
      return {
        supported: true,
        keyId: facts.key === "absent" ? null : yield* readKeyId(file),
        unavailable,
        model: macModelName(facts),
        computerName: facts.computerName,
      } as const;
    },
    Effect.orElseSucceed(() => ({ supported: false }) as const),
  );

  const confirm = Effect.fn("DesktopDeviceApproval.confirm")(function* (
    file: string,
    message: Uint8Array,
    purpose: "approve" | "setup" | "remove",
  ) {
    const result = yield* decodeSign(
      yield* run(["sign", "--key", file, "--purpose", purpose], Base64Url.encode(message)),
    ).pipe(Effect.mapError(() => fail("Touch ID answered in a way T3 Code doesn't understand.")));
    return result.ok ? result.signature : yield* helperFailure(result.error);
  });

  const createKey: DesktopDeviceApproval["Service"]["createKey"] = Effect.fn(
    "DesktopDeviceApproval.createKey",
  )(function* ({ environmentId, operationId }) {
    if (!(yield* helperPresent)) return yield* fail("This build of T3 Code can't use Touch ID.");
    const file = yield* keyFile(environmentId);
    const pending = `${file}.new`;
    const discard = fs.remove(pending, { force: true }).pipe(Effect.ignore);
    const created = yield* abortable(
      operationId,
      Effect.gen(function* () {
        const result = yield* decodeCreate(yield* run(["create", "--key", pending])).pipe(
          Effect.mapError(() => fail("Couldn't make a key on this Mac.")),
        );
        if (!result.ok) {
          yield* Effect.logWarning("Couldn't make a key on this Mac", result.error);
          return yield* fail("Couldn't make a key on this Mac.");
        }
        // Like the phone, setup proves the person here can use the new key before anything changes.
        const challenge = yield* crypto
          .randomBytes(32)
          .pipe(Effect.mapError(() => fail("Couldn't make a key on this Mac.")));
        const signature = yield* confirm(pending, challenge, "setup");
        return signature === null ? null : { publicKey: result.publicKey };
      }),
    ).pipe(Effect.tapError(() => discard));
    if (created === null) {
      yield* discard;
      return null;
    }
    // A key that never got enrolled is replaced; an enrolled one is removed first (`forget`).
    yield* fs
      .rename(pending, file)
      .pipe(Effect.mapError(() => fail("Couldn't save this Mac's key.")));
    return created;
  });

  const sign: DesktopDeviceApproval["Service"]["sign"] = Effect.fn("DesktopDeviceApproval.sign")(
    function* ({ environmentId, operationId, payload }) {
      return yield* abortable(
        operationId,
        Effect.gen(function* () {
          const bytes = decodeElevationBase64Url(payload);
          const decoded = bytes === null ? null : decodeElevationPayload(bytes);
          // The card rendered these bytes; anything it couldn't render is never signed.
          if (bytes === null || decoded === null || Result.isFailure(decoded)) {
            return yield* fail("This request can't be shown, so it can't be approved here.");
          }
          if (!(yield* helperPresent))
            return yield* fail("This build of T3 Code can't use Touch ID.");
          const file = yield* keyFile(environmentId);
          const keyId = yield* readKeyId(file);
          if (keyId === null) return yield* fail("This Mac isn't set up to approve here.");
          if (!decoded.success.keyIds.includes(keyId)) {
            return yield* fail("This Mac's key isn't enrolled on that machine anymore.");
          }
          const signature = yield* confirm(file, bytes, signingPurpose(decoded.success, keyId));
          return signature === null
            ? null
            : ({ keyId, alg: "es256-der", signature } satisfies ElevationSignedResponse);
        }),
      );
    },
  );

  const abort: DesktopDeviceApproval["Service"]["abort"] = (operationId) =>
    FiberMap.remove(operations, operationId);

  const forget: DesktopDeviceApproval["Service"]["forget"] = Effect.fn(
    "DesktopDeviceApproval.forget",
  )(function* (environmentId) {
    // A CryptoKit enclave key is only this blob: deleting the file deletes the key.
    const file = yield* keyFile(environmentId);
    yield* fs
      .remove(file, { force: true })
      .pipe(Effect.mapError(() => fail("Couldn't remove this Mac's key.")));
  });

  return DesktopDeviceApproval.of({ state, createKey, sign, abort, forget });
});

export const layer = Layer.effect(DesktopDeviceApproval, make);
