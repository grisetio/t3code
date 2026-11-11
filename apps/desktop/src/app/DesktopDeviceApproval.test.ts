import * as NodeServices from "@effect/platform-node/NodeServices";
import { expect, it } from "@effect/vitest";
import {
  EnvironmentId,
  elevationKeyIdFromSpkiSha256,
  type ElevationPayload,
} from "@t3tools/contracts";
import * as Crypto from "effect/Crypto";
import * as Deferred from "effect/Deferred";
import * as Effect from "effect/Effect";
import * as Base64Url from "effect/encoding/Base64Url";
import * as Fiber from "effect/Fiber";
import * as FileSystem from "effect/FileSystem";
import * as Option from "effect/Option";
import * as Path from "effect/Path";
import * as Sink from "effect/Sink";
import * as Stream from "effect/Stream";
import * as ChildProcess from "effect/process/ChildProcess";
import * as ChildProcessSpawner from "effect/process/ChildProcessSpawner";

import * as DesktopAppIdentity from "./DesktopAppIdentity.ts";
import * as DesktopDeviceApproval from "./DesktopDeviceApproval.ts";
import * as DesktopEnvironment from "./DesktopEnvironment.ts";

const ENVIRONMENT = EnvironmentId.make("env-1");
const SPKI = new Uint8Array(91).fill(7);
const PUBLIC_KEY = Base64Url.encode(SPKI);
const NONCE = "A".repeat(43);

const facts = (
  overrides: Partial<DesktopDeviceApproval.TouchIdFacts> = {},
): DesktopDeviceApproval.TouchIdFacts => ({
  ok: true,
  secureEnclave: true,
  biometry: "available",
  touchId: true,
  clamshellClosed: false,
  key: "absent",
  productName: "MacBook Pro (14-inch, Nov 2024)",
  hwModel: "Mac16,8",
  computerName: "studio",
  ...overrides,
});

const payloadFor = (
  keyIds: ReadonlyArray<string>,
  argv: ReadonlyArray<string>,
): ElevationPayload => ({
  v: 1,
  kind: "sudo",
  nonce: NONCE,
  issuedAt: 1_793_318_400,
  expiresAt: 1_793_318_500,
  host: { name: "mac", machineId: NONCE },
  user: "alice",
  uid: 501,
  runAs: "root",
  runAsGroup: null,
  argv: ["sudo", ...argv],
  command: { argv, resolvedPath: argv[0] ?? null, warnings: [] },
  cwd: "/Users/alice",
  service: "sudo",
  keyIds,
});

const encodePayload = (payload: ElevationPayload) =>
  Base64Url.encode(new TextEncoder().encode(JSON.stringify(payload)));

interface Call {
  readonly args: ReadonlyArray<string>;
  readonly stdin: string | null;
}

/** Answers like the Swift helper: `reply` returns its stdout, or never answers. */
const fakeHelper = (
  reply: (call: Call) => Effect.Effect<string | "stall", never, FileSystem.FileSystem>,
) => {
  const calls: Call[] = [];
  const closed: string[] = [];
  const spawner = Effect.gen(function* () {
    const fs = yield* FileSystem.FileSystem;
    return ChildProcessSpawner.make((command) =>
      Effect.gen(function* () {
        const { args, options } = command as ChildProcess.StandardCommand;
        const stdin = Stream.isStream(options.stdin)
          ? Option.getOrNull(yield* Stream.runHead(options.stdin).pipe(Effect.orDie))
          : null;
        const call = { args, stdin: stdin === null ? null : new TextDecoder().decode(stdin) };
        calls.push(call);
        yield* Effect.addFinalizer(() => Effect.sync(() => closed.push(args[0] ?? "")));
        const out = yield* reply(call).pipe(Effect.provideService(FileSystem.FileSystem, fs));
        return ChildProcessSpawner.makeHandle({
          pid: ChildProcessSpawner.ProcessId(1),
          exitCode: Effect.never,
          isRunning: Effect.succeed(true),
          kill: () => Effect.void,
          unref: Effect.succeed(Effect.void),
          stdin: Sink.drain,
          stdout: out === "stall" ? Stream.never : Stream.make(new TextEncoder().encode(out)),
          stderr: Stream.empty,
          all: Stream.empty,
          getInputFd: () => Sink.drain,
          getOutputFd: () => Stream.empty,
        });
      }),
    );
  });
  return { calls, closed, spawner };
};

const approvalIn = (helper: ReturnType<typeof fakeHelper>) =>
  Effect.gen(function* () {
    const fs = yield* FileSystem.FileSystem;
    const path = yield* Path.Path;
    const root = yield* fs.makeTempDirectoryScoped();
    const bundle = path.join(root, "native/t3-se-sign/dist/T3 Code.app/Contents/MacOS");
    yield* fs.makeDirectory(bundle, { recursive: true });
    yield* fs.writeFileString(path.join(bundle, "T3 Code"), "");
    const userData = path.join(root, "userData");
    const service = yield* DesktopDeviceApproval.make.pipe(
      Effect.provideService(
        DesktopEnvironment.DesktopEnvironment,
        DesktopEnvironment.DesktopEnvironment.of({
          path,
          platform: "darwin",
          isPackaged: false,
          rootDir: root,
          resourcesPath: path.join(root, "Resources"),
        } as unknown as DesktopEnvironment.DesktopEnvironment["Service"]),
      ),
      Effect.provideService(DesktopAppIdentity.DesktopAppIdentity, {
        resolveUserDataPath: Effect.succeed(userData),
        configure: Effect.void,
      } as unknown as DesktopAppIdentity.DesktopAppIdentity["Service"]),
      Effect.provideService(ChildProcessSpawner.ChildProcessSpawner, yield* helper.spawner),
    );
    const crypto = yield* Crypto.Crypto;
    const keyId = elevationKeyIdFromSpkiSha256(yield* crypto.digest("SHA-256", SPKI));
    const keyDirectory = path.join(userData, "device-approval");
    const keyFiles = fs
      .readDirectory(keyDirectory)
      .pipe(Effect.orElseSucceed((): ReadonlyArray<string> => []));
    return { service, keyId, keyFiles, keyDirectory };
  });

const writeKey = (call: Call) =>
  Effect.gen(function* () {
    const fs = yield* FileSystem.FileSystem;
    yield* fs.writeFileString(call.args[2]!, JSON.stringify({ publicKey: PUBLIC_KEY, blob: "x" }));
  }).pipe(Effect.orDie);

const signature = (call: Call) =>
  Effect.succeed(
    call.args[0] === "create"
      ? JSON.stringify({ ok: true, publicKey: PUBLIC_KEY })
      : JSON.stringify({ ok: true, signature: "MEUCIQ" }),
  );

it("names the Mac by its model", () => {
  expect(DesktopDeviceApproval.macModelName(facts())).toBe("MacBook Pro");
  expect(
    DesktopDeviceApproval.macModelName(facts({ productName: null, hwModel: "MacBookAir10,1" })),
  ).toBe("MacBook Air");
  expect(
    DesktopDeviceApproval.macModelName(facts({ productName: null, hwModel: "Macmini9,1" })),
  ).toBe("Mac mini");
  expect(DesktopDeviceApproval.macModelName(facts({ productName: null, hwModel: null }))).toBe(
    "Mac",
  );
});

it("says why Touch ID can't approve, and offers nothing on a Mac without it", () => {
  const unavailable = DesktopDeviceApproval.touchIdUnavailable;
  expect(unavailable(facts())).toBeNull();
  expect(unavailable(facts({ biometry: "not_available", clamshellClosed: true }))).toBe(
    "lid_closed",
  );
  expect(unavailable(facts({ biometry: "disconnected", clamshellClosed: null }))).toBe(
    "keyboard_away",
  );
  expect(
    unavailable(facts({ biometry: "not_available", clamshellClosed: null, key: "unknown" })),
  ).toBe("keyboard_away");
  expect(unavailable(facts({ biometry: "lockout" }))).toBe("locked_out");
  expect(unavailable(facts({ biometry: "not_enrolled" }))).toBe("no_fingerprints");
  expect(unavailable(facts({ key: "invalidated" }))).toBe("needs_fixing");
  expect(unavailable(facts({ biometry: "not_available", clamshellClosed: null }))).toBe(
    "unsupported",
  );
  expect(unavailable(facts({ secureEnclave: false }))).toBe("unsupported");
});

it("asks to remove this Mac only for the revoke of its own key", () => {
  const revoke = (keyId: string) => [
    "/usr/local/lib/t3-elevation/t3-elevation",
    "revoke",
    "--user",
    "alice",
    "--key-id",
    keyId,
  ];
  const own = "k".repeat(22);
  expect(DesktopDeviceApproval.signingPurpose(payloadFor([own], revoke(own)), own)).toBe("remove");
  expect(DesktopDeviceApproval.signingPurpose(payloadFor([own], revoke("o".repeat(22))), own)).toBe(
    "approve",
  );
  expect(DesktopDeviceApproval.signingPurpose(payloadFor([own], ["/bin/ls"]), own)).toBe("approve");
});

it.layer(NodeServices.layer)("DesktopDeviceApproval", (it) => {
  it.effect("sets up a key only after Touch ID confirms it, then reports it", () =>
    Effect.gen(function* () {
      const helper = fakeHelper((call) =>
        call.args[0] === "status"
          ? Effect.succeed(JSON.stringify(facts({ key: "valid" })))
          : call.args[0] === "create"
            ? writeKey(call).pipe(Effect.andThen(signature(call)))
            : signature(call),
      );
      const { service, keyId, keyFiles } = yield* approvalIn(helper);

      expect(yield* service.createKey({ environmentId: ENVIRONMENT, operationId: "op" })).toEqual({
        publicKey: PUBLIC_KEY,
      });
      expect(helper.calls.map((call) => [call.args[0], call.args.at(-1)])).toEqual([
        ["create", expect.stringMatching(/\.json\.new$/)],
        ["sign", "setup"],
      ]);
      expect(helper.calls[1]?.args[2]).toBe(helper.calls[0]?.args[2]);
      expect(yield* keyFiles).toEqual([expect.stringMatching(/^[A-Za-z0-9_-]{43}\.json$/)]);
      expect(yield* service.state(ENVIRONMENT)).toEqual({
        supported: true,
        keyId,
        unavailable: null,
        model: "MacBook Pro",
        computerName: "studio",
      });

      yield* service.forget(ENVIRONMENT);
      expect(yield* keyFiles).toEqual([]);
    }).pipe(Effect.scoped),
  );

  it.effect("keeps no key when setup's Touch ID is cancelled", () =>
    Effect.gen(function* () {
      const helper = fakeHelper((call) =>
        call.args[0] === "create"
          ? writeKey(call).pipe(Effect.andThen(signature(call)))
          : Effect.succeed(
              JSON.stringify({ ok: false, error: { code: "cancelled", message: "-2" } }),
            ),
      );
      const { service, keyFiles } = yield* approvalIn(helper);

      expect(
        yield* service.createKey({ environmentId: ENVIRONMENT, operationId: "op" }),
      ).toBeNull();
      expect(yield* keyFiles).toEqual([]);
    }).pipe(Effect.scoped),
  );

  it.effect("says Touch ID or the key failed in words, leaving the helper's error out", () =>
    Effect.gen(function* () {
      const failure = (message: string) =>
        Effect.succeed(JSON.stringify({ ok: false, error: { code: "failed", message } }));
      const signFails = fakeHelper((call) =>
        call.args[0] === "create"
          ? writeKey(call).pipe(Effect.andThen(signature(call)))
          : failure("com.apple.LocalAuthentication -1: Error Domain=LAErrorDomain Code=-1"),
      );
      const createFails = fakeHelper(() => failure("create: Error Domain=NSOSStatusErrorDomain"));

      for (const [helper, message] of [
        [signFails, "Touch ID failed."],
        [createFails, "Couldn't make a key on this Mac."],
      ] as const) {
        const { service } = yield* approvalIn(helper);
        const error = yield* service
          .createKey({ environmentId: ENVIRONMENT, operationId: "op" })
          .pipe(Effect.flip);
        expect(error.message).toBe(message);
      }
    }).pipe(Effect.scoped),
  );

  it.effect("signs exactly the payload bytes, with the sheet's reason taken from them", () =>
    Effect.gen(function* () {
      const helper = fakeHelper((call) =>
        call.args[0] === "create"
          ? writeKey(call).pipe(Effect.andThen(signature(call)))
          : signature(call),
      );
      const { service, keyId } = yield* approvalIn(helper);
      yield* service.createKey({ environmentId: ENVIRONMENT, operationId: "setup" });
      const ls = encodePayload(payloadFor([keyId], ["/bin/ls"]));
      const remove = encodePayload(
        payloadFor(
          [keyId],
          [
            "/usr/local/lib/t3-elevation/t3-elevation",
            "revoke",
            "--user",
            "alice",
            "--key-id",
            keyId,
          ],
        ),
      );

      expect(
        yield* service.sign({ environmentId: ENVIRONMENT, operationId: "a", payload: ls }),
      ).toEqual({ keyId, alg: "es256-der", signature: "MEUCIQ" });
      yield* service.sign({ environmentId: ENVIRONMENT, operationId: "b", payload: remove });

      const signs = helper.calls.slice(2);
      expect(signs.map((call) => [call.args.at(-1), call.stdin])).toEqual([
        ["approve", `${ls}\n`],
        ["remove", `${remove}\n`],
      ]);
    }).pipe(Effect.scoped),
  );

  it.effect("refuses bytes the card couldn't render, and keys the machine doesn't list", () =>
    Effect.gen(function* () {
      const helper = fakeHelper((call) =>
        call.args[0] === "create"
          ? writeKey(call).pipe(Effect.andThen(signature(call)))
          : signature(call),
      );
      const { service } = yield* approvalIn(helper);
      yield* service.createKey({ environmentId: ENVIRONMENT, operationId: "setup" });
      const sign = (payload: string) =>
        Effect.flip(service.sign({ environmentId: ENVIRONMENT, operationId: "a", payload }));

      const unknownField = encodePayload({
        ...payloadFor([], ["/bin/ls"]),
        extra: true,
      } as ElevationPayload);
      expect((yield* sign(unknownField)).message).toContain("can't be shown");
      const otherKey = encodePayload(payloadFor(["o".repeat(22)], ["/bin/ls"]));
      expect((yield* sign(otherKey)).message).toContain("isn't enrolled");
      expect(helper.calls.map((call) => call.args[0])).toEqual(["create", "sign"]);
    }).pipe(Effect.scoped),
  );

  it.effect("closes the sheet when another device answers first", () =>
    Effect.gen(function* () {
      const signing = yield* Deferred.make<void>();
      const helper = fakeHelper((call) =>
        call.args[0] === "create"
          ? writeKey(call).pipe(Effect.andThen(signature(call)))
          : call.args.at(-1) === "setup"
            ? signature(call)
            : Deferred.succeed(signing, undefined).pipe(Effect.as("stall" as const)),
      );
      const { service, keyId } = yield* approvalIn(helper);
      yield* service.createKey({ environmentId: ENVIRONMENT, operationId: "setup" });
      const payload = encodePayload(payloadFor([keyId], ["/bin/ls"]));

      const pending = yield* Effect.forkChild(
        service.sign({ environmentId: ENVIRONMENT, operationId: "race", payload }),
      );
      yield* Deferred.await(signing);
      yield* service.abort("race");

      expect(yield* Fiber.join(pending)).toBeNull();
      // Ending the helper's scope stops it: SIGTERM and the end of stdin close the sheet.
      expect(helper.closed).toEqual(["create", "sign", "sign"]);
    }).pipe(Effect.scoped),
  );

  it.effect("offers nothing where the helper isn't built", () =>
    Effect.gen(function* () {
      const fs = yield* FileSystem.FileSystem;
      const path = yield* Path.Path;
      const root = yield* fs.makeTempDirectoryScoped();
      const helper = fakeHelper(signature);
      const service = yield* DesktopDeviceApproval.make.pipe(
        Effect.provideService(
          DesktopEnvironment.DesktopEnvironment,
          DesktopEnvironment.DesktopEnvironment.of({
            path,
            platform: "darwin",
            isPackaged: true,
            rootDir: root,
            resourcesPath: root,
          } as unknown as DesktopEnvironment.DesktopEnvironment["Service"]),
        ),
        Effect.provideService(DesktopAppIdentity.DesktopAppIdentity, {
          resolveUserDataPath: Effect.succeed(root),
          configure: Effect.void,
        } as unknown as DesktopAppIdentity.DesktopAppIdentity["Service"]),
        Effect.provideService(ChildProcessSpawner.ChildProcessSpawner, yield* helper.spawner),
      );
      expect(yield* service.state(ENVIRONMENT)).toEqual({ supported: false });
      expect(helper.calls).toEqual([]);
    }).pipe(Effect.scoped),
  );
});
