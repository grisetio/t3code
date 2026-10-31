// @effect-diagnostics nodeBuiltinImport:off -- Plays the PAM module over a real Unix socket and fakes sudo with scripts.
import * as NodeCrypto from "node:crypto";
import * as NodeFSP from "node:fs/promises";
import * as NodeNet from "node:net";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";

import * as NodeServices from "@effect/platform-node/NodeServices";
import { assert, describe, it } from "@effect/vitest";
import {
  CommandId,
  ELEVATION_SIGNATURE_CONTEXT,
  EventId,
  MessageId,
  NodeId,
  ProjectId,
  ProviderDriverKind,
  ProviderInstanceId,
  RunId,
  ThreadId,
  TurnItemId,
  decodeElevationBase64Url,
  type ElevationKeyId,
  type ElevationRequestId,
  type OrchestrationV2ServerCommand,
} from "@t3tools/contracts";
import type * as ProviderAdapter from "@t3tools/provider-core/server/ProviderAdapter";
import * as HostProcess from "@t3tools/shared/HostProcess";
import { ProviderProcesses, type ProviderProcess } from "@t3tools/shared/ProviderProcesses";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Queue from "effect/Queue";
import * as Stream from "effect/Stream";
import * as TestClock from "effect/testing/TestClock";

import vectorsJson from "../../../../packages/contracts/test-vectors/device-approval.json" with { type: "json" };
import { CodexProviderCapabilitiesV2 } from "../orchestration-v2/Adapters/CodexAdapterV2.ts";
import * as EffectOutbox from "../orchestration-v2/EffectOutbox.ts";
import * as Orchestrator from "../orchestration-v2/Orchestrator.ts";
import * as ProjectionStore from "../orchestration-v2/ProjectionStore.ts";
import * as ProviderAdapterRegistry from "../orchestration-v2/ProviderAdapterRegistry.ts";
import * as ProviderReplayHarness from "../orchestration-v2/testkit/ProviderReplayHarness.ts";
import * as SqlitePersistence from "../persistence/Sqlite.ts";
import * as ProcessRunner from "../processRunner.ts";
import * as ElevationService from "./ElevationService.ts";

const instanceId = ProviderInstanceId.make("codex");
const modelSelection = { instanceId, model: "gpt-5.1-codex" };
const adapter = {
  instanceId,
  driver: ProviderDriverKind.make("codex"),
  getCapabilities: () => Effect.succeed(CodexProviderCapabilitiesV2),
  planSelectionTransition: () => Effect.succeed({ type: "apply_on_next_turn" as const }),
  openSession: () => Effect.die("No provider process needed for elevation requests"),
} as ProviderAdapter.ProviderAdapterV2["Service"];
const layerDatabase = SqlitePersistence.layerMemory;
const layerTest = Layer.mergeAll(
  layerDatabase,
  ProjectionStore.layer.pipe(Layer.provide(layerDatabase)),
  EffectOutbox.layer.pipe(Layer.provide(layerDatabase)),
  ProviderReplayHarness.layerWithRegistry(
    { name: "elevation-service" },
    ProviderAdapterRegistry.layerFromAdapters([adapter]),
    { databaseLayer: layerDatabase, runEffectWorker: false },
  ),
  ProcessRunner.layer.pipe(Layer.provide(NodeServices.layer)),
);

const threadId = ThreadId.make("thread:elevation");
const runId = RunId.make("run:elevation");
const nodeId = NodeId.make("node:elevation");

const basic = vectorsJson.payloads[0]!;
const payloadBytes = decodeElevationBase64Url(basic.payload)!;
const commandText = basic.decoded.argv.join(" ");
const enrolledKeyId = vectorsJson.keys.enrolled.keyId as ElevationKeyId;

/** Signs as an enrolled phone would. */
const sign = (keyPkcs8: string, bytes: Uint8Array) =>
  NodeCrypto.sign(
    "sha256",
    Buffer.concat([Buffer.from(ELEVATION_SIGNATURE_CONTEXT, "latin1"), bytes]),
    { key: Buffer.from(decodeElevationBase64Url(keyPkcs8)!), format: "der", type: "pkcs8" },
  ).toString("base64url");

const server = { pid: 4242, startTime: 1 };
const chainEntry = (pid: number, argv: ReadonlyArray<string>, startTime = 7) => ({
  pid,
  ppid: 0,
  startTime,
  exe: null,
  argv,
  argvTruncated: false,
});
const serverEntry = chainEntry(server.pid, ["node", "t3"], server.startTime);
const hello = (chain: ReadonlyArray<ReturnType<typeof chainEntry>>) => ({
  type: "hello",
  v: 1,
  user: "me",
  uid: 501,
  service: "sudo",
  host: { name: "macbook", machineId: basic.decoded.host.machineId },
  argv: basic.decoded.argv,
  cwd: "/repo",
  chain,
});
// Codex execs the agent's shell under its shared app-server.
const agentChain = [
  chainEntry(500, ["/bin/zsh", "-lc", commandText]),
  chainEntry(300, ["codex", "app-server"]),
  serverEntry,
];

const setupRunningThread = Effect.gen(function* () {
  const orchestrator = yield* Orchestrator.OrchestratorV2;
  const projections = yield* ProjectionStore.ProjectionStoreV2;
  const now = yield* DateTime.now;
  yield* orchestrator.dispatch({
    type: "thread.create",
    commandId: CommandId.make("create-elevation"),
    threadId,
    projectId: ProjectId.make("project:elevation"),
    title: "Elevation",
    modelSelection,
    runtimeMode: "full-access",
    interactionMode: "default",
    branch: null,
    worktreePath: null,
    createdBy: "user",
    creationSource: "web",
  });
  yield* projections.apply({
    id: EventId.make("elevation:run"),
    type: "run.created",
    threadId,
    occurredAt: now,
    payload: {
      id: runId,
      threadId,
      ordinal: 1,
      providerInstanceId: instanceId,
      modelSelection,
      providerThreadId: null,
      userMessageId: MessageId.make("message:elevation"),
      rootNodeId: nodeId,
      activeAttemptId: null,
      status: "running",
      requestedAt: now,
      startedAt: now,
      completedAt: null,
      checkpointId: null,
      contextHandoffId: null,
    },
  });
  yield* projections.apply({
    id: EventId.make("elevation:command"),
    type: "turn-item.updated",
    threadId,
    runId,
    nodeId,
    providerInstanceId: instanceId,
    occurredAt: now,
    payload: {
      id: TurnItemId.make("turn-item:command"),
      threadId,
      runId,
      nodeId,
      providerThreadId: null,
      providerTurnId: null,
      nativeItemRef: null,
      parentItemId: null,
      ordinal: 1,
      status: "running",
      title: null,
      startedAt: now,
      completedAt: null,
      updatedAt: now,
      type: "command_execution",
      input: commandText,
      description: "Free disk space",
    },
  });
});

interface Fixture {
  readonly dir: string;
  readonly socketPath: string;
  readonly service: ElevationService.ElevationService["Service"];
  /** Every elevation command the service dispatched, in order. */
  readonly commands: Queue.Queue<OrchestrationV2ServerCommand>;
}

const installedHelper = (dir: string) => NodePath.join(dir, "lib", "t3-elevation", "t3-elevation");

const writeScript = (path: string, text: string) =>
  NodeFSP.writeFile(path, `#!/bin/sh\n${text}`, { mode: 0o755 });

const makeFixture = Effect.fn("test.makeFixture")(function* (options?: {
  readonly peerUid?: number;
  readonly providerProcesses?: ReadonlyArray<ProviderProcess>;
  /** Set to run without peer credentials, as under Electron's Node. */
  readonly plausiblePeer?: (hello: { readonly chain: ReadonlyArray<{ pid: number }> }) => boolean;
}) {
  const dir = yield* Effect.acquireRelease(
    Effect.promise(() => NodeFSP.mkdtemp(NodePath.join(NodeOS.tmpdir(), "t3-elev-"))),
    (directory) => Effect.promise(() => NodeFSP.rm(directory, { recursive: true, force: true })),
  );
  const socketPath = NodePath.join(dir, "elevation.sock");
  const etcDir = NodePath.join(dir, "etc");
  yield* Effect.promise(async () => {
    await NodeFSP.mkdir(NodePath.join(etcDir, "users"), { recursive: true });
    await NodeFSP.mkdir(NodePath.join(etcDir, "keys", "me"), { recursive: true });
    await NodeFSP.writeFile(
      NodePath.join(etcDir, "users", "me.toml"),
      `version = 1\nenabled = true\nsocket = ${JSON.stringify(socketPath)}\n`,
    );
    await NodeFSP.writeFile(
      NodePath.join(etcDir, "keys", "me", `${enrolledKeyId}.json`),
      JSON.stringify({
        version: 1,
        keyId: enrolledKeyId,
        alg: "es256",
        publicKey: vectorsJson.keys.enrolled.spkiDer,
        label: "Pixel",
        securityLevel: "strongbox",
        enrolledAt: "2026-10-30T12:00:00Z",
      }),
    );
    // sudo strips its options and runs the command; the log shows what it got.
    // With a `touch-id` file PAM approves without asking for the password, and
    // with `no-approval` nothing approves `sudo -n`.
    await writeScript(
      NodePath.join(dir, "sudo"),
      `printf '%s\\n' "$@" > "${dir}/sudo.args"
while [ $# -gt 0 ]; do
  case "$1" in -S) S=1; shift;; -n) N=1; shift;; -k) shift;; -p) shift 2;; *) break;; esac
done
if [ -n "$N" ] && [ -e "${dir}/no-approval" ]; then
  echo "sudo: a password is required" >&2; exit 1
fi
if [ -n "$S" ] && [ ! -e "${dir}/touch-id" ]; then
  IFS= read -r password
  if [ "$password" != "hunter2" ]; then echo "Sorry, try again." >&2; exit 1; fi
fi
exec "$@"
`,
    );
    const helper = `printf '%s\\n' "$@" > "${dir}/helper.args"
case "$1" in
  status) echo '{"ok":true,"protocol":1,"platform":"test","checks":[],"config":null,"keys":[],"plannedChanges":[{"path":"/etc/pam.d/sudo","summary":"Add the device approval line"}],"setupOutsideT3":true}';;
  install)
    while [ $# -gt 0 ]; do [ "$1" = "--key" ] && cp "$2" "${dir}/helper.key"; shift; done
    echo '{"ok":true}';;
  enroll) cat > "${dir}/helper.stdin"; echo '{"ok":true}';;
  revoke) echo '{"ok":false,"error":{"code":"not_found","message":"No such key"}}'; exit 1;;
esac
`;
    // The dev override, and the copy install leaves, closed to others like a root-owned one.
    await writeScript(NodePath.join(dir, "helper"), helper);
    await NodeFSP.mkdir(NodePath.dirname(installedHelper(dir)), { recursive: true });
    await NodeFSP.chmod(NodePath.join(dir, "lib"), 0o755);
    await NodeFSP.chmod(NodePath.dirname(installedHelper(dir)), 0o755);
    await writeScript(installedHelper(dir), helper);
  });

  const commands = yield* Queue.unbounded<OrchestrationV2ServerCommand>();
  const orchestrator = yield* Orchestrator.OrchestratorV2;
  const spy = Orchestrator.OrchestratorV2.of({
    ...orchestrator,
    dispatch: (command) =>
      orchestrator
        .dispatch(command)
        .pipe(
          Effect.tap(() =>
            command.type.startsWith("elevation_request.")
              ? Queue.offer(commands, command)
              : Effect.void,
          ),
        ),
  });
  const listed = options?.providerProcesses ?? [];
  const service = yield* ElevationService.make({
    user: "me",
    socketPath,
    hostPaths: {
      etcDir,
      pamDir: NodePath.join(dir, "pam.d"),
      helperPath: installedHelper(dir),
      helperRoot: dir,
      rootUid: NodeOS.userInfo().uid,
      platform: "darwin",
    },
    helperOverride: NodePath.join(dir, "helper"),
    bundledHelperPath: null,
    sudoPath: NodePath.join(dir, "sudo"),
    attestation: "release",
    devicesStatePath: NodePath.join(dir, "elevation-devices.json"),
    server: () => server,
    trustedPeerUid: 0,
    peerUid: () => (options?.plausiblePeer === undefined ? (options?.peerUid ?? 0) : null),
    peerCredentialsSupported: () => options?.plausiblePeer === undefined,
    plausiblePeer: options?.plausiblePeer ?? (() => true),
  }).pipe(
    Effect.provideService(Orchestrator.OrchestratorV2, spy),
    Effect.provideService(HostProcess.Platform, "darwin"),
    Effect.provideService(ProviderProcesses, { register: () => () => {}, list: () => listed }),
  );
  // Status starts the listener once the config points at this server.
  assert.isTrue((yield* service.status).ownsApprovals);
  return { dir, socketPath, service, commands } satisfies Fixture;
});

/** Plays the PAM module's side of one connection. */
const connectModule = Effect.fn("test.connectModule")(function* (socketPath: string) {
  const socket = yield* Effect.acquireRelease(
    Effect.callback<NodeNet.Socket>((resume) => {
      const socket = NodeNet.createConnection(socketPath);
      socket.once("connect", () => resume(Effect.succeed(socket)));
      socket.once("error", (cause) => resume(Effect.die(cause)));
    }),
    (socket) => Effect.sync(() => socket.destroy()),
  );
  const lines = yield* Queue.unbounded<string | null>();
  let buffer = "";
  socket.on("data", (chunk: Buffer) => {
    buffer += chunk.toString("utf8");
    for (let end = buffer.indexOf("\n"); end !== -1; end = buffer.indexOf("\n")) {
      Queue.offerUnsafe(lines, buffer.slice(0, end));
      buffer = buffer.slice(end + 1);
    }
  });
  socket.once("close", () => Queue.offerUnsafe(lines, null));
  return {
    send: (message: object) => Effect.sync(() => socket.write(`${JSON.stringify(message)}\n`)),
    /** The next message, or null once the server closed. */
    receive: Queue.take(lines).pipe(
      Effect.map((line): Record<string, unknown> | null =>
        line === null ? null : JSON.parse(line),
      ),
    ),
    close: Effect.sync(() => socket.destroy()),
  };
});

const firstPending = (service: Fixture["service"]) =>
  service.pendingRequests.pipe(
    Stream.filter((pending) => pending.requests.length > 0),
    Stream.runHead,
    Effect.map((pending) => Option.getOrThrow(pending).requests),
  );

/** Hello, `mine`, request, and the pending entry phones see. */
const openRequest = Effect.fn("test.openRequest")(function* (fixture: Fixture) {
  const module = yield* connectModule(fixture.socketPath);
  yield* module.send(hello(agentChain));
  assert.deepStrictEqual(yield* module.receive, { type: "hello_reply", v: 1, decision: "mine" });
  yield* module.send({ type: "request", payload: basic.payload });
  const [request] = yield* firstPending(fixture.service);
  return { module, request: request! };
});

const approval = (
  requestId: ElevationRequestId,
  signature = sign(vectorsJson.keys.enrolled.pkcs8Der, payloadBytes),
) => ({
  requestId,
  decision: "approve" as const,
  keyId: enrolledKeyId,
  alg: "es256-der" as const,
  signature,
});

const nextResolve = (commands: Fixture["commands"]) =>
  Effect.gen(function* () {
    const command = yield* Queue.take(commands);
    assert.strictEqual(command.type, "elevation_request.resolve");
    return command.type === "elevation_request.resolve"
      ? command
      : yield* Effect.die("not resolve");
  });

describe("ElevationService", () => {
  it.effect(
    "records an attributed request, forwards a verified approval, and resolves on the result",
    () =>
      Effect.gen(function* () {
        yield* setupRunningThread;
        const fixture = yield* makeFixture();
        const { module, request } = yield* openRequest(fixture);
        assert.strictEqual(request.threadId, threadId);
        assert.strictEqual(request.explanation, "Free disk space");
        assert.strictEqual(request.agentCommand, commandText);
        assert.strictEqual(request.payload, basic.payload);

        const recorded = yield* Queue.take(fixture.commands);
        assert.strictEqual(recorded.type, "elevation_request.record");
        if (recorded.type === "elevation_request.record") {
          assert.strictEqual(recorded.elevationStatus, "pending");
          assert.strictEqual(recorded.turnItemId, request.turnItemId);
          assert.deepStrictEqual(recorded.argv, basic.decoded.argv);
          assert.strictEqual(recorded.agentCommand, commandText);
        }

        const signature = sign(vectorsJson.keys.enrolled.pkcs8Der, payloadBytes);
        yield* fixture.service.respond(approval(request.requestId, signature));
        assert.deepStrictEqual(yield* module.receive, {
          type: "response",
          decision: "approve",
          keyId: enrolledKeyId,
          alg: "es256-der",
          signature,
        });
        // Answered requests leave the set phones sign from.
        assert.deepStrictEqual(
          (yield* Stream.runHead(fixture.service.pendingRequests)).pipe(Option.getOrThrow),
          { requests: [] },
        );

        yield* module.send({ type: "result", outcome: "approved" });
        const resolved = yield* nextResolve(fixture.commands);
        assert.strictEqual(resolved.elevationStatus, "approved");
        assert.deepStrictEqual(resolved.resolvedBy, { deviceLabel: "Pixel", keyId: enrolledKeyId });
        assert.isNull(yield* module.receive);
        const devices = (yield* fixture.service.status).devices;
        assert.isNotNull(devices[0]?.lastUsedAt);
      }).pipe(Effect.scoped, Effect.provide(layerTest)),
  );

  it.effect("forwards a deny without a signature", () =>
    Effect.gen(function* () {
      yield* setupRunningThread;
      const fixture = yield* makeFixture();
      const { module, request } = yield* openRequest(fixture);
      yield* fixture.service.respond({ requestId: request.requestId, decision: "deny" });
      assert.deepStrictEqual(yield* module.receive, { type: "response", decision: "deny" });
      yield* module.send({ type: "result", outcome: "denied" });
      yield* Queue.take(fixture.commands);
      const resolved = yield* nextResolve(fixture.commands);
      assert.strictEqual(resolved.elevationStatus, "denied");
      assert.isNull(resolved.resolvedBy);
    }).pipe(Effect.scoped, Effect.provide(layerTest)),
  );

  it.effect("cancels an interrupted run's unanswered request and resolves it cancelled", () =>
    Effect.gen(function* () {
      yield* setupRunningThread;
      const fixture = yield* makeFixture();
      const { module, request } = yield* openRequest(fixture);
      yield* Queue.take(fixture.commands);
      yield* fixture.service.cancelRun(runId);
      assert.deepStrictEqual(yield* module.receive, { type: "cancel", reason: "interrupted" });
      const resolved = yield* nextResolve(fixture.commands);
      assert.strictEqual(resolved.elevationStatus, "cancelled");
      assert.isNull(resolved.resolvedBy);
      assert.deepStrictEqual(
        (yield* Stream.runHead(fixture.service.pendingRequests)).pipe(Option.getOrThrow),
        { requests: [] },
      );
      const late = yield* fixture.service
        .respond({ requestId: request.requestId, decision: "deny" })
        .pipe(Effect.flip);
      assert.strictEqual(late.reason, "not_found");
    }).pipe(Effect.scoped, Effect.provide(layerTest)),
  );

  it.effect("rejects a bad signature before anything reaches the module", () =>
    Effect.gen(function* () {
      yield* setupRunningThread;
      const fixture = yield* makeFixture();
      const { module, request } = yield* openRequest(fixture);
      const otherKey = sign(vectorsJson.keys.other.pkcs8Der, payloadBytes);
      const error = yield* fixture.service
        .respond(approval(request.requestId, otherKey))
        .pipe(Effect.flip);
      assert.strictEqual(error.reason, "invalid_signature");

      // Still answerable, and the deny is the first thing the module hears.
      yield* fixture.service.respond({ requestId: request.requestId, decision: "deny" });
      assert.deepStrictEqual(yield* module.receive, { type: "response", decision: "deny" });
    }).pipe(Effect.scoped, Effect.provide(layerTest)),
  );

  it.effect("lets only the first of two answers through", () =>
    Effect.gen(function* () {
      yield* setupRunningThread;
      const fixture = yield* makeFixture();
      const { module, request } = yield* openRequest(fixture);
      const answers = yield* Effect.all(
        [
          fixture.service.respond(approval(request.requestId)).pipe(Effect.result),
          fixture.service
            .respond({ requestId: request.requestId, decision: "deny" })
            .pipe(Effect.result),
        ],
        { concurrency: "unbounded" },
      );
      const failures = answers.flatMap((answer) =>
        answer._tag === "Failure" ? [answer.failure.reason] : [],
      );
      assert.deepStrictEqual(failures, ["already_resolved"]);

      const response = yield* module.receive;
      assert.strictEqual(response?.type, "response");
      yield* module.send({
        type: "result",
        outcome: response?.decision === "approve" ? "approved" : "denied",
      });
      assert.isNull(yield* module.receive);
      const late = yield* fixture.service
        .respond({ requestId: request.requestId, decision: "deny" })
        .pipe(Effect.flip);
      assert.strictEqual(late.reason, "not_found");
    }).pipe(Effect.scoped, Effect.provide(layerTest)),
  );

  it.effect("expires a request five seconds after its expiresAt and closes", () =>
    Effect.gen(function* () {
      yield* setupRunningThread;
      const fixture = yield* makeFixture();
      const { module } = yield* openRequest(fixture);
      yield* Queue.take(fixture.commands);
      yield* TestClock.setTime((basic.decoded.expiresAt + 5) * 1000);
      const resolved = yield* nextResolve(fixture.commands);
      assert.strictEqual(resolved.elevationStatus, "expired");
      assert.isNull(yield* module.receive);
    }).pipe(Effect.scoped, Effect.provide(layerTest)),
  );

  it.effect("cancels a request whose module hung up", () =>
    Effect.gen(function* () {
      yield* setupRunningThread;
      const fixture = yield* makeFixture();
      const { module } = yield* openRequest(fixture);
      yield* Queue.take(fixture.commands);
      yield* module.close;
      const resolved = yield* nextResolve(fixture.commands);
      assert.strictEqual(resolved.elevationStatus, "cancelled");
      assert.deepStrictEqual(
        Option.getOrThrow(yield* Stream.runHead(fixture.service.pendingRequests)),
        { requests: [] },
      );
    }).pipe(Effect.scoped, Effect.provide(layerTest)),
  );

  it.effect("records a request the module couldn't encode as already ended", () =>
    Effect.gen(function* () {
      yield* setupRunningThread;
      const fixture = yield* makeFixture();
      const module = yield* connectModule(fixture.socketPath);
      yield* module.send(hello(agentChain));
      yield* module.receive;
      yield* module.send({ type: "result", outcome: "too_large" });
      const recorded = yield* Queue.take(fixture.commands);
      assert.strictEqual(recorded.type, "elevation_request.record");
      if (recorded.type === "elevation_request.record") {
        assert.strictEqual(recorded.elevationStatus, "cancelled");
        assert.strictEqual(recorded.failure, "too_large");
        assert.isNull(recorded.payload);
      }
    }).pipe(Effect.scoped, Effect.provide(layerTest)),
  );

  it.effect("shows a sudo from a shared provider process without a thread", () =>
    Effect.gen(function* () {
      yield* setupRunningThread;
      const fixture = yield* makeFixture({
        providerProcesses: [{ pid: 300, startTime: 7, threadId: null }],
      });
      const module = yield* connectModule(fixture.socketPath);
      yield* module.send({
        ...hello([chainEntry(300, ["codex", "app-server"]), serverEntry]),
        argv: ["sudo", "whoami"],
      });
      assert.deepStrictEqual(yield* module.receive, {
        type: "hello_reply",
        v: 1,
        decision: "mine",
      });
      yield* module.send({ type: "request", payload: basic.payload });
      const [request] = yield* firstPending(fixture.service);
      assert.isNull(request?.threadId);
      assert.isNull(request?.turnItemId);
      yield* fixture.service.respond({ requestId: request!.requestId, decision: "deny" });
      assert.deepStrictEqual(yield* module.receive, { type: "response", decision: "deny" });
    }).pipe(Effect.scoped, Effect.provide(layerTest)),
  );

  it.effect("answers not_mine for sudo outside this server and for unknown versions", () =>
    Effect.gen(function* () {
      yield* setupRunningThread;
      const fixture = yield* makeFixture();
      const outside = yield* connectModule(fixture.socketPath);
      yield* outside.send(hello([chainEntry(9, ["-zsh"]), chainEntry(1, ["launchd"])]));
      assert.deepStrictEqual(yield* outside.receive, {
        type: "hello_reply",
        v: 1,
        decision: "not_mine",
      });
      assert.isNull(yield* outside.receive);

      const future = yield* connectModule(fixture.socketPath);
      yield* future.send({ type: "hello", v: 2 });
      assert.deepStrictEqual(yield* future.receive, {
        type: "hello_reply",
        v: 1,
        decision: "not_mine",
      });
    }).pipe(Effect.scoped, Effect.provide(layerTest)),
  );

  it.effect("drops a connection that doesn't come from root", () =>
    Effect.gen(function* () {
      const fixture = yield* makeFixture({ peerUid: 501 });
      const module = yield* connectModule(fixture.socketPath);
      yield* module.send(hello(agentChain));
      assert.isNull(yield* module.receive);
    }).pipe(Effect.scoped, Effect.provide(layerTest)),
  );

  it.effect("without peer credentials, still serves and drops an implausible hello", () =>
    Effect.gen(function* () {
      yield* setupRunningThread;
      const fixture = yield* makeFixture({
        plausiblePeer: (hello) => hello.chain[0]?.pid === 500,
      });
      assert.isTrue((yield* fixture.service.status).supported);
      const { request } = yield* openRequest(fixture);
      assert.strictEqual(request.threadId, threadId);

      const fake = yield* connectModule(fixture.socketPath);
      yield* fake.send(hello([chainEntry(600, ["/bin/zsh", "-lc", commandText]), serverEntry]));
      assert.isNull(yield* fake.receive);
    }).pipe(Effect.scoped, Effect.provide(layerTest)),
  );
});

describe("ElevationService helper", () => {
  const read = (path: string) => Effect.promise(() => NodeFSP.readFile(path, "utf8"));
  const lines = (text: string) => text.trimEnd().split("\n");

  it.live("installs with the password on sudo's stdin and the key in a removed 0600 file", () =>
    Effect.gen(function* () {
      const fixture = yield* makeFixture();
      const device = {
        label: "Pixel",
        publicKey: vectorsJson.keys.newDevice.spkiDer,
        challenge: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
        attestationChain: ["AAAA"] as [string],
      };
      const result = yield* fixture.service.install({ password: "hunter2", device });
      assert.strictEqual(result.type, "installed");
      if (result.type === "installed") {
        assert.deepStrictEqual(result.status.plannedChanges, [
          { path: "/etc/pam.d/sudo", summary: "Add the device approval line" },
        ]);
        assert.isTrue(result.status.setupOutsideT3);
      }
      const sudoArgs = lines(yield* read(NodePath.join(fixture.dir, "sudo.args")));
      assert.deepStrictEqual(sudoArgs.slice(0, 5), [
        "-S",
        "-k",
        "-p",
        "",
        NodePath.join(fixture.dir, "helper"),
      ]);
      const helperArgs = lines(yield* read(NodePath.join(fixture.dir, "helper.args")));
      // `status` ran after install and overwrote the log; the key copy shows install ran.
      assert.deepStrictEqual(helperArgs, ["status", "--user", "me"]);
      assert.deepStrictEqual(
        JSON.parse(yield* read(NodePath.join(fixture.dir, "helper.key"))),
        device,
      );
      const keyPath = sudoArgs[sudoArgs.indexOf("--key") + 1]!;
      assert.isFalse(
        yield* Effect.promise(() =>
          NodeFSP.access(keyPath).then(
            () => true,
            () => false,
          ),
        ),
      );
    }).pipe(Effect.scoped, Effect.provide(layerTest)),
  );

  it.live("returns a terminal command when there is no password", () =>
    Effect.gen(function* () {
      const fixture = yield* makeFixture();
      const result = yield* fixture.service.install({
        password: null,
        device: {
          label: "Pixel",
          publicKey: vectorsJson.keys.newDevice.spkiDer,
          challenge: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
          attestationChain: ["AAAA"] as [string],
        },
      });
      assert.strictEqual(result.type, "terminal_command");
      if (result.type !== "terminal_command") return;
      assert.match(result.command, /^'sudo' '.*\/helper' 'install' '--user' 'me' '--socket' /);
      const keyPath = /'--key' '([^']+)'/.exec(result.command)?.[1];
      assert.isDefined(keyPath);
      assert.include(result.command, `; rm -f '${keyPath}'`);
      const stat = yield* Effect.promise(() => NodeFSP.stat(keyPath!));
      assert.strictEqual(stat.mode & 0o777, 0o600);

      // A command the user never ran leaves its key file until it is an hour old.
      const exists = (path: string) =>
        Effect.promise(() =>
          NodeFSP.access(path).then(
            () => true,
            () => false,
          ),
        );
      yield* fixture.service.status;
      assert.isTrue(yield* exists(keyPath!));
      yield* Effect.promise(() => NodeFSP.utimes(keyPath!, 1_000_000, 1_000_000));
      yield* fixture.service.status;
      assert.isFalse(yield* exists(keyPath!));
      assert.isTrue(yield* exists(NodePath.join(fixture.dir, "helper")));
    }).pipe(Effect.scoped, Effect.provide(layerTest)),
  );

  it.live("reports a wrong password and the helper's own error", () =>
    Effect.gen(function* () {
      const fixture = yield* makeFixture();
      const wrong = yield* fixture.service.uninstall({ password: "nope" }).pipe(Effect.flip);
      assert.strictEqual(wrong.reason, "wrong_password");
      const failed = yield* fixture.service
        .revoke({ keyId: enrolledKeyId, password: "hunter2" })
        .pipe(Effect.flip);
      assert.strictEqual(failed.reason, "helper_failed");
      assert.strictEqual(failed.detail, "No such key");
    }).pipe(Effect.scoped, Effect.provide(layerTest)),
  );

  it.live("enrolls through sudo -n with the enrollment object on stdin", () =>
    Effect.gen(function* () {
      const fixture = yield* makeFixture();
      const device = {
        label: "Pixel 2",
        publicKey: vectorsJson.keys.newDevice.spkiDer,
        challenge: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
        attestationChain: ["AAAA"] as [string],
      };
      yield* fixture.service.enroll({ device });
      assert.deepStrictEqual(lines(yield* read(NodePath.join(fixture.dir, "sudo.args"))), [
        "-n",
        installedHelper(fixture.dir),
        "enroll",
        "--user",
        "me",
        "--label",
        "Pixel 2",
        "--public-key",
        device.publicKey,
        "--challenge",
        device.challenge,
      ]);
      assert.strictEqual(
        yield* read(NodePath.join(fixture.dir, "helper.stdin")),
        `${vectorsJson.helperInput.marker}\n${JSON.stringify(device)}`,
      );
    }).pipe(Effect.scoped, Effect.provide(layerTest)),
  );

  it.live(
    "frames the enrollment so the helper finds it whether or not sudo read the password",
    () =>
      Effect.gen(function* () {
        const fixture = yield* makeFixture();
        const device = {
          label: "Pixel 2",
          publicKey: vectorsJson.keys.newDevice.spkiDer,
          challenge: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
          attestationChain: ["AAAA"] as [string],
        };
        const framed = `${vectorsJson.helperInput.marker}\n${JSON.stringify(device)}`;
        const helperStdin = NodePath.join(fixture.dir, "helper.stdin");
        yield* fixture.service.enroll({ device, password: "hunter2" });
        assert.strictEqual(yield* read(helperStdin), framed);

        // Touch ID, or an enrolled phone, approves without sudo reading the password.
        yield* Effect.promise(() => NodeFSP.writeFile(NodePath.join(fixture.dir, "touch-id"), ""));
        yield* fixture.service.enroll({ device, password: "hunter2" });
        assert.strictEqual(yield* read(helperStdin), `hunter2\n${framed}`);
      }).pipe(Effect.scoped, Effect.provide(layerTest)),
  );

  it.live("says the password is needed when nothing approved sudo -n", () =>
    Effect.gen(function* () {
      const fixture = yield* makeFixture();
      yield* Effect.promise(() => NodeFSP.writeFile(NodePath.join(fixture.dir, "no-approval"), ""));
      const failed = yield* fixture.service.uninstall({}).pipe(Effect.flip);
      assert.strictEqual(failed.reason, "password_required");
      assert.isUndefined(failed.detail);
    }).pipe(Effect.scoped, Effect.provide(layerTest)),
  );

  it.live("reports an installed helper someone other than root could replace", () =>
    Effect.gen(function* () {
      const fixture = yield* makeFixture();
      const trusted = yield* fixture.service.status;
      assert.isTrue(trusted.helperInstalled);
      assert.isFalse(trusted.checks.some((check) => check.id === "helper"));

      yield* Effect.promise(() => NodeFSP.chmod(NodePath.join(fixture.dir, "lib"), 0o777));
      const untrusted = yield* fixture.service.status;
      assert.isFalse(untrusted.helperInstalled);
      const check = untrusted.checks.find((candidate) => candidate.id === "helper");
      assert.isFalse(check?.ok);
      assert.include(check?.message, installedHelper(fixture.dir));
      // Agent sudo still goes to the phone; only managing devices needs the helper.
      assert.strictEqual(untrusted.ready, trusted.ready);
    }).pipe(Effect.scoped, Effect.provide(layerTest)),
  );

  it.live("runs only the installed helper as root once installed, never the override", () =>
    Effect.gen(function* () {
      const fixture = yield* makeFixture();
      const sudoArgs = NodePath.join(fixture.dir, "sudo.args");
      const device = {
        label: "Pixel 2",
        publicKey: vectorsJson.keys.newDevice.spkiDer,
        challenge: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
        attestationChain: ["AAAA"] as [string],
      };
      yield* fixture.service.enroll({ device, password: "hunter2" });
      assert.include(lines(yield* read(sudoArgs)), installedHelper(fixture.dir));
      assert.notInclude(lines(yield* read(sudoArgs)), NodePath.join(fixture.dir, "helper"));

      // Anyone who can write a folder above it could swap it between approval and exec.
      yield* Effect.promise(() => NodeFSP.rm(sudoArgs));
      yield* Effect.promise(() => NodeFSP.chmod(NodePath.join(fixture.dir, "lib"), 0o777));
      const refused = yield* fixture.service.enroll({ device }).pipe(Effect.flip);
      assert.strictEqual(refused.reason, "not_available");
      assert.include(refused.detail, installedHelper(fixture.dir));
      const sudoRan = yield* Effect.promise(() =>
        NodeFSP.access(sudoArgs).then(
          () => true,
          () => false,
        ),
      );
      assert.isFalse(sudoRan);
    }).pipe(Effect.scoped, Effect.provide(layerTest)),
  );
});

describe("elevationSudoPath", () => {
  // A user-writable folder early in PATH (Homebrew on Apple Silicon) could
  // hold a sudo that takes the setup password or fakes the helper's reply.
  it("runs the system sudo by absolute path, NixOS's wrapper where it exists", () => {
    const exists = (present: ReadonlyArray<string>) => (path: string) => present.includes(path);
    assert.deepStrictEqual(
      [
        ElevationService.elevationSudoPath("darwin", exists(["/usr/bin/sudo"])),
        ElevationService.elevationSudoPath("linux", exists(["/usr/bin/sudo"])),
        ElevationService.elevationSudoPath(
          "linux",
          exists(["/run/wrappers/bin/sudo", "/usr/bin/sudo"]),
        ),
        ElevationService.elevationSudoPath("linux", exists([])),
      ],
      ["/usr/bin/sudo", "/usr/bin/sudo", "/run/wrappers/bin/sudo", "/usr/bin/sudo"],
    );
  });
});

describe("elevationAttestation", () => {
  it("takes test attestation from the environment only when running from source", () => {
    const test = { T3_ELEVATION_ALLOW_TEST_ATTESTATION: "1" };
    const both = { ...test, T3_ELEVATION_ALLOW_DEV_ATTESTATION: "1" };
    assert.strictEqual(
      ElevationService.elevationAttestation({ env: test, packaged: false }),
      "test",
    );
    assert.strictEqual(
      ElevationService.elevationAttestation({ env: test, packaged: true }),
      "release",
    );
    assert.strictEqual(ElevationService.elevationAttestation({ env: both, packaged: true }), "dev");
    assert.strictEqual(
      ElevationService.elevationAttestation({
        env: { T3_ELEVATION_ALLOW_DEV_ATTESTATION: "1" },
        packaged: true,
      }),
      "dev",
    );
  });
});
