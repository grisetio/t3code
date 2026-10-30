import { assert, it } from "@effect/vitest";
import {
  CommandId,
  ElevationRequestId,
  EventId,
  MessageId,
  NodeId,
  ProjectId,
  ProviderDriverKind,
  ProviderInstanceId,
  RunId,
  RuntimeRequestId,
  ThreadId,
  TurnItemId,
} from "@t3tools/contracts";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as SqlitePersistence from "../persistence/Sqlite.ts";
import { CodexProviderCapabilitiesV2 } from "./Adapters/CodexAdapterV2.ts";
import * as EffectOutbox from "./EffectOutbox.ts";
import * as Orchestrator from "./Orchestrator.ts";
import * as ProjectionStore from "./ProjectionStore.ts";
import * as ProviderAdapterRegistry from "./ProviderAdapterRegistry.ts";
import * as ProviderReplayHarness from "./testkit/ProviderReplayHarness.ts";
import type * as ProviderAdapter from "@t3tools/provider-core/server/ProviderAdapter";

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
    { name: "elevation-request" },
    ProviderAdapterRegistry.layerFromAdapters([adapter]),
    { databaseLayer: layerDatabase, runEffectWorker: false },
  ),
);

const threadId = ThreadId.make("thread:elevation");
const runId = RunId.make("run:elevation");
const nodeId = NodeId.make("node:elevation");
const turnItemId = TurnItemId.make("turn-item:elevation:1");

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
});

const record = (orchestrator: Orchestrator.OrchestratorV2["Service"]) =>
  orchestrator.dispatch({
    type: "elevation_request.record",
    commandId: CommandId.make("elevation:record"),
    threadId,
    runId,
    nodeId,
    turnItemId,
    requestId: ElevationRequestId.make("elevation-request-1"),
    kind: "sudo",
    argv: ["sudo", "nix-collect-garbage", "-d"],
    runAs: "root",
    cwd: "/repo",
    host: "macbook",
    warnings: [],
    explanation: "Free disk space.",
    payload: "e30",
    elevationStatus: "pending",
  });

const elevationItem = Effect.fn("test.elevationItem")(function* () {
  const projections = yield* ProjectionStore.ProjectionStoreV2;
  const records = yield* projections.getThreadRecords(threadId, ["turnItems"], {
    turnItemTypes: ["elevation_request"],
    messageRoles: [],
  });
  const item = records.turnItems.find((candidate) => candidate.id === turnItemId);
  assert.strictEqual(item?.type, "elevation_request");
  return item?.type === "elevation_request" ? item : yield* Effect.die("no elevation item");
});

const pendingRequests = Effect.fn("test.pendingRequests")(function* () {
  const projections = yield* ProjectionStore.ProjectionStoreV2;
  const shell = yield* projections.getThreadShell(threadId);
  const projection = yield* projections.getThreadProjection(threadId);
  return [
    shell?.pendingRuntimeRequest ?? null,
    ProjectionStore.threadShellFromProjection(projection).pendingRuntimeRequest,
  ];
});

it.effect("a recorded request waits in the thread, then resolves with who answered", () =>
  Effect.gen(function* () {
    const orchestrator = yield* Orchestrator.OrchestratorV2;
    yield* setupRunningThread;
    yield* record(orchestrator);

    const pending = yield* elevationItem();
    assert.strictEqual(pending.elevationStatus, "pending");
    assert.strictEqual(pending.status, "waiting");
    assert.deepStrictEqual(pending.argv, ["sudo", "nix-collect-garbage", "-d"]);
    for (const summary of yield* pendingRequests()) {
      assert.strictEqual(summary?.id, RuntimeRequestId.make(turnItemId));
      assert.strictEqual(summary?.kind, "command");
      assert.strictEqual(summary?.blocking, true);
    }

    yield* orchestrator.dispatch({
      type: "elevation_request.resolve",
      commandId: CommandId.make("elevation:approve"),
      threadId,
      turnItemId,
      elevationStatus: "approved",
      resolvedBy: { deviceLabel: "Pixel 9 Pro Fold", keyId: "AAAAAAAAAAAAAAAAAAAAAA" },
    });

    const approved = yield* elevationItem();
    assert.strictEqual(approved.elevationStatus, "approved");
    assert.strictEqual(approved.status, "completed");
    assert.deepStrictEqual(approved.resolvedBy, {
      deviceLabel: "Pixel 9 Pro Fold",
      keyId: "AAAAAAAAAAAAAAAAAAAAAA",
    });
    assert.isNotNull(approved.completedAt);
    assert.deepStrictEqual(yield* pendingRequests(), [null, null]);
  }).pipe(Effect.provide(layerTest)),
);

it.effect("the first answer wins and a request is recorded once", () =>
  Effect.gen(function* () {
    const orchestrator = yield* Orchestrator.OrchestratorV2;
    yield* setupRunningThread;
    yield* record(orchestrator);
    yield* orchestrator.dispatch({
      type: "elevation_request.resolve",
      commandId: CommandId.make("elevation:deny"),
      threadId,
      turnItemId,
      elevationStatus: "denied",
      resolvedBy: { deviceLabel: "Web" },
    });

    const late = yield* orchestrator
      .dispatch({
        type: "elevation_request.resolve",
        commandId: CommandId.make("elevation:late-approve"),
        threadId,
        turnItemId,
        elevationStatus: "approved",
        resolvedBy: { deviceLabel: "Pixel 9 Pro Fold", keyId: "AAAAAAAAAAAAAAAAAAAAAA" },
      })
      .pipe(Effect.flip);
    assert.strictEqual(late._tag, "OrchestratorDispatchError");

    const duplicate = yield* orchestrator
      .dispatch({
        type: "elevation_request.record",
        commandId: CommandId.make("elevation:record-again"),
        threadId,
        runId,
        nodeId,
        turnItemId,
        requestId: ElevationRequestId.make("elevation-request-1"),
        kind: "sudo",
        argv: ["sudo", "true"],
        runAs: "root",
        cwd: "/repo",
        host: "macbook",
        warnings: [],
        explanation: null,
        payload: "e30",
        elevationStatus: "pending",
      })
      .pipe(Effect.flip);
    assert.strictEqual(duplicate._tag, "OrchestratorDispatchError");

    const denied = yield* elevationItem();
    assert.strictEqual(denied.elevationStatus, "denied");
    assert.deepStrictEqual(denied.resolvedBy, { deviceLabel: "Web" });
    assert.deepStrictEqual(denied.argv, ["sudo", "nix-collect-garbage", "-d"]);
  }).pipe(Effect.provide(layerTest)),
);

it.effect("a request that failed before a payload existed is recorded already ended", () =>
  Effect.gen(function* () {
    const orchestrator = yield* Orchestrator.OrchestratorV2;
    yield* setupRunningThread;
    yield* orchestrator.dispatch({
      type: "elevation_request.record",
      commandId: CommandId.make("elevation:too-large"),
      threadId,
      runId,
      nodeId,
      turnItemId,
      requestId: ElevationRequestId.make("elevation-request-1"),
      kind: "sudo",
      argv: ["sudo", "cat", "huge"],
      runAs: null,
      cwd: "/repo",
      host: "macbook",
      warnings: [],
      explanation: null,
      payload: null,
      elevationStatus: "cancelled",
      failure: "too_large",
    });

    const item = yield* elevationItem();
    assert.strictEqual(item.elevationStatus, "cancelled");
    assert.strictEqual(item.failure, "too_large");
    assert.deepStrictEqual(yield* pendingRequests(), [null, null]);
  }).pipe(Effect.provide(layerTest)),
);
