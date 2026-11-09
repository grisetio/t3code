// @effect-diagnostics nodeBuiltinImport:off -- A root-only Unix socket and 0600 key files, which Effect's platform APIs don't cover.
/**
 * Device approval for agent `sudo` (docs/internals/device-approval.md): the
 * PAM module asks this server over a Unix socket, a phone signs, and the
 * module checks the signature. This service owns that socket, picks the
 * thread a request belongs to, keeps the pending set, and runs the root
 * helper for setup.
 */
import * as NodeCrypto from "node:crypto";
import * as NodeFS from "node:fs";
import * as NodeFSP from "node:fs/promises";
import * as NodeNet from "node:net";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";

import {
  CommandId,
  type RunId,
  decodeElevationBase64Url,
  decodeElevationPayload,
  ELEVATION_HELPER_INSTALL_PATH,
  ElevationError,
  ElevationRequestId,
  ProviderDriverKind,
  TurnItemId,
  type ElevationCheck,
  type ElevationDevice,
  type ElevationEndedRequest,
  type ElevationEnrollInput,
  ElevationEnrollmentDevice,
  elevationApproverKind,
  elevationWebauthnRegistrationRefusal,
  isElevationUnattestedDevice,
  type ElevationFailureReason,
  type ElevationInstallInput,
  type ElevationInstallResult,
  type ElevationPayload,
  type ElevationPendingRequest,
  type ElevationPendingRequests,
  type ElevationRequestSeries,
  type ElevationRespondInput,
  type ElevationRevokeInput,
  type ElevationStatus,
  type ElevationUninstallInput,
  type OrchestrationV2ElevationChanges,
  type OrchestrationV2ElevationRequestFailure,
  type OrchestrationV2ElevationResolvedBy,
  type OrchestrationV2ProviderRef,
} from "@t3tools/contracts";
import { DeviceApprovalInstructions } from "@t3tools/provider-core/server/runtimeInstructions";
import * as HostProcess from "@t3tools/shared/HostProcess";
import { ProviderProcesses } from "@t3tools/shared/ProviderProcesses";
import * as Clock from "effect/Clock";
import * as Context from "effect/Context";
import * as DateTime from "effect/DateTime";
import * as Deferred from "effect/Deferred";
import type * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as Fiber from "effect/Fiber";
import * as FiberSet from "effect/FiberSet";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Queue from "effect/Queue";
import * as Schema from "effect/Schema";
import * as Scope from "effect/Scope";
import * as Semaphore from "effect/Semaphore";
import type * as Stream from "effect/Stream";
import * as SubscriptionRef from "effect/SubscriptionRef";

import * as ServerConfig from "../config.ts";
import * as Orchestrator from "../orchestration-v2/Orchestrator.ts";
import * as ProjectionStore from "../orchestration-v2/ProjectionStore.ts";
import * as ProcessRunner from "../processRunner.ts";
import { attribute, type LiveRun, type ServerSudo } from "./attribution.ts";
import { uncommittedChanges } from "./changes.ts";
import { ElevationRunCancellation } from "./runCancellation.ts";
import {
  checkSignature,
  type HostCheck,
  isManagedPath,
  isTrustedHelper,
  pathOwner,
  type PathOwner,
  readEnrolledKeys,
  readT3Install,
  readUserConfig,
  staticChecks,
  withFixBy,
  type HostPaths,
} from "./hostState.ts";
import {
  linuxSudoChildExists,
  peerCredentialsSupported,
  processStartTime,
  socketPeerUid,
} from "./native.ts";
import {
  decodeHello,
  encodeServerMessage,
  type Hello,
  makeLineSplitter,
  parseModuleLine,
  type ModuleMessage,
  type ServerMessage,
} from "./protocol.ts";

// Stay below macOS's 104-byte and Linux's 108-byte sockaddr_un limits, including NUL.
const UNIX_SOCKET_PATH_BYTES = 100;
const MAX_CONNECTIONS = 32;
const HELLO_TIMEOUT = "5 seconds";
const REQUEST_TIMEOUT = "5 seconds";
const EXPIRY_GRACE_SECONDS = 5;
// The checkout is read from the hello on; a slow read leaves the pointer out
// rather than holding the request back.
const CHANGES_WAIT = "750 millis";
// A device-approved helper call waits for the phone, up to the 300 s window.
const DEVICE_SUDO_TIMEOUT = "6 minutes";
const PASSWORD_SUDO_TIMEOUT = "60 seconds";
// A pasted install command reads its key file once; one never run is left behind.
/** `INPUT_MARKER` in native/t3-elevation/src/enroll.rs. */
const HELPER_INPUT_MARKER = "t3-elevation-input-v1";
const INSTALL_KEY_FILE = /^elevation-install-[0-9a-f-]{36}\.json$/;
const INSTALL_KEY_FILE_MAX_AGE_MS = 60 * 60 * 1000;
const LIVE_RUN_STATUSES = new Set(["preparing", "starting", "running", "waiting"]);
const RUNNING_ITEM_STATUSES = new Set(["pending", "running", "waiting"]);
const FINISHED_ITEM_STATUSES = new Set(["completed"]);
const ENDED_KEPT = 8;
// With no thread to bound a series, a machine's requests this close together read as one.
const MACHINE_SERIES_WINDOW_MS = 5 * 60_000;
const NO_HELPER_MESSAGE = "This build of T3 Code doesn't include the device approval helper.";

export interface ElevationOptions {
  readonly user: string;
  readonly socketPath: string;
  readonly hostPaths: HostPaths;
  /** `T3_ELEVATION_HELPER`, a dev build of the helper; used ahead of the installed copy for setup. */
  readonly helperOverride: string | null;
  /** The helper shipped with T3, for the first install only; null in builds that ship none. */
  readonly bundledHelperPath: string | null;
  readonly sudoPath: string;
  readonly attestation: ElevationAttestation;
  /** Where last-used times live; the root-owned key files never record them. */
  readonly devicesStatePath: string;
  /** Read when a sudo asks, so servers that never use device approval never load FFI. */
  readonly server: () => { readonly pid: number; readonly startTime: number | null };
  /** The PAM module runs inside setuid sudo, so its connection comes from root. */
  readonly trustedPeerUid: number;
  readonly peerUid: (socket: NodeNet.Socket) => number | null;
  readonly peerCredentialsSupported: () => boolean;
  /** The weaker check used when peer credentials can't be read. */
  readonly plausiblePeer: (hello: Hello) => boolean;
}

interface Answer {
  readonly resolvedBy: OrchestrationV2ElevationResolvedBy | null;
}

/** One turn's requests, or a machine's when no thread claims them. */
interface RequestSeries {
  /** Null for a machine's series, which ends after a quiet window instead. */
  readonly runId: RunId | null;
  count: number;
  first: ElevationRequestSeries["first"];
  lastAt: number;
}

interface PendingEntry {
  readonly request: ElevationPendingRequest;
  readonly series: { readonly of: RequestSeries; readonly ordinal: number } | null;
  /** The run attribution picked, even when its thread item couldn't be recorded. */
  readonly runId: RunId | null;
  readonly interrupted: Deferred.Deferred<void>;
  readonly payload: ElevationPayload;
  readonly payloadBytes: Uint8Array;
  readonly send: (message: ServerMessage) => void;
  answer: Answer | null;
}

/** A sudo this server spawned, with what became of it for the live test. */
interface OwnSudo extends ServerSudo {
  reached: boolean;
  outcome: string | null;
}

type Outcome = {
  readonly elevationStatus: "approved" | "denied" | "expired" | "cancelled";
  readonly failure?: OrchestrationV2ElevationRequestFailure;
};

const fail = (reason: ElevationFailureReason, detail?: string) =>
  Effect.fail(
    new ElevationError({
      reason,
      ...(detail === undefined ? {} : { detail: detail.slice(0, 500) }),
    }),
  );

const HelperReply = Schema.Union([
  Schema.Struct({ ok: Schema.Literal(true) }),
  Schema.Struct({
    ok: Schema.Literal(false),
    error: Schema.Struct({ code: Schema.String, message: Schema.String }),
  }),
]);
const decodeHelperReply = Schema.decodeUnknownOption(Schema.fromJsonString(HelperReply));
const HelperStatus = Schema.Struct({
  ok: Schema.Literal(true),
  plannedChanges: Schema.Array(Schema.Struct({ path: Schema.String, summary: Schema.String })),
  setupOutsideT3: Schema.Boolean,
});
const decodeHelperStatus = Schema.decodeUnknownOption(Schema.fromJsonString(HelperStatus));
const DevicesState = Schema.Struct({ lastUsed: Schema.Record(Schema.String, Schema.String) });
const decodeDevicesState = Schema.decodeUnknownOption(Schema.fromJsonString(DevicesState));
const encodeDevicesState = Schema.encodeSync(Schema.fromJsonString(DevicesState));

class ListenerError extends Schema.TaggedError<ListenerError>()("ElevationListenerError", {
  cause: Schema.Defect(),
}) {}

const shellQuote = (value: string) => `'${value.replaceAll("'", `'\\''`)}'`;
const lastLine = (text: string) => text.trim().split("\n").at(-1) ?? "";

/** The helper's enrollment object has exactly the device's fields. */
const enrollmentObject = Schema.encodeSync(Schema.fromJsonString(ElevationEnrollmentDevice));

/**
 * A synced passkey is refused before anything asks for an approval it would only waste; the
 * helper refuses it too (`check_registration`).
 */
const refuseUnenrollablePasskey = (device: ElevationEnrollmentDevice) => {
  if (!isElevationUnattestedDevice(device) || device.webauthn === undefined) return Effect.void;
  const { webauthn } = device;
  const authenticatorData = decodeElevationBase64Url(webauthn.authenticatorData);
  const credentialId = decodeElevationBase64Url(webauthn.credentialId);
  const refusal =
    authenticatorData === null || credentialId === null
      ? "invalid"
      : elevationWebauthnRegistrationRefusal({
          authenticatorData,
          rpIdHash: NodeCrypto.createHash("sha256").update(webauthn.rpId).digest(),
          credentialId,
        });
  if (refusal === null) return Effect.void;
  return fail(refusal === "synced" ? "synced_passkey" : "invalid_passkey");
};

export class ElevationService extends Context.Service<
  ElevationService,
  {
    readonly respond: (input: ElevationRespondInput) => Effect.Effect<void, ElevationError>;
    /** Ends the run's unanswered requests; the module treats a cancel as expired. */
    readonly cancelRun: (runId: RunId) => Effect.Effect<void>;
    /** The complete pending set, current value first. */
    readonly pendingRequests: Stream.Stream<ElevationPendingRequests>;
    readonly status: Effect.Effect<ElevationStatus, ElevationError>;
    readonly test: Effect.Effect<ElevationCheck, ElevationError>;
    readonly install: (
      input: ElevationInstallInput,
    ) => Effect.Effect<ElevationInstallResult, ElevationError>;
    readonly enroll: (
      input: ElevationEnrollInput,
    ) => Effect.Effect<ElevationStatus, ElevationError>;
    readonly revoke: (
      input: ElevationRevokeInput,
    ) => Effect.Effect<ElevationStatus, ElevationError>;
    readonly uninstall: (
      input: ElevationUninstallInput,
    ) => Effect.Effect<ElevationStatus, ElevationError>;
  }
>()("t3/elevation/ElevationService") {}

export const make = Effect.fn("ElevationService.make")(function* (options: ElevationOptions) {
  const orchestrator = yield* Orchestrator.OrchestratorV2;
  const projections = yield* ProjectionStore.ProjectionStoreV2;
  const processRunner = yield* ProcessRunner.ProcessRunner;
  const providerProcesses = yield* ProviderProcesses;
  const instructions = yield* DeviceApprovalInstructions;
  const platform = yield* HostProcess.Platform;
  const uid = yield* HostProcess.UserId;
  const serviceScope = yield* Effect.scope;

  const pending = new Map<ElevationRequestId, PendingEntry>();
  const pendingRef = yield* SubscriptionRef.make<ElevationPendingRequests>({ requests: [] });
  // Read at publish time, so a second request learns how the first ended once it does.
  const published = (entry: PendingEntry): ElevationPendingRequest =>
    entry.series === null || entry.series.ordinal < 2
      ? entry.request
      : {
          ...entry.request,
          series: { ordinal: entry.series.ordinal, first: entry.series.of.first },
        };
  // Enough for every card a phone could still be showing; older ones are long gone from screen.
  const ended: ElevationEndedRequest[] = [];
  /** The first word on how a request ended stands: an approval sent is what the user saw. */
  const recordEnded = (request: ElevationEndedRequest) => {
    if (ended.some((entry) => entry.requestId === request.requestId)) return;
    ended.push(request);
    if (ended.length > ENDED_KEPT) ended.shift();
  };
  // Answered requests leave the set: the phone has nothing left to sign.
  const publish = Effect.suspend(() =>
    SubscriptionRef.set(pendingRef, {
      requests: [...pending.values()].filter((entry) => entry.answer === null).map(published),
      ended: [...ended],
    }),
  );
  const series = new Map<string, RequestSeries>();
  /** Counts an agent's request in its run, or its machine's for one no thread claims. */
  const joinSeries = (
    owner: { readonly runId: RunId } | { readonly machineId: string },
    now: number,
    liveRunIds: ReadonlySet<RunId>,
  ): NonNullable<PendingEntry["series"]> => {
    for (const [key, entry] of series) {
      const ended =
        entry.runId === null
          ? now - entry.lastAt > MACHINE_SERIES_WINDOW_MS
          : !liveRunIds.has(entry.runId);
      if (ended) series.delete(key);
    }
    const key = "runId" in owner ? `run:${owner.runId}` : `machine:${owner.machineId}`;
    const existing = series.get(key);
    if (existing !== undefined) {
      existing.count++;
      existing.lastAt = now;
      return { of: existing, ordinal: existing.count };
    }
    const created: RequestSeries = {
      runId: "runId" in owner ? owner.runId : null,
      count: 1,
      first: { elevationStatus: "pending" },
      lastAt: now,
    };
    series.set(key, created);
    return { of: created, ordinal: 1 };
  };
  const serverSudos = new Set<OwnSudo>();
  let serverIdentity: ReturnType<ElevationOptions["server"]> | undefined;
  const serverProcess = () => (serverIdentity ??= options.server());

  const lastUsed = new Map<string, string>();
  const savedDevices = yield* Effect.promise(() =>
    NodeFSP.readFile(options.devicesStatePath, "utf8").catch(() => null),
  );
  const decodedDevices = savedDevices === null ? Option.none() : decodeDevicesState(savedDevices);
  if (Option.isSome(decodedDevices)) {
    for (const [keyId, at] of Object.entries(decodedDevices.value.lastUsed))
      lastUsed.set(keyId, at);
  }
  const markUsed = Effect.fn("ElevationService.markUsed")(function* (keyId: string) {
    lastUsed.set(keyId, DateTime.formatIso(yield* DateTime.now));
    const text = encodeDevicesState({ lastUsed: Object.fromEntries(lastUsed) });
    yield* Effect.promise(() =>
      NodeFSP.writeFile(options.devicesStatePath, text, { mode: 0o600 }).catch(() => undefined),
    );
  });

  const removeStaleInstallKeys = Effect.gen(function* () {
    const now = yield* Clock.currentTimeMillis;
    const directory = NodePath.dirname(options.socketPath);
    yield* Effect.promise(async () => {
      const names = await NodeFSP.readdir(directory).catch(() => []);
      for (const name of names) {
        if (!INSTALL_KEY_FILE.test(name)) continue;
        const path = NodePath.join(directory, name);
        const stat = await NodeFSP.lstat(path).catch(() => null);
        if (stat?.isFile() && now - stat.mtimeMs > INSTALL_KEY_FILE_MAX_AGE_MS) {
          await NodeFSP.unlink(path).catch(() => undefined);
        }
      }
    });
  });
  yield* removeStaleInstallKeys;

  const record = (
    run: LiveRun,
    turnItemId: TurnItemId,
    fields: {
      readonly requestId: ElevationRequestId;
      readonly argv: ReadonlyArray<string>;
      readonly runAs: string | null;
      readonly cwd: string;
      readonly host: string;
      readonly warnings: ElevationPayload["command"]["warnings"];
      readonly explanation: string | null;
      readonly agentCommand: string | undefined;
      readonly commandItemId: TurnItemId | undefined;
      readonly changes: OrchestrationV2ElevationChanges | null;
      readonly payload: string | null;
      readonly elevationStatus: "pending" | "cancelled";
      readonly failure?: OrchestrationV2ElevationRequestFailure;
    },
  ) => {
    const { agentCommand, commandItemId, changes, ...rest } = fields;
    return orchestrator.dispatch({
      type: "elevation_request.record",
      commandId: CommandId.make(`elevation:${turnItemId}:record`),
      threadId: run.threadId,
      runId: run.runId,
      nodeId: run.rootNodeId,
      turnItemId,
      kind: "sudo",
      ...rest,
      ...(agentCommand === undefined ? {} : { agentCommand }),
      ...(commandItemId === undefined ? {} : { commandItemId }),
      ...(changes === null ? {} : { changes }),
    });
  };

  const liveRuns = Effect.gen(function* () {
    const threadIds = yield* projections.listLiveRunThreadIds();
    const runs = yield* Effect.forEach(threadIds, (threadId) =>
      Effect.gen(function* () {
        const { runs, providerThreads } = yield* projections.getThreadRecords(
          threadId,
          ["runs", "providerThreads"],
          { messageRoles: [] },
        );
        const backgroundWork = providerThreads.some(
          (thread) => (thread.pendingBackgroundTasks?.length ?? 0) > 0,
        );
        const live = runs.flatMap((run) =>
          LIVE_RUN_STATUSES.has(run.status) && run.rootNodeId !== null
            ? [{ ...run, rootNodeId: run.rootNodeId }]
            : [],
        );
        if (live.length === 0) return [];
        const { turnItems } = yield* projections.getThreadRecords(threadId, ["turnItems"], {
          messageRoles: [],
          turnItemTypes: ["command_execution", "approval_request"],
          turnItemRunIds: live.map((run) => run.id),
        });
        return live.map((run): LiveRun => {
          const items = turnItems.filter((item) => item.runId === run.id);
          // Codex states its reason on the approval for the command, not on the command.
          const reasonFor = (ref: OrchestrationV2ProviderRef | null) => {
            if (ref?.nativeId == null) return null;
            for (const item of items) {
              if (item.type !== "approval_request" || item.reason === undefined) continue;
              const other = item.nativeItemRef;
              if (other?.driver === ref.driver && other.nativeId === ref.nativeId)
                return item.reason;
            }
            return null;
          };
          return {
            threadId: run.threadId,
            runId: run.id,
            rootNodeId: run.rootNodeId,
            commands: items
              .toSorted(
                (left, right) =>
                  DateTime.toEpochMillis(right.updatedAt) - DateTime.toEpochMillis(left.updatedAt),
              )
              .flatMap((item) =>
                item.type === "command_execution" &&
                (RUNNING_ITEM_STATUSES.has(item.status) || FINISHED_ITEM_STATUSES.has(item.status))
                  ? [
                      {
                        id: item.id,
                        text: item.input,
                        explanation: item.description ?? reasonFor(item.nativeItemRef),
                        finishedAt: RUNNING_ITEM_STATUSES.has(item.status)
                          ? null
                          : DateTime.toEpochMillis(item.updatedAt),
                      },
                    ]
                  : [],
              ),
            backgroundWork,
          };
        });
      }),
    );
    return runs.flat();
  }).pipe(
    Effect.tapError((cause) => Effect.logWarning("Device approval couldn't read live runs", cause)),
    Effect.orElseSucceed((): ReadonlyArray<LiveRun> => []),
  );

  const resolveItem = (
    threadId: LiveRun["threadId"],
    turnItemId: TurnItemId,
    outcome: Outcome,
    resolvedBy: OrchestrationV2ElevationResolvedBy | null,
  ) =>
    orchestrator
      .dispatch({
        type: "elevation_request.resolve",
        commandId: CommandId.make(`elevation:${turnItemId}:resolve`),
        threadId,
        turnItemId,
        elevationStatus: outcome.elevationStatus,
        ...(outcome.failure === undefined ? {} : { failure: outcome.failure }),
        resolvedBy,
      })
      .pipe(
        Effect.tapError((cause) =>
          Effect.logWarning("Device approval couldn't resolve its turn item", cause),
        ),
        Effect.ignore,
      );

  const handleConnection = Effect.fn("ElevationService.handleConnection")(function* (
    socket: NodeNet.Socket,
  ) {
    const lines = yield* Queue.unbounded<string | null>();
    const split = makeLineSplitter();
    socket.on("data", (chunk: Buffer) => {
      const complete = split(chunk);
      if (complete === null) {
        Queue.offerUnsafe(lines, null);
        socket.destroy();
        return;
      }
      for (const line of complete) Queue.offerUnsafe(lines, line);
    });
    socket.once("close", () => Queue.offerUnsafe(lines, null));
    const send = (message: ServerMessage) => {
      if (!socket.destroyed) socket.write(encodeServerMessage(message));
    };
    // Any protocol violation ends in null; the module fails closed on a close.
    const next = (timeout: Duration.Input) =>
      Queue.take(lines).pipe(
        Effect.timeoutOption(timeout),
        Effect.map((line) => {
          if (Option.isNone(line) || line.value === null) return null;
          return parseModuleLine(line.value);
        }),
      );

    const hello = yield* next(HELLO_TIMEOUT);
    if (hello?.message.type !== "hello") return;
    const helloJson = hello.json as { readonly v?: unknown };
    const decoded = helloJson.v === 1 ? decodeHello(hello.json) : Option.none();
    if (Option.isNone(decoded)) {
      if (helloJson.v !== 1) send({ type: "hello_reply", v: 1, decision: "not_mine" });
      return;
    }
    if (!options.peerCredentialsSupported() && !options.plausiblePeer(decoded.value)) return;
    const runs = yield* liveRuns;
    const attribution = attribute({
      hello: decoded.value,
      now: DateTime.toEpochMillis(yield* DateTime.now),
      server: serverProcess(),
      liveRuns: runs,
      providerProcesses: providerProcesses.list(),
      serverSudos: [...serverSudos],
    });
    if (attribution.type === "not_mine") {
      send({ type: "hello_reply", v: 1, decision: "not_mine" });
      return;
    }
    const ownSudo = attribution.serverSudo as OwnSudo | undefined;
    send({
      type: "hello_reply",
      v: 1,
      decision: "mine",
      ...(ownSudo === undefined ? {} : { ownSudo: true }),
    });
    if (ownSudo !== undefined) ownSudo.reached = true;
    // Only checkouts the server already runs git in for this thread's checkpoints.
    const changesRoots =
      attribution.run === null
        ? Effect.succeed([])
        : projections.getCheckpointContext(attribution.run.threadId).pipe(
            Effect.map(({ checkpointScopes }) => checkpointScopes.map((scope) => scope.cwd)),
            Effect.orElseSucceed((): ReadonlyArray<string> => []),
          );
    const changesFiber =
      ownSudo === undefined
        ? yield* changesRoots.pipe(
            Effect.flatMap((roots) => uncommittedChanges(decoded.value.cwd, roots)),
            Effect.provideService(ProcessRunner.ProcessRunner, processRunner),
            Effect.forkChild,
          )
        : null;
    const changes =
      changesFiber === null
        ? Effect.succeed(null)
        : Fiber.join(changesFiber).pipe(
            Effect.timeoutOption(CHANGES_WAIT),
            Effect.map(Option.getOrNull),
          );
    const finish = (outcome: string) => {
      if (ownSudo !== undefined) ownSudo.outcome = outcome;
    };

    const second = yield* next(REQUEST_TIMEOUT);
    const message: ModuleMessage | undefined = second?.message;
    if (message?.type === "result") {
      finish(message.outcome);
      if (
        attribution.run !== null &&
        (message.outcome === "too_large" || message.outcome === "invalid_encoding")
      ) {
        const requestId = ElevationRequestId.make(NodeCrypto.randomUUID());
        yield* record(attribution.run, TurnItemId.make(`elevation:${requestId}`), {
          requestId,
          argv: decoded.value.argv,
          runAs: null,
          cwd: decoded.value.cwd,
          host: decoded.value.host.name,
          warnings: [],
          explanation: attribution.explanation,
          agentCommand: attribution.command,
          commandItemId: attribution.commandItemId,
          changes: null,
          payload: null,
          elevationStatus: "cancelled",
          failure: message.outcome,
        }).pipe(
          Effect.tapError((cause) => Effect.logWarning("Device approval couldn't record", cause)),
          Effect.ignore,
        );
      }
      return;
    }
    if (message?.type !== "request") return;
    const payloadBytes = decodeElevationBase64Url(message.payload);
    const payload = payloadBytes === null ? null : decodeElevationPayload(payloadBytes);
    if (payloadBytes === null || payload === null || payload._tag === "Failure") return;

    const requestId = ElevationRequestId.make(NodeCrypto.randomUUID());
    const requestChanges = yield* changes;
    let item: { readonly run: LiveRun; readonly turnItemId: TurnItemId } | null = null;
    if (attribution.run !== null) {
      const turnItemId = TurnItemId.make(`elevation:${requestId}`);
      const recorded = yield* record(attribution.run, turnItemId, {
        requestId,
        argv: payload.success.argv,
        runAs: payload.success.runAs,
        cwd: payload.success.cwd,
        host: payload.success.host.name,
        warnings: payload.success.command.warnings,
        explanation: attribution.explanation,
        agentCommand: attribution.command,
        commandItemId: attribution.commandItemId,
        changes: requestChanges,
        payload: message.payload,
        elevationStatus: "pending",
      }).pipe(
        Effect.tapError((cause) => Effect.logWarning("Device approval couldn't record", cause)),
        Effect.option,
      );
      // A run that ended meanwhile still gets the banner, without a thread item.
      if (Option.isSome(recorded)) item = { run: attribution.run, turnItemId };
    }
    const createdAt = yield* DateTime.now;
    const entry: PendingEntry = {
      request: {
        requestId,
        threadId: item?.run.threadId ?? null,
        turnItemId: item?.turnItemId ?? null,
        payload: message.payload,
        explanation: attribution.explanation,
        ...(attribution.command === undefined ? {} : { agentCommand: attribution.command }),
        ...(requestChanges === null ? {} : { changes: requestChanges }),
        ...(attribution.driver === undefined
          ? {}
          : { driver: ProviderDriverKind.make(attribution.driver) }),
        ...(ownSudo === undefined ? {} : { raisedByT3: true }),
        createdAt,
      },
      series:
        ownSudo !== undefined
          ? null
          : joinSeries(
              attribution.run === null
                ? { machineId: payload.success.host.machineId }
                : { runId: attribution.run.runId },
              DateTime.toEpochMillis(createdAt),
              new Set(runs.map((run) => run.runId)),
            ),
      runId: attribution.run?.runId ?? null,
      interrupted: yield* Deferred.make<void>(),
      payload: payload.success,
      payloadBytes,
      send,
      answer: null,
    };

    const waitForResult = Effect.gen(function* () {
      const line = yield* Queue.take(lines);
      const parsed = line === null ? null : parseModuleLine(line);
      if (parsed?.message.type !== "result") return { elevationStatus: "cancelled" } as Outcome;
      finish(parsed.message.outcome);
      switch (parsed.message.outcome) {
        case "approved":
        case "denied":
        case "expired":
          return { elevationStatus: parsed.message.outcome } as Outcome;
        default:
          return { elevationStatus: "cancelled", failure: parsed.message.outcome } as Outcome;
      }
    });
    const expire = Effect.gen(function* () {
      const now = yield* Clock.currentTimeMillis;
      yield* Effect.sleep(
        Math.max(0, (payload.success.expiresAt + EXPIRY_GRACE_SECONDS) * 1000 - now),
      );
      finish("expired");
      return { elevationStatus: "expired" } as Outcome;
    });

    pending.set(requestId, entry);
    yield* publish;
    const interrupted = Deferred.await(entry.interrupted).pipe(
      Effect.as<Outcome>({ elevationStatus: "cancelled" }),
    );
    let endedStatus: Outcome["elevationStatus"] = "cancelled";
    const outcome = yield* Effect.raceAllFirst([waitForResult, expire, interrupted]).pipe(
      Effect.tap((ended) =>
        Effect.gen(function* () {
          endedStatus = ended.elevationStatus;
          if (entry.series?.ordinal !== 1) return;
          entry.series.of.first = {
            elevationStatus: ended.elevationStatus,
            resolvedAt: yield* DateTime.now,
          };
        }),
      ),
      Effect.onInterrupt(() =>
        Effect.sync(() => send({ type: "cancel", reason: "shutdown" })).pipe(
          Effect.andThen(
            item === null
              ? Effect.void
              : resolveItem(
                  item.run.threadId,
                  item.turnItemId,
                  { elevationStatus: "cancelled" },
                  null,
                ),
          ),
        ),
      ),
      Effect.ensuring(
        Effect.sync(() => {
          pending.delete(requestId);
          recordEnded({ requestId, elevationStatus: endedStatus, resolvedBy: null });
        }).pipe(Effect.andThen(publish)),
      ),
    );
    if (item !== null) {
      const resolvedBy =
        outcome.elevationStatus === "approved" || outcome.elevationStatus === "denied"
          ? (entry.answer?.resolvedBy ?? null)
          : null;
      yield* resolveItem(item.run.threadId, item.turnItemId, outcome, resolvedBy);
    }
  });

  const startListener = Effect.fn("ElevationService.startListener")(function* (scope: Scope.Scope) {
    const directory = NodePath.dirname(options.socketPath);
    const io = <A>(f: () => Promise<A>) =>
      Effect.tryPromise({ try: f, catch: (cause) => new ListenerError({ cause }) });
    yield* io(async () => {
      if (Buffer.byteLength(options.socketPath) > UNIX_SOCKET_PATH_BYTES)
        throw new Error("Socket path too long");
      const stat = await NodeFSP.lstat(directory);
      if (!stat.isDirectory() || stat.uid !== uid || (stat.mode & 0o022) !== 0)
        throw new Error("Untrusted state directory");
      // Only a socket is ours to replace; one left by a crashed server is stale.
      const existing = await NodeFSP.lstat(options.socketPath).catch(() => null);
      if (existing !== null) {
        if (!existing.isSocket()) throw new Error("Something else is at the socket path");
        await NodeFSP.unlink(options.socketPath);
      }
    });
    const connections = yield* FiberSet.make<void>().pipe(Scope.provide(scope));
    const runConnection = yield* FiberSet.runtime(connections)();
    let open = 0;
    const server = NodeNet.createServer((socket) => {
      socket.on("error", () => {});
      // Without peer credentials, the hello gets the weaker plausibility check instead.
      if (
        open >= MAX_CONNECTIONS ||
        (options.peerCredentialsSupported() && options.peerUid(socket) !== options.trustedPeerUid)
      ) {
        socket.destroy();
        return;
      }
      open++;
      socket.once("close", () => open--);
      runConnection(
        handleConnection(socket).pipe(
          Effect.ignoreCause,
          Effect.ensuring(Effect.sync(() => socket.end())),
        ),
      );
    });
    server.on("error", () => {});
    yield* Scope.addFinalizer(
      scope,
      Effect.promise(
        () =>
          new Promise<void>((resolve) => {
            server.close(() => resolve());
          }),
      ),
    );
    yield* Effect.callback<void, ListenerError>((resume) => {
      const onError = (cause: Error) => resume(Effect.fail(new ListenerError({ cause })));
      server.once("error", onError);
      server.listen(options.socketPath, () => resume(Effect.void));
      return Effect.sync(() => server.off("error", onError));
    });
    yield* io(() => NodeFSP.chmod(options.socketPath, 0o600));
  });

  // The listener runs only while the installed config points at this server,
  // so a dev worktree server never answers for the installed one.
  const listenerLock = yield* Semaphore.make(1);
  let listener: Scope.Closeable | null = null;
  const syncListener = (shouldListen: boolean, deviceCount: number) =>
    listenerLock.withPermits(1)(
      Effect.gen(function* () {
        if (shouldListen && listener === null) {
          const scope = yield* Scope.fork(serviceScope);
          const started = yield* startListener(scope).pipe(Effect.exit);
          if (Exit.isSuccess(started)) listener = scope;
          else {
            yield* Effect.logWarning("Device approval listener didn't start", started.cause);
            yield* Scope.close(scope, Exit.void);
          }
        } else if (!shouldListen && listener !== null) {
          yield* Scope.close(listener, Exit.void);
          listener = null;
        }
        instructions.setEnabled(listener !== null && deviceCount > 0);
        return listener !== null;
      }),
    );

  const unsupportedReason = Effect.gen(function* () {
    if (platform !== "darwin" && platform !== "linux") {
      return "Device approval needs Linux or macOS.";
    }
    if (Buffer.byteLength(options.socketPath) > UNIX_SOCKET_PATH_BYTES) {
      return "The T3 state directory path is too long for its approval socket.";
    }
    if (platform === "linux") {
      // Confined SELinux users can't reach the socket from sudo; sudo falls back to the password.
      const context = yield* processRunner
        .run({ command: "id", args: ["-Z"], timeout: "5 seconds" })
        .pipe(Effect.option);
      const user =
        Option.isSome(context) && context.value.code === 0
          ? context.value.stdout.trim().split(":")[0]
          : undefined;
      if (user !== undefined && user !== "" && user !== "unconfined_u") {
        return "Device approval isn't supported for confined SELinux users.";
      }
    }
    return null;
  });

  /** The only helper run as root once installed; null when missing or replaceable without root. */
  const installedHelper = Effect.gen(function* () {
    return (yield* isTrustedHelper(options.hostPaths)) ? options.hostPaths.helperPath : null;
  });

  /** Before install there is no root-owned copy, so setup trusts this account's helper. */
  const setupHelper = Effect.gen(function* () {
    if (options.helperOverride !== null) return options.helperOverride;
    return (yield* installedHelper) ?? options.bundledHelperPath;
  });

  /** The helper's own status, or why setup can't run, said before the phone makes its key. */
  const helperStatus = Effect.gen(function* () {
    const helper = yield* setupHelper;
    if (helper === null) return { status: null, setupUnavailableReason: NO_HELPER_MESSAGE };
    const output = yield* processRunner
      .run({
        command: helper,
        args: ["status", "--user", options.user],
        timeout: "10 seconds",
      })
      .pipe(Effect.option);
    const status = Option.isNone(output)
      ? null
      : Option.getOrNull(decodeHelperStatus(lastLine(output.value.stdout)));
    return status === null
      ? { status, setupUnavailableReason: "T3 Code's device approval helper didn't run here." }
      : { status, setupUnavailableReason: null };
  });

  const untrustedHelperMessage = `${options.hostPaths.helperPath} is missing, or it or a folder above it isn't root-owned and closed to other users.`;

  const status: Effect.Effect<ElevationStatus, ElevationError> = Effect.gen(function* () {
    yield* removeStaleInstallKeys;
    const unsupported = yield* unsupportedReason;
    const host = yield* staticChecks(options.hostPaths, {
      user: options.user,
      socketPath: options.socketPath,
    });
    const { status: helper, setupUnavailableReason } = yield* helperStatus;
    const helperInstalled = (yield* installedHelper) !== null;
    const configured =
      host.config !== null &&
      host.config.version === 1 &&
      host.config.enabled &&
      host.config.socket === options.socketPath;
    const listening = yield* syncListener(unsupported === null && configured, host.keys.length);
    const devices = host.keys.map((key): ElevationDevice => ({
      keyId: key.keyId,
      label: key.label,
      securityLevel: key.securityLevel,
      kind: elevationApproverKind(key.securityLevel),
      ...(key.webauthn === undefined ? {} : { webauthn: key.webauthn }),
      enrolledAt: Option.getOrElse(DateTime.make(key.enrolledAt), () => DateTime.makeUnsafe(0)),
      lastUsedAt: Option.getOrNull(DateTime.make(lastUsed.get(key.keyId) ?? "")),
    }));
    // Agent sudo doesn't need the helper, so it doesn't count against `ready`;
    // adding and removing devices does.
    const helperCheck: ReadonlyArray<HostCheck> =
      !helperInstalled && (listening || devices.length > 0)
        ? [
            {
              id: "helper",
              ok: false,
              message: untrustedHelperMessage,
              path: options.hostPaths.helperPath,
              missing: true,
            },
          ]
        : [];
    const hostChecks = [...host.checks, ...helperCheck];
    const plannedChanges = helper?.plannedChanges ?? [];
    const install = yield* readT3Install(options.hostPaths);
    const writtenByT3 = install?.written ?? new Set<string>();
    const managed = new Set<string>();
    const owners = new Map<string, PathOwner>();
    for (const check of hostChecks) {
      if (check.ok || check.path === undefined) continue;
      if (check.missing === true && (yield* isManagedPath(check.path))) managed.add(check.path);
      const owner = yield* pathOwner(check.path, writtenByT3);
      if (owner !== undefined) owners.set(check.path, owner);
    }
    const fixContext = { plannedChanges, writtenByT3, managed, owners };
    return {
      supported: unsupported === null,
      ...(unsupported === null ? {} : { unsupportedReason: unsupported }),
      ...(setupUnavailableReason === null ? {} : { setupUnavailableReason }),
      ready: unsupported === null && listening && host.checks.every((check) => check.ok),
      ownsApprovals: listening,
      user: options.user,
      setupOutsideT3: helper?.setupOutsideT3 ?? false,
      installedByT3: install?.user === options.user,
      helperInstalled,
      checks: hostChecks.map((check) => withFixBy(check, fixContext)),
      plannedChanges,
      devices,
    };
  }).pipe(Effect.withSpan("ElevationService.status"));

  const requireSetupHelper = Effect.gen(function* () {
    const helper = yield* setupHelper;
    if (helper === null) {
      return yield* fail("not_available", NO_HELPER_MESSAGE);
    }
    return helper;
  });

  // A helper this account can write could be swapped between approval and sudo's exec.
  const requireInstalledHelper = Effect.gen(function* () {
    const helper = yield* installedHelper;
    if (helper === null) return yield* fail("not_available", untrustedHelperMessage);
    return helper;
  });

  /**
   * With a password, sudo reads it from stdin (`-S`, with `-k` so a cached
   * login can't skip the prompt). PAM can still approve without asking for
   * it (Touch ID, an enrolled phone), leaving the password line unread, so
   * the helper's input follows a marker line and the helper skips at most
   * one line before it. Without a password, `sudo -n` goes to an enrolled
   * device like any other request.
   */
  const runHelper = Effect.fn("ElevationService.runHelper")(function* (input: {
    readonly helper: string;
    readonly args: ReadonlyArray<string>;
    readonly password?: string | undefined;
    readonly stdin?: string;
    readonly explanation: string;
  }) {
    const { helper } = input;
    const withPassword = input.password !== undefined;
    const helperInput =
      input.stdin === undefined ? undefined : `${HELPER_INPUT_MARKER}\n${input.stdin}`;
    const run = (args: ReadonlyArray<string>, stdin: string | undefined, timeout: Duration.Input) =>
      processRunner
        .run({
          command: options.sudoPath,
          args,
          ...(stdin === undefined ? {} : { stdin }),
          timeout,
        })
        .pipe(
          Effect.mapError(
            (cause) => new ElevationError({ reason: "helper_failed", detail: cause.message }),
          ),
        );
    const output = withPassword
      ? yield* run(
          ["-S", "-k", "-p", "", helper, ...input.args],
          `${input.password}\n${helperInput ?? ""}`,
          PASSWORD_SUDO_TIMEOUT,
        )
      : yield* Effect.acquireUseRelease(
          Effect.sync(() => {
            const own: OwnSudo = {
              argv: [options.sudoPath, "-n", helper, ...input.args],
              explanation: input.explanation,
              reached: false,
              outcome: null,
            };
            serverSudos.add(own);
            return own;
          }),
          (own) => run(own.argv.slice(1), helperInput, DEVICE_SUDO_TIMEOUT),
          (own) => Effect.sync(() => serverSudos.delete(own)),
        );
    const reply = decodeHelperReply(lastLine(output.stdout));
    if (Option.isSome(reply)) {
      if (reply.value.ok) return;
      return yield* fail("helper_failed", reply.value.error.message);
    }
    const stderr = output.stderr.trim();
    if (/incorrect password|try again|password is required|no password/i.test(stderr)) {
      return yield* fail(withPassword ? "wrong_password" : "password_required");
    }
    return yield* fail("helper_failed", stderr === "" ? `sudo exited with ${output.code}` : stderr);
  });

  const attestationFlag = ATTESTATION_FLAGS[options.attestation];
  // A Mac's or browser's key has no attestation to check; the flag puts that in the approved argv.
  const proofFlags = (device: ElevationEnrollmentDevice) =>
    isElevationUnattestedDevice(device) ? ["--unattested"] : attestationFlag;

  const withKeyFile = <A, E, R>(
    device: ElevationEnrollmentDevice,
    use: (path: string) => Effect.Effect<A, E, R>,
  ) =>
    Effect.acquireUseRelease(
      Effect.tryPromise({
        try: async () => {
          const directory = await NodeFSP.mkdtemp(NodePath.join(NodeOS.tmpdir(), "t3-elevation-"));
          const path = NodePath.join(directory, "key.json");
          await NodeFSP.writeFile(path, enrollmentObject(device), { mode: 0o600 });
          return { directory, path };
        },
        catch: (cause) => new ElevationError({ reason: "helper_failed", detail: String(cause) }),
      }),
      ({ path }) => use(path),
      ({ directory }) =>
        Effect.promise(() => NodeFSP.rm(directory, { recursive: true, force: true })),
    );

  const requireSupported = Effect.gen(function* () {
    const unsupported = yield* unsupportedReason;
    if (unsupported !== null) return yield* fail("unsupported", unsupported);
  });

  const install = Effect.fn("ElevationService.install")(function* (input: ElevationInstallInput) {
    yield* requireSupported;
    yield* refuseUnenrollablePasskey(input.device);
    const helper = yield* requireSetupHelper;
    const installArgs = (keyPath: string) => [
      "install",
      "--user",
      options.user,
      "--socket",
      options.socketPath,
      "--key",
      keyPath,
      ...proofFlags(input.device),
    ];
    if (input.password === null) {
      // The key file outlives this call, so it sits in the private state dir.
      const keyPath = NodePath.join(
        NodePath.dirname(options.socketPath),
        `elevation-install-${NodeCrypto.randomUUID()}.json`,
      );
      yield* Effect.tryPromise({
        try: () => NodeFSP.writeFile(keyPath, enrollmentObject(input.device), { mode: 0o600 }),
        catch: (cause) => new ElevationError({ reason: "helper_failed", detail: String(cause) }),
      });
      const command = ["sudo", helper, ...installArgs(keyPath)].map(shellQuote).join(" ");
      return {
        type: "terminal_command",
        command: `${command}; rm -f ${shellQuote(keyPath)}`,
      } as const;
    }
    const password = input.password;
    yield* withKeyFile(input.device, (keyPath) =>
      runHelper({
        helper,
        args: installArgs(keyPath),
        password,
        explanation: "Set up device approval",
      }),
    );
    return { type: "installed", status: yield* status } as const;
  });

  const enroll = Effect.fn("ElevationService.enroll")(function* (input: ElevationEnrollInput) {
    yield* requireSupported;
    yield* refuseUnenrollablePasskey(input.device);
    const { device } = input;
    const proof = !isElevationUnattestedDevice(device)
      ? ["--challenge", device.challenge, ...attestationFlag]
      : device.webauthn === undefined
        ? ["--unattested"]
        : ["--unattested", "--rp-id", device.webauthn.rpId, "--origin", device.webauthn.origin];
    yield* runHelper({
      helper: yield* requireInstalledHelper,
      args: [
        "enroll",
        "--user",
        options.user,
        "--label",
        input.device.label,
        "--public-key",
        input.device.publicKey,
        ...proof,
      ],
      password: input.password,
      stdin: enrollmentObject(input.device),
      explanation: `Add device ${input.device.label}`,
    });
    return yield* status;
  });

  const revoke = Effect.fn("ElevationService.revoke")(function* (input: ElevationRevokeInput) {
    yield* runHelper({
      helper: yield* requireInstalledHelper,
      args: ["revoke", "--user", options.user, "--key-id", input.keyId],
      password: input.password,
      explanation: "Remove a device from device approval",
    });
    return yield* status;
  });

  const uninstall = Effect.fn("ElevationService.uninstall")(function* (
    input: ElevationUninstallInput,
  ) {
    yield* runHelper({
      helper: yield* requireInstalledHelper,
      args: ["uninstall", "--user", options.user],
      password: input.password,
      explanation: "Turn off device approval",
    });
    return yield* status;
  });

  /** The live half of verification: proves the sudoers settings and placement nothing else can read. */
  const test: Effect.Effect<ElevationCheck, ElevationError> = Effect.gen(function* () {
    yield* requireSupported;
    if (listener === null) {
      return {
        id: "live_test",
        ok: false,
        message: "This server doesn't receive approvals",
        fixBy: "agent" as const,
      };
    }
    const own: OwnSudo = {
      argv: [options.sudoPath, "-n", "true"],
      explanation: "Test device approval",
      reached: false,
      outcome: null,
    };
    const output = yield* Effect.acquireUseRelease(
      Effect.sync(() => serverSudos.add(own)),
      () =>
        processRunner
          .run({ command: options.sudoPath, args: ["-n", "true"], timeout: DEVICE_SUDO_TIMEOUT })
          .pipe(Effect.option),
      () => Effect.sync(() => serverSudos.delete(own)),
    );
    const succeeded = Option.isSome(output) && output.value.code === 0;
    if (!own.reached) {
      return {
        id: "live_test",
        ok: false,
        message: succeeded
          ? "sudo -n succeeded without asking a device"
          : "sudo -n doesn't reach device approval",
        fixBy: "agent" as const,
      };
    }
    // The user declined or let it expire; nothing is broken.
    if (own.outcome !== "approved") {
      return { id: "live_test", ok: false, message: "The test wasn't approved on a device" };
    }
    return succeeded
      ? { id: "live_test", ok: true, message: "sudo -n is approved on a device" }
      : {
          id: "live_test",
          ok: false,
          message: "sudo -n failed after approval",
          fixBy: "agent" as const,
        };
  }).pipe(Effect.withSpan("ElevationService.test"));

  const respond = Effect.fn("ElevationService.respond")(function* (input: ElevationRespondInput) {
    const entry = pending.get(input.requestId);
    if (entry === undefined) return yield* fail("not_found");
    if (entry.answer !== null) return yield* fail("already_resolved");
    if (input.decision === "deny") {
      // Unsigned, so the key only labels the row; one that isn't enrolled labels nothing.
      const key =
        input.keyId === undefined
          ? undefined
          : (yield* readEnrolledKeys(options.hostPaths, options.user)).find(
              (candidate) => candidate.keyId === input.keyId,
            );
      if (entry.answer !== null) return yield* fail("already_resolved");
      entry.answer = {
        resolvedBy: key === undefined ? null : { deviceLabel: key.label, keyId: key.keyId },
      };
      recordEnded({ requestId: input.requestId, elevationStatus: "denied", ...entry.answer });
      entry.send({ type: "response", decision: "deny" });
      yield* publish;
      return;
    }
    const { requestId: _, decision: __, ...response } = input;
    const keys = yield* readEnrolledKeys(options.hostPaths, options.user);
    const check = checkSignature({
      payloadBytes: entry.payloadBytes,
      payload: entry.payload,
      response,
      keys,
    });
    if (check !== "ok") return yield* fail("invalid_signature", check);
    // Reading the keys yielded; another answer may have won meanwhile.
    if (entry.answer !== null) return yield* fail("already_resolved");
    const key = keys.find((candidate) => candidate.keyId === response.keyId);
    entry.answer = {
      resolvedBy: { deviceLabel: key?.label ?? response.keyId, keyId: response.keyId },
    };
    recordEnded({ requestId: input.requestId, elevationStatus: "approved", ...entry.answer });
    entry.send({ type: "response", decision: "approve", ...response });
    yield* publish;
    yield* markUsed(response.keyId);
  });

  const cancelRun = Effect.fn("ElevationService.cancelRun")(function* (runId: RunId) {
    for (const entry of pending.values()) {
      // An approval already sent can't be taken back; its sudo is running.
      if (entry.runId !== runId || entry.answer !== null) continue;
      entry.answer = { resolvedBy: null };
      recordEnded({
        requestId: entry.request.requestId,
        elevationStatus: "cancelled",
        resolvedBy: null,
      });
      entry.send({ type: "cancel", reason: "interrupted" });
      yield* Deferred.succeed(entry.interrupted, undefined);
    }
    yield* publish;
  });

  // Start listening at boot only when the installed config already points
  // here; every other server stays away from the native calls.
  const bootConfig = yield* readUserConfig(options.hostPaths, options.user);
  if (bootConfig?.socket === options.socketPath) {
    yield* status.pipe(Effect.ignoreCause, Effect.forkIn(serviceScope));
  }

  return ElevationService.of({
    respond,
    cancelRun,
    pendingRequests: SubscriptionRef.changes(pendingRef),
    status,
    test,
    install,
    enroll,
    revoke,
    uninstall,
  });
});

/** Hands interrupts from the effect worker to this service. */
export const runCancellationLayer = Layer.effect(
  ElevationRunCancellation,
  Effect.gen(function* () {
    const service = yield* ElevationService;
    return { cancelRun: service.cancelRun };
  }),
);

/** Set by ElevationService; adapters read it when they build instructions. */
export const instructionsLayer = Layer.sync(DeviceApprovalInstructions, () => {
  let enabled = false;
  return {
    enabled: () => enabled,
    setEnabled: (value: boolean) => {
      enabled = value;
    },
  };
});

/**
 * The helper a release ships beside the server, which first setup runs once:
 * the CLI archive keeps it next to `t3`, and the desktop app under Resources,
 * because its server runs from Resources/app.asar/apps/server/dist and sudo
 * can't run a file inside an asar. A build from source ships none.
 */
export function bundledElevationHelperPath(input: {
  readonly serverDir: string;
  readonly packaged: boolean;
  readonly exists: (path: string) => boolean;
}): string | null {
  if (!input.packaged) return null;
  const candidates = [
    NodePath.join(input.serverDir, "t3-elevation", "t3-elevation"),
    NodePath.resolve(input.serverDir, "../../../..", "t3-elevation", "t3-elevation"),
  ];
  return candidates.find(input.exists) ?? null;
}

/** Which helper attestation option setup and enroll pass; docs/internals/device-approval.md. */
export type ElevationAttestation = "release" | "dev" | "test";

const ATTESTATION_FLAGS: Record<ElevationAttestation, ReadonlyArray<string>> = {
  release: [],
  dev: ["--allow-dev-attestation"],
  test: ["--allow-test-attestation"],
};

declare const __T3CODE_BUILD_CHANNEL__: "nightly" | "latest" | undefined;

/**
 * Dev attestation still requires real hardware and a Google root, so its
 * variable works in any build. Test attestation accepts emulators, so a
 * packaged server ignores its variable: only `vp pack` defines the build
 * channel, and no environment variable can undefine it.
 */
export function elevationAttestation(input: {
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly packaged: boolean;
}): ElevationAttestation {
  if (!input.packaged && input.env.T3_ELEVATION_ALLOW_TEST_ATTESTATION === "1") return "test";
  return input.env.T3_ELEVATION_ALLOW_DEV_ATTESTATION === "1" ? "dev" : "release";
}

/**
 * sudo by absolute path: a folder early in PATH can be user-writable (Homebrew
 * on Apple Silicon), and a sudo planted there would get the setup password or
 * fake the helper's reply. NixOS keeps its setuid sudo in /run/wrappers.
 */
export function elevationSudoPath(
  platform: NodeJS.Platform,
  exists: (path: string) => boolean,
): string {
  if (platform === "linux" && exists("/run/wrappers/bin/sudo")) return "/run/wrappers/bin/sudo";
  return "/usr/bin/sudo";
}

export const layer = Layer.effect(
  ElevationService,
  Effect.gen(function* () {
    const config = yield* ServerConfig.ServerConfig;
    const platform = yield* HostProcess.Platform;
    const host = { platform, arch: yield* HostProcess.Architecture };
    const packaged = typeof __T3CODE_BUILD_CHANNEL__ !== "undefined";
    return yield* make({
      user: NodeOS.userInfo().username,
      socketPath: NodePath.join(config.stateDir, "elevation.sock"),
      hostPaths: {
        etcDir: "/etc/t3-elevation",
        pamDir: "/etc/pam.d",
        helperPath: ELEVATION_HELPER_INSTALL_PATH,
        helperRoot: "/",
        rootUid: 0,
        platform,
      },
      helperOverride: process.env.T3_ELEVATION_HELPER ?? null,
      bundledHelperPath: bundledElevationHelperPath({
        serverDir: import.meta.dirname,
        packaged,
        exists: NodeFS.existsSync,
      }),
      sudoPath: elevationSudoPath(platform, NodeFS.existsSync),
      attestation: elevationAttestation({ env: process.env, packaged }),
      devicesStatePath: NodePath.join(config.stateDir, "elevation-devices.json"),
      server: () => ({ pid: process.pid, startTime: processStartTime(host, process.pid) }),
      trustedPeerUid: 0,
      peerUid: (socket) => socketPeerUid(host, socket),
      peerCredentialsSupported: () => peerCredentialsSupported(host),
      plausiblePeer: (hello) =>
        platform !== "linux" ||
        hello.chain[0] === undefined ||
        linuxSudoChildExists({ dir: "/proc", rootUid: 0 }, hello.chain[0].pid, hello.argv),
    });
  }),
);
