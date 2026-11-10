import {
  WS_METHODS,
  type ElevationEndedRequest,
  type ElevationPayloadDecodeFailure,
  type ElevationPendingRequest,
  type ElevationPendingRequests,
  type EnvironmentId,
  type ServerConfig,
} from "@t3tools/contracts";
import * as Effect from "effect/Effect";
import * as Option from "effect/Option";
import * as Result from "effect/Result";
import * as Stream from "effect/Stream";
import * as SubscriptionRef from "effect/SubscriptionRef";
import { AsyncResult, Atom } from "effect/reactivity";

import type * as EnvironmentRegistry from "../connection/registry.ts";
import * as EnvironmentSupervisor from "../connection/supervisor.ts";
import { decodeElevationRequestPayload, type DecodedElevationPayload } from "../elevation.ts";
import {
  createEnvironmentRpcCommand,
  createEnvironmentRpcQueryAtomFamily,
  createEnvironmentRpcSubscriptionAtomFamily,
} from "./runtime.ts";

export interface PendingElevationRequest {
  readonly environmentId: EnvironmentId;
  readonly request: ElevationPendingRequest;
  readonly decoded: Result.Result<DecodedElevationPayload, ElevationPayloadDecodeFailure>;
}

const EMPTY_PENDING: readonly PendingElevationRequest[] = [];

export function environmentSupportsDeviceApproval(
  config: Pick<ServerConfig, "environment"> | null | undefined,
) {
  return config?.environment.capabilities.deviceApproval === true;
}

/**
 * Collects the pending requests of every environment that advertises device
 * approval, oldest first. Decoding happens once per stream update, so readers
 * (banner, thread item, approval sheet) share one decode of the signed bytes.
 */
export function collectPendingElevationRequests(
  sources: ReadonlyArray<{
    readonly environmentId: EnvironmentId;
    readonly requests: readonly ElevationPendingRequest[];
  }>,
  previous: readonly PendingElevationRequest[],
): readonly PendingElevationRequest[] {
  const previousById = new Map(
    previous.map((entry) => [`${entry.environmentId}\u0000${entry.request.requestId}`, entry]),
  );
  const next = sources
    .flatMap(({ environmentId, requests }) =>
      requests.map((request): PendingElevationRequest => {
        const reused = previousById.get(`${environmentId}\u0000${request.requestId}`);
        return reused !== undefined && reused.request.payload === request.payload
          ? reused
          : { environmentId, request, decoded: decodeElevationRequestPayload(request.payload) };
      }),
    )
    .sort(
      (left, right) =>
        left.request.createdAt.epochMilliseconds - right.request.createdAt.epochMilliseconds,
    );
  if (next.length === previous.length && next.every((entry, index) => entry === previous[index])) {
    return previous;
  }
  return next.length === 0 ? EMPTY_PENDING : next;
}

/** `live` is false for the empty list held between sessions, which isn't the server's word. */
export type PendingElevationList = ElevationPendingRequests & { readonly live: boolean };

const NO_PENDING: PendingElevationList = { requests: [], live: false };

/**
 * The server's list while the environment has a session, none while it doesn't: every subscribe
 * starts with the whole list, so a request seen before a disconnect never outlives it. Mobile
 * replaces its session after a long background, so a card waits for a `live` list.
 */
export function followPendingElevationRequests<E, R>(
  sessions: Stream.Stream<Option.Option<unknown>>,
  requests: Stream.Stream<ElevationPendingRequests, E, R>,
): Stream.Stream<PendingElevationList, E, R> {
  return sessions.pipe(
    Stream.map(Option.isSome),
    Stream.changes,
    Stream.switchMap((connected) =>
      connected
        ? requests.pipe(Stream.map((list): PendingElevationList => ({ ...list, live: true })))
        : Stream.succeed(NO_PENDING),
    ),
  );
}

export function createElevationAtoms<R, E>(
  runtime: Atom.AtomRuntime<EnvironmentRegistry.EnvironmentRegistry | R, E>,
  options: {
    readonly environmentServerConfigsAtom: Atom.Atom<ReadonlyMap<EnvironmentId, ServerConfig>>;
  },
) {
  const pendingRequests = createEnvironmentRpcSubscriptionAtomFamily(runtime, {
    label: "environment-data:elevation:pending",
    tag: WS_METHODS.elevationSubscribe,
    transform: (requests) =>
      Stream.unwrap(
        Effect.map(EnvironmentSupervisor.EnvironmentSupervisor, (supervisor) =>
          followPendingElevationRequests(SubscriptionRef.changes(supervisor.session), requests),
        ),
      ),
  });

  let previousPending = EMPTY_PENDING;
  /** Every connected environment's pending requests, for the app-wide banner. */
  const pendingAcrossEnvironmentsAtom = Atom.make((get) => {
    const sources: Array<{
      environmentId: EnvironmentId;
      requests: readonly ElevationPendingRequest[];
    }> = [];
    for (const [environmentId, config] of get(options.environmentServerConfigsAtom)) {
      if (!environmentSupportsDeviceApproval(config)) continue;
      const result = get(pendingRequests({ environmentId, input: {} }));
      const value = Option.getOrNull(AsyncResult.value(result));
      if (value !== null) sources.push({ environmentId, requests: value.requests });
    }
    previousPending = collectPendingElevationRequests(sources, previousPending);
    return previousPending;
  }).pipe(Atom.withLabel("environment-data:elevation:pending-across-environments"));

  /** How requests that just left the pending set ended, by environment, for cards still showing them. */
  const endedAcrossEnvironmentsAtom = Atom.make((get) => {
    const ended = new Map<EnvironmentId, readonly ElevationEndedRequest[]>();
    for (const [environmentId, config] of get(options.environmentServerConfigsAtom)) {
      if (!environmentSupportsDeviceApproval(config)) continue;
      const result = get(pendingRequests({ environmentId, input: {} }));
      const value = Option.getOrNull(AsyncResult.value(result));
      if (value?.ended !== undefined && value.ended.length > 0) {
        ended.set(environmentId, value.ended);
      }
    }
    return ended;
  }).pipe(Atom.withLabel("environment-data:elevation:ended-across-environments"));

  /**
   * Environments whose pending list came from their current session. A request missing from any
   * other environment's list may only be waiting on the reconnect.
   */
  const liveEnvironmentsAtom = Atom.make((get) => {
    const live = new Set<EnvironmentId>();
    for (const [environmentId, config] of get(options.environmentServerConfigsAtom)) {
      if (!environmentSupportsDeviceApproval(config)) continue;
      const result = get(pendingRequests({ environmentId, input: {} }));
      if (Option.getOrNull(AsyncResult.value(result))?.live === true) live.add(environmentId);
    }
    return live;
  }).pipe(Atom.withLabel("environment-data:elevation:live-environments"));

  const status = createEnvironmentRpcQueryAtomFamily(runtime, {
    label: "environment-data:elevation:status",
    tag: WS_METHODS.elevationStatus,
  });
  // Setup changes return the new status; refetch so every reader sees it.
  const refreshStatus = (
    target: { readonly environmentId: EnvironmentId },
    registry: { readonly refresh: (atom: Atom.Atom<unknown>) => void },
  ) =>
    Effect.sync(() => registry.refresh(status({ environmentId: target.environmentId, input: {} })));
  const setupConcurrency = {
    mode: "singleFlight" as const,
    key: ({ environmentId }: { readonly environmentId: EnvironmentId }) => environmentId,
  };

  return {
    pendingRequests,
    pendingAcrossEnvironmentsAtom,
    endedAcrossEnvironmentsAtom,
    liveEnvironmentsAtom,
    status,
    // One answer per request at a time; the server keeps the first answer.
    respond: createEnvironmentRpcCommand(runtime, {
      label: "environment-data:elevation:respond",
      tag: WS_METHODS.elevationRespond,
      concurrency: {
        mode: "singleFlight",
        key: ({ environmentId, input }) => JSON.stringify([environmentId, input.requestId]),
      },
    }),
    // Runs `sudo -n true` on the server and waits, up to the approval window, for a phone.
    test: createEnvironmentRpcCommand(runtime, {
      label: "environment-data:elevation:test",
      tag: WS_METHODS.elevationTest,
      concurrency: setupConcurrency,
    }),
    install: createEnvironmentRpcCommand(runtime, {
      label: "environment-data:elevation:install",
      tag: WS_METHODS.elevationInstall,
      concurrency: setupConcurrency,
      onSuccess: refreshStatus,
    }),
    enroll: createEnvironmentRpcCommand(runtime, {
      label: "environment-data:elevation:enroll",
      tag: WS_METHODS.elevationEnroll,
      concurrency: setupConcurrency,
      onSuccess: refreshStatus,
    }),
    revoke: createEnvironmentRpcCommand(runtime, {
      label: "environment-data:elevation:revoke",
      tag: WS_METHODS.elevationRevoke,
      concurrency: setupConcurrency,
      onSuccess: refreshStatus,
    }),
    uninstall: createEnvironmentRpcCommand(runtime, {
      label: "environment-data:elevation:uninstall",
      tag: WS_METHODS.elevationUninstall,
      concurrency: setupConcurrency,
      onSuccess: refreshStatus,
    }),
    setPolicy: createEnvironmentRpcCommand(runtime, {
      label: "environment-data:elevation:set-policy",
      tag: WS_METHODS.elevationSetPolicy,
      concurrency: setupConcurrency,
      onSuccess: refreshStatus,
    }),
  };
}
