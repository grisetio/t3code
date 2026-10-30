import {
  WS_METHODS,
  type ElevationPayloadDecodeFailure,
  type ElevationPendingRequest,
  type EnvironmentId,
  type ServerConfig,
} from "@t3tools/contracts";
import * as Effect from "effect/Effect";
import * as Option from "effect/Option";
import * as Result from "effect/Result";
import { AsyncResult, Atom } from "effect/reactivity";

import type * as EnvironmentRegistry from "../connection/registry.ts";
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

export function environmentSupportsDeviceApproval(config: ServerConfig | null | undefined) {
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

export function createElevationAtoms<R, E>(
  runtime: Atom.AtomRuntime<EnvironmentRegistry.EnvironmentRegistry | R, E>,
  options: {
    readonly environmentServerConfigsAtom: Atom.Atom<ReadonlyMap<EnvironmentId, ServerConfig>>;
  },
) {
  const pendingRequests = createEnvironmentRpcSubscriptionAtomFamily(runtime, {
    label: "environment-data:elevation:pending",
    tag: WS_METHODS.elevationSubscribe,
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
  };
}
