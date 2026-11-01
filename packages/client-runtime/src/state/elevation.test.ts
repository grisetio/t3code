import { describe, expect, it } from "@effect/vitest";
import {
  ElevationRequestId,
  EnvironmentId,
  ThreadId,
  type ElevationPendingRequest,
} from "@t3tools/contracts";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as Fiber from "effect/Fiber";
import * as Option from "effect/Option";
import * as Queue from "effect/Queue";
import * as Stream from "effect/Stream";
import * as SubscriptionRef from "effect/SubscriptionRef";

import { collectPendingElevationRequests, followPendingElevationRequests } from "./elevation.ts";

const request = (
  id: string,
  createdAtMs: number,
  threadId: string | null,
): ElevationPendingRequest => ({
  requestId: ElevationRequestId.make(id),
  threadId: threadId === null ? null : ThreadId.make(threadId),
  turnItemId: null,
  payload: "e30",
  explanation: null,
  createdAt: DateTime.makeUnsafe(createdAtMs),
});

describe("collectPendingElevationRequests", () => {
  it("merges environments oldest first, keeping requests no thread owns", () => {
    const local = EnvironmentId.make("local");
    const remote = EnvironmentId.make("remote");
    const merged = collectPendingElevationRequests(
      [
        { environmentId: local, requests: [request("b", 2_000, "thread-1")] },
        { environmentId: remote, requests: [request("a", 1_000, null)] },
      ],
      [],
    );
    expect(merged.map((entry) => [entry.environmentId, entry.request.requestId])).toEqual([
      [remote, "a"],
      [local, "b"],
    ]);
  });

  it("keeps the previous list when a stream update changed nothing", () => {
    const env = EnvironmentId.make("local");
    const first = collectPendingElevationRequests(
      [{ environmentId: env, requests: [request("a", 1_000, null)] }],
      [],
    );
    const second = collectPendingElevationRequests(
      [{ environmentId: env, requests: [request("a", 1_000, null)] }],
      first,
    );
    expect(second).toBe(first);
  });
});

describe("followPendingElevationRequests", () => {
  it.effect("drops what the last session sent when it ends and takes the next session's list", () =>
    Effect.gen(function* () {
      const session = yield* SubscriptionRef.make<Option.Option<string>>(Option.some("first"));
      // Each subscribe gets its own server stream, like a fresh RPC on a new session.
      type Server = Queue.Queue<{ requests: ElevationPendingRequest[] }>;
      const subscriptions = yield* Queue.unbounded<Server>();
      const subscribe = Stream.unwrap(
        Effect.gen(function* () {
          const server = yield* Queue.unbounded<{ requests: ElevationPendingRequest[] }>();
          yield* Queue.offer(subscriptions, server);
          return Stream.fromQueue(server);
        }),
      );
      const seen = yield* Queue.unbounded<readonly string[]>();
      const fiber = yield* followPendingElevationRequests(
        SubscriptionRef.changes(session),
        subscribe,
      ).pipe(
        Stream.runForEach((value) =>
          Queue.offer(
            seen,
            value.requests.map((entry) => entry.requestId),
          ),
        ),
        Effect.forkChild,
      );
      const first = yield* Queue.take(subscriptions);
      yield* Queue.offer(first, { requests: [request("a", 1, "t")] });
      expect(yield* Queue.take(seen)).toEqual(["a"]);

      // The server restarts: the socket drops, and the request it held is gone.
      yield* SubscriptionRef.set(session, Option.none());
      expect(yield* Queue.take(seen)).toEqual([]);

      yield* SubscriptionRef.set(session, Option.some("second"));
      const second = yield* Queue.take(subscriptions);
      yield* Queue.offer(second, { requests: [request("b", 2, "t")] });
      expect(yield* Queue.take(seen)).toEqual(["b"]);
      yield* Fiber.interrupt(fiber);
    }),
  );
});
