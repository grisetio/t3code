import { describe, expect, it } from "vite-plus/test";
import {
  ElevationRequestId,
  EnvironmentId,
  ThreadId,
  type ElevationPendingRequest,
} from "@t3tools/contracts";
import * as DateTime from "effect/DateTime";

import { collectPendingElevationRequests } from "./elevation.ts";

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
