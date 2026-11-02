import type { PendingElevationRequest } from "@t3tools/client-runtime/state/elevation";
import { ElevationRequestId, EnvironmentId, ThreadId } from "@t3tools/contracts";
import * as DateTime from "effect/DateTime";
import * as Result from "effect/Result";
import { describe, expect, it } from "vite-plus/test";

import {
  lockScreenRequestState,
  pendingRequestForNotificationIntent,
} from "./elevationApprovalTarget";

const environmentId = EnvironmentId.make("env-1");
const threadId = ThreadId.make("thread-1");

function pending(requestId: string, createdAt: number, thread = threadId): PendingElevationRequest {
  return {
    environmentId,
    request: {
      requestId: ElevationRequestId.make(requestId),
      threadId: thread,
      turnItemId: null,
      payload: "",
      explanation: null,
      createdAt: DateTime.makeUnsafe(createdAt),
    },
    decoded: Result.fail("invalid_json"),
  };
}

describe("pendingRequestForNotificationIntent", () => {
  const intent = { environmentId, threadId, tappedAt: 10_000 };

  it("opens the newest request the tapped push could have been about", () => {
    const requests = [pending("old", 1_000), pending("pushed", 9_000), pending("later", 11_000)];
    expect(pendingRequestForNotificationIntent(intent, requests, 10_500)).toBe(requests[1]);
  });

  it("ignores other threads and requests created after the tap", () => {
    const requests = [pending("other", 9_000, ThreadId.make("thread-2")), pending("later", 11_000)];
    expect(pendingRequestForNotificationIntent(intent, requests, 12_000)).toBeNull();
  });

  it("gives up once the tap is stale", () => {
    expect(pendingRequestForNotificationIntent(intent, [pending("pushed", 9_000)], 200_000)).toBe(
      "expired",
    );
  });
});

describe("lockScreenRequestState", () => {
  const shown = pending("shown", 9_000);
  const approved = {
    requestId: shown.request.requestId,
    elevationStatus: "approved" as const,
    resolvedBy: null,
  };

  it("keeps the card while the list is between sessions", () => {
    // Back from a long lock, the app replaces its session and the list is empty until it's back.
    expect(lockScreenRequestState({ shown, current: null, live: false, ended: [] })).toEqual({
      kind: "pending",
      entry: shown,
    });
  });

  it("says how the request ended once a fresh list no longer has it", () => {
    expect(lockScreenRequestState({ shown, current: null, live: true, ended: [approved] })).toEqual(
      { kind: "ended", entry: shown, ended: approved },
    );
  });

  it("is gone when a fresh list has neither it nor how it ended", () => {
    expect(lockScreenRequestState({ shown, current: null, live: true, ended: [] })).toEqual({
      kind: "gone",
    });
  });

  it("waits for the request while the list is between sessions", () => {
    expect(lockScreenRequestState({ shown: null, current: null, live: false, ended: [] })).toEqual({
      kind: "waiting",
    });
  });

  it("is gone at once when a fresh list never had it", () => {
    // Answered elsewhere during the lock: nothing will arrive, so the card says so instead of waiting.
    expect(lockScreenRequestState({ shown: null, current: null, live: true, ended: [] })).toEqual({
      kind: "gone",
    });
  });
});
