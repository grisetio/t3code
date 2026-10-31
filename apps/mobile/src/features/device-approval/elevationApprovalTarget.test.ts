import type { PendingElevationRequest } from "@t3tools/client-runtime/state/elevation";
import { ElevationRequestId, EnvironmentId, ThreadId } from "@t3tools/contracts";
import * as DateTime from "effect/DateTime";
import * as Result from "effect/Result";
import { describe, expect, it } from "vite-plus/test";

import { pendingRequestForNotificationIntent } from "./elevationApprovalTarget";

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
