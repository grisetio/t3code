import { assert, it } from "@effect/vitest";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";

import { decodeTurnItemPayload } from "./TurnItemPayload.ts";

// Shape of a row written by a server with device-approval elevation requests.
const elevationRequest = {
  id: "elevation:c992f488-d1ed-4c24-9684-689affe32708",
  threadId: "thread:unknown-turn-items",
  runId: "run:thread:unknown-turn-items:ordinal:205",
  nodeId: null,
  providerThreadId: null,
  providerTurnId: null,
  nativeItemRef: null,
  parentItemId: null,
  ordinal: 205_000_007,
  status: "completed",
  title: null,
  startedAt: "2026-11-03T12:00:18.792Z",
  completedAt: "2026-11-03T12:00:59.049Z",
  updatedAt: "2026-11-03T12:00:59.049Z",
  type: "elevation_request",
  requestId: "c992f488-d1ed-4c24-9684-689affe32708",
  kind: "sudo",
  argv: ["sudo", "/bin/ls", "/var/root"],
  runAs: "root",
  elevationStatus: "approved",
  resolvedBy: { deviceLabel: "phone", keyId: "key" },
};

it.effect("reads an unknown turn item type as a notice in its place", () =>
  Effect.gen(function* () {
    const item = yield* decodeTurnItemPayload(JSON.stringify(elevationRequest));
    assert.strictEqual(item.type, "system_notice");
    assert.strictEqual(String(item.id), elevationRequest.id);
    assert.strictEqual(item.ordinal, elevationRequest.ordinal);
    assert.strictEqual(String(item.runId), elevationRequest.runId);
    assert.strictEqual(item.status, "completed");
    assert.include(item.type === "system_notice" ? item.message : "", "elevation_request");
    assert.notProperty(item, "argv");
  }),
);

it.effect("settles an unknown turn item that was still in progress", () =>
  Effect.gen(function* () {
    for (const status of ["idle", "pending", "running", "waiting"]) {
      const item = yield* decodeTurnItemPayload(JSON.stringify({ ...elevationRequest, status }));
      assert.strictEqual(item.status, "cancelled");
    }
    const failed = yield* decodeTurnItemPayload(
      JSON.stringify({ ...elevationRequest, status: "failed" }),
    );
    assert.strictEqual(failed.status, "failed");
  }),
);

it.effect("still rejects a malformed row of a known type", () =>
  Effect.gen(function* () {
    const exit = yield* Effect.exit(
      decodeTurnItemPayload(JSON.stringify({ ...elevationRequest, type: "system_notice" })),
    );
    assert.isTrue(Exit.isFailure(exit));
    const invalid = yield* Effect.exit(decodeTurnItemPayload("{not json"));
    assert.isTrue(Exit.isFailure(invalid));
  }),
);
