import { assert, it } from "@effect/vitest";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";

import { decodeTurnItemPayload } from "./TurnItemPayload.ts";

// A row as written by a server with device approval; this branch knows the type.
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
  cwd: "/repo",
  host: "mac",
  warnings: [],
  explanation: null,
  payload: null,
  resolvedBy: { deviceLabel: "phone" },
};
// The same row from a server with an item type this one lacks.
const futureItem = { ...elevationRequest, type: "future_item" };

it.effect("reads an unknown turn item type as a notice in its place", () =>
  Effect.gen(function* () {
    const item = yield* decodeTurnItemPayload(JSON.stringify(futureItem));
    assert.strictEqual(item.type, "system_notice");
    assert.strictEqual(String(item.id), futureItem.id);
    assert.strictEqual(item.ordinal, futureItem.ordinal);
    assert.strictEqual(String(item.runId), futureItem.runId);
    assert.strictEqual(item.status, "completed");
    assert.include(item.type === "system_notice" ? item.message : "", "future_item");
    assert.notProperty(item, "argv");
  }),
);

it.effect("settles an unknown turn item that was still in progress", () =>
  Effect.gen(function* () {
    for (const status of ["idle", "pending", "running", "waiting"]) {
      const item = yield* decodeTurnItemPayload(JSON.stringify({ ...futureItem, status }));
      assert.strictEqual(item.status, "cancelled");
    }
    const failed = yield* decodeTurnItemPayload(
      JSON.stringify({ ...futureItem, status: "failed" }),
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

it.effect("decodes elevation requests strictly, never as notices", () =>
  Effect.gen(function* () {
    const item = yield* decodeTurnItemPayload(JSON.stringify(elevationRequest));
    assert.strictEqual(item.type, "elevation_request");
    const { cwd: _cwd, ...withoutCwd } = elevationRequest;
    const exit = yield* Effect.exit(decodeTurnItemPayload(JSON.stringify(withoutCwd)));
    assert.isTrue(Exit.isFailure(exit));
  }),
);
