import {
  ElevationKeyId,
  ElevationRequestId,
  EnvironmentId,
  RunId,
  ThreadId,
  TurnItemId,
} from "@t3tools/contracts";
import type { ElevationRequestItem } from "@t3tools/client-runtime/elevation";
import * as DateTime from "effect/DateTime";
import * as Base64Url from "effect/encoding/Base64Url";
import { AsyncResult } from "effect/reactivity";
import { describe, expect, it, vi } from "vite-plus/test";
import { userEvent } from "vite-plus/test/browser";

const testState = vi.hoisted(() => ({ respond: vi.fn() }));

vi.mock(import("../../state/elevation"), async () => {
  const { Atom } = await import("effect/reactivity");
  const allowed = Atom.make(true);
  const pending = Atom.make([]);
  return {
    elevation: {
      respond: { permissionAtom: () => allowed },
      pendingAcrossEnvironmentsAtom: pending,
    },
  } as never;
});
vi.mock(import("../../state/use-atom-command"), async (original) => ({
  ...(await original()),
  useAtomCommand: (() => testState.respond) as never,
}));
vi.mock(import("../../state/environments"), async (original) => ({
  ...(await original()),
  useEnvironment: (() => ({ label: "oracle" })) as never,
}));
vi.mock(import("../elevation/ElevationAgentMark"), async (original) => ({
  ...(await original()),
  useElevationAgent: () => null,
}));

import { act, fakeTimers, render, type Screen } from "../../../test/render";
import { enrollThisBrowser, virtualAuthenticator } from "../../../test/virtualPasskey";
import { ELEVATION_COLLAPSE_MS, ELEVATION_SETTLE_MS } from "../elevation/ElevationPendingCard";
import { useElevationHandoverStore } from "../elevation/elevationHandoverStore";
import { ElevationRequestCard } from "./ElevationRequestCard";
import {
  TimelineRowActivityCtx,
  TimelineRowCtx,
  type TimelineRowSharedState,
} from "./timelineRowContext";

const environmentId = EnvironmentId.make("env-request-card");
const runId = RunId.make("run-sudo");
const PHONE_KEY = ElevationKeyId.make("cGhvbmUta2V5LWlkLTAwMA");
const now = DateTime.makeUnsafe("2026-11-01T00:00:00.000Z");

function setup() {
  testState.respond.mockReset();
  testState.respond.mockResolvedValue(AsyncResult.success(undefined));
}

function payload(keyIds: readonly string[]) {
  const argv = ["systemctl", "reload", "nginx"];
  const signed = {
    v: 1,
    kind: "sudo",
    nonce: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    issuedAt: 1793318400,
    expiresAt: 1793318500,
    host: { name: "box", machineId: "PrG9Q5lH63YpmOVmzMLgmceREYsvQFecxPfaK1Bht_k" },
    user: "kgriset",
    uid: 501,
    runAs: "root",
    runAsGroup: null,
    argv: ["sudo", ...argv],
    command: { argv, resolvedPath: "/bin/systemctl", warnings: [] },
    cwd: "/repo",
    service: "sudo",
    keyIds,
  };
  return Base64Url.encode(new TextEncoder().encode(JSON.stringify(signed)));
}

function request(
  keyIds: readonly string[],
  ended: Pick<ElevationRequestItem, "elevationStatus" | "resolvedBy"> = {
    elevationStatus: "pending",
    resolvedBy: null,
  },
): ElevationRequestItem {
  return {
    id: TurnItemId.make("elevation"),
    threadId: ThreadId.make("thread-sudo"),
    runId,
    nodeId: null,
    providerThreadId: null,
    providerTurnId: null,
    nativeItemRef: null,
    parentItemId: null,
    ordinal: 1,
    status: ended.elevationStatus === "pending" ? "waiting" : "completed",
    title: null,
    startedAt: now,
    completedAt: null,
    updatedAt: now,
    type: "elevation_request",
    requestId: ElevationRequestId.make("req-sudo"),
    kind: "sudo",
    argv: ["sudo", "systemctl", "reload", "nginx"],
    runAs: "root",
    cwd: "/repo",
    host: "box",
    warnings: [],
    explanation: "Reload nginx",
    payload: payload(keyIds),
    ...ended,
  };
}

/** `foldsAfter`: the turn has ended and folds once the card hands over. */
function timeline(item: ElevationRequestItem, foldsAfter = false) {
  return (
    <TimelineRowCtx value={{ workspaceRoot: "/repo" } as TimelineRowSharedState}>
      <TimelineRowActivityCtx
        value={{
          isWorking: true,
          isCompacting: false,
          isRevertingCheckpoint: false,
          activeTurnInProgress: true,
          awaitingUser: false,
          isPreparingWorktree: false,
          latestRunId: runId,
          backgroundWorktreeSetup: null,
          elevationFoldRunIds: new Set(foldsAfter ? [runId] : []),
        }}
      >
        <ElevationRequestCard
          environmentId={environmentId}
          item={item}
          visibility="local"
          commandKey={null}
        />
      </TimelineRowActivityCtx>
    </TimelineRowCtx>
  );
}

const advance = (ms: number) => act(() => vi.advanceTimersByTime(ms));
const outcomeLine = (screen: Screen) => screen.getByRole("status").query()?.textContent;
const settledRow = (screen: Screen) => screen.getByRole("button", { name: /^Approved/ }).query();

/** The outcome stays for the hold and through the collapse, then the row takes its place. */
async function expectHoldThenRow(screen: Screen, line: string) {
  expect(outcomeLine(screen)).toBe(line);
  await advance(ELEVATION_SETTLE_MS - 1);
  expect(outcomeLine(screen)).toBe(line);
  expect(settledRow(screen)).toBeNull();
  // The card collapses, still saying how it ended, as its row opens beneath it.
  await advance(1);
  expect(outcomeLine(screen)).toBe(line);
  await advance(ELEVATION_COLLAPSE_MS);
  expect(outcomeLine(screen)).toBeUndefined();
  expect(settledRow(screen)).not.toBeNull();
}

// Fake timers stand in for the hold and collapse; every way a card ends leaves the same way.
describe("ElevationRequestCard", () => {
  it("holds its own approval like any other ending, from when the request settles", async () => {
    setup();
    await using _authenticator = await virtualAuthenticator(environmentId);
    const { keyId } = await enrollThisBrowser(environmentId);
    await using screen = await render(timeline(request([PHONE_KEY, keyId])));
    await userEvent.click(screen.getByRole("button", { name: "Approve" }));
    await expect.element(screen.getByRole("status")).toHaveTextContent("Approved");
    using _timers = fakeTimers();

    // Answering here doesn't start the leave: the request is still pending until the server says.
    await advance(ELEVATION_SETTLE_MS + ELEVATION_COLLAPSE_MS);
    expect(outcomeLine(screen)).toBe("Approved");

    await screen.rerender(
      timeline(
        request([PHONE_KEY, keyId], {
          elevationStatus: "approved",
          resolvedBy: { deviceLabel: "kgriset on oracle", keyId },
        }),
      ),
    );
    await expectHoldThenRow(screen, "Approved");
  });

  it("holds an approval from another device the same way", async () => {
    setup();
    await using screen = await render(timeline(request([PHONE_KEY])));
    using _timers = fakeTimers();
    await screen.rerender(
      timeline(
        request([PHONE_KEY], {
          elevationStatus: "approved",
          resolvedBy: { deviceLabel: "Galaxy Z Fold", keyId: PHONE_KEY },
        }),
      ),
    );
    await expectHoldThenRow(screen, "Approved on Galaxy Z Fold");
  });

  it("closes its ended turn's fold along with it", async () => {
    setup();
    await using screen = await render(timeline(request([PHONE_KEY]), true));
    using _timers = fakeTimers();
    await screen.rerender(
      timeline(
        request([PHONE_KEY], {
          elevationStatus: "denied",
          resolvedBy: { deviceLabel: "Galaxy Z Fold", keyId: PHONE_KEY },
        }),
        true,
      ),
    );
    await advance(ELEVATION_SETTLE_MS - 1);
    expect(useElevationHandoverStore.getState().foldingRunIds.has(runId)).toBe(false);
    await advance(1);
    // The timeline closes the rows the fold hides over the same collapse.
    expect(useElevationHandoverStore.getState().foldingRunIds.has(runId)).toBe(true);
    await advance(ELEVATION_COLLAPSE_MS);
    expect(useElevationHandoverStore.getState().runIds.has(runId)).toBe(false);
    expect(screen.getByRole("button", { name: /^Denied/ }).query()).not.toBeNull();
  });
});
