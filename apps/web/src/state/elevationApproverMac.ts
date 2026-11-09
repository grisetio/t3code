import { uniqueElevationApproverLabel } from "@t3tools/client-runtime/elevation";
import type {
  DesktopBridge,
  DesktopDeviceApprovalState,
  DesktopTouchIdUnavailable,
  EnvironmentId,
} from "@t3tools/contracts";
import * as Base64Url from "effect/encoding/Base64Url";

import { randomUUID } from "../lib/utils";
import type { ElevationApprover, ElevationApproverSource } from "./elevationApprover";

type DeviceApprovalBridge = NonNullable<DesktopBridge["deviceApproval"]>;

const UNAVAILABLE_REASONS: Record<DesktopTouchIdUnavailable, string> = {
  lid_closed: "Touch ID needs the lid open",
  keyboard_away: "Connect your Touch ID keyboard",
  locked_out: "Touch ID is locked. Unlock it with your Mac password, then try again",
  no_fingerprints: "Add a fingerprint in System Settings → Touch ID & Password",
  needs_fixing: "This Mac needs fixing",
  unavailable: "Touch ID isn't available right now",
};

/** Main's message without Electron's "Error invoking remote method '…':" and the error's name. */
export function deviceApprovalErrorMessage(error: unknown): string {
  const raw = error instanceof Error ? error.message : String(error);
  const message = raw
    .replace(/^Error invoking remote method '[^']*':\s*/u, "")
    .replace(/^(?:DesktopDeviceApprovalError|Error):\s*/u, "")
    .trim();
  return message === "" ? "Touch ID failed." : message;
}

/**
 * This Mac's Touch ID, one key per environment, through the desktop's main process. Its state is
 * read when a card or settings row subscribes and when the window regains focus (the lid opened,
 * a keyboard came back), never on a timer.
 */
export function createMacApproverSource(
  getBridge: () => DeviceApprovalBridge | undefined,
  focusTarget: Pick<Window, "addEventListener" | "removeEventListener"> | undefined,
): ElevationApproverSource {
  const entries = new Map<
    EnvironmentId,
    { readonly state: MacState | null; readonly approver: ElevationApprover | null }
  >();
  // Environments being read; true when something changed meanwhile, so it reads again after.
  const reading = new Map<EnvironmentId, boolean>();
  const listeners = new Set<() => void>();

  const refresh = (environmentId: EnvironmentId) => {
    const bridge = getBridge();
    if (bridge === undefined) return;
    if (reading.has(environmentId)) {
      reading.set(environmentId, true);
      return;
    }
    reading.set(environmentId, false);
    void bridge
      .getState(environmentId)
      .catch((): DesktopDeviceApprovalState => ({ supported: false }))
      .then((read) => {
        const again = reading.get(environmentId) === true;
        reading.delete(environmentId);
        if (again) return refresh(environmentId);
        const state = read.supported ? read : null;
        if (sameState(entries.get(environmentId)?.state ?? null, state)) return;
        entries.set(environmentId, {
          state,
          approver: state === null ? null : approverFor(bridge, environmentId, state, refresh),
        });
        for (const listener of listeners) listener();
      });
  };
  const refreshAll = () => {
    for (const environmentId of entries.keys()) refresh(environmentId);
  };

  return {
    subscribe: (listener) => {
      listeners.add(listener);
      if (listeners.size === 1) focusTarget?.addEventListener("focus", refreshAll);
      refreshAll();
      return () => {
        listeners.delete(listener);
        if (listeners.size === 0) focusTarget?.removeEventListener("focus", refreshAll);
      };
    },
    get: (environmentId) => {
      if (getBridge() === undefined) return null;
      const entry = entries.get(environmentId);
      if (entry !== undefined) return entry.approver;
      entries.set(environmentId, { state: null, approver: null });
      refresh(environmentId);
      return null;
    },
  };
}

type MacState = Extract<DesktopDeviceApprovalState, { supported: true }>;

function sameState(a: MacState | null, b: MacState | null): boolean {
  return a === null || b === null
    ? a === b
    : a.keyId === b.keyId &&
        a.unavailable === b.unavailable &&
        a.model === b.model &&
        a.computerName === b.computerName;
}

function approverFor(
  bridge: DeviceApprovalBridge,
  environmentId: EnvironmentId,
  state: MacState,
  refresh: (environmentId: EnvironmentId) => void,
): ElevationApprover {
  /** One Touch ID sheet, closed through main when the card's signal aborts. */
  const operation = async <A>(
    signal: AbortSignal,
    run: (operationId: string) => Promise<A>,
  ): Promise<A | null> => {
    if (signal.aborted) return null;
    const operationId = randomUUID();
    const abort = () => void bridge.abort(operationId);
    signal.addEventListener("abort", abort, { once: true });
    try {
      const result = await run(operationId);
      return signal.aborted ? null : result;
    } catch (error) {
      if (signal.aborted) return null;
      throw new Error(deviceApprovalErrorMessage(error), { cause: error });
    } finally {
      signal.removeEventListener("abort", abort);
      refresh(environmentId);
    }
  };
  return {
    kind: "mac",
    keyId: state.keyId,
    unavailableReason: state.unavailable === null ? null : UNAVAILABLE_REASONS[state.unavailable],
    label: (existing) => uniqueElevationApproverLabel(state.model, state.computerName, existing),
    sign: (payloadBytes, signal) =>
      operation(signal, (operationId) =>
        bridge.sign({ environmentId, operationId, payload: Base64Url.encode(payloadBytes) }),
      ),
    createKey: (signal) =>
      operation(signal, (operationId) => bridge.createKey({ environmentId, operationId })),
    forget: async () => {
      try {
        await bridge.forget(environmentId);
      } catch (error) {
        throw new Error(deviceApprovalErrorMessage(error), { cause: error });
      } finally {
        refresh(environmentId);
      }
    },
  };
}

export const macApproverSource = createMacApproverSource(
  () => (typeof window === "undefined" ? undefined : window.desktopBridge?.deviceApproval),
  typeof window === "undefined" ? undefined : window,
);
