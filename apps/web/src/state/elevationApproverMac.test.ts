import type {
  DesktopBridge,
  DesktopDeviceApprovalState,
  ElevationKeyId,
  ElevationSignedResponse,
  EnvironmentId,
} from "@t3tools/contracts";
import { describe, expect, it, vi } from "vite-plus/test";

import { createMacApproverSource, deviceApprovalErrorMessage } from "./elevationApproverMac";

type Bridge = NonNullable<DesktopBridge["deviceApproval"]>;

const ENV = "env-1" as EnvironmentId;
const KEY = "AAAAAAAAAAAAAAAAAAAAAA" as ElevationKeyId;
const READY = {
  supported: true as const,
  keyId: KEY as ElevationKeyId | null,
  unavailable: null,
  model: "MacBook Pro",
  computerName: "studio",
} satisfies DesktopDeviceApprovalState;

function setup(initial: DesktopDeviceApprovalState) {
  let state = initial;
  const aborted: string[] = [];
  const signs: Array<{
    operationId: string;
    payload: string;
    finish: (r: ElevationSignedResponse | null) => void;
  }> = [];
  const bridge: Bridge = {
    getState: vi.fn(async () => state),
    createKey: async () => {
      state = { ...READY, keyId: KEY };
      return { publicKey: "spki" };
    },
    sign: (input) =>
      new Promise((resolve) => {
        signs.push({ operationId: input.operationId, payload: input.payload, finish: resolve });
      }),
    abort: async (operationId) => {
      aborted.push(operationId);
      // Main interrupts the helper, which closes the sheet and answers null.
      signs.find((sign) => sign.operationId === operationId)?.finish(null);
    },
    forget: async () => {
      state = { ...READY, keyId: null };
    },
  };
  const focus = new EventTarget();
  const source = createMacApproverSource(() => bridge, focus);
  const changed = vi.fn();
  const unsubscribe = source.subscribe(changed);
  return {
    source,
    bridge,
    focus,
    changed,
    unsubscribe,
    aborted,
    signs,
    setState: (next: DesktopDeviceApprovalState) => {
      state = next;
    },
  };
}

describe("createMacApproverSource", () => {
  it("reads the state once, keeps the object stable, and reads again on focus", async () => {
    const t = setup(READY);
    expect(t.source.get(ENV)).toBeNull();
    await vi.waitFor(() => expect(t.source.get(ENV)?.keyId).toBe(KEY));
    const approver = t.source.get(ENV);
    expect(approver?.unavailableReason).toBeNull();

    t.focus.dispatchEvent(new Event("focus"));
    await vi.waitFor(() => expect(t.bridge.getState).toHaveBeenCalledTimes(2));
    expect(t.source.get(ENV)).toBe(approver);

    t.setState({ ...READY, unavailable: "lid_closed" });
    t.focus.dispatchEvent(new Event("focus"));
    await vi.waitFor(() =>
      expect(t.source.get(ENV)?.unavailableReason).toBe("Touch ID needs the lid open"),
    );
    expect(t.changed).toHaveBeenCalledTimes(2);

    t.unsubscribe();
    t.focus.dispatchEvent(new Event("focus"));
    expect(t.bridge.getState).toHaveBeenCalledTimes(3);
  });

  it("offers nothing where this Mac can't approve", async () => {
    const t = setup({ supported: false });
    t.source.get(ENV);
    await vi.waitFor(() => expect(t.bridge.getState).toHaveBeenCalled());
    expect(t.source.get(ENV)).toBeNull();
    expect(t.changed).not.toHaveBeenCalled();
  });

  it("closes the sheet when another device answers, and that reads as no answer", async () => {
    const t = setup(READY);
    t.source.get(ENV);
    await vi.waitFor(() => expect(t.source.get(ENV)).not.toBeNull());
    const controller = new AbortController();
    const signed = t.source.get(ENV)!.sign(new Uint8Array([0xfb, 0xff]), controller.signal);
    await vi.waitFor(() => expect(t.signs).toHaveLength(1));
    expect(t.signs[0]!.payload).toBe("-_8");

    controller.abort();
    await expect(signed).resolves.toBeNull();
    expect(t.aborted).toEqual([t.signs[0]!.operationId]);
  });

  it("sees the new key after setup even when a read was already under way", async () => {
    const t = setup({ ...READY, keyId: null });
    t.source.get(ENV);
    await vi.waitFor(() => expect(t.source.get(ENV)).not.toBeNull());
    t.focus.dispatchEvent(new Event("focus"));
    await t.source.get(ENV)!.createKey(new AbortController().signal);
    await vi.waitFor(() => expect(t.source.get(ENV)?.keyId).toBe(KEY));

    await t.source.get(ENV)!.forget();
    await vi.waitFor(() => expect(t.source.get(ENV)?.keyId).toBeNull());
  });

  it("adds the computer's name only when the model's label is taken", async () => {
    const t = setup(READY);
    t.source.get(ENV);
    await vi.waitFor(() => expect(t.source.get(ENV)).not.toBeNull());
    const approver = t.source.get(ENV)!;
    expect(approver.label(["Pixel 9"])).toBe("MacBook Pro");
    expect(approver.label(["MacBook Pro"])).toBe("MacBook Pro (studio)");
  });
});

describe("deviceApprovalErrorMessage", () => {
  it("shows main's message without Electron's wrapping", () => {
    expect(
      deviceApprovalErrorMessage(
        new Error(
          "Error invoking remote method 'desktop:device-approval-sign': DesktopDeviceApprovalError: This Mac needs fixing.",
        ),
      ),
    ).toBe("This Mac needs fixing.");
    expect(deviceApprovalErrorMessage(new Error(""))).toBe("Touch ID failed.");
  });
});
