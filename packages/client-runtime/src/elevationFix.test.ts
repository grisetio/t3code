import type { ElevationCheck, ElevationStatus } from "@t3tools/contracts";
import * as DateTime from "effect/DateTime";
import { describe, expect, it } from "vite-plus/test";

import {
  deviceApprovalAgentPrompt,
  deviceApprovalCheckPaths,
  deviceApprovalFailingChecks,
  deviceApprovalState,
  pickDeviceApprovalFixProject,
  planDeviceApprovalFix,
} from "./elevationFix.ts";

const KEY_A = "AAAAAAAAAAAAAAAAAAAAAA";
const KEY_B = "BBBBBBBBBBBBBBBBBBBBBB";

const device = (keyId: string) => ({
  keyId,
  label: "Pixel",
  securityLevel: "strongbox" as const,
  enrolledAt: DateTime.makeUnsafe(0),
  lastUsedAt: null,
});

const check = (id: string, ok: boolean, extra: Partial<ElevationCheck> = {}): ElevationCheck => ({
  id,
  ok,
  message: ok ? `${id} ok` : `${id} failing`,
  ...extra,
});

const status = (overrides: Partial<ElevationStatus> = {}): ElevationStatus => ({
  user: "kim",
  supported: true,
  ready: true,
  ownsApprovals: true,
  setupOutsideT3: false,
  helperInstalled: true,
  checks: [check("pam:sudo_local", true), check("config", true), check("devices", true)],
  plannedChanges: [],
  devices: [device(KEY_A)],
  ...overrides,
});

describe("deviceApprovalState", () => {
  it("is off until anything is installed", () => {
    expect(deviceApprovalState(status({ ownsApprovals: false, devices: [] }), null)).toBe("off");
  });

  it("needs fixing when this phone's key is gone even though another phone keeps it ready", () => {
    const current = status({ devices: [device(KEY_B)] });
    expect(deviceApprovalState(current, { keyId: KEY_B })).toBe("on");
    expect(deviceApprovalState(current, { keyId: KEY_A })).toBe("needs_fixing");
    // A phone that was never set up here doesn't make a working machine look broken.
    expect(deviceApprovalState(current, { keyId: null })).toBe("on");
  });
});

describe("planDeviceApprovalFix", () => {
  it("re-adds this phone's key with enroll when that's all that's wrong", () => {
    const current = status({ devices: [device(KEY_B)] });
    expect(planDeviceApprovalFix(current, { keyId: KEY_A }, { canRepair: true })).toEqual({
      kind: "repair",
      install: false,
      enroll: true,
      agentAfter: false,
    });
  });

  it("repairs a missing PAM line T3 wrote with install, which also adds the key", () => {
    const current = status({
      ready: false,
      checks: [check("pam:sudo_local", false), check("devices", false)],
      devices: [],
    });
    expect(planDeviceApprovalFix(current, { keyId: KEY_A }, { canRepair: true })).toEqual({
      kind: "repair",
      install: true,
      enroll: false,
      agentAfter: false,
    });
  });

  it("follows the server's fixBy, so a Nix-managed PAM line goes to an agent", () => {
    const current = status({
      ready: false,
      checks: [check("pam:sudo_local", false, { fixBy: "agent" })],
    });
    expect(planDeviceApprovalFix(current, { keyId: KEY_A }, { canRepair: true })).toEqual({
      kind: "agent",
    });
  });

  it("repairs the key first and continues into an agent for the rest", () => {
    const current = status({
      ready: false,
      checks: [check("pam:sudo_local", false, { fixBy: "agent" })],
      devices: [device(KEY_B)],
    });
    expect(planDeviceApprovalFix(current, { keyId: KEY_A }, { canRepair: true })).toEqual({
      kind: "repair",
      install: false,
      enroll: true,
      agentAfter: true,
    });
  });

  it("hands parts set up outside T3 to an agent when the server doesn't say", () => {
    const current = status({
      ready: false,
      setupOutsideT3: true,
      checks: [check("pam:sudo_local", false)],
    });
    expect(planDeviceApprovalFix(current, null, { canRepair: true })).toEqual({ kind: "agent" });
  });

  it("points a client that can't create keys at the phone for T3's own repairs", () => {
    const current = status({ ready: false, checks: [check("devices", false)], devices: [] });
    expect(planDeviceApprovalFix(current, null, { canRepair: false })).toEqual({ kind: "phone" });
    const mixed = status({
      ready: false,
      checks: [check("devices", false), check("pam:sudo_local", false, { fixBy: "agent" })],
      devices: [],
    });
    expect(planDeviceApprovalFix(mixed, null, { canRepair: false })).toEqual({ kind: "agent" });
  });
});

describe("pickDeviceApprovalFixProject", () => {
  const projects = [
    { id: "home", environmentId: "env", workspaceRoot: "/Users/kim" },
    { id: "nix", environmentId: "env", workspaceRoot: "/Users/kim/nix-hosts" },
    { id: "other-env", environmentId: "env2", workspaceRoot: "/Users/kim/nix-hosts" },
  ];

  it("picks the innermost project on the machine that holds a failing path", () => {
    const paths = deviceApprovalCheckPaths([
      check("pam:sudo_local", false, {
        message:
          "PAM line missing in /etc/pam.d/sudo_local (from /Users/kim/nix-hosts/modules/sudo.nix).",
      }),
    ]);
    expect(paths).toEqual(["/etc/pam.d/sudo_local", "/Users/kim/nix-hosts/modules/sudo.nix"]);
    expect(pickDeviceApprovalFixProject(projects, "env", paths)?.id).toBe("nix");
  });

  it("finds none when no project holds the paths", () => {
    expect(pickDeviceApprovalFixProject(projects, "env", ["/etc/pam.d/sudo_local"])).toBeNull();
    expect(pickDeviceApprovalFixProject(projects, "env", ["/Users/kimberly/x"])).toBeNull();
  });
});

describe("deviceApprovalAgentPrompt", () => {
  it("carries the failing checks, the machine and T3's repair attempt", () => {
    const current = status({
      ready: false,
      checks: [
        check("pam:sudo_local", false, {
          message: "PAM line in /etc/pam.d/sudo_local isn't first or has the wrong control",
          fixBy: "t3",
        }),
        check("config", true, {
          message: "/etc/t3-elevation/users/kim.toml points at this server",
        }),
      ],
    });
    const prompt = deviceApprovalAgentPrompt({
      machine: "Mac mini",
      status: current,
      failing: deviceApprovalFailingChecks(current, null),
      repair: { ran: ["install"], error: null },
      projectOwnsConfig: false,
    });
    expect(prompt).toContain(
      "Device approval on Mac mini needs fixing: agents' sudo asks for the password again. T3 tried to repair it, but the checks still fail.",
    );
    expect(prompt).toContain("Machine: Mac mini (user kim)");
    expect(prompt).toContain(
      "- PAM line in /etc/pam.d/sudo_local isn't first or has the wrong control [pam:sudo_local, fix by t3]",
    );
    expect(prompt).toContain("- /etc/t3-elevation/users/kim.toml points at this server");
    expect(prompt).toContain(
      "T3's repair attempt: ran t3-elevation install; the re-check still fails.",
    );
  });
});
