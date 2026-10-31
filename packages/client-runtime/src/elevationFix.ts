import type { ElevationCheck, ElevationStatus } from "@t3tools/contracts";

// Settings → Device approval: one state, one Fix. T3 repairs a part itself when
// it knows the cause and the repair lasts; anything else, or anything a repair
// didn't fix, goes to an agent with the diagnosis (FLOW moment 5).

export type DeviceApprovalState = "on" | "needs_fixing" | "off";

/** Id of the check a phone adds when its own key is missing from the machine. */
const THIS_PHONE_CHECK_ID = "this_phone";

export interface DeviceApprovalPhone {
  /** This phone's key on this machine, or null when it was never set up here. */
  readonly keyId: string | null;
}

type StatusFields = Pick<
  ElevationStatus,
  "ready" | "ownsApprovals" | "devices" | "checks" | "setupOutsideT3"
>;

function deviceApprovalInstalled(status: Pick<StatusFields, "ownsApprovals" | "devices">) {
  return status.ownsApprovals || status.devices.length > 0;
}

/**
 * The failing checks, plus "This phone isn't enrolled" when a phone that was
 * set up here no longer finds its key on the machine.
 */
export function deviceApprovalFailingChecks(
  status: StatusFields,
  phone: DeviceApprovalPhone | null,
): readonly ElevationCheck[] {
  const failing = status.checks.filter((check) => !check.ok);
  const phoneMissing =
    phone !== null &&
    phone.keyId !== null &&
    status.devices.length > 0 &&
    !status.devices.some((device) => device.keyId === phone.keyId);
  return phoneMissing
    ? [
        ...failing,
        {
          id: THIS_PHONE_CHECK_ID,
          ok: false,
          message: "This phone isn't enrolled",
          fixBy: "t3",
        },
      ]
    : failing;
}

export function deviceApprovalState(
  status: StatusFields,
  phone: DeviceApprovalPhone | null,
): DeviceApprovalState {
  if (!deviceApprovalInstalled(status)) return "off";
  return status.ready && deviceApprovalFailingChecks(status, phone).length === 0
    ? "on"
    : "needs_fixing";
}

// Parts the helper's `install` rewrites when they're missing or misplaced.
const INSTALL_REPAIRS = /^(pam:[a-z_-]+|module|config|keys)$/;
// Parts that are this phone's key; only a phone can add it back.
const ENROLL_REPAIRS = new Set(["devices", THIS_PHONE_CHECK_ID]);

/**
 * Who repairs a failing check. The server says so in `fixBy`; older servers
 * don't, so infer it: install rewrites only what T3 wrote, so anything set up
 * outside T3 goes to an agent. A wrong guess costs one re-check, after which
 * the agent gets it anyway.
 */
function deviceApprovalFixBy(
  check: ElevationCheck,
  status: Pick<StatusFields, "setupOutsideT3">,
): "t3" | "agent" {
  if (check.fixBy !== undefined) return check.fixBy;
  if (ENROLL_REPAIRS.has(check.id)) return "t3";
  return INSTALL_REPAIRS.test(check.id) && !status.setupOutsideT3 ? "t3" : "agent";
}

export type DeviceApprovalFixPlan =
  | { readonly kind: "none" }
  /** T3 repairs with the Mac password, then re-checks; `agentAfter` continues into an agent. */
  | {
      readonly kind: "repair";
      readonly install: boolean;
      readonly enroll: boolean;
      readonly agentAfter: boolean;
    }
  | { readonly kind: "agent" }
  /** Only T3's own repairs remain, and they need a phone (web can't create a key). */
  | { readonly kind: "phone" };

/**
 * Every T3 repair sends a new key from this phone: `install` and `enroll`
 * both take one. So a client without a signer can only hand off or point at
 * the phone.
 */
export function planDeviceApprovalFix(
  status: StatusFields,
  phone: DeviceApprovalPhone | null,
  options: { readonly canRepair: boolean },
): DeviceApprovalFixPlan {
  const failing = deviceApprovalFailingChecks(status, phone);
  if (failing.length === 0) return { kind: "none" };
  const t3 = failing.filter((check) => deviceApprovalFixBy(check, status) === "t3");
  const agentAfter = t3.length < failing.length;
  if (t3.length === 0) return { kind: "agent" };
  if (!options.canRepair) return agentAfter ? { kind: "agent" } : { kind: "phone" };
  const install = t3.some((check) => !ENROLL_REPAIRS.has(check.id));
  return {
    kind: "repair",
    install,
    // Install adds the key it's given, so a separate enroll only runs without it.
    enroll: !install,
    agentAfter,
  };
}

export function deviceApprovalFixSheetText(
  plan: Extract<DeviceApprovalFixPlan, { kind: "repair" }>,
  machine: string,
): { readonly message: string; readonly action: string } {
  if (plan.agentAfter) {
    return {
      message: plan.install
        ? "Your Mac password lets T3 repair its part. An agent fixes the rest next."
        : "Your Mac password adds this phone back. An agent fixes the sudo setup next.",
      action: "Fix and continue",
    };
  }
  return {
    message: `Enter your Mac password to repair device approval on ${machine}.`,
    action: "Fix",
  };
}

export interface DeviceApprovalRepairAttempt {
  /** The helper subcommands T3 ran, e.g. `install`. */
  readonly ran: readonly string[];
  /** Why the repair didn't run to the end, when it didn't. */
  readonly error: string | null;
}

/** Absolute paths named in the failing checks, for picking the project that owns them. */
export function deviceApprovalCheckPaths(checks: readonly ElevationCheck[]): readonly string[] {
  const paths = new Set<string>();
  for (const check of checks) {
    if (check.path !== undefined && check.path.startsWith("/")) paths.add(check.path);
    for (const match of check.message.matchAll(/(?:^|[\s(`'"])(\/[^\s`'",;:)]+)/g)) {
      const path = match[1]?.replace(/[.]+$/, "");
      if (path !== undefined && path.length > 1) paths.add(path);
    }
  }
  return [...paths];
}

const isWithin = (path: string, root: string) => {
  const base = root.endsWith("/") ? root.slice(0, -1) : root;
  return path === base || path.startsWith(`${base}/`);
};

/**
 * The project whose folder holds a failing part, such as a Nix repo that
 * renders the PAM file. Null when none does; callers fall back to the
 * environment's project-less threads.
 */
export function pickDeviceApprovalFixProject<
  P extends { readonly environmentId: string; readonly workspaceRoot: string },
>(projects: readonly P[], environmentId: string, paths: readonly string[]): P | null {
  let best: P | null = null;
  for (const project of projects) {
    if (project.environmentId !== environmentId) continue;
    if (!paths.some((path) => isWithin(path, project.workspaceRoot))) continue;
    if (best === null || project.workspaceRoot.length > best.workspaceRoot.length) best = project;
  }
  return best;
}

/** Who owns a failing part, in the words Settings shows beside it. */
export function deviceApprovalCheckOwner(check: ElevationCheck): string | null {
  return check.managedBy === "nix"
    ? "managed by Nix"
    : check.managedBy === "hand"
      ? "customised by hand"
      : null;
}

/**
 * How Turn off undoes the setup: T3's helper removes what T3 installed; anything set up outside
 * T3, such as a Nix config, would come back on the next rebuild, so an agent removes it there.
 * Null when nothing is installed.
 */
export function deviceApprovalTurnOff(
  status: Pick<StatusFields, "ownsApprovals" | "devices" | "setupOutsideT3"> & {
    readonly helperInstalled: boolean;
  },
): "uninstall" | "agent" | null {
  if (!deviceApprovalInstalled(status)) return null;
  return status.setupOutsideT3 || !status.helperInstalled ? "agent" : "uninstall";
}

export const DEVICE_APPROVAL_DIAGNOSIS_FILE_NAME = "Device approval diagnosis.txt";

export interface DeviceApprovalHandoff {
  /** The short message the user reads and sends. */
  readonly draft: string;
  /** The full diagnosis, attached to the message as a file. */
  readonly diagnosis: string;
}

/**
 * The unsent message for the agent that fixes or turns off device approval, and the diagnosis it
 * attaches. Check messages and paths come from the server and stay plain data in the text.
 */
export function deviceApprovalHandoff(input: {
  readonly purpose: "fix" | "turn_off";
  readonly machine: string;
  readonly status: Pick<StatusFields, "checks" | "devices" | "setupOutsideT3"> & {
    readonly user?: string;
  };
  readonly failing: readonly ElevationCheck[];
  readonly repair: DeviceApprovalRepairAttempt | null;
  /** The project was picked because a failing part lives in it. */
  readonly projectOwnsConfig: boolean;
}): DeviceApprovalHandoff {
  const { status } = input;
  const draft =
    input.purpose === "turn_off"
      ? `Turn off device approval on ${input.machine}, so agents' sudo asks for the password again. Its setup comes from config outside T3; remove it there rather than editing the machine directly.`
      : `Device approval on ${input.machine} needs fixing: agents' sudo asks for the password again. ${
          input.repair
            ? "T3 tried to repair it, but the checks still fail."
            : input.projectOwnsConfig
              ? "Part of the setup comes from this project, so fix it in the config rather than editing the machine directly."
              : "T3 can't repair this part safely on its own."
        } Find the cause and fix it.`;
  const lines = [
    "Device approval diagnosis",
    "",
    "Device approval is T3 Code's phone approval for sudo: a PAM module (pam_t3_elevation.so) in sudo's PAM stack, a per-user config and key directory under /etc/t3-elevation, and a root-owned helper at /usr/local/lib/t3-elevation/t3-elevation. Sudo you run while it's broken asks for the user's password; ask the user instead of piping a password in.",
    "",
    `Machine: ${input.machine}${status.user === undefined ? "" : ` (user ${status.user})`}`,
  ];
  const label = (check: ElevationCheck) => {
    const tags = [
      check.id,
      ...(check.fixBy === undefined ? [] : [`fix by ${check.fixBy}`]),
      ...(check.managedBy === undefined ? [] : [`managed by ${check.managedBy}`]),
    ];
    return `- ${check.message}${check.path === undefined ? "" : ` (${check.path})`} [${tags.join(", ")}]`;
  };
  if (input.failing.length > 0) lines.push("", "Failing checks:", ...input.failing.map(label));
  const passing = status.checks.filter((check) => check.ok);
  if (passing.length > 0) {
    lines.push("", "Passing checks:", ...passing.map((check) => `- ${check.message}`));
  }
  lines.push(
    "",
    `Enrolled devices: ${status.devices.length}`,
    `Parts set up outside T3: ${status.setupOutsideT3 ? "yes" : "no"}`,
  );
  if (input.repair) {
    lines.push(
      "",
      `T3's repair attempt: ran ${
        input.repair.ran.length === 0
          ? "nothing"
          : input.repair.ran.map((command) => `t3-elevation ${command}`).join(", then ")
      }${input.repair.error === null ? "; the re-check still fails." : `; it failed: ${input.repair.error}`}`,
    );
  }
  return { draft, diagnosis: lines.join("\n") };
}
