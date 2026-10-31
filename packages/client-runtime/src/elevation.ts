import {
  decodeElevationBase64Url,
  decodeElevationPayload,
  escapeElevationDisplayText,
  parseElevationEnrollCommand,
  type ElevationPayload,
  type ElevationPayloadDecodeFailure,
  type ElevationStatus,
  type ElevationWarning,
  type EnvironmentId,
  type OrchestrationV2ElevationRequestFailure,
  type OrchestrationV2TurnItem,
  type ServerProvider,
} from "@t3tools/contracts";
import * as Result from "effect/Result";

import { elevationCommandDisplay } from "./elevationCommand.ts";
import { resolveProviderInstanceDisplayName } from "./state/providerInstanceDisplay.ts";

// Formats: docs/internals/device-approval.md. Every string a client shows from a
// request goes through `escapeElevationDisplayText`, so this module returns only
// escaped text.

export type ElevationRequestItem = Extract<
  OrchestrationV2TurnItem,
  { readonly type: "elevation_request" }
>;

export const ELEVATION_APPROVE_ON_PHONE = "Approve on your phone";
/** The approval window is configurable, so the text names no duration. */
const ELEVATION_EXPIRED_TEXT = "Nobody approved in time";
/** Every surface that can't sign says so in these words. */
export const ELEVATION_CANT_APPROVE_HERE =
  "Approving needs the T3 app on Android 11 or later with a fingerprint sensor.";
/** pam_tid sits before the password in a nix-darwin or Apple sudo stack; no sudo option skips it. */
export const ELEVATION_TOUCH_ID_HINT =
  "On a Mac that uses Touch ID for sudo, a Touch ID prompt may appear there first; Cancel continues with the password.";

export interface ElevationWarningView {
  readonly code: string;
  readonly message: string;
}

export interface ElevationEnrollView {
  readonly label: string;
  /** SPKI DER; callers hash it for the comparison code with their platform's SHA-256. */
  readonly publicKey: Uint8Array;
  readonly allowDevAttestation: boolean;
  readonly allowTestAttestation: boolean;
}

/** What a client shows for one request, all text escaped. */
export interface ElevationRequestView {
  readonly host: string;
  readonly user: string;
  readonly runAs: string;
  readonly runAsGroup: string | null;
  /** What will run, one element per entry, never truncated. */
  readonly commandArgv: readonly string[];
  /** sudo's own argv, for when the parse in `commandArgv` needs checking. */
  readonly sudoArgv: readonly string[];
  readonly resolvedPath: string | null;
  readonly cwd: string;
  readonly warnings: readonly ElevationWarningView[];
  /** Unix seconds, the PAM module's clock. */
  readonly expiresAt: number;
  /** Set when the command is the helper's `enroll`: the prompt reads "Add device". */
  readonly enroll: ElevationEnrollView | null;
}

const ELEVATION_DECODE_FAILURE_MESSAGES: Record<ElevationPayloadDecodeFailure, string> = {
  too_large: "Too long to approve on a device; use the terminal.",
  invalid_json: "This request can't be read; use the terminal.",
  unsupported_version: "This request needs a newer version of the app.",
  unknown_kind: "This kind of request needs a newer version of the app.",
  invalid: "This request is malformed and can't be approved.",
};

function elevationDecodeFailureMessage(failure: ElevationPayloadDecodeFailure): string {
  return ELEVATION_DECODE_FAILURE_MESSAGES[failure];
}

function warningMessage(warning: ElevationWarning, argv: readonly string[]): string {
  switch (warning.code) {
    case "user_writable_program":
      return "You can write to the program it runs, so anything running as you could have replaced it.";
    case "user_writable_argument": {
      const arg = warning.arg === undefined ? undefined : argv[warning.arg];
      return arg === undefined
        ? "An argument is a file you can write, so anything running as you could change it."
        : `${escapeElevationDisplayText(arg)} is a file you can write, so anything running as you could change it.`;
    }
    case "shell":
      return "Starts a shell, which can run anything.";
    case "unparsed_options":
      return "sudo's options weren't understood; the full command is shown as given.";
    case "edit":
      return "Edits files as the target user.";
    case "unresolved_program":
      return "Couldn't determine which program sudo will run.";
    case "user_writable_cwd":
      return "You can write to the working directory, so anything running as you could change what the command reads from it.";
    case "user_environment":
      return "sudo passes some of your environment variables to the command, so they could point it at your files.";
    case "dev_attestation":
      return "Accepts debug builds of the T3 app.";
    case "test_attestation":
      return "Accepts emulators and test keys.";
    default:
      return `Warning: ${escapeElevationDisplayText(warning.code)}`;
  }
}

function elevationRequestViewFromPayload(payload: ElevationPayload): ElevationRequestView {
  const enroll = parseElevationEnrollCommand(payload);
  const publicKey = enroll === null ? null : decodeElevationBase64Url(enroll.publicKey);
  // Flagged even when the module doesn't warn, as the enroll grammar requires.
  const attestationCode = enroll?.allowTestAttestation
    ? "test_attestation"
    : enroll?.allowDevAttestation
      ? "dev_attestation"
      : null;
  const warnings: ReadonlyArray<ElevationWarning> =
    attestationCode !== null &&
    !payload.command.warnings.some((warning) => warning.code === attestationCode)
      ? [{ code: attestationCode }, ...payload.command.warnings]
      : payload.command.warnings;
  return {
    host: escapeElevationDisplayText(payload.host.name),
    user: escapeElevationDisplayText(payload.user),
    runAs: escapeElevationDisplayText(payload.runAs),
    runAsGroup: payload.runAsGroup === null ? null : escapeElevationDisplayText(payload.runAsGroup),
    commandArgv: payload.command.argv.map(escapeElevationDisplayText),
    sudoArgv: payload.argv.map(escapeElevationDisplayText),
    resolvedPath:
      payload.command.resolvedPath === null
        ? null
        : escapeElevationDisplayText(payload.command.resolvedPath),
    cwd: escapeElevationDisplayText(payload.cwd),
    warnings: warnings.map((warning) => ({
      code: warning.code,
      message: warningMessage(warning, payload.command.argv),
    })),
    expiresAt: payload.expiresAt,
    enroll:
      enroll === null || publicKey === null
        ? null
        : {
            label: escapeElevationDisplayText(enroll.label),
            publicKey,
            allowDevAttestation: enroll.allowDevAttestation,
            allowTestAttestation: enroll.allowTestAttestation,
          },
  };
}

export interface DecodedElevationPayload {
  /** The exact bytes to sign. */
  readonly bytes: Uint8Array;
  readonly payload: ElevationPayload;
  readonly view: ElevationRequestView;
}

/** Decodes base64url payload bytes; renders only from what decoded. */
export function decodeElevationRequestPayload(
  payloadBase64Url: string,
): Result.Result<DecodedElevationPayload, ElevationPayloadDecodeFailure> {
  const bytes = decodeElevationBase64Url(payloadBase64Url);
  if (bytes === null) return Result.fail("invalid_json");
  return Result.map(decodeElevationPayload(bytes), (payload) => ({
    bytes,
    payload,
    view: elevationRequestViewFromPayload(payload),
  }));
}

/** The agent's reason, trimmed and escaped, or null when it gave none. */
export function elevationReason(explanation: string | null | undefined): string | null {
  const trimmed = explanation?.trim() ?? "";
  return trimmed === "" ? null : escapeElevationDisplayText(trimmed);
}

export interface ElevationHeadline {
  readonly text: string;
  /** The command stands in for a missing reason, so it reads as code. */
  readonly command: boolean;
}

/**
 * What a pending request leads with on every surface: the agent's reason in quotes, "Add device
 * X" for a new phone, or the command when the agent gave no reason.
 */
export function elevationHeadline(input: {
  readonly explanation: string | null;
  readonly decoded: Result.Result<DecodedElevationPayload, ElevationPayloadDecodeFailure>;
}): ElevationHeadline {
  const decoded = Result.isSuccess(input.decoded) ? input.decoded.success : null;
  if (decoded?.view.enroll)
    return { text: `Add device ${decoded.view.enroll.label}`, command: false };
  const reason = elevationReason(input.explanation);
  if (reason !== null) return { text: `“${reason}”`, command: false };
  if (decoded !== null) {
    return { text: elevationCommandDisplay(decoded.payload).collapsed, command: true };
  }
  return Result.isFailure(input.decoded)
    ? { text: elevationDecodeFailureMessage(input.decoded.failure), command: false }
    : { text: "Approval needed", command: false };
}

export interface ElevationAgent {
  readonly driver: ServerProvider["driver"];
  readonly instanceId: ServerProvider["instanceId"];
  readonly iconUrl: ServerProvider["iconUrl"];
  readonly name: string;
}

/**
 * The agent that asked, from the provider instance its thread ran on. Null when the thread or its
 * provider isn't known here, in which case surfaces show no mark rather than a guess.
 */
export function elevationAgent(
  thread: {
    readonly modelSelection: { readonly instanceId: ServerProvider["instanceId"] };
    readonly runtime: { readonly providerInstanceId: ServerProvider["instanceId"] } | null;
  } | null,
  providers: readonly ServerProvider[],
): ElevationAgent | null {
  if (thread === null) return null;
  const instanceId = thread.runtime?.providerInstanceId ?? thread.modelSelection.instanceId;
  const provider = providers.find((candidate) => candidate.instanceId === instanceId);
  return provider === undefined
    ? null
    : {
        driver: provider.driver,
        instanceId: provider.instanceId,
        iconUrl: provider.iconUrl,
        name: resolveProviderInstanceDisplayName(provider),
      };
}

const ELEVATION_FAILURE_MESSAGES: Record<OrchestrationV2ElevationRequestFailure, string> = {
  too_large: "Too long to approve on a device; use the terminal.",
  invalid_encoding: "The command has text that can't be shown faithfully; use the terminal.",
  bad_signature: "The device's signature didn't verify.",
};

export type ElevationRequestStatusView =
  | { readonly kind: "pending"; readonly label: string }
  | {
      readonly kind: "approved" | "done" | "denied" | "expired" | "cancelled";
      /** "Approved", "Done", "Denied", "Expired" or "Cancelled". */
      readonly label: string;
      /** When it ended, for the collapsed row: "1:18 PM". */
      readonly time: string;
      /** How and when it ended: "Approved on this phone · 1:18 PM · finished". */
      readonly how: string;
      /** Why the module refused it, when it did. */
      readonly detail: string | null;
    };

const timeFormat = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" });

/** The same status words on every surface, for rows that show a request after it ended. */
export function elevationRequestStatusView(
  item: Pick<ElevationRequestItem, "elevationStatus" | "failure" | "resolvedBy"> & {
    readonly completedAt?: ElevationRequestItem["completedAt"];
    readonly updatedAt: ElevationRequestItem["updatedAt"];
  },
  options: {
    /** The approved command's run has ended. */
    readonly finished: boolean;
    /** This phone's key on the machine; null on clients without one. */
    readonly thisKeyId?: string | null;
    /** This phone denied it, for servers that don't record the denying device. */
    readonly deniedHere?: boolean;
  },
): ElevationRequestStatusView {
  if (item.elevationStatus === "pending") return { kind: "pending", label: "Waiting for approval" };
  const time = timeFormat.format((item.completedAt ?? item.updatedAt).epochMilliseconds);
  const detail = item.failure === undefined ? null : ELEVATION_FAILURE_MESSAGES[item.failure];
  const { resolvedBy } = item;
  const approvedOn =
    resolvedBy === null
      ? ""
      : resolvedBy.keyId !== undefined && resolvedBy.keyId === options.thisKeyId
        ? " on this phone"
        : ` on ${escapeElevationDisplayText(resolvedBy.deviceLabel)}`;
  switch (item.elevationStatus) {
    case "approved":
      return options.finished
        ? {
            kind: "done",
            label: "Done",
            time,
            how: `Approved${approvedOn} · ${time} · finished`,
            detail,
          }
        : {
            kind: "approved",
            label: "Approved",
            time,
            how: `Approved${approvedOn} · ${time}`,
            detail,
          };
    case "denied":
      return {
        kind: "denied",
        label: "Denied",
        time,
        how: `Denied${options.deniedHere ? " on this phone" : approvedOn} · ${time}`,
        detail,
      };
    case "expired":
      return {
        kind: "expired",
        label: "Expired",
        time,
        how: `${ELEVATION_EXPIRED_TEXT} · ${time}`,
        detail,
      };
    case "cancelled":
      return { kind: "cancelled", label: "Cancelled", time, how: `Cancelled · ${time}`, detail };
  }
}

/** The display fields the server mirrored, for items that have no payload to decode. */
export function elevationRequestFallbackView(
  item: Pick<ElevationRequestItem, "argv" | "runAs" | "cwd" | "host" | "warnings">,
): Pick<ElevationRequestView, "host" | "runAs" | "commandArgv" | "cwd" | "warnings"> {
  return {
    host: escapeElevationDisplayText(item.host),
    runAs: escapeElevationDisplayText(item.runAs ?? "root"),
    commandArgv: item.argv.map(escapeElevationDisplayText),
    cwd: escapeElevationDisplayText(item.cwd),
    // `arg` indexes the payload's `command.argv`, but the item mirrors sudo's own argv.
    warnings: item.warnings.map((warning) => ({
      code: warning.code,
      message: warningMessage(warning, []),
    })),
  };
}

/** One signer key per environment and user; the Android module rejects other aliases. */
export function elevationKeyAlias(environmentId: EnvironmentId, user: string): string {
  return `t3-elevation:${encodeURIComponent(environmentId)}:${encodeURIComponent(user)}`;
}

const USER_FACING_FAILURE_TAGS = new Set(["ElevationError", "EnvironmentAuthorizationError"]);

/** Only known server errors pass their message through; everything else gets generic copy. */
export function elevationFailureMessage(failure: unknown, fallback: string): string {
  if (
    typeof failure === "object" &&
    failure !== null &&
    "_tag" in failure &&
    typeof failure._tag === "string" &&
    USER_FACING_FAILURE_TAGS.has(failure._tag) &&
    "message" in failure &&
    typeof failure.message === "string" &&
    failure.message.trim().length > 0
  ) {
    const detail =
      "detail" in failure && typeof failure.detail === "string" && failure.detail.trim() !== ""
        ? ` ${failure.detail.trim()}`
        : "";
    return `${failure.message}${detail}`;
  }
  return fallback;
}

/**
 * Who can approve a change made through sudo. Without an enrolled device only
 * the password can; setup alone can fall back to a terminal command instead.
 */
export function elevationSudoApproval(status: Pick<ElevationStatus, "ownsApprovals" | "devices">): {
  readonly passwordRequired: boolean;
  readonly testUnavailableReason: string | null;
} {
  const enrolled = status.devices.length > 0;
  return {
    passwordRequired: status.ownsApprovals && !enrolled,
    testUnavailableReason: enrolled ? null : "Add a phone first; the test is approved on a phone.",
  };
}
