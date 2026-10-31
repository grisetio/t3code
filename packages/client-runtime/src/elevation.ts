import {
  decodeElevationBase64Url,
  decodeElevationPayload,
  escapeElevationDisplayText,
  parseElevationEnrollCommand,
  type ElevationPayload,
  type ElevationPayloadDecodeFailure,
  type ElevationWarning,
  type EnvironmentId,
  type OrchestrationV2ElevationRequestFailure,
  type OrchestrationV2TurnItem,
} from "@t3tools/contracts";
import * as Result from "effect/Result";

// Formats: docs/internals/device-approval.md. Every string a client shows from a
// request goes through `escapeElevationDisplayText`, so this module returns only
// escaped text.

export type ElevationRequestItem = Extract<
  OrchestrationV2TurnItem,
  { readonly type: "elevation_request" }
>;

export const ELEVATION_EXPLANATION_LABEL = "Agent's explanation (unverified)";
export const ELEVATION_APPROVE_ON_PHONE = "Approve on your phone";

export interface ElevationWarningView {
  readonly code: string;
  readonly message: string;
}

export interface ElevationEnrollView {
  readonly label: string;
  /** SPKI DER; callers hash it for the comparison code with their platform's SHA-256. */
  readonly publicKey: Uint8Array;
  readonly allowDevAttestation: boolean;
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

export function elevationDecodeFailureMessage(failure: ElevationPayloadDecodeFailure): string {
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
  const warnings: ReadonlyArray<ElevationWarning> =
    enroll?.allowDevAttestation &&
    !payload.command.warnings.some((warning) => warning.code === "dev_attestation")
      ? [{ code: "dev_attestation" }, ...payload.command.warnings]
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

const ELEVATION_FAILURE_MESSAGES: Record<OrchestrationV2ElevationRequestFailure, string> = {
  too_large: "Too long to approve on a device; use the terminal.",
  invalid_encoding: "The command has text that can't be shown faithfully; use the terminal.",
  bad_signature: "The device's signature didn't verify.",
};

export type ElevationRequestStatusView =
  | { readonly kind: "pending"; readonly label: string }
  | {
      readonly kind: "approved" | "denied" | "expired" | "cancelled";
      readonly label: string;
      readonly detail: string | null;
    };

export function elevationRequestStatusView(
  item: Pick<ElevationRequestItem, "elevationStatus" | "failure" | "resolvedBy">,
): ElevationRequestStatusView {
  const device =
    item.resolvedBy === null
      ? ""
      : ` on ${escapeElevationDisplayText(item.resolvedBy.deviceLabel)}`;
  const detail = item.failure === undefined ? null : ELEVATION_FAILURE_MESSAGES[item.failure];
  switch (item.elevationStatus) {
    case "pending":
      return { kind: "pending", label: "Waiting for approval" };
    case "approved":
      return { kind: "approved", label: `Approved${device}`, detail };
    case "denied":
      return { kind: "denied", label: `Denied${device}`, detail };
    case "expired":
      return { kind: "expired", label: "Expired", detail };
    case "cancelled":
      return { kind: "cancelled", label: "Cancelled", detail };
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
    warnings: item.warnings.map((warning) => ({
      code: warning.code,
      message: warningMessage(warning, item.argv),
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
