import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import * as Base64Url from "effect/encoding/Base64Url";

import { NonNegativeInt, ThreadId, TrimmedNonEmptyString, TurnItemId } from "./baseSchemas.ts";

// Formats are specified in docs/internals/device-approval.md; the shared test
// vectors in packages/contracts/test-vectors/device-approval.json pin them.

const ELEVATION_PAYLOAD_MAX_BYTES = 16384;

/** Signatures cover the ASCII bytes of this context followed by the payload bytes. */
export const ELEVATION_SIGNATURE_CONTEXT = "t3-elevation-v1\0";
const ELEVATION_MAX_WINDOW_SECONDS = 300;

const base64UrlOfLength = (length: number) =>
  Schema.String.check(Schema.isPattern(new RegExp(`^[A-Za-z0-9_-]{${length}}$`)));

/** Unpadded base64url. */
export const ElevationBase64Url = Schema.String.check(
  Schema.isPattern(/^[A-Za-z0-9_-]*$/),
  Schema.makeFilter((value) => value.length % 4 !== 1),
);

/** First 16 bytes of SHA-256(SPKI DER), base64url. */
export const ElevationKeyId = base64UrlOfLength(22);
export type ElevationKeyId = typeof ElevationKeyId.Type;

export const ElevationRequestId = TrimmedNonEmptyString.pipe(Schema.brand("ElevationRequestId"));
export type ElevationRequestId = typeof ElevationRequestId.Type;

const Bytes32 = base64UrlOfLength(43);

export const ElevationWarning = Schema.Struct({
  code: Schema.String.check(Schema.isPattern(/^[a-z_]{1,64}$/)),
  arg: Schema.optionalKey(NonNegativeInt),
});
export type ElevationWarning = typeof ElevationWarning.Type;

export const ElevationPayload = Schema.Struct({
  v: Schema.Literal(1),
  kind: Schema.Literal("sudo"),
  nonce: Bytes32,
  issuedAt: NonNegativeInt,
  expiresAt: NonNegativeInt,
  host: Schema.Struct({ name: Schema.String, machineId: Bytes32 }),
  user: Schema.String,
  uid: NonNegativeInt,
  runAs: Schema.String,
  runAsGroup: Schema.NullOr(Schema.String),
  argv: Schema.Array(Schema.String),
  command: Schema.Struct({
    argv: Schema.Array(Schema.String),
    resolvedPath: Schema.NullOr(Schema.String),
    warnings: Schema.Array(ElevationWarning),
  }),
  cwd: Schema.String,
  service: Schema.String,
  keyIds: Schema.Array(ElevationKeyId),
}).check(
  Schema.makeFilter(
    (payload) =>
      payload.expiresAt > payload.issuedAt &&
      payload.expiresAt - payload.issuedAt <= ELEVATION_MAX_WINDOW_SECONDS,
  ),
);
export type ElevationPayload = typeof ElevationPayload.Type;

export type ElevationPayloadDecodeFailure =
  | "too_large"
  | "invalid_json"
  | "unsupported_version"
  | "unknown_kind"
  | "invalid";

const decodePayloadFields = Schema.decodeUnknownResult(ElevationPayload, {
  // An unknown field could carry meaning a client would sign without showing.
  onExcessProperty: "error",
});

/** Decodes payload bytes for display. Clients that sign render only from the result. */
export function decodeElevationPayload(
  bytes: Uint8Array,
): Result.Result<ElevationPayload, ElevationPayloadDecodeFailure> {
  if (bytes.length > ELEVATION_PAYLOAD_MAX_BYTES) return Result.fail("too_large");
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return Result.fail("invalid_json");
  }
  const text = new TextDecoder().decode(bytes);
  // Re-encoding catches invalid UTF-8 without relying on the decoder's
  // `fatal` option, which not every JS runtime honours.
  const reencoded = new TextEncoder().encode(text);
  if (reencoded.length !== bytes.length || reencoded.some((byte, i) => byte !== bytes[i])) {
    return Result.fail("invalid_json");
  }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return Result.fail("invalid_json");
  }
  if (typeof json !== "object" || json === null || Array.isArray(json)) {
    return Result.fail("invalid_json");
  }
  if (!("v" in json) || json.v !== 1) return Result.fail("unsupported_version");
  if (!("kind" in json) || json.kind !== "sudo") return Result.fail("unknown_kind");
  return Result.mapError(decodePayloadFields(json), () => "invalid" as const);
}

/** Decodes unpadded base64url; null when the text is not strictly that. */
export function decodeElevationBase64Url(text: string): Uint8Array | null {
  if (!Schema.is(ElevationBase64Url)(text)) return null;
  return Result.getOrNull(Base64Url.decode(text));
}

const DISPLAY_ESCAPED = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}\p{Zs}\\]/u;

/** Makes controls, bidi, zero-width and look-alike spaces visible. */
export function escapeElevationDisplayText(text: string): string {
  let out = "";
  for (const char of text) {
    if (char === " " || !DISPLAY_ESCAPED.test(char)) out += char;
    else if (char === "\\") out += "\\\\";
    else if (char === "\n") out += "\\n";
    else if (char === "\r") out += "\\r";
    else if (char === "\t") out += "\\t";
    else out += `\\u{${char.codePointAt(0)!.toString(16).toUpperCase()}}`;
  }
  return out;
}

const CROCKFORD_BASE32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** `XXXXX-XXXXX` from SHA-256(SPKI DER); callers hash with their platform's crypto. */
export function elevationComparisonCode(spkiSha256: Uint8Array): string {
  let bits = 0n;
  for (let index = 0; index < 7; index++) bits = (bits << 8n) | BigInt(spkiSha256[index] ?? 0);
  bits >>= 6n;
  let code = "";
  for (let index = 9; index >= 0; index--) {
    code += CROCKFORD_BASE32[Number((bits >> BigInt(index * 5)) & 31n)];
  }
  return `${code.slice(0, 5)}-${code.slice(5)}`;
}

export function elevationKeyIdFromSpkiSha256(spkiSha256: Uint8Array): ElevationKeyId {
  return Base64Url.encode(spkiSha256.subarray(0, 16));
}

export interface ElevationEnrollCommand {
  readonly user: string;
  readonly label: string;
  readonly publicKey: string;
  readonly challenge: string;
  readonly allowDevAttestation: boolean;
}

const ENROLL_VALUE_OPTIONS = {
  "--user": "user",
  "--label": "label",
  "--public-key": "publicKey",
  "--challenge": "challenge",
} as const;

/**
 * The enroll grammar the helper accepts. A match makes clients show
 * "Add device" with the comparison code; anything else renders as a plain command.
 */
export function parseElevationEnrollCommand(
  payload: ElevationPayload,
): ElevationEnrollCommand | null {
  const [program, subcommand, ...rest] = payload.command.argv;
  if (program === undefined || program.split("/").at(-1) !== "t3-elevation") return null;
  if (subcommand !== "enroll") return null;
  const values: Partial<
    Record<(typeof ENROLL_VALUE_OPTIONS)[keyof typeof ENROLL_VALUE_OPTIONS], string>
  > = {};
  let allowDevAttestation = false;
  for (let index = 0; index < rest.length; index++) {
    const option = rest[index];
    if (option === "--allow-dev-attestation") {
      if (allowDevAttestation) return null;
      allowDevAttestation = true;
      continue;
    }
    if (option === undefined || !Object.hasOwn(ENROLL_VALUE_OPTIONS, option)) return null;
    const field = ENROLL_VALUE_OPTIONS[option as keyof typeof ENROLL_VALUE_OPTIONS];
    const value = rest[index + 1];
    if (value === undefined || values[field] !== undefined) return null;
    values[field] = value;
    index++;
  }
  const { user, label, publicKey, challenge } = values;
  if (user === undefined || label === undefined || publicKey === undefined) return null;
  if (challenge === undefined) return null;
  if (decodeElevationBase64Url(publicKey) === null || !Schema.is(Bytes32)(challenge)) return null;
  return { user, label, publicKey, challenge, allowDevAttestation };
}

export const ElevationSignedResponse = Schema.Struct({
  keyId: ElevationKeyId,
  alg: Schema.Literals(["es256-der", "webauthn-es256"]),
  signature: ElevationBase64Url,
  webauthn: Schema.optionalKey(
    Schema.Struct({ authenticatorData: ElevationBase64Url, clientDataJSON: ElevationBase64Url }),
  ),
});
export type ElevationSignedResponse = typeof ElevationSignedResponse.Type;

/** Deny carries no signature: a forged deny is only a denial of service. */
export const ElevationRespondInput = Schema.Union([
  Schema.Struct({ requestId: ElevationRequestId, decision: Schema.Literal("deny") }),
  Schema.Struct({
    requestId: ElevationRequestId,
    decision: Schema.Literal("approve"),
    ...ElevationSignedResponse.fields,
  }),
]);
export type ElevationRespondInput = typeof ElevationRespondInput.Type;

/** A waiting request, including ones attributed to no thread. */
export const ElevationPendingRequest = Schema.Struct({
  requestId: ElevationRequestId,
  threadId: Schema.NullOr(ThreadId),
  turnItemId: Schema.NullOr(TurnItemId),
  payload: ElevationBase64Url,
  explanation: Schema.NullOr(Schema.String),
  createdAt: Schema.DateTimeUtc,
});
export type ElevationPendingRequest = typeof ElevationPendingRequest.Type;

/** Each stream element is the complete current set. */
export const ElevationPendingRequests = Schema.Struct({
  requests: Schema.Array(ElevationPendingRequest),
});
export type ElevationPendingRequests = typeof ElevationPendingRequests.Type;

export const ElevationSecurityLevel = Schema.Literals(["strongbox", "tee", "software"]);
export type ElevationSecurityLevel = typeof ElevationSecurityLevel.Type;

export const ElevationDevice = Schema.Struct({
  keyId: ElevationKeyId,
  label: Schema.String,
  securityLevel: ElevationSecurityLevel,
  enrolledAt: Schema.DateTimeUtc,
  lastUsedAt: Schema.NullOr(Schema.DateTimeUtc),
});
export type ElevationDevice = typeof ElevationDevice.Type;

/** A generic, tool-agnostic result, e.g. "PAM line missing in /etc/pam.d/sudo". */
export const ElevationCheck = Schema.Struct({
  id: Schema.String,
  ok: Schema.Boolean,
  message: Schema.String,
});
export type ElevationCheck = typeof ElevationCheck.Type;

export const ElevationStatus = Schema.Struct({
  /** The OS user whose sudo this server approves; phones name their key after it. */
  user: Schema.optionalKey(Schema.String),
  /** False on platforms or accounts that can't use it (e.g. confined SELinux users). */
  supported: Schema.Boolean,
  unsupportedReason: Schema.optionalKey(Schema.String),
  /** Static checks pass, this server owns the socket, and a device is enrolled. */
  ready: Schema.Boolean,
  /** The installed config points at this server's socket. */
  ownsApprovals: Schema.Boolean,
  /** Parts exist that `installed-by-t3.json` doesn't record; uninstall leaves them. */
  setupOutsideT3: Schema.Boolean,
  checks: Schema.Array(ElevationCheck),
  /** What install would change, shown before it runs. */
  plannedChanges: Schema.Array(Schema.Struct({ path: Schema.String, summary: Schema.String })),
  devices: Schema.Array(ElevationDevice),
});
export type ElevationStatus = typeof ElevationStatus.Type;

export const ElevationEnrollmentDevice = Schema.Struct({
  label: TrimmedNonEmptyString.check(Schema.isMaxLength(64)),
  /** SPKI DER. */
  publicKey: ElevationBase64Url,
  /** 32 random bytes from the phone, also the key's attestation challenge. */
  challenge: Bytes32,
  /** DER certificates, leaf first. */
  attestationChain: Schema.NonEmptyArray(ElevationBase64Url),
});
export type ElevationEnrollmentDevice = typeof ElevationEnrollmentDevice.Type;

/** The sudo password goes to the server once and is never stored. */
const ElevationPassword = Schema.String;

export const ElevationInstallInput = Schema.Struct({
  /** Null asks for a command to paste into a terminal instead. */
  password: Schema.NullOr(ElevationPassword),
  device: ElevationEnrollmentDevice,
});
export type ElevationInstallInput = typeof ElevationInstallInput.Type;

export const ElevationInstallResult = Schema.Union([
  Schema.Struct({ type: Schema.Literal("installed"), status: ElevationStatus }),
  Schema.Struct({ type: Schema.Literal("terminal_command"), command: Schema.String }),
]);
export type ElevationInstallResult = typeof ElevationInstallResult.Type;

/** Without a password, an enrolled device approves the helper's sudo call. */
export const ElevationEnrollInput = Schema.Struct({
  device: ElevationEnrollmentDevice,
  password: Schema.optionalKey(ElevationPassword),
});
export type ElevationEnrollInput = typeof ElevationEnrollInput.Type;

export const ElevationRevokeInput = Schema.Struct({
  keyId: ElevationKeyId,
  password: Schema.optionalKey(ElevationPassword),
});
export type ElevationRevokeInput = typeof ElevationRevokeInput.Type;

export const ElevationUninstallInput = Schema.Struct({
  password: Schema.optionalKey(ElevationPassword),
});
export type ElevationUninstallInput = typeof ElevationUninstallInput.Type;

const ELEVATION_FAILURE_MESSAGES = {
  not_available: "Device approval isn't available on this server.",
  unsupported: "Device approval isn't supported on this machine.",
  not_found: "This approval request no longer exists.",
  already_resolved: "This approval request was already answered.",
  invalid_signature: "The device's signature didn't verify.",
  wrong_password: "The sudo password was not accepted.",
  helper_failed: "The device approval helper failed.",
} as const;

export const ElevationFailureReason = Schema.Literals(
  Object.keys(ELEVATION_FAILURE_MESSAGES) as Array<keyof typeof ELEVATION_FAILURE_MESSAGES>,
);
export type ElevationFailureReason = typeof ElevationFailureReason.Type;

export class ElevationError extends Schema.TaggedError<ElevationError>()("ElevationError", {
  reason: ElevationFailureReason,
  /** The helper's own error text, shown under the generic message. */
  detail: Schema.optionalKey(Schema.String),
}) {
  override get message(): string {
    return ELEVATION_FAILURE_MESSAGES[this.reason];
  }
}
