import { requireOptionalNativeModule } from "expo";
import { Platform } from "react-native";

// Hardware-backed signer for device approval (docs/internals/device-approval.md). Android only;
// on iOS every call reports `unavailable`.

export type SecurityLevel = "strongbox" | "tee";

export type ApprovalError =
  | "unavailable"
  | "no_biometrics"
  | "cancelled"
  | "lockout"
  | "key_invalidated"
  | "not_found"
  | "failed";

export interface DeviceApprovalAvailability {
  readonly available: boolean;
  readonly strongBox: boolean;
  /** An `ApprovalError` code, set when `available` is false. */
  readonly reason?: string;
}

export interface DeviceApprovalKey {
  readonly keyId: string;
  /** base64url SPKI DER. */
  readonly publicKeySpki: string;
  /** base64url DER certificates, leaf first. */
  readonly attestationChain: ReadonlyArray<string>;
  readonly securityLevel: SecurityLevel;
}

export interface DeviceApprovalPrompt {
  readonly title: string;
  readonly subtitle?: string;
  readonly description?: string;
}

/** Every function rejects with this; `code` says why. */
export class DeviceApprovalError extends Error {
  readonly code: ApprovalError;

  constructor(code: ApprovalError) {
    super(`Device approval failed: ${code}`);
    this.name = "DeviceApprovalError";
    this.code = code;
  }
}

/**
 * Keystore alias of the key that approves `sudo` for one host user of one environment:
 * `t3-elevation:<environmentId>:<user>`, each part percent-encoded so `:` can't make two pairs
 * collide. The native module rejects any other alias, so it never touches another module's key.
 */
export function deviceApprovalKeyAlias(environmentId: string, user: string): string {
  return `t3-elevation:${encodeURIComponent(environmentId)}:${encodeURIComponent(user)}`;
}

interface NativeDeviceApproval {
  getAvailability(): Promise<DeviceApprovalAvailability>;
  generateKey(alias: string, attestationChallenge: string): Promise<DeviceApprovalKey>;
  sign(
    alias: string,
    payload: string,
    prompt: DeviceApprovalPrompt,
  ): Promise<{ signature: string }>;
  deleteKey(alias: string): Promise<void>;
  hasKey(alias: string): Promise<boolean>;
}

const native =
  Platform.OS === "android"
    ? requireOptionalNativeModule<NativeDeviceApproval>("T3DeviceApproval")
    : null;

const approvalErrors: ReadonlyArray<string> = [
  "unavailable",
  "no_biometrics",
  "cancelled",
  "lockout",
  "key_invalidated",
  "not_found",
  "failed",
] satisfies ReadonlyArray<ApprovalError>;

function isApprovalError(code: unknown): code is ApprovalError {
  return typeof code === "string" && approvalErrors.includes(code);
}

async function call<T>(run: (module: NativeDeviceApproval) => Promise<T>): Promise<T> {
  if (!native) throw new DeviceApprovalError("unavailable");
  try {
    return await run(native);
  } catch (error) {
    const code = typeof error === "object" && error !== null && "code" in error ? error.code : null;
    throw new DeviceApprovalError(isApprovalError(code) ? code : "failed");
  }
}

export function getAvailability(): Promise<DeviceApprovalAvailability> {
  if (!native) {
    return Promise.resolve({ available: false, strongBox: false, reason: "unavailable" });
  }
  return call((module) => module.getAvailability());
}

/**
 * Creates a P-256 key in StrongBox (else the TEE) that signs only after a fresh strong
 * biometric, replacing any key under `alias`. `attestationChallenge` is 32 random bytes,
 * base64url; the helper requires the attestation to carry them.
 */
export function generateKey(
  alias: string,
  attestationChallenge: string,
): Promise<DeviceApprovalKey> {
  return call((module) => module.generateKey(alias, attestationChallenge));
}

/**
 * Shows the biometric prompt and signs `t3-elevation-v1\0 || payload`. `payload` is the exact
 * payload bytes, base64url; render the prompt only from what decodes out of these same bytes.
 * The signature is base64url DER (`es256-der`).
 */
export function sign(
  alias: string,
  payload: string,
  prompt: DeviceApprovalPrompt,
): Promise<{ signature: string }> {
  return call((module) => module.sign(alias, payload, prompt));
}

export function deleteKey(alias: string): Promise<void> {
  return call((module) => module.deleteKey(alias));
}

/** True for an invalidated key too; `sign` reports `key_invalidated`. */
export function hasKey(alias: string): Promise<boolean> {
  return call((module) => module.hasKey(alias));
}
