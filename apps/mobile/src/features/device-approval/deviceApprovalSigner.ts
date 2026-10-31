import { requireOptionalNativeModule } from "expo";
import { Platform } from "react-native";

// The Android signer module (modules/t3-device-approval). It is optional: builds
// without it, and iOS, report `unavailable` and the app only shows requests.

export type DeviceApprovalErrorCode =
  | "unavailable"
  | "no_biometrics"
  | "cancelled"
  /** The user backed out of the prompt: its Cancel button or Back. */
  | "declined"
  | "lockout"
  | "key_invalidated"
  | "not_found"
  | "failed";

export interface DeviceApprovalAvailability {
  readonly available: boolean;
  readonly strongBox: boolean;
  readonly reason?: string;
}

export interface DeviceApprovalKey {
  readonly keyId: string;
  /** base64url SPKI DER. */
  readonly publicKeySpki: string;
  /** base64url DER certificates, leaf first. */
  readonly attestationChain: readonly string[];
  readonly securityLevel: "strongbox" | "tee";
}

interface NativeDeviceApproval {
  getAvailability(): Promise<DeviceApprovalAvailability>;
  generateKey(alias: string, attestationChallengeB64url: string): Promise<DeviceApprovalKey>;
  /** Signs `t3-elevation-v1\0 || payload` after a strong biometric. */
  sign(
    alias: string,
    payloadB64url: string,
    prompt: { readonly title: string; readonly subtitle?: string; readonly description?: string },
  ): Promise<{ readonly signature: string }>;
  deleteKey(alias: string): Promise<void>;
  hasKey(alias: string): Promise<boolean>;
  /** False for keys from builds that required an unlocked phone; absent on older builds. */
  signsWhileLocked?(alias: string): Promise<boolean>;
}

const native =
  Platform.OS === "android"
    ? requireOptionalNativeModule<NativeDeviceApproval>("T3DeviceApproval")
    : null;

const ERROR_CODES: ReadonlySet<string> = new Set<DeviceApprovalErrorCode>([
  "unavailable",
  "no_biometrics",
  "cancelled",
  "declined",
  "lockout",
  "key_invalidated",
  "not_found",
  "failed",
]);

export class DeviceApprovalSignerError extends Error {
  constructor(readonly code: DeviceApprovalErrorCode) {
    super(`Device approval signer failed: ${code}`);
    this.name = "DeviceApprovalSignerError";
  }
}

async function call<A>(run: (module: NativeDeviceApproval) => Promise<A>): Promise<A> {
  if (native === null) throw new DeviceApprovalSignerError("unavailable");
  try {
    return await run(native);
  } catch (error) {
    const code = typeof error === "object" && error !== null && "code" in error ? error.code : null;
    throw new DeviceApprovalSignerError(
      typeof code === "string" && ERROR_CODES.has(code)
        ? (code as DeviceApprovalErrorCode)
        : "failed",
    );
  }
}

export const deviceApprovalSigner = {
  isPresent: () => native !== null,
  getAvailability: (): Promise<DeviceApprovalAvailability> =>
    native === null
      ? Promise.resolve({ available: false, strongBox: false, reason: "unavailable" })
      : call((module) => module.getAvailability()),
  generateKey: (alias: string, attestationChallengeB64url: string) =>
    call((module) => module.generateKey(alias, attestationChallengeB64url)),
  sign: (
    alias: string,
    payloadB64url: string,
    prompt: { readonly title: string; readonly subtitle?: string; readonly description?: string },
  ) => call((module) => module.sign(alias, payloadB64url, prompt)),
  deleteKey: (alias: string) => call((module) => module.deleteKey(alias)),
  hasKey: (alias: string) => call((module) => module.hasKey(alias)),
  /** Whether the key can sign from the lock screen; keys from earlier builds can't. */
  signsWhileLocked: (alias: string) =>
    call((module) => module.signsWhileLocked?.(alias) ?? Promise.resolve(true)),
};

export function deviceApprovalSignerErrorCode(error: unknown): DeviceApprovalErrorCode {
  return error instanceof DeviceApprovalSignerError ? error.code : "failed";
}

const SIGNER_ERROR_MESSAGES: Record<DeviceApprovalErrorCode, string> = {
  unavailable:
    "This phone can't approve requests: it needs Android 11 or later with a fingerprint sensor.",
  no_biometrics: "Add a fingerprint in Android settings first.",
  cancelled: "Cancelled.",
  declined: "Cancelled.",
  lockout: "Too many attempts. Unlock the phone with its PIN, then try again.",
  key_invalidated:
    "A fingerprint was added or removed on this phone, so its key no longer works. Set it up again in Settings → Device approval.",
  not_found: "This phone isn't set up for this machine. Set it up in Settings → Device approval.",
  failed: "Signing failed. Try again.",
};

export function deviceApprovalSignerErrorMessage(code: DeviceApprovalErrorCode): string {
  return SIGNER_ERROR_MESSAGES[code];
}
