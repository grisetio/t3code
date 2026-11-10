import {
  ELEVATION_SIGNATURE_CONTEXT,
  decodeElevationBase64Url,
  elevationPasskeyProvider,
  elevationSyncedPasskeyRefusal,
  elevationWebauthnAaguid,
  elevationWebauthnRegistrationRefusal,
  elevationWebauthnSite,
  type ElevationKeyId,
  type EnvironmentId,
} from "@t3tools/contracts";
import * as Base64Url from "effect/encoding/Base64Url";

import { isElectron } from "../env";
import type { ElevationApprover, ElevationApproverSource } from "./elevationApprover";

/**
 * Which passkey this browser approves with on each machine. It lives where the passkey does: this
 * browser profile, on this origin. Nothing in it is secret, and the server can't hold it: its
 * status lists every passkey on the origin, not which browser holds which. Clearing site data
 * loses only the binding; the machine still lists the key, and Remove there still works.
 */
const STORAGE_KEY = "t3code:device-approval:passkeys:v1";

interface StoredPasskey {
  readonly keyId: ElevationKeyId;
  readonly credentialId: string;
  readonly rpId: string;
}

const INSECURE_REASON =
  "Passkeys need a secure address. Open T3 over https, such as through Tailscale or T3 Connect, to approve here.";
const SAFARI_REASON =
  "Safari only saves passkeys that sync to your other devices, so it can't approve.";
const NO_PASSKEYS_REASON = "This browser can't make passkeys, so it can't approve.";

const encode = (bytes: ArrayBuffer | Uint8Array) =>
  Base64Url.encode(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));

const sha256 = async (bytes: Uint8Array<ArrayBuffer>) =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));

/** WebKit alone, on any platform: it saves passkeys only to Apple Passwords, which syncs. */
const isSafari = (userAgent: string) =>
  /Safari\//.test(userAgent) &&
  !/(Chrome|Chromium|CriOS|Edg|EdgiOS|OPR|FxiOS|Firefox)\//.test(userAgent);

/** Why this page can't hold a passkey that approves, in Settings' words; null when it can. */
export function browserApproverUnavailableReason(input: {
  readonly hostname: string;
  readonly origin: string;
  readonly secureContext: boolean;
  readonly webauthn: boolean;
  readonly userAgent: string;
}): string | null {
  // A LAN IP is no valid rpId, and the desktop's t3code:// origin can't call WebAuthn at all.
  if (!input.secureContext || elevationWebauthnSite(input.hostname, input.origin) === null) {
    return INSECURE_REASON;
  }
  if (!input.webauthn) return NO_PASSKEYS_REASON;
  if (isSafari(input.userAgent)) return SAFARI_REASON;
  return null;
}

/** "Chrome on Mac": what the browser and its OS are called, like a phone's model name. */
export function browserApproverLabel(userAgent: string): string {
  const browser = /Edg(?:e|A|iOS)?\//.test(userAgent)
    ? "Edge"
    : /OPR\//.test(userAgent)
      ? "Opera"
      : /(Firefox|FxiOS)\//.test(userAgent)
        ? "Firefox"
        : /(Chrome|Chromium|CriOS)\//.test(userAgent)
          ? "Chrome"
          : /Safari\//.test(userAgent)
            ? "Safari"
            : "Browser";
  const os = /(iPhone|iPad)/.test(userAgent)
    ? "iPhone"
    : /Mac OS X|Macintosh/.test(userAgent)
      ? "Mac"
      : /Windows/.test(userAgent)
        ? "Windows"
        : /Android/.test(userAgent)
          ? "Android"
          : /CrOS/.test(userAgent)
            ? "ChromeOS"
            : /Linux/.test(userAgent)
              ? "Linux"
              : null;
  return os === null ? browser : `${browser} on ${os}`;
}

/**
 * Where the passkey lives decides the words: Chrome on a Mac calls its device-only store "Your
 * Chrome profile", Windows calls its "Windows Hello".
 */
function deviceOnlyStore(userAgent: string): string {
  if (/Windows/.test(userAgent)) return "Windows Hello";
  if (/(Chrome|Chromium)\//.test(userAgent) && /Mac OS X|Macintosh/.test(userAgent)) {
    return "“Your Chrome profile”";
  }
  return "this device";
}

function readStored(): Partial<Record<EnvironmentId, StoredPasskey>> {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    const parsed: unknown = raw === null ? null : JSON.parse(raw);
    return typeof parsed === "object" && parsed !== null ? parsed : {};
  } catch {
    return {};
  }
}

/** A DOMException name from a WebAuthn call: the user cancelling reads as NotAllowedError. */
const domErrorName = (error: unknown) => (error instanceof DOMException ? error.name : null);

const cancelled = (error: unknown) => {
  const name = domErrorName(error);
  return name === "NotAllowedError" || name === "AbortError";
};

function createBrowserElevationApproverSource(): ElevationApproverSource {
  const listeners = new Set<() => void>();
  const approvers = new Map<EnvironmentId, ElevationApprover>();
  const notify = () => {
    approvers.clear();
    for (const listener of listeners) listener();
  };
  const write = (environmentId: EnvironmentId, passkey: StoredPasskey | null) => {
    const { [environmentId]: _previous, ...others } = readStored();
    const next = passkey === null ? others : { ...others, [environmentId]: passkey };
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } finally {
      notify();
    }
  };

  const make = (environmentId: EnvironmentId): ElevationApprover => {
    const { userAgent } = navigator;
    const unavailableReason = browserApproverUnavailableReason({
      hostname: window.location.hostname,
      origin: window.location.origin,
      secureContext: window.isSecureContext,
      webauthn: typeof PublicKeyCredential !== "undefined",
      userAgent,
    });
    const stored = readStored()[environmentId] ?? null;
    return {
      kind: "browser",
      label: browserApproverLabel(userAgent),
      computerName: null,
      // The binding can name the key of a setup the machine never accepted; every surface checks
      // it against the machine's keys before treating this browser as an approver there.
      keyId: unavailableReason === null ? (stored?.keyId ?? null) : null,
      unavailableReason,
      sign: async (payloadBytes, signal) => {
        if (stored === null) throw new Error("This browser isn't set up on this machine.");
        const credentialId = decodeElevationBase64Url(stored.credentialId);
        if (credentialId === null) throw new Error("This browser's passkey record is damaged.");
        const message = new Uint8Array(ELEVATION_SIGNATURE_CONTEXT.length + payloadBytes.length);
        message.set(new TextEncoder().encode(ELEVATION_SIGNATURE_CONTEXT));
        message.set(payloadBytes, ELEVATION_SIGNATURE_CONTEXT.length);
        let credential: Credential | null;
        try {
          credential = await navigator.credentials.get({
            publicKey: {
              // The module checks the assertion's challenge against these exact bytes.
              challenge: await sha256(message),
              rpId: stored.rpId,
              allowCredentials: [{ type: "public-key", id: new Uint8Array(credentialId) }],
              userVerification: "required",
            },
            signal,
          });
        } catch (error) {
          if (cancelled(error)) return null;
          throw new Error("This browser couldn't use its passkey. Approve on your phone.", {
            cause: error,
          });
        }
        if (!(credential instanceof PublicKeyCredential)) return null;
        const response = credential.response as AuthenticatorAssertionResponse;
        return {
          keyId: stored.keyId,
          alg: "webauthn-es256",
          signature: encode(response.signature),
          webauthn: {
            authenticatorData: encode(response.authenticatorData),
            clientDataJSON: encode(response.clientDataJSON),
          },
        };
      },
      createKey: async (signal, account) => {
        const rpId = window.location.hostname;
        let credential: Credential | null;
        try {
          credential = await navigator.credentials.create({
            publicKey: {
              rp: { id: rpId, name: "T3 Code" },
              user: {
                id: crypto.getRandomValues(new Uint8Array(16)),
                name: account.name,
                displayName: account.name,
              },
              challenge: crypto.getRandomValues(new Uint8Array(32)),
              pubKeyCredParams: [{ type: "public-key", alg: -7 }],
              authenticatorSelection: {
                authenticatorAttachment: "platform",
                // Approvals always name the credential, so it needn't be discoverable.
                residentKey: "discouraged",
                userVerification: "required",
              },
              attestation: "none",
            },
            signal,
          });
        } catch (error) {
          if (cancelled(error)) return null;
          throw new Error("This browser couldn't make a passkey.", { cause: error });
        }
        if (!(credential instanceof PublicKeyCredential)) return null;
        const response = credential.response as AuthenticatorAttestationResponse;
        const publicKey = response.getPublicKey();
        if (publicKey === null || response.getPublicKeyAlgorithm() !== -7) {
          throw new Error("This browser made a passkey T3 can't use.");
        }
        const authenticatorData = new Uint8Array(response.getAuthenticatorData());
        const credentialId = new Uint8Array(credential.rawId);
        const refusal = elevationWebauthnRegistrationRefusal({
          authenticatorData,
          rpIdHash: await sha256(new TextEncoder().encode(rpId)),
          credentialId,
        });
        if (refusal === "synced" && !account.allowSynced) {
          // Chrome hides a refused Google Password Manager passkey; others may ignore this.
          void PublicKeyCredential.signalUnknownCredential?.({
            rpId,
            credentialId: encode(credentialId),
          }).catch(() => undefined);
          throw new Error(
            elevationSyncedPasskeyRefusal({
              provider: elevationPasskeyProvider(elevationWebauthnAaguid(authenticatorData)),
              saveTo: deviceOnlyStore(userAgent),
            }),
          );
        }
        if (refusal === "invalid") throw new Error("This browser made a passkey T3 can't use.");
        const spki = new Uint8Array(publicKey);
        const keyId = encode((await sha256(spki)).subarray(0, 16));
        write(environmentId, { keyId, credentialId: encode(credentialId), rpId });
        return {
          publicKey: encode(spki),
          webauthn: {
            rpId,
            origin: window.location.origin,
            credentialId: encode(credentialId),
            authenticatorData: encode(authenticatorData),
          },
        };
      },
      forget: async () => write(environmentId, null),
    };
  };

  return {
    subscribe: (listener) => {
      listeners.add(listener);
      // Another tab of this origin set up or removed a passkey.
      const onStorage = (event: StorageEvent) => {
        if (event.key === STORAGE_KEY) notify();
      };
      window.addEventListener("storage", onStorage);
      return () => {
        listeners.delete(listener);
        window.removeEventListener("storage", onStorage);
      };
    },
    get: (environmentId) => {
      // The desktop isn't a browser: its renderer can't call WebAuthn, and its approver is the Mac's.
      if (isElectron || typeof window === "undefined") return null;
      const existing = approvers.get(environmentId);
      if (existing !== undefined) return existing;
      const approver = make(environmentId);
      approvers.set(environmentId, approver);
      return approver;
    },
  };
}

export const browserElevationApproverSource = createBrowserElevationApproverSource();
