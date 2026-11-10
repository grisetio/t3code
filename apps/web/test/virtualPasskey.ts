import {
  ELEVATION_SIGNATURE_CONTEXT,
  decodeElevationBase64Url,
  type ElevationSignedResponse,
  type EnvironmentId,
} from "@t3tools/contracts";
import * as Base64Url from "effect/encoding/Base64Url";
import { commands } from "vite-plus/test/browser";

import { browserElevationApproverSource } from "../src/state/browserElevationApprover";

const bytes = (value: string) => {
  const decoded = decodeElevationBase64Url(value);
  if (decoded === null) throw new Error(`Not base64url: ${value}`);
  return new Uint8Array(decoded);
};

/**
 * A virtual platform authenticator for the test, removed with this browser's passkey binding for
 * `environmentId` when disposed.
 */
export async function virtualAuthenticator(
  environmentId: EnvironmentId,
  options: { readonly backupEligible?: boolean } = {},
): Promise<AsyncDisposable> {
  await commands.addVirtualAuthenticator(options);
  return {
    [Symbol.asyncDispose]: async () => {
      await browserElevationApproverSource.get(environmentId)?.forget();
      await commands.removeVirtualAuthenticator();
    },
  };
}

/** Sets this browser up on `environmentId` as the machine would accept it; returns the key. */
export async function enrollThisBrowser(environmentId: EnvironmentId, allowSynced = false) {
  const approver = browserElevationApproverSource.get(environmentId);
  if (approver === null) throw new Error("No browser approver here.");
  const created = await approver.createKey(new AbortController().signal, {
    name: "kgriset on oracle",
    allowSynced,
  });
  if (created === null) throw new Error("Passkey creation was cancelled.");
  const keyId = browserElevationApproverSource.get(environmentId)?.keyId;
  if (keyId == null) throw new Error("The passkey binding wasn't stored.");
  return { ...created, keyId };
}

/** DER ECDSA (r, s) to the fixed 64-byte form WebCrypto verifies. */
function derToRaw(der: Uint8Array): Uint8Array<ArrayBuffer> {
  const raw = new Uint8Array(64);
  let offset = 2;
  for (const half of [0, 1]) {
    const length = der[offset + 1] ?? 0;
    const integer = der.subarray(offset + 2, offset + 2 + length);
    const trimmed = integer.subarray(Math.max(0, integer.length - 32));
    raw.set(trimmed, half * 32 + 32 - trimmed.length);
    offset += 2 + length;
  }
  return raw;
}

/**
 * What the PAM module checks of a browser's approval: the client data names this origin and a
 * challenge of SHA-256(context ‖ payload), the authenticator verified the user, and the key
 * signed authenticatorData ‖ SHA-256(clientDataJSON).
 */
export async function verifyBrowserApproval(input: {
  readonly publicKey: string;
  readonly payload: Uint8Array;
  readonly signed: ElevationSignedResponse;
}) {
  const { signed } = input;
  if (signed.webauthn === undefined) throw new Error("No WebAuthn assertion.");
  const clientDataJSON = bytes(signed.webauthn.clientDataJSON);
  const authenticatorData = bytes(signed.webauthn.authenticatorData);
  const clientData = JSON.parse(new TextDecoder().decode(clientDataJSON)) as {
    type: string;
    challenge: string;
    origin: string;
  };
  const message = new Uint8Array([
    ...new TextEncoder().encode(ELEVATION_SIGNATURE_CONTEXT),
    ...input.payload,
  ]);
  const challenge = Base64Url.encode(
    new Uint8Array(await crypto.subtle.digest("SHA-256", message)),
  );
  const key = await crypto.subtle.importKey(
    "spki",
    bytes(input.publicKey),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const signedBytes = new Uint8Array([
    ...authenticatorData,
    ...new Uint8Array(await crypto.subtle.digest("SHA-256", clientDataJSON)),
  ]);
  return {
    type: clientData.type,
    origin: clientData.origin,
    challengeMatches: clientData.challenge === challenge,
    userVerified: ((authenticatorData[32] ?? 0) & 0x04) !== 0,
    backupEligible: ((authenticatorData[32] ?? 0) & 0x08) !== 0,
    signatureValid: await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      derToRaw(bytes(signed.signature)),
      signedBytes,
    ),
  };
}
