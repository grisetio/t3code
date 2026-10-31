import { elevationKeyAlias } from "@t3tools/client-runtime/elevation";
import type { ElevationEnrollmentDevice, EnvironmentId } from "@t3tools/contracts";
import * as Base64Url from "effect/encoding/Base64Url";
import * as Result from "effect/Result";
import * as ExpoCrypto from "expo-crypto";
import * as Device from "expo-device";

import type { DeviceApprovalKeyRecord } from "./deviceApprovalKeys";
import { deviceApprovalSigner, DeviceApprovalSignerError } from "./deviceApprovalSigner";

export interface PhoneKey {
  readonly challenge: string;
  readonly device: ElevationEnrollmentDevice;
  /** Written once the machine accepted the key. */
  readonly record: DeviceApprovalKeyRecord;
  /** SPKI DER, for the comparison code another phone shows. */
  readonly publicKey: Uint8Array | null;
}

const deviceLabel = () => (Device.modelName ?? "Android phone").trim().slice(0, 64);

/**
 * Creates this phone's key for one machine and user, with its attestation. A replacement goes in
 * the slot the working key doesn't use, so backing out before the machine accepts it leaves the
 * working key in place; the caller deletes the old alias once the new key is enrolled.
 */
export async function createPhoneKey(
  environmentId: EnvironmentId,
  user: string,
  current: DeviceApprovalKeyRecord | null = null,
): Promise<PhoneKey> {
  const challenge = Base64Url.encode(ExpoCrypto.getRandomBytes(32));
  const base = elevationKeyAlias(environmentId, user);
  const alias = current?.alias === base ? `${base}~2` : base;
  const key = await deviceApprovalSigner.generateKey(alias, challenge);
  const [leaf, ...rest] = key.attestationChain;
  if (leaf === undefined) throw new DeviceApprovalSignerError("failed");
  const label = deviceLabel();
  const publicKey = Base64Url.decode(key.publicKeySpki);
  return {
    challenge,
    device: { label, publicKey: key.publicKeySpki, challenge, attestationChain: [leaf, ...rest] },
    record: { alias, keyId: key.keyId, user, label },
    publicKey: Result.isSuccess(publicKey) ? publicKey.success : null,
  };
}

/**
 * Asks for the fingerprint with the new key before the machine is changed, so setting up, fixing
 * and replacing a key all prove the person holding this phone can use it. Throws the signer's
 * error when the prompt is cancelled.
 */
export async function confirmPhoneKey(
  key: PhoneKey,
  prompt: { readonly title: string; readonly subtitle: string },
): Promise<void> {
  await deviceApprovalSigner.sign(key.record.alias, key.challenge, prompt);
}

/** Removes a key that never reached the machine, or one a replacement made redundant. */
export async function discardPhoneKey(alias: string): Promise<void> {
  await deviceApprovalSigner.deleteKey(alias).catch(() => undefined);
}
