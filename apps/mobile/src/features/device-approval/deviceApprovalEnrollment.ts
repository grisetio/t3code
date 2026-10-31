import { elevationKeyAlias } from "@t3tools/client-runtime/elevation";
import type { ElevationEnrollmentDevice, EnvironmentId } from "@t3tools/contracts";
import * as Base64Url from "effect/encoding/Base64Url";
import * as Result from "effect/Result";
import * as ExpoCrypto from "expo-crypto";
import * as Device from "expo-device";

import type { DeviceApprovalKeyRecord } from "./deviceApprovalKeys";
import { deviceApprovalSigner, DeviceApprovalSignerError } from "./deviceApprovalSigner";

export interface PhoneKey {
  readonly device: ElevationEnrollmentDevice;
  /** Written once the machine accepted the key. */
  readonly record: DeviceApprovalKeyRecord;
  /** SPKI DER, for the comparison code another phone shows. */
  readonly publicKey: Uint8Array | null;
}

const deviceLabel = () => (Device.modelName ?? "Android phone").trim().slice(0, 64);

/**
 * Creates this phone's key for one machine and user, with its attestation.
 * It replaces any previous key under the same alias, which is how a key
 * invalidated by a fingerprint change, or lost from the machine, is recovered.
 */
export async function createPhoneKey(
  environmentId: EnvironmentId,
  user: string,
): Promise<PhoneKey> {
  const challenge = Base64Url.encode(ExpoCrypto.getRandomBytes(32));
  const alias = elevationKeyAlias(environmentId, user);
  const key = await deviceApprovalSigner.generateKey(alias, challenge);
  const [leaf, ...rest] = key.attestationChain;
  if (leaf === undefined) throw new DeviceApprovalSignerError("failed");
  const label = deviceLabel();
  const publicKey = Base64Url.decode(key.publicKeySpki);
  return {
    device: { label, publicKey: key.publicKeySpki, challenge, attestationChain: [leaf, ...rest] },
    record: { alias, keyId: key.keyId, user, label },
    publicKey: Result.isSuccess(publicKey) ? publicKey.success : null,
  };
}
