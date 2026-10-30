import type { EnvironmentId } from "@t3tools/contracts";
import * as Base64Url from "effect/encoding/Base64Url";
import * as SecureStore from "expo-secure-store";

/**
 * Which key this phone holds for an environment. The signer returns only a
 * signature, and the response must name the keyId, so the phone keeps it from
 * enrollment. The private key itself never leaves the Keystore.
 */
export interface DeviceApprovalKeyRecord {
  readonly alias: string;
  readonly keyId: string;
  readonly user: string;
  readonly label: string;
}

// SecureStore keys allow only `[A-Za-z0-9._-]`.
const storageKey = (environmentId: EnvironmentId) =>
  `t3-elevation.${Base64Url.encode(new TextEncoder().encode(environmentId))}`;

function parseRecord(text: string | null): DeviceApprovalKeyRecord | null {
  if (text === null) return null;
  try {
    const value: unknown = JSON.parse(text);
    if (typeof value !== "object" || value === null) return null;
    const { alias, keyId, user, label } = value as Record<string, unknown>;
    return typeof alias === "string" &&
      typeof keyId === "string" &&
      typeof user === "string" &&
      typeof label === "string"
      ? { alias, keyId, user, label }
      : null;
  } catch {
    return null;
  }
}

export const deviceApprovalKeys = {
  read: async (environmentId: EnvironmentId) =>
    parseRecord(await SecureStore.getItemAsync(storageKey(environmentId))),
  write: (environmentId: EnvironmentId, record: DeviceApprovalKeyRecord) =>
    SecureStore.setItemAsync(storageKey(environmentId), JSON.stringify(record)),
  remove: (environmentId: EnvironmentId) => SecureStore.deleteItemAsync(storageKey(environmentId)),
};
