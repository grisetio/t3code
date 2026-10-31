import type { EnvironmentId } from "@t3tools/contracts";
import * as Base64Url from "effect/encoding/Base64Url";
import * as SecureStore from "expo-secure-store";
import { useEffect, useSyncExternalStore } from "react";

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

// Rows ask for this phone's key ID on every render; SecureStore is async, so reads are cached.
const keyIds = new Map<EnvironmentId, string | null>();
const listeners = new Set<() => void>();

function remember(environmentId: EnvironmentId, record: DeviceApprovalKeyRecord | null): void {
  if (keyIds.has(environmentId) && keyIds.get(environmentId) === (record?.keyId ?? null)) return;
  keyIds.set(environmentId, record?.keyId ?? null);
  for (const listener of listeners) listener();
}

export const deviceApprovalKeys = {
  read: async (environmentId: EnvironmentId) => {
    const record = parseRecord(await SecureStore.getItemAsync(storageKey(environmentId)));
    remember(environmentId, record);
    return record;
  },
  write: async (environmentId: EnvironmentId, record: DeviceApprovalKeyRecord) => {
    await SecureStore.setItemAsync(storageKey(environmentId), JSON.stringify(record));
    remember(environmentId, record);
  },
  remove: async (environmentId: EnvironmentId) => {
    await SecureStore.deleteItemAsync(storageKey(environmentId));
    remember(environmentId, null);
  },
};

/** This phone's key ID on a machine, so rows can say "on this phone". Null until known. */
export function useThisPhoneKeyId(environmentId: EnvironmentId): string | null {
  const keyId = useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => keyIds.get(environmentId) ?? null,
  );
  useEffect(() => {
    if (!keyIds.has(environmentId)) void deviceApprovalKeys.read(environmentId).catch(() => null);
  }, [environmentId]);
  return keyId;
}
