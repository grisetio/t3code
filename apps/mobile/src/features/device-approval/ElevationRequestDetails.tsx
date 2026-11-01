import { elevationComparisonCode } from "@t3tools/contracts";
import * as ExpoCrypto from "expo-crypto";
import { useEffect, useState } from "react";

/** The code a new phone shows for its key; both phones must show the same one. */
export function useComparisonCode(publicKey: Uint8Array | null): string | null {
  const [computed, setComputed] = useState<{
    readonly publicKey: Uint8Array;
    readonly code: string;
  } | null>(null);
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- hashes the key with the native crypto module, which is async
  useEffect(() => {
    if (publicKey === null) return;
    let cancelled = false;
    void ExpoCrypto.digest(ExpoCrypto.CryptoDigestAlgorithm.SHA256, new Uint8Array(publicKey)).then(
      (digest) => {
        if (!cancelled) {
          setComputed({ publicKey, code: elevationComparisonCode(new Uint8Array(digest)) });
        }
      },
    );
    return () => {
      cancelled = true;
    };
  }, [publicKey]);
  return computed !== null && computed.publicKey === publicKey ? computed.code : null;
}
