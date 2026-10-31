import type { ElevationRequestView } from "@t3tools/client-runtime/elevation";
import { elevationComparisonCode } from "@t3tools/contracts";
import * as ExpoCrypto from "expo-crypto";
import { useEffect, useState } from "react";
import { View } from "react-native";

import { SymbolView } from "../../components/ui/AppSymbol";
import { AppText as Text } from "../../components/ui/AppText";

type DetailsView = Pick<ElevationRequestView, "host" | "runAs" | "cwd" | "warnings"> &
  Partial<Pick<ElevationRequestView, "user" | "runAsGroup" | "resolvedPath">>;

/** The code a new phone shows for its key; both phones must show the same one. */
export function useComparisonCode(publicKey: Uint8Array | null): string | null {
  const [computed, setComputed] = useState<{
    readonly publicKey: Uint8Array;
    readonly code: string;
  } | null>(null);
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

/**
 * The technical side of a request, behind a resolved row's Details: module warnings, who it ran
 * as, where, and which program. Every string arrives escaped.
 */
export function ElevationTechnicalDetails(props: { readonly view: DetailsView }) {
  const { view } = props;
  return (
    <View className="gap-2">
      {view.warnings.map((warning, index) => (
        <View key={`${warning.code}:${index}`} className="flex-row items-start gap-2">
          <SymbolView
            name="exclamationmark.triangle"
            size={13}
            tintColorClassName="accent-icon"
            type="monochrome"
          />
          <Text className="min-w-0 flex-1 text-sm text-foreground-muted">{warning.message}</Text>
        </View>
      ))}
      <View className="gap-1">
        <DetailLine
          label="Runs as"
          value={`${view.user ? `${view.user} → ` : ""}${view.runAs}${
            view.runAsGroup ? ` (group ${view.runAsGroup})` : ""
          }`}
        />
        <DetailLine label="Machine" value={view.host} />
        <DetailLine label="Directory" value={view.cwd} mono />
        {view.resolvedPath ? <DetailLine label="Program" value={view.resolvedPath} mono /> : null}
      </View>
    </View>
  );
}

function DetailLine(props: {
  readonly label: string;
  readonly value: string;
  readonly mono?: boolean;
}) {
  return (
    <View className="flex-row gap-3">
      <Text className="w-20 text-sm text-foreground-muted">{props.label}</Text>
      <Text
        selectable
        className={`min-w-0 flex-1 text-sm text-foreground ${props.mono ? "font-mono" : ""}`}
      >
        {props.value}
      </Text>
    </View>
  );
}
