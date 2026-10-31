import {
  ELEVATION_EXPLANATION_LABEL,
  type ElevationRequestView,
} from "@t3tools/client-runtime/elevation";
import { elevationComparisonCode, escapeElevationDisplayText } from "@t3tools/contracts";
import * as ExpoCrypto from "expo-crypto";
import { useEffect, useState } from "react";
import { View } from "react-native";

import { SymbolView } from "../../components/ui/AppSymbol";
import { AppText as Text } from "../../components/ui/AppText";

type DetailsView = Pick<
  ElevationRequestView,
  "host" | "runAs" | "commandArgv" | "cwd" | "warnings"
> &
  Partial<Pick<ElevationRequestView, "user" | "runAsGroup" | "resolvedPath" | "enroll">>;

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

/**
 * What a sudo request will do. Every string arrives escaped; the argv is shown
 * whole, one entry per line, never truncated.
 */
export function ElevationRequestDetails(props: {
  readonly view: DetailsView;
  readonly explanation: string | null;
}) {
  const { view } = props;
  const comparisonCode = useComparisonCode(view.enroll?.publicKey ?? null);
  return (
    <View className="gap-3">
      {view.enroll ? (
        <View className="gap-1">
          <Text className="font-t3-bold text-base text-foreground">
            Add device {view.enroll.label}
          </Text>
          <Text selectable className="font-mono text-2xl tracking-widest text-foreground">
            {comparisonCode ?? "…"}
          </Text>
          <Text className="text-sm text-foreground-muted">
            Approve only if the new phone shows this same code.
          </Text>
        </View>
      ) : null}
      {view.warnings.map((warning, index) => (
        // oxlint-disable-next-line react/no-array-index-key -- Warnings can repeat and have no local state.
        <ElevationWarning key={`${warning.code}:${index}`} message={warning.message} />
      ))}
      <View accessibilityLabel="Command" className="gap-0.5 rounded-xl bg-subtle px-3 py-2">
        {view.commandArgv.map((arg, index) => (
          // oxlint-disable-next-line react/no-array-index-key -- argv is positional; entries can repeat.
          <Text key={index} selectable className="font-mono text-sm text-foreground">
            {arg}
          </Text>
        ))}
      </View>
      <View className="gap-1">
        <DetailLine
          label="Runs as"
          value={`${view.user ? `${view.user} → ` : ""}${view.runAs}${
            view.runAsGroup ? ` (group ${view.runAsGroup})` : ""
          }`}
        />
        <DetailLine label="Host" value={view.host} />
        <DetailLine label="Directory" value={view.cwd} mono />
        {view.resolvedPath ? <DetailLine label="Program" value={view.resolvedPath} mono /> : null}
      </View>
      {props.explanation ? (
        <View className="gap-0.5">
          <Text className="text-sm text-foreground-muted">{ELEVATION_EXPLANATION_LABEL}</Text>
          <Text selectable className="text-sm text-foreground">
            {escapeElevationDisplayText(props.explanation)}
          </Text>
        </View>
      ) : null}
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

function ElevationWarning({ message }: { readonly message: string }) {
  return (
    <View className="flex-row items-start gap-2">
      <SymbolView
        name="exclamationmark.triangle"
        size={15}
        tintColorClassName="accent-danger-foreground"
        type="monochrome"
      />
      <Text className="min-w-0 flex-1 text-sm text-danger-foreground">{message}</Text>
    </View>
  );
}
