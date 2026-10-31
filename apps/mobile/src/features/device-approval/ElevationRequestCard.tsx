import {
  decodeElevationRequestPayload,
  elevationReason,
  elevationRequestFallbackView,
  elevationRequestStatusView,
} from "@t3tools/client-runtime/elevation";
import {
  elevationCommandDisplay,
  elevationCommandOneLine,
} from "@t3tools/client-runtime/elevation-command";
import type { EnvironmentId, OrchestrationV2ProjectedTurnItem } from "@t3tools/contracts";
import * as Result from "effect/Result";
import { useEffect, useMemo, useRef, useState } from "react";
import { Pressable, View, type ColorValue } from "react-native";

import { SymbolView, type AppSymbolName } from "../../components/ui/AppSymbol";
import { AppText as Text } from "../../components/ui/AppText";
import { approvalHaptic } from "./approvalHaptics";
import { useThisPhoneKeyId } from "./deviceApprovalKeys";
import { ElevationApprovalCard, useElevationRequestContext } from "./ElevationApprovalCard";
import { ELEVATION_SETTLE_MS } from "./elevationApproval";
import { wasDeniedHere } from "./elevationApprovalTarget";
import { ElevationTechnicalDetails } from "./ElevationRequestDetails";

const SYMBOL: Record<"done" | "approved" | "denied" | "expired" | "cancelled", AppSymbolName> = {
  done: "checkmark",
  approved: "checkmark",
  denied: "xmark",
  expired: "clock",
  cancelled: "minus",
};

export function ElevationRequestCard(props: {
  readonly environmentId: EnvironmentId;
  readonly projectedItem: OrchestrationV2ProjectedTurnItem;
  readonly iconColor: ColorValue;
  /** The item's run is still going, so an approved command may not have finished yet. */
  readonly runActive: boolean;
}) {
  const { item, visibility } = props.projectedItem;
  const payload = item.type === "elevation_request" ? item.payload : null;
  // Stable bytes keep the comparison code from recomputing on every render.
  const decoded = useMemo(
    () => (payload === null ? null : decodeElevationRequestPayload(payload)),
    [payload],
  );
  // Approved on this card: it stays, showing "✓ Approved", a moment after the request resolves.
  const [held, setHeld] = useState(false);
  const [settled, setSettled] = useState(false);
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- releases the held card on a timer after the approval settles
  useEffect(() => {
    if (!settled) return;
    const timer = setTimeout(() => setHeld(false), ELEVATION_SETTLE_MS);
    return () => clearTimeout(timer);
  }, [settled]);
  if (item.type !== "elevation_request") return null;

  if (
    (held || (item.elevationStatus === "pending" && visibility === "local")) &&
    decoded !== null
  ) {
    return (
      <View className="mb-3 rounded-[20px] border border-border bg-card-alt p-4">
        <ElevationApprovalCard
          inline
          request={{
            environmentId: props.environmentId,
            requestId: item.requestId,
            threadId: item.threadId,
            decoded,
            explanation: item.explanation,
            changes: item.changes,
          }}
          onApproving={setHeld}
          onAnswered={(decision) => {
            if (decision === "approve") setSettled(true);
          }}
        />
      </View>
    );
  }
  return (
    <ResolvedElevationRow
      environmentId={props.environmentId}
      item={item}
      decoded={decoded}
      iconColor={props.iconColor}
      runActive={props.runActive}
    />
  );
}

type ElevationItem = Extract<
  OrchestrationV2ProjectedTurnItem["item"],
  { readonly type: "elevation_request" }
>;

/** One line; tap for who asked, the whole command, how it ended, and the technical details. */
function ResolvedElevationRow(props: {
  readonly environmentId: EnvironmentId;
  readonly item: ElevationItem;
  readonly decoded: ReturnType<typeof decodeElevationRequestPayload> | null;
  readonly iconColor: ColorValue;
  readonly runActive: boolean;
}) {
  const { item } = props;
  const [expanded, setExpanded] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const thisKeyId = useThisPhoneKeyId(props.environmentId);
  const status = elevationRequestStatusView(item, {
    finished: !props.runActive,
    thisKeyId,
    deniedHere: wasDeniedHere(item.requestId),
  });
  const decodedSuccess =
    props.decoded !== null && Result.isSuccess(props.decoded) ? props.decoded.success : null;
  const view = decodedSuccess?.view ?? elevationRequestFallbackView(item);
  const context = useElevationRequestContext(props.environmentId, item.threadId, view.host);
  const display = elevationCommandDisplay(
    decodedSuccess?.payload ?? { command: { argv: item.argv } },
  );
  const oneLine = elevationCommandOneLine(display);

  // A light tick when an approved command finishes while its row is on screen.
  const previousKind = useRef(status.kind);
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- fires a haptic when this row's approved command finishes
  useEffect(() => {
    if (previousKind.current === "approved" && status.kind === "done") approvalHaptic("done");
    previousKind.current = status.kind;
  }, [status.kind]);

  if (status.kind === "pending") {
    // Pending on another client: the request is answered there or from the banner.
    return (
      <View className="mb-3 min-h-9 flex-row items-center gap-2 px-1">
        <SymbolView
          name={{ ios: "lock", android: "lock" }}
          size={13}
          tintColor={props.iconColor}
          type="monochrome"
        />
        <Text className="font-t3-medium text-sm text-foreground">{status.label}</Text>
        <Text className="min-w-0 flex-1 font-mono text-sm text-foreground-muted" numberOfLines={1}>
          {oneLine}
        </Text>
      </View>
    );
  }

  const reason = elevationReason(item.explanation);
  const agentName = context.agent?.name ?? null;
  const asked =
    reason === null ? agentName : agentName === null ? `“${reason}”` : `${agentName}: “${reason}”`;

  return (
    <View className="mb-3 px-1">
      <Pressable
        accessibilityRole="button"
        accessibilityState={{ expanded }}
        className="min-h-9 flex-row items-center gap-2"
        onPress={() => setExpanded((current) => !current)}
      >
        <SymbolView
          name={SYMBOL[status.kind]}
          size={13}
          tintColor={props.iconColor}
          type="monochrome"
        />
        <Text className="font-t3-medium text-sm text-foreground">{status.label}</Text>
        <Text className="min-w-0 flex-1 font-mono text-sm text-foreground-muted" numberOfLines={1}>
          {oneLine}
        </Text>
        <Text className="text-xs tabular-nums text-foreground-muted">{status.time}</Text>
        <SymbolView
          name={expanded ? "chevron.up" : "chevron.down"}
          size={12}
          tintColor={props.iconColor}
          type="monochrome"
        />
      </Pressable>
      {expanded ? (
        <View className="gap-1.5 pt-1 pb-2 pl-5">
          {asked === null ? null : (
            <Text selectable className="text-sm text-foreground-muted">
              {asked}
            </Text>
          )}
          <Text selectable className="font-mono text-sm text-foreground">
            {display.lines.join("\n")}
          </Text>
          <Text className="text-xs text-foreground-muted">{status.how}</Text>
          {status.detail ? (
            <Text className="text-xs text-foreground-muted">{status.detail}</Text>
          ) : null}
          <Pressable
            accessibilityRole="button"
            accessibilityState={{ expanded: detailsOpen }}
            className="min-h-9 flex-row items-center gap-1.5 self-start"
            onPress={() => setDetailsOpen((current) => !current)}
          >
            <Text className="text-sm text-foreground-muted">Details</Text>
            {view.warnings.length > 0 ? (
              <SymbolView
                name="exclamationmark.triangle"
                size={12}
                tintColor={props.iconColor}
                type="monochrome"
              />
            ) : null}
            <SymbolView
              name={detailsOpen ? "chevron.up" : "chevron.down"}
              size={11}
              tintColor={props.iconColor}
              type="monochrome"
            />
          </Pressable>
          {detailsOpen ? <ElevationTechnicalDetails view={view} /> : null}
        </View>
      ) : null}
    </View>
  );
}
