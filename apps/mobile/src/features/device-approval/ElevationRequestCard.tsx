import {
  decodeElevationRequestPayload,
  elevationRequestFallbackView,
  elevationRequestStatusView,
} from "@t3tools/client-runtime/elevation";
import { elevationCommandDisplay } from "@t3tools/client-runtime/elevation-command";
import {
  escapeElevationDisplayText,
  type EnvironmentId,
  type OrchestrationV2ProjectedTurnItem,
} from "@t3tools/contracts";
import * as DateTime from "effect/DateTime";
import * as Result from "effect/Result";
import { useEffect, useMemo, useRef, useState } from "react";
import { Pressable, View, type ColorValue } from "react-native";

import { SymbolView, type AppSymbolName } from "../../components/ui/AppSymbol";
import { AppText as Text } from "../../components/ui/AppText";
import { approvalHaptic } from "./approvalHaptics";
import { ElevationApprovalCard, useElevationRequestContext } from "./ElevationApprovalCard";

type ResolvedKind = "done" | "approved" | "denied" | "expired" | "cancelled";

const STATUS: Record<ResolvedKind, { readonly label: string; readonly symbol: AppSymbolName }> = {
  done: { label: "Done", symbol: "checkmark" },
  approved: { label: "Approved", symbol: "checkmark" },
  denied: { label: "Denied", symbol: "xmark" },
  expired: { label: "Expired", symbol: "clock" },
  cancelled: { label: "Cancelled", symbol: "minus" },
};

const timeFormat = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" });

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
  if (item.type !== "elevation_request") return null;

  if (item.elevationStatus === "pending" && visibility === "local" && decoded !== null) {
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
            agentCommand: item.agentCommand,
            changes: item.changes,
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

/** One line, tap for who asked, the whole command and how it ended. */
function ResolvedElevationRow(props: {
  readonly environmentId: EnvironmentId;
  readonly item: ElevationItem;
  readonly decoded: ReturnType<typeof decodeElevationRequestPayload> | null;
  readonly iconColor: ColorValue;
  readonly runActive: boolean;
}) {
  const { item } = props;
  const [expanded, setExpanded] = useState(false);
  const status = elevationRequestStatusView(item);
  const kind: ResolvedKind | "pending" =
    status.kind === "approved" && !props.runActive ? "done" : status.kind;
  const view =
    props.decoded !== null && Result.isSuccess(props.decoded)
      ? props.decoded.success.view
      : elevationRequestFallbackView(item);
  const context = useElevationRequestContext(props.environmentId, item.threadId, view.host);
  const display = elevationCommandDisplay({
    commandArgv:
      props.decoded !== null && Result.isSuccess(props.decoded)
        ? props.decoded.success.payload.command.argv
        : item.argv,
    agentCommand: item.agentCommand,
  });

  // A light tick when an approved command finishes while its row is on screen.
  const previousKind = useRef(kind);
  useEffect(() => {
    if (previousKind.current === "approved" && kind === "done") approvalHaptic("done");
    previousKind.current = kind;
  }, [kind]);

  if (kind === "pending") {
    // Pending on another client: the request is answered there or from the banner.
    return (
      <View className="mb-3 min-h-9 flex-row items-center gap-2 px-1">
        <SymbolView
          name={{ ios: "lock", android: "lock" }}
          size={13}
          tintColor={props.iconColor}
          type="monochrome"
        />
        <Text className="flex-1 text-sm text-foreground-muted" numberOfLines={1}>
          Waiting for approval · {display.lines.join(" ")}
        </Text>
      </View>
    );
  }

  const time = timeFormat.format(DateTime.toDateUtc(item.completedAt ?? item.updatedAt));
  const device =
    item.resolvedBy === null
      ? ""
      : ` on ${escapeElevationDisplayText(item.resolvedBy.deviceLabel)}`;
  const how = {
    done: `Approved${device} · ${time} · finished`,
    approved: `Approved${device} · ${time}`,
    denied: `Denied${device} · ${time}`,
    expired: `Nobody approved in time · ${time}`,
    cancelled: `Cancelled · ${time}`,
  }[kind];
  const reason =
    item.explanation && item.explanation.trim() !== ""
      ? escapeElevationDisplayText(item.explanation.trim())
      : null;
  const agentName = context.agent?.name ?? "The agent";

  return (
    <View className="mb-3 px-1">
      <Pressable
        accessibilityRole="button"
        accessibilityState={{ expanded }}
        className="min-h-9 flex-row items-center gap-2"
        onPress={() => setExpanded((current) => !current)}
      >
        <SymbolView
          name={STATUS[kind].symbol}
          size={13}
          tintColor={props.iconColor}
          type="monochrome"
        />
        <Text className="font-t3-medium text-sm text-foreground">{STATUS[kind].label}</Text>
        <Text className="min-w-0 flex-1 font-mono text-sm text-foreground-muted" numberOfLines={1}>
          {display.lines.map((line) => line.replace(/\\$/, "").trim()).join(" ")}
        </Text>
        <SymbolView
          name={expanded ? "chevron.up" : "chevron.down"}
          size={12}
          tintColor={props.iconColor}
          type="monochrome"
        />
      </Pressable>
      {expanded ? (
        <View className="gap-1.5 pt-1 pb-2">
          <Text className="text-sm text-foreground-muted">
            {reason ? `${agentName}: “${reason}”` : agentName}
          </Text>
          {display.lines.map((line, index) => (
            <Text key={index} selectable className="font-mono text-sm text-foreground">
              {line}
            </Text>
          ))}
          <Text className="text-xs text-foreground-muted">{how}</Text>
          {status.kind !== "pending" && status.detail ? (
            <Text className="text-xs text-foreground-muted">{status.detail}</Text>
          ) : null}
        </View>
      ) : null}
    </View>
  );
}
