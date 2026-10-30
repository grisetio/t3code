import {
  decodeElevationRequestPayload,
  elevationRequestFallbackView,
  elevationRequestStatusView,
} from "@t3tools/client-runtime/elevation";
import type { EnvironmentId, OrchestrationV2ProjectedTurnItem } from "@t3tools/contracts";
import * as Result from "effect/Result";
import { useState } from "react";
import { Pressable, View, type ColorValue } from "react-native";

import { SymbolView, type AppSymbolName } from "../../components/ui/AppSymbol";
import { AppText as Text } from "../../components/ui/AppText";
import { Button } from "../../components/ui/Button";
import { openElevationApproval } from "./elevationApprovalTarget";
import { useElevationRespond } from "./ElevationApprovalHost";
import { ElevationRequestDetails } from "./ElevationRequestDetails";

const STATUS_SYMBOLS: Record<ReturnType<typeof elevationRequestStatusView>["kind"], AppSymbolName> =
  {
    pending: { ios: "lock", android: "lock" },
    approved: "checkmark",
    denied: "xmark",
    expired: "clock",
    cancelled: "minus",
  };

export function ElevationRequestCard(props: {
  readonly environmentId: EnvironmentId;
  readonly projectedItem: OrchestrationV2ProjectedTurnItem;
  readonly iconColor: ColorValue;
}) {
  const { item, visibility } = props.projectedItem;
  const [expanded, setExpanded] = useState(false);
  if (item.type !== "elevation_request") return null;
  const status = elevationRequestStatusView(item);
  const decoded = item.payload === null ? null : decodeElevationRequestPayload(item.payload);
  const decodedView = decoded !== null && Result.isSuccess(decoded) ? decoded.success.view : null;
  const view = decodedView ?? elevationRequestFallbackView(item);

  if (status.kind === "pending" && visibility === "local") {
    return (
      <PendingElevationCard
        environmentId={props.environmentId}
        requestId={item.requestId}
        title={
          decodedView?.enroll ? `Add device ${decodedView.enroll.label}` : `sudo on ${view.host}`
        }
        command={view.commandArgv.join(" ")}
      />
    );
  }
  return (
    <View className="mb-3 px-1">
      <Pressable
        accessibilityRole="button"
        accessibilityState={{ expanded }}
        className="min-h-9 flex-row items-center gap-2"
        onPress={() => setExpanded((current) => !current)}
      >
        <SymbolView
          name={STATUS_SYMBOLS[status.kind]}
          size={13}
          tintColor={props.iconColor}
          type="monochrome"
        />
        <Text className="flex-1 font-sans text-sm text-foreground-muted" numberOfLines={2}>
          sudo {view.commandArgv.join(" ")} · {status.label}
        </Text>
      </Pressable>
      {expanded ? (
        <View className="gap-2 pt-1 pb-2">
          {status.kind !== "pending" && status.detail ? (
            <Text className="text-xs text-foreground-muted">{status.detail}</Text>
          ) : null}
          <ElevationRequestDetails view={view} explanation={item.explanation} />
        </View>
      ) : null}
    </View>
  );
}

/** The full request is reviewed in the sheet, which renders from the signed bytes. */
function PendingElevationCard(props: {
  readonly environmentId: EnvironmentId;
  readonly requestId: Parameters<typeof openElevationApproval>[0]["requestId"];
  readonly title: string;
  readonly command: string;
}) {
  const answer = useElevationRespond(props.environmentId);
  return (
    <View className="mb-3 gap-3 rounded-[20px] border border-border bg-card-alt p-4">
      <View className="gap-1">
        <Text className="font-t3-bold text-base text-foreground">
          The agent wants to run a command as root
        </Text>
        <Text className="font-mono text-sm text-foreground" numberOfLines={3}>
          {props.command}
        </Text>
        <Text className="text-sm text-foreground-muted">{props.title}</Text>
      </View>
      {answer.error !== null ? (
        <Text accessibilityRole="alert" className="text-sm text-danger-foreground">
          {answer.error}
        </Text>
      ) : null}
      <Button
        label="Review and approve"
        tone="primary"
        fullWidth
        onPress={() =>
          openElevationApproval({ environmentId: props.environmentId, requestId: props.requestId })
        }
      />
      <View className="flex-row justify-end">
        <Button
          label="Deny"
          tone="text"
          disabled={!answer.canRespond || answer.pending}
          onPress={() => void answer.run({ requestId: props.requestId, decision: "deny" })}
        />
      </View>
    </View>
  );
}
