import { useAtomValue } from "@effect/atom-react";
import type { PendingElevationRequest } from "@t3tools/client-runtime/state/elevation";
import { elevationCommandDisplay } from "@t3tools/client-runtime/elevation-command";
import { escapeElevationDisplayText } from "@t3tools/contracts";
import * as Result from "effect/Result";
import { useState } from "react";
import { Pressable, View } from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";

import { ProviderIcon } from "../../components/ProviderIcon";
import { AppText as Text } from "../../components/ui/AppText";
import { GlassSurface } from "../../components/ui/GlassSurface";
import { IconButton } from "../../components/ui/IconButton";
import { MOBILE_SHAPE } from "../../lib/designTokens";
import { APP_BAR_HEIGHT } from "../../lib/layoutMetrics";
import { elevation } from "../../state/elevation";
import {
  encodeThreadDeepLink,
  threadDeepLinkOnScreen,
} from "../agent-awareness/notificationPayload";
import { useElevationRequestContext } from "./ElevationApprovalCard";
import {
  elevationApprovalTargetAtom,
  elevationLockScreenAtom,
  openElevationApproval,
} from "./elevationApprovalTarget";

/**
 * Pending sudo requests from every connected environment, so a request is
 * seen even when another environment or screen is in front. Hidden while its
 * own thread, which shows the request inline, is on screen.
 */
export function ElevationPendingBanner(props: { readonly pathname: string }) {
  const pending = useAtomValue(elevation.pendingAcrossEnvironmentsAtom);
  const target = useAtomValue(elevationApprovalTargetAtom);
  const lockScreen = useAtomValue(elevationLockScreenAtom);
  const insets = useSafeAreaInsets();
  const [dismissed, setDismissed] = useState<ReadonlySet<string>>(() => new Set());
  const threadOnScreen = threadDeepLinkOnScreen(props.pathname);
  const visible = pending.filter(
    (entry) =>
      !dismissed.has(entry.request.requestId) &&
      (entry.request.threadId === null ||
        encodeThreadDeepLink({
          environmentId: entry.environmentId,
          threadId: entry.request.threadId,
        }) !== threadOnScreen),
  );
  const first = visible[0];
  // One entry per request: not while its sheet or the lock screen shows it.
  if (target !== null || lockScreen !== null || first === undefined) return null;
  return (
    <View
      className="absolute inset-x-3 z-[100]"
      style={{ top: insets.top + APP_BAR_HEIGHT + 8 }}
      pointerEvents="box-none"
    >
      <BannerContent
        key={first.request.requestId}
        entry={first}
        more={visible.length - 1}
        onDismiss={() => setDismissed((current) => new Set(current).add(first.request.requestId))}
      />
    </View>
  );
}

function BannerContent(props: {
  readonly entry: PendingElevationRequest;
  readonly more: number;
  readonly onDismiss: () => void;
}) {
  const { environmentId, request, decoded } = props.entry;
  const view = Result.isSuccess(decoded) ? decoded.success : null;
  const context = useElevationRequestContext(
    environmentId,
    request.threadId,
    view?.view.host ?? null,
  );
  const reason = request.explanation?.trim();
  const headline = view?.view.enroll
    ? `Add device ${view.view.enroll.label}`
    : reason
      ? `“${escapeElevationDisplayText(reason)}”`
      : view
        ? (elevationCommandDisplay({
            commandArgv: view.payload.command.argv,
            agentCommand: request.agentCommand,
          }).lines[0] ?? "")
        : "Approval needed";
  const where = [context.threadTitle, context.machine].filter(Boolean).join(" · ");
  const open = () => openElevationApproval({ environmentId, requestId: request.requestId });
  return (
    <GlassSurface className="p-3" style={{ borderRadius: MOBILE_SHAPE.toast }}>
      <View className="flex-row items-center gap-3">
        <Pressable
          accessibilityRole="button"
          accessibilityHint="Opens the request"
          className="min-w-0 flex-1 flex-row items-center gap-3"
          onPress={open}
        >
          {context.agent ? (
            <ProviderIcon
              provider={context.agent.driver}
              iconUrl={context.agent.iconUrl}
              size={18}
            />
          ) : null}
          <View className="min-w-0 flex-1">
            <Text numberOfLines={2} className="font-t3-semibold text-sm text-foreground">
              {headline}
            </Text>
            <Text numberOfLines={1} className="text-xs text-foreground-muted">
              {props.more > 0 ? `${where} · ${props.more} more` : where}
            </Text>
          </View>
        </Pressable>
        <IconButton accessibilityLabel="Dismiss" icon="xmark" onPress={props.onDismiss} />
      </View>
    </GlassSurface>
  );
}
