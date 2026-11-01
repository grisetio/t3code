import { useAtomValue } from "@effect/atom-react";
import { elevationHeadline } from "@t3tools/client-runtime/elevation";
import type { PendingElevationRequest } from "@t3tools/client-runtime/state/elevation";
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
  claimedElevationRequestAtom,
  elevationApprovalTargetAtom,
  elevationLockScreenAtom,
  isClaimedElevationRequest,
  openElevationApproval,
} from "./elevationApprovalTarget";

/**
 * Pending sudo requests from every connected environment, so a request is
 * seen even when another environment or screen is in front. Hidden while its
 * own thread, which shows the request inline, is on screen. Once dismissed, the
 * thread list's Approval tag is what's left of it.
 */
export function ElevationPendingBanner(props: { readonly pathname: string }) {
  const pending = useAtomValue(elevation.pendingAcrossEnvironmentsAtom);
  const target = useAtomValue(elevationApprovalTargetAtom);
  const lockScreen = useAtomValue(elevationLockScreenAtom);
  const claim = useAtomValue(claimedElevationRequestAtom);
  const insets = useSafeAreaInsets();
  const [dismissed, setDismissed] = useState<ReadonlySet<string>>(() => new Set());
  const threadOnScreen = threadDeepLinkOnScreen(props.pathname);
  const visible = pending.filter(
    (entry) =>
      !dismissed.has(entry.request.requestId) &&
      !isClaimedElevationRequest(claim, entry) &&
      (entry.request.threadId === null ||
        encodeThreadDeepLink({
          environmentId: entry.environmentId,
          threadId: entry.request.threadId,
        }) !== threadOnScreen),
  );
  const first = visible[0];
  // One entry per request: not while its own screen or the lock screen shows it.
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
  const headline = elevationHeadline({
    explanation: request.explanation,
    decoded,
    agentName: context.agent?.name ?? null,
  });
  const who = context.agent ? `${context.agent.name} · ${context.machine}` : context.machine;
  const more = props.more > 0 ? `+${props.more}` : null;
  const open = () => openElevationApproval({ environmentId, requestId: request.requestId });
  return (
    <GlassSurface className="p-3" style={{ borderRadius: MOBILE_SHAPE.toast }}>
      <View className="flex-row items-center gap-3">
        <Pressable
          accessibilityRole="button"
          accessibilityLabel={[headline, who, more && `${props.more} more waiting`]
            .filter(Boolean)
            .join(", ")}
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
            <View className="flex-row items-center gap-1.5">
              <Text numberOfLines={1} className="min-w-0 shrink text-xs text-foreground-muted">
                {who}
              </Text>
              {more ? (
                <Text className="shrink-0 font-t3-medium text-xs tabular-nums text-foreground-muted">
                  {more}
                </Text>
              ) : null}
            </View>
          </View>
        </Pressable>
        <IconButton accessibilityLabel="Dismiss" icon="xmark" onPress={props.onDismiss} />
      </View>
    </GlassSurface>
  );
}
