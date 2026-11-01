import { useAtomValue } from "@effect/atom-react";
import { elevationHeadline, elevationNoticeText } from "@t3tools/client-runtime/elevation";
import type { PendingElevationRequest } from "@t3tools/client-runtime/state/elevation";
import * as Result from "effect/Result";
import { useState } from "react";
import { Pressable, View } from "react-native";
import Animated, { Keyframe, ReduceMotion } from "react-native-reanimated";
import { useSafeAreaInsets } from "react-native-safe-area-context";

import { ProviderIcon } from "../../components/ProviderIcon";
import { AppText as Text } from "../../components/ui/AppText";
import { GlassSurface } from "../../components/ui/GlassSurface";
import { IconButton } from "../../components/ui/IconButton";
import { MOBILE_MOTION, MOBILE_SHAPE } from "../../lib/designTokens";
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
  elevationListsOnScreenAtom,
  elevationLockScreenAtom,
  isClaimedElevationRequest,
  openElevationApproval,
} from "./elevationApprovalTarget";

const enter = () =>
  new Keyframe({
    0: { opacity: 0, transform: [{ translateY: 6 }] },
    100: { opacity: 1, transform: [{ translateY: 0 }] },
  })
    .duration(MOBILE_MOTION.enter)
    .reduceMotion(ReduceMotion.System);
const BANNER_ENTERING = enter();
// The next request waits for the answered one to leave, so it reads as a new banner.
const BANNER_ENTERING_NEXT = enter().delay(MOBILE_MOTION.exit);
const BANNER_EXITING = new Keyframe({
  0: { opacity: 1, transform: [{ translateY: 0 }] },
  100: { opacity: 0, transform: [{ translateY: -8 }] },
})
  .duration(MOBILE_MOTION.exit)
  .reduceMotion(ReduceMotion.System);

/**
 * Pending sudo requests from every connected environment, so a request is
 * seen even when another environment or screen is in front. Hidden while its
 * own thread, which shows the request inline, is on screen, and for requests
 * no thread claims while a threads list, which holds them, is. Once dismissed,
 * the thread list's Approval tag is what's left of it. An answered request's
 * banner leaves; the next one arrives as a banner of its own.
 */
export function ElevationPendingBanner(props: { readonly pathname: string }) {
  const pending = useAtomValue(elevation.pendingAcrossEnvironmentsAtom);
  const target = useAtomValue(elevationApprovalTargetAtom);
  const lockScreen = useAtomValue(elevationLockScreenAtom);
  const claim = useAtomValue(claimedElevationRequestAtom);
  const listOnScreen = useAtomValue(elevationListsOnScreenAtom) > 0;
  const insets = useSafeAreaInsets();
  const [dismissed, setDismissed] = useState<ReadonlySet<string>>(() => new Set());
  const threadOnScreen = threadDeepLinkOnScreen(props.pathname);
  const visible = pending.filter(
    (entry) =>
      !dismissed.has(entry.request.requestId) &&
      !isClaimedElevationRequest(claim, entry) &&
      (entry.request.threadId === null
        ? !listOnScreen
        : encodeThreadDeepLink({
            environmentId: entry.environmentId,
            threadId: entry.request.threadId,
          }) !== threadOnScreen),
  );
  // One entry per request: not while its own screen or the lock screen shows it.
  const first = target !== null || lockScreen !== null ? undefined : visible[0];
  const shownId = first?.request.requestId ?? null;
  const [shown, setShown] = useState({ id: shownId, replacing: false });
  if (shown.id !== shownId) {
    setShown({ id: shownId, replacing: shown.id !== null && shownId !== null });
  }
  // Stays mounted, so a banner's exit can play after the last request leaves.
  return (
    <View
      className="absolute inset-x-3 z-[100]"
      style={{ top: insets.top + APP_BAR_HEIGHT + 8 }}
      pointerEvents="box-none"
    >
      {first === undefined ? null : (
        <Animated.View
          key={first.request.requestId}
          entering={shown.replacing ? BANNER_ENTERING_NEXT : BANNER_ENTERING}
          // A leaving banner keeps its frame while the next one lays out in its place.
          exiting={BANNER_EXITING}
        >
          <BannerContent
            entry={first}
            more={visible.length - 1}
            onDismiss={() =>
              setDismissed((current) => new Set(current).add(first.request.requestId))
            }
          />
        </Animated.View>
      )}
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
    request.driver,
  );
  const notice = elevationNoticeText({
    headline: elevationHeadline({
      explanation: request.explanation,
      decoded,
      agentName: context.agent?.name ?? null,
    }),
    series: request.series,
    threadId: request.threadId,
    threadTitle: context.threadTitle,
    raisedByT3: request.raisedByT3,
    machine: context.machine,
  });
  const more = props.more > 0 ? `+${props.more}` : null;
  const open = () => openElevationApproval({ environmentId, requestId: request.requestId });
  return (
    <GlassSurface className="p-3" style={{ borderRadius: MOBILE_SHAPE.toast }}>
      <View className="flex-row items-center gap-3">
        <Pressable
          accessibilityRole="button"
          accessibilityLabel={[notice.title, notice.detail, more && `${props.more} more waiting`]
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
              {notice.title}
            </Text>
            <View className="flex-row items-center gap-1.5">
              <Text numberOfLines={1} className="min-w-0 shrink text-xs text-foreground-muted">
                {notice.detail}
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
