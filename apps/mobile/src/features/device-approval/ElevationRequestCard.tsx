import {
  decodeElevationRequestPayload,
  elevationHeadline,
  elevationRequestFacts,
  elevationRequestFallbackView,
  elevationRequestStatusView,
  elevationResolvedSummary,
} from "@t3tools/client-runtime/elevation";
import { elevationCommandDisplay } from "@t3tools/client-runtime/elevation-command";
import type { EnvironmentId, OrchestrationV2ProjectedTurnItem } from "@t3tools/contracts";
import * as Result from "effect/Result";
import { useEffect, useMemo, useRef, useState } from "react";
import { View, type ColorValue, type LayoutChangeEvent } from "react-native";
import Animated, {
  FadeIn,
  FadeOut,
  LinearTransition,
  ReduceMotion,
  runOnJS,
  useAnimatedStyle,
  useSharedValue,
  withTiming,
} from "react-native-reanimated";

import { SymbolView, type AppSymbolName } from "../../components/ui/AppSymbol";
import { AppText as Text } from "../../components/ui/AppText";
import {
  THREAD_DISCLOSURE_TRANSITION_MS,
  ThreadDisclosureChevron,
} from "../threads/thread-work-log";
import {
  WorkLogBlock,
  WorkLogIconSlot,
  WorkLogLabel,
  WorkLogPressable,
} from "../threads/work-log-layout";
import { approvalHaptic } from "./approvalHaptics";
import { useThisPhoneKeyId } from "./deviceApprovalKeys";
import {
  ElevationApprovalCard,
  ElevationRequestFacts,
  useElevationRequestContext,
} from "./ElevationApprovalCard";
import { ELEVATION_SETTLE_MS } from "./elevationApproval";
import { wasDeniedHere } from "./elevationApprovalTarget";

const SYMBOL: Record<"done" | "approved" | "denied" | "expired" | "cancelled", AppSymbolName> = {
  done: "checkmark",
  approved: "checkmark",
  denied: "xmark",
  expired: "clock",
  cancelled: "minus",
};

const COLLAPSE_MS = 240;
const CARD_FADE_MS = 140;
const ROW_LAYOUT = LinearTransition.duration(THREAD_DISCLOSURE_TRANSITION_MS);

/**
 * A request in its thread: the card while it waits here, then its resolved row. The card hands
 * over to the row in place: its height eases down to the row's while it fades, so nothing below
 * jumps. Approving here holds "✓ Approved" for a moment first.
 */
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

  const showCard =
    item.type === "elevation_request" &&
    decoded !== null &&
    (held || (item.elevationStatus === "pending" && visibility === "local"));
  // Only a card seen leaving animates; history mounts straight as rows.
  const [shownAsCard, setShownAsCard] = useState(showCard);
  const [collapsing, setCollapsing] = useState(false);
  if (shownAsCard !== showCard) {
    setShownAsCard(showCard);
    setCollapsing(!showCard);
  }

  const [cardHeight, setCardHeight] = useState(0);
  const height = useSharedValue(0);
  const animating = useSharedValue(false);
  const cardOpacity = useSharedValue(1);
  const heightStyle = useAnimatedStyle(() => (animating.get() ? { height: height.get() } : {}));
  const cardStyle = useAnimatedStyle(() => ({ opacity: cardOpacity.get() }));

  if (item.type !== "elevation_request") return null;

  const row = (
    <ResolvedElevationRow
      environmentId={props.environmentId}
      item={item}
      decoded={decoded}
      iconColor={props.iconColor}
      runActive={props.runActive}
    />
  );
  if (!showCard && !collapsing) return row;

  const onCardLayout = (event: LayoutChangeEvent) => {
    if (collapsing) return;
    const measured = event.nativeEvent.layout.height;
    height.set(measured);
    setCardHeight(measured);
  };
  const onRowLayout = (event: LayoutChangeEvent) => {
    const target = event.nativeEvent.layout.height;
    if (animating.get()) return;
    animating.set(true);
    const reduceMotion = ReduceMotion.System;
    cardOpacity.set(withTiming(0, { duration: CARD_FADE_MS, reduceMotion }));
    height.set(
      withTiming(target, { duration: COLLAPSE_MS, reduceMotion }, (finished) => {
        if (finished) runOnJS(setCollapsing)(false);
      }),
    );
  };

  return (
    <Animated.View
      className="overflow-hidden"
      style={[collapsing ? { height: cardHeight } : null, heightStyle]}
    >
      {collapsing ? (
        <View key="row" onLayout={onRowLayout}>
          {row}
        </View>
      ) : null}
      <Animated.View
        key="card"
        onLayout={onCardLayout}
        pointerEvents={collapsing ? "none" : "auto"}
        style={[cardStyle, collapsing ? { position: "absolute", top: 0, left: 0, right: 0 } : null]}
      >
        <View className="mb-3 rounded-[20px] border border-border bg-card-alt p-4">
          <ElevationApprovalCard
            request={{
              environmentId: props.environmentId,
              requestId: item.requestId,
              threadId: item.threadId,
              decoded: decoded!,
              explanation: item.explanation,
              changes: item.changes,
            }}
            onApproving={setHeld}
            onAnswered={(decision) => {
              if (decision === "approve") setSettled(true);
            }}
          />
        </View>
      </Animated.View>
    </Animated.View>
  );
}

type ElevationItem = Extract<
  OrchestrationV2ProjectedTurnItem["item"],
  { readonly type: "elevation_request" }
>;

/**
 * A work-log row: "Approved · Restart audio". Tap for the reason, the whole command, how and when
 * it ended, and where it ran when that isn't the default.
 */
function ResolvedElevationRow(props: {
  readonly environmentId: EnvironmentId;
  readonly item: ElevationItem;
  readonly decoded: ReturnType<typeof decodeElevationRequestPayload> | null;
  readonly iconColor: ColorValue;
  readonly runActive: boolean;
}) {
  const { item } = props;
  const [expanded, setExpanded] = useState(false);
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

  // A light tick when an approved command finishes while its row is on screen.
  const previousKind = useRef(status.kind);
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- fires a haptic when this row's approved command finishes
  useEffect(() => {
    if (previousKind.current === "approved" && status.kind === "done") approvalHaptic("done");
    previousKind.current = status.kind;
  }, [status.kind]);

  // Pending on another client: the request is answered there or from the banner.
  const pending = status.kind === "pending";
  const summary = elevationResolvedSummary(status.label, item.explanation, display);
  const headline = elevationHeadline({
    explanation: item.explanation,
    decoded: props.decoded ?? Result.fail("invalid"),
    agentName: context.agent?.name ?? null,
  });

  return (
    <WorkLogBlock>
      <Animated.View layout={ROW_LAYOUT} className="overflow-hidden">
        <WorkLogPressable
          accessibilityRole={pending ? undefined : "button"}
          accessibilityLabel={summary}
          accessibilityState={pending ? undefined : { expanded }}
          onPress={pending ? undefined : () => setExpanded((current) => !current)}
        >
          <WorkLogIconSlot>
            <SymbolView
              name={pending ? { ios: "lock", android: "lock" } : SYMBOL[status.kind]}
              size={14}
              weight="medium"
              tintColor={props.iconColor}
              type="monochrome"
            />
          </WorkLogIconSlot>
          <WorkLogLabel>{summary}</WorkLogLabel>
          <View className="h-4 w-4 shrink-0 items-center justify-center">
            {pending ? null : (
              <ThreadDisclosureChevron
                expanded={expanded}
                collapsedDirection="down"
                size={11}
                tintColor={props.iconColor}
              />
            )}
          </View>
        </WorkLogPressable>
        {expanded && status.kind !== "pending" ? (
          <Animated.View
            entering={FadeIn.duration(140)}
            exiting={FadeOut.duration(120)}
            layout={ROW_LAYOUT}
            className="ml-7 gap-1.5 pb-2 pt-0.5"
          >
            <Text selectable className="text-sm text-foreground">
              {headline}
            </Text>
            <Text selectable className="font-mono text-sm text-foreground-muted">
              {display.lines.join("\n")}
            </Text>
            <Text className="text-sm text-foreground-muted">{status.how}</Text>
            {status.detail ? (
              <Text className="text-sm text-foreground-muted">{status.detail}</Text>
            ) : null}
            <ElevationRequestFacts
              facts={elevationRequestFacts(view, { cwd: context.checkout })}
              warnings={view.warnings}
            />
          </Animated.View>
        ) : null}
      </Animated.View>
    </WorkLogBlock>
  );
}
