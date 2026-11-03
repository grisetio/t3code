import { useAtomValue } from "@effect/atom-react";
import {
  decodeElevationRequestPayload,
  elevationCommandFinished,
  elevationHeadline,
  elevationLinkedCommandKey,
  elevationRequestFacts,
  elevationRequestFallbackView,
  elevationRequestStatusView,
  elevationResolvedSummary,
} from "@t3tools/client-runtime/elevation";
import { elevationCommandDisplay } from "@t3tools/client-runtime/elevation-command";
import { turnItemOutputText } from "@t3tools/client-runtime/work-log/item-detail";
import type { EnvironmentId, OrchestrationV2ProjectedTurnItem } from "@t3tools/contracts";
import * as DateTime from "effect/DateTime";
import * as Result from "effect/Result";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  Animated as NativeAnimated,
  useAnimatedValue,
  View,
  type ColorValue,
  type LayoutChangeEvent,
} from "react-native";
import Animated, {
  FadeIn,
  FadeOut,
  LinearTransition,
  useReducedMotion,
} from "react-native-reanimated";

import { SymbolView, type AppSymbolName } from "../../components/ui/AppSymbol";
import { elevation } from "../../state/elevation";
import { AppText as Text } from "../../components/ui/AppText";
import { useTurnItemDetail } from "../../state/queries";
import { ThreadCommandOutput, useCommandOutputStreaming } from "../threads/thread-command-output";
import { FeedRowHeight } from "../threads/feed-row-height";
import {
  isFreshRow,
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
import { setElevationHandover } from "./elevationHandover";
import { wasDeniedHere } from "./elevationApprovalTarget";

const SYMBOL: Record<"approved" | "denied" | "expired" | "cancelled", AppSymbolName> = {
  approved: "checkmark",
  denied: "xmark",
  expired: "clock",
  cancelled: "minus",
};

const CARD_FADE_MS = 140;
const ROW_LAYOUT = LinearTransition.duration(THREAD_DISCLOSURE_TRANSITION_MS);

/**
 * A request in its thread: the card while it waits here, then its resolved row. A card arriving
 * while the thread is open grows in as it fades in; it hands over in place, easing to the row's
 * height as it fades, with its command row easing out alongside (`ElevationCommandRowExit`).
 * Approving here holds "✓ Approved" a moment first. Heights ease through `FeedRowHeight`.
 */
export function ElevationRequestCard(props: {
  readonly environmentId: EnvironmentId;
  readonly projectedItem: OrchestrationV2ProjectedTurnItem;
  /** The agent's command row this settled request stands in for, whose output it shows. */
  readonly command?: OrchestrationV2ProjectedTurnItem | undefined;
  readonly iconColor: ColorValue;
  readonly themeAppearance: "light" | "dark";
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

  // The turn item doesn't carry how many requests came before; the pending request does. The card
  // keeps the last one it saw, so its "2nd request" line doesn't drop out as the request settles.
  const pendingSeries = useAtomValue(elevation.pendingAcrossEnvironmentsAtom).find(
    (entry) =>
      entry.environmentId === props.environmentId &&
      item.type === "elevation_request" &&
      entry.request.requestId === item.requestId,
  )?.request.series;
  const [series, setSeries] = useState(pendingSeries);
  if (pendingSeries !== undefined && pendingSeries !== series) setSeries(pendingSeries);

  const showCard =
    item.type === "elevation_request" &&
    decoded !== null &&
    (held || (item.elevationStatus === "pending" && visibility === "local"));
  const reduceMotion = useReducedMotion();
  // Only a card seen leaving animates; history mounts straight as rows.
  const [shownAsCard, setShownAsCard] = useState(showCard);
  const [collapsing, setCollapsing] = useState(false);
  // Once a card, the row keeps the card's wrapper, so ending the collapse doesn't remount it.
  const [wasCard, setWasCard] = useState(showCard);
  // Only a card that just arrived eases in; rows remount when scrolled back into view.
  const [arriving, setArriving] = useState(
    () =>
      showCard && !reduceMotion && isFreshRow(DateTime.formatIso(item.startedAt ?? item.updatedAt)),
  );
  const [cardHeight, setCardHeight] = useState(0);
  const [rowHeight, setRowHeight] = useState<number | null>(null);
  if (shownAsCard !== showCard) {
    setShownAsCard(showCard);
    setCollapsing(!showCard);
    setArriving(false);
    if (showCard) setWasCard(true);
  }

  // The feed keeps the command row this request stands in for while the request is live here, and
  // drops it once the row has eased out as the request settles or its card leaves.
  const pending = item.type === "elevation_request" && item.elevationStatus === "pending";
  const [seenPending, setSeenPending] = useState(pending);
  if (pending && !seenPending) setSeenPending(true);
  const commandKey = elevationLinkedCommandKey(props.projectedItem);
  const handover = showCard || pending ? "held" : seenPending || wasCard ? "leaving" : null;
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- keeps this request's entry in the handover registry the feed reads
  useEffect(() => {
    if (commandKey !== null) setElevationHandover(commandKey, handover);
  }, [commandKey, handover]);
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- removes the handover registry entry on unmount
  useEffect(
    () => (commandKey === null ? undefined : () => setElevationHandover(commandKey, null)),
    [commandKey],
  );

  const cardOpacity = useAnimatedValue(arriving ? 0 : 1);
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- starts the card's native-driver fade as it arrives or collapses
  useEffect(() => {
    if (!arriving && !collapsing) return;
    NativeAnimated.timing(cardOpacity, {
      toValue: collapsing ? 0 : 1,
      duration: reduceMotion ? 0 : CARD_FADE_MS,
      useNativeDriver: true,
    }).start();
  }, [arriving, cardOpacity, collapsing, reduceMotion]);

  if (item.type !== "elevation_request") return null;

  const row = (
    <ResolvedElevationRow
      environmentId={props.environmentId}
      item={item}
      decoded={decoded}
      command={props.command}
      iconColor={props.iconColor}
      themeAppearance={props.themeAppearance}
      // The linked command says when the approved command itself returned; without one, the run.
      runActive={
        props.command === undefined ? props.runActive : !elevationCommandFinished(props.command)
      }
    />
  );
  if (!showCard && !collapsing && !wasCard) return row;

  const onCardLayout = (event: LayoutChangeEvent) => {
    if (!collapsing) setCardHeight(event.nativeEvent.layout.height);
  };
  const onRowLayout = (event: LayoutChangeEvent) => {
    if (collapsing) setRowHeight(event.nativeEvent.layout.height);
  };
  // Arriving, the card grows to its measured height, retargeting if its content settles mid-ease.
  // Collapsing, it holds its height until the row under it has measured, then eases to the row's.
  const wrapperHeight = arriving ? cardHeight : collapsing ? (rowHeight ?? cardHeight) : null;
  const onWrapperEased = arriving
    ? cardHeight > 0
      ? () => setArriving(false)
      : undefined
    : collapsing && rowHeight !== null
      ? () => setCollapsing(false)
      : undefined;

  return (
    <FeedRowHeight height={wrapperHeight} onEased={onWrapperEased} style={{ overflow: "hidden" }}>
      {showCard ? null : (
        <View key="row" onLayout={onRowLayout}>
          {row}
        </View>
      )}
      {showCard || collapsing ? (
        <NativeAnimated.View
          key="card"
          onLayout={onCardLayout}
          pointerEvents={collapsing ? "none" : "auto"}
          style={[
            { opacity: cardOpacity },
            // Out of flow, so the card lays out at its own height while the wrapper clips it.
            arriving || collapsing ? { position: "absolute", top: 0, left: 0, right: 0 } : null,
          ]}
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
                series,
              }}
              onApproving={setHeld}
              onAnswered={(decision) => {
                if (decision === "approve") setSettled(true);
              }}
            />
          </View>
        </NativeAnimated.View>
      ) : null}
    </FeedRowHeight>
  );
}

type ElevationItem = Extract<
  OrchestrationV2ProjectedTurnItem["item"],
  { readonly type: "elevation_request" }
>;

/**
 * A work-log row: "✓ Approved  python3 /home/…/deploy.py --wait". Tap for the reason, the whole command, how and when
 * it ended, and where it ran when that isn't the default.
 */
function ResolvedElevationRow(props: {
  readonly environmentId: EnvironmentId;
  readonly item: ElevationItem;
  readonly decoded: ReturnType<typeof decodeElevationRequestPayload> | null;
  readonly command: OrchestrationV2ProjectedTurnItem | undefined;
  readonly iconColor: ColorValue;
  readonly themeAppearance: "light" | "dark";
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
  const wasRunning = useRef(props.runActive);
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- fires a haptic when this row's approved command finishes
  useEffect(() => {
    if (wasRunning.current && !props.runActive && status.kind === "approved") {
      approvalHaptic("done");
    }
    wasRunning.current = props.runActive;
  }, [props.runActive, status.kind]);

  // Pending on another client: the request is answered there or from the banner.
  const pending = status.kind === "pending";
  const summary = elevationResolvedSummary(status.label, display);
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
          <WorkLogLabel>
            <Text className="text-foreground">{status.label}</Text>
            {display.short === "" ? null : (
              <Text className="font-mono text-xs">{`  ${display.short}`}</Text>
            )}
          </WorkLogLabel>
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
            {props.command === undefined ? null : (
              <ElevationCommandOutput
                environmentId={props.environmentId}
                command={props.command}
                themeAppearance={props.themeAppearance}
              />
            )}
          </Animated.View>
        ) : null}
      </Animated.View>
    </WorkLogBlock>
  );
}

/** The merged command's own output under the request's details, as its command row showed it. */
function ElevationCommandOutput(props: {
  readonly environmentId: EnvironmentId;
  readonly command: OrchestrationV2ProjectedTurnItem;
  readonly themeAppearance: "light" | "dark";
}) {
  const streams = useCommandOutputStreaming(props.environmentId);
  const fetched = useTurnItemDetail(
    streams ? null : { environmentId: props.environmentId, row: props.command },
  );
  const item = fetched.data?.item ?? props.command.item;
  const exitCode = item.type === "command_execution" ? item.exitCode : undefined;
  const text = streams
    ? null
    : (turnItemOutputText(item) ??
      (fetched.error
        ? `Couldn't load output: ${fetched.error}`
        : fetched.data === null
          ? "Loading output…"
          : fetched.data.item === null
            ? "Output is no longer available."
            : "No output."));
  return (
    <View>
      {streams ? (
        <ThreadCommandOutput
          environmentId={props.environmentId}
          threadId={props.command.sourceThreadId}
          itemId={props.command.sourceItemId}
          themeAppearance={props.themeAppearance}
        />
      ) : (
        <Text selectable className="pt-1.5 font-mono text-2xs leading-normal text-foreground-muted">
          {text}
        </Text>
      )}
      {exitCode ? (
        <Text className="mt-1.5 font-mono text-2xs leading-normal text-danger-foreground">
          exit {exitCode}
        </Text>
      ) : null}
    </View>
  );
}
