import { useAtomValue } from "@effect/atom-react";
import type { PendingElevationRequest } from "@t3tools/client-runtime/state/elevation";
import type { EnvironmentId } from "@t3tools/contracts";
import * as Result from "effect/Result";
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { View, type LayoutChangeEvent } from "react-native";
import Animated, {
  Easing,
  FadeIn,
  ReduceMotion,
  runOnJS,
  useAnimatedStyle,
  useSharedValue,
  withDelay,
  withTiming,
} from "react-native-reanimated";

import { SymbolView } from "../../components/ui/AppSymbol";
import { AppText as Text } from "../../components/ui/AppText";
import { cn } from "../../lib/cn";
import { appAtomRegistry } from "../../state/atom-registry";
import { elevation } from "../../state/elevation";
import { ElevationApprovalCard, useElevationRequestContext } from "./ElevationApprovalCard";
import { ELEVATION_SETTLE_MS } from "./elevationApproval";
import {
  claimedElevationRequestAtom,
  elevationListHighlightAtom,
  elevationListsOnScreenAtom,
  elevationLockScreenAtom,
  isClaimedElevationRequest,
} from "./elevationApprovalTarget";

const FADE_MS = 140;
const LEAVE_MS = 240;
const ENTER_MS = 220;
const HIGHLIGHT_DELAY_MS = 250;
const HIGHLIGHT_MS = 1200;

const keyOf = (entry: PendingElevationRequest) =>
  `${entry.environmentId}\u0000${entry.request.requestId}`;

/** Everything shown before, refreshed from `current`, then whatever `current` adds. */
function mergeShown(
  shown: readonly PendingElevationRequest[],
  current: readonly PendingElevationRequest[],
): readonly PendingElevationRequest[] {
  const currentByKey = new Map(current.map((entry) => [keyOf(entry), entry]));
  const kept = shown.map((entry) => currentByKey.get(keyOf(entry)) ?? entry);
  const keptKeys = new Set(kept.map(keyOf));
  const added = current.filter((entry) => !keptKeys.has(keyOf(entry)));
  if (added.length === 0 && kept.every((entry, index) => entry === shown[index])) return shown;
  return [...kept, ...added];
}

/**
 * Once `present` turns false, fades out and then eases its height to nothing, so the rows below
 * follow an empty space rather than a card cut off mid-line; then calls `onGone(id)`.
 */
function Leaving(props: {
  readonly id: string;
  readonly present: boolean;
  /** Stable, so a rerender doesn't restart the animation. */
  readonly onGone: (id: string) => void;
  readonly children: ReactNode;
}) {
  const height = useSharedValue(0);
  const opacity = useSharedValue(1);
  const progress = useSharedValue(1);
  const { id, present, onGone } = props;
  useEffect(() => {
    if (present) {
      opacity.set(1);
      progress.set(1);
      return;
    }
    opacity.set(withTiming(0, { duration: FADE_MS, reduceMotion: ReduceMotion.System }));
    progress.set(
      withDelay(
        FADE_MS,
        withTiming(
          0,
          {
            duration: LEAVE_MS,
            easing: Easing.inOut(Easing.quad),
            reduceMotion: ReduceMotion.System,
          },
          (finished) => {
            if (finished) runOnJS(onGone)(id);
          },
        ),
      ),
    );
  }, [id, present, onGone, opacity, progress]);
  const style = useAnimatedStyle(() =>
    opacity.get() < 1 ? { height: height.get() * progress.get(), opacity: opacity.get() } : {},
  );
  const onLayout = (event: LayoutChangeEvent) => {
    if (present) height.set(event.nativeEvent.layout.height);
  };
  return (
    <Animated.View
      className="overflow-hidden"
      entering={FadeIn.duration(ENTER_MS)}
      pointerEvents={present ? "auto" : "none"}
      style={style}
      onLayout={onLayout}
    >
      {props.children}
    </Animated.View>
  );
}

/** A ring that shows once and fades, so the request opened from the banner is easy to find. */
function Highlight(props: { readonly onDone: () => void }) {
  const opacity = useSharedValue(1);
  const { onDone } = props;
  useEffect(() => {
    opacity.set(
      withDelay(
        HIGHLIGHT_DELAY_MS,
        withTiming(0, { duration: HIGHLIGHT_MS, reduceMotion: ReduceMotion.System }, () =>
          runOnJS(onDone)(),
        ),
      ),
    );
  }, [onDone, opacity]);
  const style = useAnimatedStyle(() => ({ opacity: opacity.get() }));
  return (
    <Animated.View
      pointerEvents="none"
      className="absolute inset-0 rounded-[20px] border-2 border-primary"
      style={style}
    />
  );
}

/** Calls `onSettled(id)` once the card has said how its request ended for long enough to read. */
function Settle(props: { readonly id: string; readonly onSettled: (id: string) => void }) {
  const { id, onSettled } = props;
  useEffect(() => {
    const timer = setTimeout(() => onSettled(id), ELEVATION_SETTLE_MS);
    return () => clearTimeout(timer);
  }, [id, onSettled]);
  return null;
}

const clearHighlight = () => appAtomRegistry.set(elevationListHighlightAtom, null);

/** "{laptop} Killian's MacBook Pro", above that machine's requests. */
function MachineHeader(props: {
  readonly environmentId: EnvironmentId;
  readonly host: string | null;
  readonly sidebar: boolean;
}) {
  const { machine } = useElevationRequestContext(props.environmentId, null, props.host);
  return (
    <View
      accessibilityRole="header"
      className={cn("mb-2 mt-1 flex-row items-center gap-1.5", props.sidebar ? "px-3" : "px-5")}
    >
      <SymbolView
        name="laptopcomputer"
        size={13}
        tintColorClassName={props.sidebar ? "accent-drawer-foreground-muted" : "accent-icon-muted"}
        type="monochrome"
      />
      <Text
        numberOfLines={1}
        className={cn(
          "min-w-0 shrink text-sm",
          props.sidebar ? "text-drawer-foreground-muted" : "text-foreground-muted",
        )}
      >
        {machine}
      </Text>
    </View>
  );
}

/**
 * Requests no thread claims, at the top of a threads list under their machine's name. Every
 * agent runs in a thread, so these are T3's own or ones it couldn't place; the list is where
 * they wait instead of a screen of their own. `onScreen` says whether the user can see this
 * list, which keeps the banner from repeating them.
 */
export function ThreadlessElevationRequests(props: {
  readonly onScreen: boolean;
  readonly pane: "screen" | "sidebar";
  /** Scrolls the list to its top, so a highlighted card is in view. */
  readonly onReveal?: () => void;
}) {
  const all = useAtomValue(elevation.pendingAcrossEnvironmentsAtom);
  const endedByEnvironment = useAtomValue(elevation.endedAcrossEnvironmentsAtom);
  const claim = useAtomValue(claimedElevationRequestAtom);
  const lockScreen = useAtomValue(elevationLockScreenAtom);
  const highlight = useAtomValue(elevationListHighlightAtom);
  const current =
    lockScreen !== null
      ? []
      : all.filter(
          (entry) => entry.request.threadId === null && !isClaimedElevationRequest(claim, entry),
        );
  const currentKeys = new Set(current.map(keyOf));

  const { onScreen, onReveal } = props;
  useEffect(() => {
    if (!onScreen) return;
    appAtomRegistry.update(elevationListsOnScreenAtom, (count) => count + 1);
    return () => appAtomRegistry.update(elevationListsOnScreenAtom, (count) => count - 1);
  }, [onScreen]);

  // Approved here: "✓ Approved" stays a moment after the request leaves the pending list.
  const [held, setHeld] = useState<ReadonlySet<string>>(() => new Set());
  const hold = (key: string, active: boolean) =>
    setHeld((previous) => {
      if (previous.has(key) === active) return previous;
      const next = new Set(previous);
      if (active) next.add(key);
      else next.delete(key);
      return next;
    });

  // Ended elsewhere: the card says how ("✓ Approved on Pixel") for a moment, then leaves.
  const [settled, setSettled] = useState<ReadonlySet<string>>(() => new Set());
  const settle = useCallback(
    (key: string) => setSettled((previous) => new Set(previous).add(key)),
    [],
  );
  const endedOf = (entry: PendingElevationRequest) =>
    currentKeys.has(keyOf(entry))
      ? null
      : (endedByEnvironment
          .get(entry.environmentId)
          ?.find((ended) => ended.requestId === entry.request.requestId) ?? null);

  const [shown, setShown] = useState<readonly PendingElevationRequest[]>(current);
  const merged = mergeShown(shown, current);
  if (merged !== shown) setShown(merged);
  const forget = useCallback((gone: (key: string) => boolean) => {
    setShown((previous) => previous.filter((entry) => !gone(keyOf(entry))));
    setSettled((previous) => new Set([...previous].filter((key) => !gone(key))));
  }, []);
  const forgetRequest = useCallback((key: string) => forget((other) => other === key), [forget]);
  const forgetMachine = useCallback(
    (environmentId: string) => forget((key) => key.startsWith(`${environmentId}\u0000`)),
    [forget],
  );

  const highlighted =
    highlight === null
      ? null
      : (current.find(
          (entry) =>
            entry.environmentId === highlight.environmentId &&
            entry.request.requestId === highlight.requestId,
        ) ?? null);
  const revealed = useRef<typeof highlight>(null);
  useEffect(() => {
    if (!onScreen || highlight === null) return;
    if (highlighted === null) clearHighlight();
    else if (revealed.current !== highlight) {
      revealed.current = highlight;
      onReveal?.();
    }
  }, [onScreen, highlight, highlighted, onReveal]);

  if (merged.length === 0) return null;
  const sidebar = props.pane === "sidebar";
  const groups = new Map<EnvironmentId, PendingElevationRequest[]>();
  for (const entry of merged) {
    const group = groups.get(entry.environmentId);
    if (group === undefined) groups.set(entry.environmentId, [entry]);
    else group.push(entry);
  }
  const isPresent = (entry: PendingElevationRequest) =>
    currentKeys.has(keyOf(entry)) ||
    held.has(keyOf(entry)) ||
    (endedOf(entry) !== null && !settled.has(keyOf(entry)));

  return (
    <View>
      {[...groups].map(([environmentId, entries]) => {
        const groupPresent = entries.some(isPresent);
        const first = entries[0]!;
        return (
          <Leaving
            key={environmentId}
            id={environmentId}
            present={groupPresent}
            onGone={forgetMachine}
          >
            <MachineHeader
              environmentId={environmentId}
              host={Result.isSuccess(first.decoded) ? first.decoded.success.view.host : null}
              sidebar={sidebar}
            />
            {entries.map((entry) => {
              const key = keyOf(entry);
              const ended = endedOf(entry);
              const { request } = entry;
              return (
                <Leaving
                  key={key}
                  id={key}
                  // When the whole machine leaves, it eases away as one.
                  present={isPresent(entry) || !groupPresent}
                  onGone={forgetRequest}
                >
                  <View
                    className={cn(
                      "mb-3 rounded-[20px] border border-border bg-card-alt p-4",
                      sidebar ? "mx-1" : "mx-4",
                    )}
                  >
                    <ElevationApprovalCard
                      request={{
                        environmentId,
                        requestId: request.requestId,
                        threadId: null,
                        decoded: entry.decoded,
                        explanation: request.explanation,
                        changes: request.changes,
                        driver: request.driver,
                        raisedByT3: request.raisedByT3,
                        series: request.series,
                      }}
                      inMachineSection
                      ended={ended}
                      onApproving={(active) => hold(key, active)}
                      onAnswered={(decision) => {
                        if (decision === "approve") {
                          // Its "✓ Approved" was the settling moment; no second one.
                          setTimeout(() => {
                            settle(key);
                            hold(key, false);
                          }, ELEVATION_SETTLE_MS);
                        }
                      }}
                    />
                    {ended !== null && !held.has(key) ? (
                      <Settle id={key} onSettled={settle} />
                    ) : null}
                    {onScreen && highlighted !== null && keyOf(highlighted) === key ? (
                      <Highlight onDone={clearHighlight} />
                    ) : null}
                  </View>
                </Leaving>
              );
            })}
          </Leaving>
        );
      })}
    </View>
  );
}
