import { useAtomValue } from "@effect/atom-react";
import { elevationCommandRowKey } from "@t3tools/client-runtime/elevation";
import type { OrchestrationV2ProjectedTurnItem } from "@t3tools/contracts";
import { Atom } from "effect/reactivity";
import { useEffect, useState, type ReactNode } from "react";
import { Animated as NativeAnimated, useAnimatedValue } from "react-native";
import { useReducedMotion } from "react-native-reanimated";

import { appAtomRegistry } from "../../state/atom-registry";
import { FEED_ROW_COLLAPSE, FeedRowHeight } from "../threads/feed-row-height";

type ElevationHandover = "held" | "leaving" | "left";

/**
 * Command rows a sudo request stands beside, by `elevationCommandRowKey`. The feed keeps them so
 * a row eases out ("leaving") to no height ("left") instead of dropping out in one frame. The card
 * drops the entry after its own collapse, as that rebuilds the feed and must not land mid-ease.
 */
export const elevationHandoversAtom = Atom.make<ReadonlyMap<string, ElevationHandover>>(
  new Map(),
).pipe(Atom.keepAlive);

/** The keys alone: they change only as rows join or leave, not as a row starts leaving. */
export const elevationHandoverKeysAtom = Atom.make((get) =>
  [...get(elevationHandoversAtom).keys()].join("\n"),
);

const elevationCommandPhaseAtom = Atom.family((commandKey: string) =>
  Atom.make((get) => get(elevationHandoversAtom).get(commandKey) ?? null),
);

/** The command row linked to this request has eased out to no height. */
export function useElevationCommandLeft(commandKey: string | null): boolean {
  return useAtomValue(elevationCommandPhaseAtom(commandKey ?? "")) === "left";
}

export function setElevationHandover(commandKey: string, phase: ElevationHandover | null) {
  const current = appAtomRegistry.get(elevationHandoversAtom);
  const previous = current.get(commandKey) ?? null;
  // The card keeps asking for "leaving" until it has collapsed; a row already gone stays gone.
  if (previous === phase || (phase === "leaving" && previous === "left")) return;
  const next = new Map(current);
  if (phase === null) next.delete(commandKey);
  else next.set(commandKey, phase);
  appAtomRegistry.set(elevationHandoversAtom, next);
}

const FADE_MS = 140;

/** An agent's command row a sudo request stands in for: it fades and eases to no height, then the feed drops it once the card has collapsed. */
export function ElevationCommandRowExit(props: {
  readonly commandRow: OrchestrationV2ProjectedTurnItem;
  readonly children: ReactNode;
}) {
  const commandKey = elevationCommandRowKey(props.commandRow);
  const phase = useAtomValue(elevationCommandPhaseAtom(commandKey));
  // A row that has left stays at no height once its entry is dropped: the feed's rebuild without it
  // can land a frame after this row hears the drop, and the row must not show again meanwhile.
  const [gone, setGone] = useState(false);
  if (phase === "left" && !gone) setGone(true);
  if (phase === "held" && gone) setGone(false);
  const leaving = phase === "leaving" || phase === "left" || gone;
  const reduceMotion = useReducedMotion();
  const opacity = useAnimatedValue(1);
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- starts the native-driver fade as the row starts leaving
  useEffect(() => {
    if (!leaving) return;
    NativeAnimated.timing(opacity, {
      toValue: 0,
      duration: reduceMotion ? 0 : FADE_MS,
      useNativeDriver: true,
    }).start();
  }, [leaving, opacity, reduceMotion]);
  return (
    // A row that mounts already leaving was never seen: it starts at no height and leaves at once.
    <FeedRowHeight
      height={leaving ? 0 : null}
      // The card under it collapses on the same curve, so the rows above move on one curve.
      motion={FEED_ROW_COLLAPSE}
      onEased={phase === "leaving" ? () => setElevationHandover(commandKey, "left") : undefined}
    >
      {/* The row's content leaves with it: its layout transition starts once the row is at no
          height, and a running transition commits on the UI thread every frame. Such a commit
          can mount the card's next step before the feed has moved the rows around it. */}
      {gone ? null : (
        <NativeAnimated.View style={{ opacity }}>{props.children}</NativeAnimated.View>
      )}
    </FeedRowHeight>
  );
}
