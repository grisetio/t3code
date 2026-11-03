import { useAtomValue } from "@effect/atom-react";
import { elevationCommandRowKey } from "@t3tools/client-runtime/elevation";
import type { OrchestrationV2ProjectedTurnItem } from "@t3tools/contracts";
import { Atom } from "effect/reactivity";
import { useEffect, type ReactNode } from "react";
import { Animated as NativeAnimated, useAnimatedValue } from "react-native";
import { useReducedMotion } from "react-native-reanimated";

import { appAtomRegistry } from "../../state/atom-registry";
import { FeedRowHeight } from "../threads/feed-row-height";

/**
 * Command rows a sudo request still stands beside, by `elevationCommandRowKey`: "held" while the
 * request waits or its card shows, "leaving" while the row eases out. The feed keeps these rows,
 * so a row leaves at no height instead of dropping out of the list in one frame.
 */
export const elevationHandoversAtom = Atom.make<ReadonlyMap<string, "held" | "leaving">>(
  new Map(),
).pipe(Atom.keepAlive);

/** The keys alone: they change only as rows join or leave, not as a row starts leaving. */
export const elevationHandoverKeysAtom = Atom.make((get) =>
  [...get(elevationHandoversAtom).keys()].join("\n"),
);

const elevationCommandLeavingAtom = Atom.family((commandKey: string) =>
  Atom.make((get) => get(elevationHandoversAtom).get(commandKey) === "leaving"),
);

export function setElevationHandover(commandKey: string, phase: "held" | "leaving" | null) {
  const current = appAtomRegistry.get(elevationHandoversAtom);
  if ((current.get(commandKey) ?? null) === phase) return;
  const next = new Map(current);
  if (phase === null) next.delete(commandKey);
  else next.set(commandKey, phase);
  appAtomRegistry.set(elevationHandoversAtom, next);
}

const FADE_MS = 140;

/** An agent's command row a sudo request stands in for: it fades and eases to no height, then the feed drops it. */
export function ElevationCommandRowExit(props: {
  readonly commandRow: OrchestrationV2ProjectedTurnItem;
  readonly children: ReactNode;
}) {
  const commandKey = elevationCommandRowKey(props.commandRow);
  const leaving = useAtomValue(elevationCommandLeavingAtom(commandKey));
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
      onEased={leaving ? () => setElevationHandover(commandKey, null) : undefined}
    >
      <NativeAnimated.View style={{ opacity }}>{props.children}</NativeAnimated.View>
    </FeedRowHeight>
  );
}
