import { useSyncLayout } from "@legendapp/list/react-native";
import {
  useEffect,
  useEffectEvent,
  useLayoutEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { Easing, View, type StyleProp, type ViewStyle } from "react-native";
import { useReducedMotion } from "react-native-reanimated";

export interface FeedRowMotion {
  readonly durationMs: number;
  readonly easing: (t: number) => number;
}

// Both curves peak at about twice their average speed. Steeper ones (Material's standard and
// emphasized curves) move a sudo card's height 50-140 px in one 120 Hz frame and read as a jump.
/** Growing in: quick at first, then settling into place. */
export const FEED_ROW_ARRIVE: FeedRowMotion = { durationMs: 260, easing: Easing.out(Easing.quad) };
/** Closing up: gathers speed in a few frames, then slows into its end. */
export const FEED_ROW_COLLAPSE: FeedRowMotion = {
  durationMs: 250,
  // CSS's `ease`; React Native's `Easing.ease` is an ease-in.
  easing: Easing.bezier(0.25, 0.1, 0.25, 1),
};
/** The longest ease, when no frame stalls. */
export const FEED_ROW_EASE_MS = Math.max(FEED_ROW_ARRIVE.durationMs, FEED_ROW_COLLAPSE.durationMs);
// A step moves the ease on by the time since the last step, but by no more than a 60 Hz frame: a
// stalled JS frame then delays the rest of the ease instead of skipping part of it in one jump.
const MAX_FRAME_MS = 1000 / 60;

/**
 * A feed row's height, eased to `height` one React render per frame: LegendList measures a row in
 * the commit React renders it (`useSyncLayout`); a height set outside React reaches it a frame late.
 * `null` is the natural height; a number eases there from the last shown height. `onEased` runs in
 * the last step's render, and the children re-render once per change of `height`, not per step.
 */
export function FeedRowHeight(props: {
  readonly height: number | null;
  readonly motion: FeedRowMotion;
  readonly onEased?: (() => void) | undefined;
  readonly style?: StyleProp<ViewStyle>;
  readonly children: ReactNode;
}) {
  const triggerLayout = useSyncLayout();
  const reduceMotion = useReducedMotion();
  const laidOut = useRef(0);
  const current = useRef(props.height ?? 0);
  const [shown, setShown] = useState(props.height);
  const [target, setTarget] = useState(props.height);
  if (target !== props.height) {
    setTarget(props.height);
    // Leaving the natural height holds it in this render, so nothing moves before the first step.
    if (props.height === null) setShown(null);
    // oxlint-disable-next-line react/refs -- The row's last laid-out height comes from onLayout; holding it here keeps the row still until the first step.
    else if (shown === null) setShown(laidOut.current);
  }
  const onEased = useEffectEvent(() => props.onEased?.());
  const motion = useEffectEvent(() => props.motion);
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- reports each render's height to LegendList's synchronous layout pass
  useLayoutEffect(() => {
    current.current = shown ?? laidOut.current;
    // Any render may change the row's height, not only a step.
    triggerLayout();
  });
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- drives the per-frame requestAnimationFrame ease toward `height`
  useEffect(() => {
    const to = props.height;
    if (to === null) return;
    const from = current.current;
    if (reduceMotion || from === to) {
      current.current = to;
      setShown(to);
      onEased();
      return;
    }
    const { durationMs, easing } = motion();
    let elapsed = 0;
    let last = performance.now();
    let frame = requestAnimationFrame(function step() {
      const now = performance.now();
      elapsed += Math.min(now - last, MAX_FRAME_MS);
      last = now;
      const t = Math.min(1, elapsed / durationMs);
      const next = t === 1 ? to : from + (to - from) * easing(t);
      current.current = next;
      setShown(next);
      if (next === to) {
        onEased();
        return;
      }
      frame = requestAnimationFrame(step);
    });
    return () => cancelAnimationFrame(frame);
    // A caller that only now accepts the end (`onEased`) still needs to hear it.
  }, [props.height, props.onEased !== undefined, reduceMotion]);

  return (
    <View
      // Every layout, not only natural ones: an ease that ends at the natural height lays out
      // nothing new when it hands back, and leaving again has to start from where the row is.
      onLayout={(event) => {
        laidOut.current = event.nativeEvent.layout.height;
      }}
      style={[props.style, shown === null ? null : { height: shown, overflow: "hidden" }]}
    >
      {props.children}
    </View>
  );
}
