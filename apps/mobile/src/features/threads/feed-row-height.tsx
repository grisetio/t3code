import { useSyncLayout } from "@legendapp/list/react-native";
import {
  useEffect,
  useEffectEvent,
  useLayoutEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { View, type StyleProp, type ViewStyle } from "react-native";
import { useReducedMotion } from "react-native-reanimated";

/** How long a row's height takes to ease when no frame is capped. */
export const FEED_ROW_EASE_MS = 240;
/** dp per frame: about 21 px on a 2.6x screen, so a stalled frame slows the ease instead of jumping. */
const MAX_STEP = 8;

const easeInOutQuad = (t: number) => (t < 0.5 ? 2 * t * t : 1 - (-2 * t + 2) ** 2 / 2);

/**
 * A feed row's height, eased to `height` one React render per frame: LegendList measures a row in
 * the commit React renders it (`useSyncLayout`); a height set outside React reaches it a frame late.
 * `null` is the natural height; a number eases there from the last shown height. `onEased` runs in
 * the last step's render, and the children re-render once per change of `height`, not per step.
 */
export function FeedRowHeight(props: {
  readonly height: number | null;
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
    let start: number | null = null;
    let frame = requestAnimationFrame(function step(now) {
      start ??= now;
      const t = Math.min(1, (now - start) / FEED_ROW_EASE_MS);
      const gap = from + (to - from) * easeInOutQuad(t) - current.current;
      const next =
        t === 1 && Math.abs(to - current.current) <= MAX_STEP
          ? to
          : current.current + Math.max(-MAX_STEP, Math.min(MAX_STEP, gap));
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
