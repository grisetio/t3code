import { useAtomValue } from "@effect/atom-react";
import {
  elevationDecodeFailureMessage,
  elevationEndedLine,
  elevationHeadline,
  elevationRequestFacts,
} from "@t3tools/client-runtime/elevation";
import { elevationCommandDisplay } from "@t3tools/client-runtime/elevation-command";
import type { PendingElevationRequest } from "@t3tools/client-runtime/state/elevation";
import type { ElevationEndedRequest, EnvironmentId } from "@t3tools/contracts";
import * as Result from "effect/Result";
import { LaptopIcon } from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";

import { cn } from "~/lib/utils";
import { useStableCallback } from "../../hooks/useStableCallback";
import { useEnvironment } from "../../state/environments";
import { elevation } from "../../state/elevation";
import { useElevationApproverHere } from "../../state/elevationApprover";
import { useElevationAgent } from "./ElevationAgentMark";
import { ELEVATION_SETTLE_MS, ElevationPendingCard } from "./ElevationPendingCard";
import { useElevationSidebarStore } from "./elevationSidebarStore";

// The ring's fade, plus a margin for the sidebar opening first.
const HIGHLIGHT_MS = 1500;
const FADE_MS = 140;
const LEAVE_MS = 240;

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
 * Once `open` turns false, fades out and then eases its height to nothing, so the rows below
 * follow an empty space rather than a card cut off mid-line; then calls `onGone(id)`.
 */
function Leaving(props: {
  readonly id: string;
  readonly open: boolean;
  /** Stable, so a rerender doesn't restart the timer. */
  readonly onGone: (id: string) => void;
  readonly children: ReactNode;
}) {
  const { id, open, onGone } = props;
  useEffect(() => {
    if (open) return;
    const timer = setTimeout(() => onGone(id), FADE_MS + LEAVE_MS);
    return () => clearTimeout(timer);
  }, [id, open, onGone]);
  // The rows wait for the fade, so the space closes only once it is empty.
  return (
    <div
      inert={!open}
      className={cn(
        "grid min-w-0 transition-[grid-template-rows] duration-240 ease-in-out motion-reduce:transition-none",
        open ? "grid-rows-[1fr]" : "grid-rows-[0fr] delay-140",
      )}
    >
      <div
        className={cn(
          "min-h-0 overflow-hidden transition-opacity duration-140 ease-out motion-reduce:transition-none",
          open ? "opacity-100" : "opacity-0",
        )}
      >
        {props.children}
      </div>
    </div>
  );
}

/**
 * Requests no thread claims, at the top of the thread list under their machine's name. Every
 * agent runs in a thread, so these are T3's own or ones it couldn't place. While this is in
 * view, their notices stay away.
 */
export function ThreadlessElevationRequests(props: { readonly onScreen: boolean }) {
  const claimed = useElevationSidebarStore((state) => state.claimed);
  const pending = useAtomValue(elevation.pendingAcrossEnvironmentsAtom).filter(
    (entry) => entry.request.threadId === null && claimed?.(entry) !== true,
  );
  const endedByEnvironment = useAtomValue(elevation.endedAcrossEnvironmentsAtom);
  const currentKeys = new Set(pending.map(keyOf));
  const [shown, setShown] = useState<readonly PendingElevationRequest[]>(pending);
  const merged = mergeShown(shown, pending);
  if (merged !== shown) setShown(merged);
  // Ended elsewhere: the card says how for a moment, then leaves.
  const [settled, setSettled] = useState<ReadonlySet<string>>(() => new Set());
  // Stable, so the timers in Settle and Leaving don't restart on every render.
  const settle = useStableCallback((key: string) =>
    setSettled((previous) => new Set(previous).add(key)),
  );
  const forget = (gone: (key: string) => boolean) => {
    setShown((previous) => previous.filter((entry) => !gone(keyOf(entry))));
    setSettled((previous) => new Set([...previous].filter((key) => !gone(key))));
  };
  const forgetRequest = useStableCallback((key: string) => forget((other) => other === key));
  const forgetMachine = useStableCallback((environmentId: string) =>
    forget((key) => key.startsWith(`${environmentId}\u0000`)),
  );
  const endedOf = (entry: PendingElevationRequest) =>
    currentKeys.has(keyOf(entry))
      ? null
      : (endedByEnvironment
          .get(entry.environmentId)
          ?.find((ended) => ended.requestId === entry.request.requestId) ?? null);
  const isPresent = (entry: PendingElevationRequest) =>
    currentKeys.has(keyOf(entry)) || (endedOf(entry) !== null && !settled.has(keyOf(entry)));
  const setListOnScreen = useElevationSidebarStore((state) => state.setListOnScreen);
  const highlight = useElevationSidebarStore((state) => state.highlight);
  const clearHighlight = useElevationSidebarStore((state) => state.clearHighlight);
  const { onScreen } = props;
  useEffect(() => {
    setListOnScreen(onScreen);
    return () => setListOnScreen(false);
  }, [onScreen, setListOnScreen]);
  // Answered before the sidebar opened: nothing to point at.
  const highlightGone =
    highlight !== null &&
    !pending.some(
      (entry) =>
        entry.environmentId === highlight.environmentId &&
        entry.request.requestId === highlight.requestId,
    );
  useEffect(() => {
    if (onScreen && highlightGone) clearHighlight();
  }, [onScreen, highlightGone, clearHighlight]);

  if (merged.length === 0) return null;
  const groups = new Map<EnvironmentId, PendingElevationRequest[]>();
  for (const entry of merged) {
    const group = groups.get(entry.environmentId);
    if (group === undefined) groups.set(entry.environmentId, [entry]);
    else group.push(entry);
  }
  return (
    // Spacing lives inside what collapses, so nothing is left to jump once a card is gone.
    <div className="flex flex-col">
      {[...groups].map(([environmentId, entries]) => {
        const groupPresent = entries.some(isPresent);
        return (
          <Leaving
            key={environmentId}
            id={environmentId}
            open={groupPresent}
            onGone={forgetMachine}
          >
            <section className="flex flex-col pb-3 motion-safe:transition-opacity motion-safe:duration-200 motion-safe:starting:opacity-0">
              <MachineHeader environmentId={environmentId} />
              {entries.map((entry) => {
                const key = keyOf(entry);
                const ended = endedOf(entry);
                return (
                  <Leaving
                    key={key}
                    id={key}
                    // When the whole machine leaves, it eases away as one.
                    open={isPresent(entry) || !groupPresent}
                    onGone={forgetRequest}
                  >
                    <div className="pt-2">
                      <ThreadlessRequestCard entry={entry} ended={ended} highlightable={onScreen} />
                    </div>
                    {ended !== null ? <Settle id={key} onSettled={settle} /> : null}
                  </Leaving>
                );
              })}
            </section>
          </Leaving>
        );
      })}
    </div>
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

function MachineHeader(props: { readonly environmentId: EnvironmentId }) {
  const machine = useEnvironment(props.environmentId)?.label ?? "this machine";
  return (
    <h3 className="flex min-w-0 items-center gap-1.5 px-2 text-xs font-normal text-muted-foreground">
      <LaptopIcon className="size-3.5 shrink-0" aria-hidden />
      <span className="truncate">{machine}</span>
    </h3>
  );
}

function ThreadlessRequestCard(props: {
  readonly entry: PendingElevationRequest;
  readonly ended: ElevationEndedRequest | null;
  readonly highlightable: boolean;
}) {
  const { environmentId, request, decoded } = props.entry;
  const agent = useElevationAgent(environmentId, null, request.driver);
  const success = Result.isSuccess(decoded) ? decoded.success : null;
  const here = useElevationApproverHere(environmentId);
  const highlight = useElevationSidebarStore((state) => state.highlight);
  const clearHighlight = useElevationSidebarStore((state) => state.clearHighlight);
  const highlighted =
    props.highlightable &&
    highlight !== null &&
    highlight.environmentId === environmentId &&
    highlight.requestId === request.requestId;
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!highlighted) return;
    ref.current?.scrollIntoView({ block: "nearest", behavior: "smooth" });
    const timer = setTimeout(clearHighlight, HIGHLIGHT_MS);
    return () => clearTimeout(timer);
  }, [highlighted, clearHighlight]);
  return (
    <div ref={ref} className="relative">
      <ElevationPendingCard
        environmentId={environmentId}
        requestId={request.requestId}
        threadId={null}
        explanation={request.explanation}
        agent={agent}
        headline={elevationHeadline({
          explanation: request.explanation,
          decoded,
          agentName: agent?.name ?? null,
        })}
        enrollKey={success?.view.enroll?.publicKey ?? null}
        command={success === null ? null : elevationCommandDisplay(success.payload)}
        facts={success === null ? [] : elevationRequestFacts(success.view, { cwd: null })}
        warnings={success?.view.warnings ?? []}
        decodeFailure={
          Result.isFailure(decoded) ? elevationDecodeFailureMessage(decoded.failure) : null
        }
        changes={null}
        signable={
          success === null ? null : { bytes: success.bytes, keyIds: success.payload.keyIds }
        }
        series={request.series}
        raisedByT3={request.raisedByT3}
        ended={props.ended === null ? null : elevationEndedLine(props.ended, here)}
        inMachineSection
      />
      {highlighted ? (
        // Shown once: the ring starts lit and fades as it mounts.
        <span
          aria-hidden
          className="pointer-events-none absolute inset-0 rounded-xl ring-2 ring-transparent transition-shadow duration-1200 ease-out starting:ring-primary"
        />
      ) : null}
    </div>
  );
}
