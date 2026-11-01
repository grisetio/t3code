import { useAtomValue } from "@effect/atom-react";
import {
  elevationDecodeFailureMessage,
  elevationHeadline,
  elevationRequestFacts,
} from "@t3tools/client-runtime/elevation";
import { elevationCommandDisplay } from "@t3tools/client-runtime/elevation-command";
import type { PendingElevationRequest } from "@t3tools/client-runtime/state/elevation";
import type { EnvironmentId } from "@t3tools/contracts";
import * as Result from "effect/Result";
import { LaptopIcon } from "lucide-react";
import { useEffect, useRef } from "react";

import { useEnvironment } from "../../state/environments";
import { elevation } from "../../state/elevation";
import { useElevationAgent } from "./ElevationAgentMark";
import { ElevationPendingCard } from "./ElevationPendingCard";
import { useElevationSidebarStore } from "./elevationSidebarStore";

// The ring's fade, plus a margin for the sidebar opening first.
const HIGHLIGHT_MS = 1500;

/**
 * Requests no thread claims, at the top of the thread list under their machine's name. Every
 * agent runs in a thread, so these are T3's own or ones it couldn't place. While this is in
 * view, their notices stay away.
 */
export function ThreadlessElevationRequests(props: { readonly onScreen: boolean }) {
  const pending = useAtomValue(elevation.pendingAcrossEnvironmentsAtom).filter(
    (entry) => entry.request.threadId === null,
  );
  const setListOnScreen = useElevationSidebarStore((state) => state.setListOnScreen);
  const highlight = useElevationSidebarStore((state) => state.highlight);
  const clearHighlight = useElevationSidebarStore((state) => state.clearHighlight);
  const { onScreen } = props;
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- registers this list as on screen in the sidebar store while mounted, so notices leave its requests to it
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
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- drops a highlight in the sidebar store once its request was answered before the list showed
  useEffect(() => {
    if (onScreen && highlightGone) clearHighlight();
  }, [onScreen, highlightGone, clearHighlight]);

  if (pending.length === 0) return null;
  const groups = new Map<EnvironmentId, PendingElevationRequest[]>();
  for (const entry of pending) {
    const group = groups.get(entry.environmentId);
    if (group === undefined) groups.set(entry.environmentId, [entry]);
    else group.push(entry);
  }
  return (
    <div className="flex flex-col gap-3 pb-3">
      {[...groups].map(([environmentId, entries]) => (
        <section
          key={environmentId}
          className="flex flex-col gap-2 motion-safe:transition-opacity motion-safe:duration-200 motion-safe:starting:opacity-0"
        >
          <MachineHeader environmentId={environmentId} />
          {entries.map((entry) => (
            <ThreadlessRequestCard
              key={entry.request.requestId}
              entry={entry}
              highlightable={onScreen}
            />
          ))}
        </section>
      ))}
    </div>
  );
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
  readonly highlightable: boolean;
}) {
  const { environmentId, request, decoded } = props.entry;
  const agent = useElevationAgent(environmentId, null, request.driver);
  const success = Result.isSuccess(decoded) ? decoded.success : null;
  const highlight = useElevationSidebarStore((state) => state.highlight);
  const clearHighlight = useElevationSidebarStore((state) => state.clearHighlight);
  const highlighted =
    props.highlightable &&
    highlight !== null &&
    highlight.environmentId === environmentId &&
    highlight.requestId === request.requestId;
  const ref = useRef<HTMLDivElement>(null);
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- scrolls the highlighted card into view and clears the highlight on a timer
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
        series={request.series}
        raisedByT3={request.raisedByT3}
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
