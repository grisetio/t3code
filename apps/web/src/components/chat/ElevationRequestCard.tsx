import { useAtomValue } from "@effect/atom-react";
import {
  decodeElevationRequestPayload,
  elevationCommandFinished,
  elevationDecodeFailureMessage,
  elevationEndedLine,
  elevationHeadline,
  elevationRequestFacts,
  elevationRequestFallbackView,
  elevationRequestStatusView,
  elevationResolvedSummary,
  type ElevationRequestFact,
  type ElevationRequestItem,
  type ElevationWarningView,
} from "@t3tools/client-runtime/elevation";
import {
  elevationCommandDisplay,
  type ElevationCommandDisplay,
} from "@t3tools/client-runtime/elevation-command";
import { scopeThreadRef, scopedThreadKey } from "@t3tools/client-runtime/environment";
import type {
  ElevationPayloadDecodeFailure,
  EnvironmentId,
  OrchestrationV2ProjectedTurnItem,
} from "@t3tools/contracts";
import * as Result from "effect/Result";
import { CheckIcon, ClockIcon, MinusIcon, ShieldIcon, XIcon } from "lucide-react";
import {
  use,
  useEffect,
  useEffectEvent,
  useLayoutEffect,
  useState,
  type KeyboardEvent,
  type ReactNode,
} from "react";
import { flushSync } from "react-dom";

import { elevation } from "../../state/elevation";
import { useElevationApproverHere } from "../../state/elevationApprover";
import { useElevationAgent } from "../elevation/ElevationAgentMark";
import { cn } from "~/lib/utils";
import { useMediaQuery } from "../../hooks/useMediaQuery";
import {
  DisclosureChevron,
  ELEVATION_ARRIVE_CLASS,
  ELEVATION_COLLAPSE_CLASS,
  ELEVATION_COLLAPSE_MS,
  ELEVATION_ROW_GROW_CLASS,
  ELEVATION_SETTLE_MS,
  ElevationPendingCard,
} from "../elevation/ElevationPendingCard";
import { useElevationHandoverStore } from "../elevation/elevationHandoverStore";
import { ElevationRequestFactLines } from "../elevation/ElevationRequestDetails";
import { TimelineRowActivityCtx, TimelineRowCtx } from "./timelineRowContext";
import { CommandItemOutput } from "./V2ItemInspector";
import { WorkLogDetails, WorkLogRow } from "./WorkLog";

const STATUS_ICONS = {
  pending: ShieldIcon,
  approved: CheckIcon,
  denied: XIcon,
  expired: ClockIcon,
  cancelled: MinusIcon,
} as const;

// The headline reads the payload only to name an enrollment, which an unsigned item never is.
const UNSIGNED: Result.Result<never, ElevationPayloadDecodeFailure> = Result.fail("invalid");

function itemView(item: ElevationRequestItem) {
  // Unsigned fallbacks never claim to be an enrollment.
  const fallback = { ...elevationRequestFallbackView(item), enroll: null };
  const unsigned = { command: { argv: item.argv } };
  if (item.payload === null) {
    return { view: fallback, signed: unsigned, decoded: null };
  }
  const decoded = decodeElevationRequestPayload(item.payload);
  return Result.isSuccess(decoded)
    ? { view: decoded.success.view, signed: decoded.success.payload, decoded }
    : { view: fallback, signed: unsigned, decoded };
}

// A card only grows in when it arrives while the thread is open; rows remount as they scroll in.
const FRESH_CARD_MS = 3_000;

/**
 * Matches the phone: a pending request is a card that leads with words, never the command; once
 * it ends it becomes a work-log row. A card seen ending says how for a moment, however it ended
 * (answered here or elsewhere, or expired), then collapses. The agent's command row the request
 * stands in for stays until then (`useElevationHandoverStore`), and the settled row replaces it in
 * the same commit that removes the card, so nothing around them moves. A turn that ended folds
 * then too, so the rows its fold hides close with the card.
 */
export function ElevationRequestCard(props: {
  readonly environmentId: EnvironmentId;
  readonly item: ElevationRequestItem;
  readonly visibility: OrchestrationV2ProjectedTurnItem["visibility"];
  /** `elevationLinkedCommandKey` of the agent's command row, if the server linked one. */
  readonly commandKey: string | null;
  /** The agent's command row this settled request stands in for, whose output it shows. */
  readonly command?: OrchestrationV2ProjectedTurnItem | undefined;
}) {
  const { item } = props;
  const { activeTurnInProgress, latestRunId, elevationFoldRunIds } = use(TimelineRowActivityCtx);
  const { workspaceRoot } = use(TimelineRowCtx);
  const agent = useElevationAgent(props.environmentId, item.threadId);
  // The turn item doesn't carry how many requests came before; the pending request does.
  const series = useAtomValue(elevation.pendingAcrossEnvironmentsAtom).find(
    (entry) =>
      entry.environmentId === props.environmentId && entry.request.requestId === item.requestId,
  )?.request.series;
  const runActive = activeTurnInProgress && item.runId !== null && item.runId === latestRunId;
  const here = useElevationApproverHere(props.environmentId);
  const status = elevationRequestStatusView(item, {
    finished: props.command === undefined ? !runActive : elevationCommandFinished(props.command),
    here,
  });
  const reduceMotion = useMediaQuery("(prefers-reduced-motion: reduce)");
  const pendingHere = status.kind === "pending" && props.visibility === "local";
  const [phase, setPhase] = useState<"card" | "collapsing" | "row">(pendingHere ? "card" : "row");
  const [arriving] = useState(
    () =>
      pendingHere &&
      !reduceMotion &&
      Date.now() - (item.startedAt ?? item.updatedAt).epochMilliseconds < FRESH_CARD_MS,
  );
  // With no command row to take over, the row opens as the card closes.
  const [rowGrows, setRowGrows] = useState(false);
  if (pendingHere && phase !== "card") setPhase("card");
  // No longer shown here, yet still pending: nothing to say, so no moment to say it.
  if (phase === "card" && !pendingHere && item.elevationStatus === "pending") setPhase("row");
  const settling = phase === "card" && !pendingHere;

  const cardKey = `${props.environmentId}\u0000${item.requestId}`;
  const threadKey = scopedThreadKey(scopeThreadRef(props.environmentId, item.threadId));
  const hold = useElevationHandoverStore((state) => state.hold);
  const fold = useElevationHandoverStore((state) => state.fold);
  const release = useElevationHandoverStore((state) => state.release);
  const onScreen = phase !== "row";
  const { commandKey } = props;
  useLayoutEffect(() => {
    if (!onScreen) return;
    hold(cardKey, { commandKey, runId: item.runId, threadKey });
    return () => release(cardKey);
  }, [onScreen, cardKey, commandKey, item.runId, threadKey, hold, release]);
  // One commit removes the card, shows its row and drops the command row it stands in for.
  const handOver = () =>
    flushSync(() => {
      setPhase("row");
      setRowGrows(false);
      release(cardKey);
    });
  const replacesCommand = props.command !== undefined;
  const foldsAfter = item.runId !== null && elevationFoldRunIds.has(item.runId);
  const endHold = useEffectEvent(() => {
    if (reduceMotion) return handOver();
    // A turn that ended folds as the card hands over: the rows it hides, the agent's command row
    // among them, close with the card while the row opens under the fold's header.
    if (foldsAfter) fold(cardKey);
    setRowGrows(foldsAfter || !replacesCommand);
    setPhase("collapsing");
  });
  const endCollapse = useEffectEvent(handOver);
  useEffect(() => {
    if (!settling) return;
    const timer = setTimeout(endHold, ELEVATION_SETTLE_MS);
    return () => clearTimeout(timer);
  }, [settling]);
  useEffect(() => {
    if (phase !== "collapsing") return;
    const timer = setTimeout(endCollapse, ELEVATION_COLLAPSE_MS);
    return () => clearTimeout(timer);
  }, [phase]);
  const { view, signed, decoded } = itemView(item);
  const command = elevationCommandDisplay(signed);
  const headline = elevationHeadline({
    explanation: item.explanation,
    decoded: decoded ?? UNSIGNED,
    agentName: agent?.name ?? null,
  });
  const facts = elevationRequestFacts(view, { cwd: workspaceRoot ?? null });
  const card =
    phase === "row" ? null : (
      <div
        key="card"
        inert={phase === "collapsing"}
        className={cn(
          "grid",
          phase === "collapsing"
            ? ELEVATION_COLLAPSE_CLASS
            : arriving
              ? ELEVATION_ARRIVE_CLASS
              : "grid-rows-[1fr]",
        )}
      >
        {/* The row's spacing collapses with the card: the command row it hands over to brings its own. */}
        <div className="min-h-0 overflow-hidden">
          <div className="pb-2">
            <ElevationPendingCard
              environmentId={props.environmentId}
              requestId={item.requestId}
              threadId={item.threadId}
              explanation={item.explanation}
              changes={item.changes ?? null}
              series={series}
              dataItemType={item.type}
              agent={agent}
              headline={headline}
              enrollKey={view.enroll?.publicKey ?? null}
              command={command}
              facts={facts}
              warnings={view.warnings}
              decodeFailure={
                decoded !== null && Result.isFailure(decoded)
                  ? elevationDecodeFailureMessage(decoded.failure)
                  : null
              }
              signable={
                decoded !== null && Result.isSuccess(decoded)
                  ? { bytes: decoded.success.bytes, keyIds: decoded.success.payload.keyIds }
                  : null
              }
              ended={
                item.elevationStatus === "pending"
                  ? null
                  : elevationEndedLine(
                      { elevationStatus: item.elevationStatus, resolvedBy: item.resolvedBy },
                      here,
                    )
              }
            />
          </div>
        </div>
      </div>
    );
  if (phase === "card") return card;
  if (phase === "collapsing" && !rowGrows) return card;
  const row = (
    <div key="row" className={rowGrows ? cn("grid", ELEVATION_ROW_GROW_CLASS) : undefined}>
      <div className={rowGrows ? "min-h-0 overflow-hidden" : undefined}>
        <div className="pb-2">
          <ElevationRequestRow
            item={item}
            icon={STATUS_ICONS[status.kind]}
            label={status.label}
            summary={elevationResolvedSummary(status.label, command)}
            headline={headline}
            command={command}
            how={status.kind === "pending" ? null : status.how}
            detail={status.kind === "pending" ? null : status.detail}
            facts={facts}
            warnings={view.warnings}
            output={
              props.command === undefined ? null : (
                <CommandItemOutput
                  projectedItem={props.command}
                  environmentId={props.environmentId}
                />
              )
            }
          />
        </div>
      </div>
    </div>
  );
  return card === null ? row : [card, row];
}

/** A work-log row like the tool rows around it: muted, one line, the details on click. */
function ElevationRequestRow(props: {
  readonly item: ElevationRequestItem;
  readonly icon: (typeof STATUS_ICONS)[keyof typeof STATUS_ICONS];
  readonly label: string;
  readonly summary: string;
  readonly headline: string;
  readonly command: ElevationCommandDisplay;
  readonly how: string | null;
  readonly detail: string | null;
  readonly facts: readonly ElevationRequestFact[];
  readonly warnings: readonly ElevationWarningView[];
  readonly output: ReactNode;
}) {
  const [expanded, setExpanded] = useState(false);
  const Icon = props.icon;
  const toggle = () => setExpanded((current) => !current);
  return (
    <WorkLogRow
      data-v2-item-type={props.item.type}
      role="button"
      tabIndex={0}
      aria-label={props.summary}
      aria-expanded={expanded}
      onClick={toggle}
      onKeyDown={(event: KeyboardEvent<HTMLDivElement>) => {
        if (event.target === event.currentTarget && (event.key === "Enter" || event.key === " ")) {
          event.preventDefault();
          toggle();
        }
      }}
      icon={<Icon className="size-4 shrink-0 text-icon-muted" aria-hidden />}
      label={
        <>
          <span className="text-foreground">{props.label}</span>
          {props.command.short === "" ? null : (
            <span className="ms-2 font-mono text-xs">{props.command.short}</span>
          )}
        </>
      }
      trailing={<DisclosureChevron open={expanded} />}
    >
      {expanded ? (
        <WorkLogDetails>
          <div className="flex min-w-0 flex-col gap-1.5 text-xs">
            <p className="text-sm break-words text-foreground">{props.headline}</p>
            <code className="block font-mono break-all whitespace-pre-wrap text-muted-foreground">
              {props.command.lines.join("\n")}
            </code>
            {props.how ? <p className="text-muted-foreground">{props.how}</p> : null}
            {props.detail ? <p className="text-muted-foreground">{props.detail}</p> : null}
            <ElevationRequestFactLines facts={props.facts} warnings={props.warnings} />
            {props.output}
          </div>
        </WorkLogDetails>
      ) : null}
    </WorkLogRow>
  );
}
