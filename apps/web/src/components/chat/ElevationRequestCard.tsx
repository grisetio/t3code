import { useAtomValue } from "@effect/atom-react";
import {
  decodeElevationRequestPayload,
  elevationDecodeFailureMessage,
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
import type {
  ElevationPayloadDecodeFailure,
  EnvironmentId,
  OrchestrationV2ProjectedTurnItem,
} from "@t3tools/contracts";
import * as Result from "effect/Result";
import { CheckIcon, ClockIcon, MinusIcon, ShieldIcon, XIcon } from "lucide-react";
import { use, useState, type KeyboardEvent } from "react";

import { elevation } from "../../state/elevation";
import { useElevationAgent } from "../elevation/ElevationAgentMark";
import { DisclosureChevron, ElevationPendingCard } from "../elevation/ElevationPendingCard";
import { ElevationRequestFactLines } from "../elevation/ElevationRequestDetails";
import { TimelineRowActivityCtx, TimelineRowCtx } from "./timelineRowContext";
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

/**
 * Matches the phone: a pending request is a card that leads with words, never the command; once
 * it ends it becomes a work-log row. Web can't sign, so approving happens on the phone; Deny
 * works here.
 */
export function ElevationRequestCard(props: {
  readonly environmentId: EnvironmentId;
  readonly item: ElevationRequestItem;
  readonly visibility: OrchestrationV2ProjectedTurnItem["visibility"];
}) {
  const { item } = props;
  const { activeTurnInProgress, latestRunId } = use(TimelineRowActivityCtx);
  const { workspaceRoot } = use(TimelineRowCtx);
  const agent = useElevationAgent(props.environmentId, item.threadId);
  // The turn item doesn't carry how many requests came before; the pending request does.
  const series = useAtomValue(elevation.pendingAcrossEnvironmentsAtom).find(
    (entry) =>
      entry.environmentId === props.environmentId && entry.request.requestId === item.requestId,
  )?.request.series;
  const runActive = activeTurnInProgress && item.runId !== null && item.runId === latestRunId;
  const status = elevationRequestStatusView(item, { finished: !runActive });
  const showCard = status.kind === "pending" && props.visibility === "local";
  // Only a row that replaced this card fades in; rows mounted by scrolling appear as they are.
  const [replacesCard] = useState(showCard);
  const { view, signed, decoded } = itemView(item);
  const command = elevationCommandDisplay(signed);
  const headline = elevationHeadline({
    explanation: item.explanation,
    decoded: decoded ?? UNSIGNED,
    agentName: agent?.name ?? null,
  });
  const facts = elevationRequestFacts(view, { cwd: workspaceRoot ?? null });
  if (showCard) {
    return (
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
      />
    );
  }
  return (
    <div
      className={
        replacesCard
          ? "motion-safe:transition-opacity motion-safe:duration-200 motion-safe:starting:opacity-0"
          : undefined
      }
    >
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
      />
    </div>
  );
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
          </div>
        </WorkLogDetails>
      ) : null}
    </WorkLogRow>
  );
}
