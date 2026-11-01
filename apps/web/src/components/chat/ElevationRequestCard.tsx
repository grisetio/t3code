import { useAtomValue } from "@effect/atom-react";
import {
  ELEVATION_APPROVE_ON_PHONE,
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
import { scopeThreadRef } from "@t3tools/client-runtime/environment";
import type {
  ElevationPayloadDecodeFailure,
  EnvironmentId,
  OrchestrationV2ProjectedTurnItem,
} from "@t3tools/contracts";
import * as Result from "effect/Result";
import {
  CheckIcon,
  ChevronRightIcon,
  ClockIcon,
  FileDiffIcon,
  MinusIcon,
  ShieldIcon,
  SmartphoneIcon,
  XIcon,
} from "lucide-react";
import { use, useState, type KeyboardEvent } from "react";

import { cn } from "~/lib/utils";
import { useDiffPanelStore } from "../../diffPanelStore";
import { useRightPanelStore } from "../../rightPanelStore";
import { useEnvironment } from "../../state/environments";
import { elevation } from "../../state/elevation";
import {
  ElevationAgentMark,
  useElevationAgent,
  type ElevationAgentView,
} from "../elevation/ElevationAgentMark";
import {
  ElevationComparisonCode,
  ElevationRequestFactLines,
} from "../elevation/ElevationRequestDetails";
import { useElevationDeny } from "../elevation/useElevationDeny";
import { Button } from "../ui/button";
import { TimelineRowActivityCtx, TimelineRowCtx } from "./timelineRowContext";
import { WorkLogDetails, WorkLogRow } from "./WorkLog";

const STATUS_ICONS = {
  pending: ShieldIcon,
  approved: CheckIcon,
  done: CheckIcon,
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
      <PendingElevationRequest
        environmentId={props.environmentId}
        item={item}
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
        summary={elevationResolvedSummary(status.label, item.explanation, command)}
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
      label={props.summary}
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

function DisclosureChevron(props: { readonly open: boolean }) {
  return (
    <span className="flex size-4 shrink-0 items-center justify-center" aria-hidden>
      <ChevronRightIcon
        className={cn(
          "size-3 shrink-0 text-icon-muted opacity-70 transition-transform duration-200",
          props.open && "rotate-90",
        )}
      />
    </span>
  );
}

function PendingElevationRequest(props: {
  readonly environmentId: EnvironmentId;
  readonly item: ElevationRequestItem;
  readonly agent: ElevationAgentView | null;
  readonly headline: string;
  readonly enrollKey: Uint8Array | null;
  readonly command: ElevationCommandDisplay;
  readonly facts: readonly ElevationRequestFact[];
  readonly warnings: readonly ElevationWarningView[];
  readonly decodeFailure: string | null;
}) {
  const { item, agent } = props;
  const canRespond = useAtomValue(elevation.respond.permissionAtom(props.environmentId));
  const deny = useElevationDeny();
  const machine = useEnvironment(props.environmentId)?.label ?? null;
  return (
    <div
      data-v2-item-type={item.type}
      className="flex min-w-0 flex-col gap-2 rounded-xl border border-border/60 bg-card p-4"
    >
      <p className="line-clamp-3 text-sm font-semibold break-words text-foreground">
        {props.headline}
      </p>
      {agent !== null || machine !== null ? (
        <p className="flex min-w-0 items-center gap-1.5 text-xs text-muted-foreground">
          {agent !== null ? <ElevationAgentMark agent={agent} /> : null}
          {agent !== null && machine !== null ? <span aria-hidden>·</span> : null}
          {machine !== null ? <span className="truncate">{machine}</span> : null}
        </p>
      ) : null}
      {props.enrollKey !== null ? (
        <ElevationComparisonCode publicKey={props.enrollKey} />
      ) : (
        <CommandDisclosure command={props.command} facts={props.facts} warnings={props.warnings} />
      )}
      {props.decodeFailure !== null ? (
        <p className="text-xs text-muted-foreground">{props.decodeFailure}</p>
      ) : null}
      {item.changes ? (
        <ChangesPointer
          environmentId={props.environmentId}
          threadId={item.threadId}
          changes={item.changes}
        />
      ) : null}
      {deny.error ? (
        <p role="alert" className="text-xs text-destructive">
          {deny.error}
        </p>
      ) : null}
      <div className="flex min-w-0 items-center justify-between gap-2">
        <p className="flex min-w-0 items-center gap-1.5 text-xs text-muted-foreground">
          <SmartphoneIcon className="size-3.5 shrink-0" aria-hidden />
          {ELEVATION_APPROVE_ON_PHONE}
        </p>
        <Button
          type="button"
          size="xs"
          variant="ghost-muted"
          disabled={!canRespond || deny.pending}
          onClick={() =>
            void deny.run({ environmentId: props.environmentId, requestId: item.requestId })
          }
        >
          Deny
        </Button>
      </div>
    </div>
  );
}

/** The short command as one quiet line; opens to the full command and non-default facts. */
function CommandDisclosure(props: {
  readonly command: ElevationCommandDisplay;
  readonly facts: readonly ElevationRequestFact[];
  readonly warnings: readonly ElevationWarningView[];
}) {
  const { command } = props;
  const [open, setOpen] = useState(false);
  const full = command.lines.join("\n");
  const expandable = full !== command.short || props.facts.length > 0 || props.warnings.length > 0;
  const line = <code className="min-w-0 truncate font-mono">{command.short}</code>;
  if (!expandable) {
    return (
      <p aria-label="Command" className="flex min-w-0 text-xs text-muted-foreground">
        {line}
      </p>
    );
  }
  return (
    <div className="flex min-w-0 flex-col gap-1.5 text-xs text-muted-foreground">
      <button
        type="button"
        aria-expanded={open}
        className="flex max-w-full min-w-0 items-center gap-1 self-start text-left hover:text-foreground"
        onClick={() => setOpen((current) => !current)}
      >
        {line}
        <DisclosureChevron open={open} />
      </button>
      {open ? (
        <>
          <code className="block font-mono break-all whitespace-pre-wrap">{full}</code>
          <ElevationRequestFactLines facts={props.facts} warnings={props.warnings} />
        </>
      ) : null}
    </div>
  );
}

/** The checkout's uncommitted changes when the request arrived; opens the diff panel. */
function ChangesPointer(props: {
  readonly environmentId: EnvironmentId;
  readonly threadId: ElevationRequestItem["threadId"];
  readonly changes: NonNullable<ElevationRequestItem["changes"]>;
}) {
  const { changes } = props;
  const openDiff = () => {
    const threadRef = scopeThreadRef(props.environmentId, props.threadId);
    useDiffPanelStore.getState().selectGitScope(threadRef, "unstaged");
    useRightPanelStore.getState().open(threadRef, "diff");
  };
  return (
    <button
      type="button"
      className="flex min-w-0 items-center gap-1.5 self-start text-xs text-muted-foreground hover:text-foreground"
      onClick={openDiff}
    >
      <FileDiffIcon className="size-3.5 shrink-0" aria-hidden />
      <span>Uncommitted changes</span>
      <span aria-hidden>·</span>
      <span>
        {changes.files} file{changes.files === 1 ? "" : "s"}
      </span>
      <span className="text-success">+{changes.additions}</span>
      <span className="text-destructive">−{changes.deletions}</span>
      <ChevronRightIcon className="size-3.5 shrink-0" aria-hidden />
    </button>
  );
}
