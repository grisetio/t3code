import { useAtomValue } from "@effect/atom-react";
import {
  ELEVATION_APPROVE_ON_PHONE,
  decodeElevationRequestPayload,
  elevationHeadline,
  elevationReason,
  elevationRequestFallbackView,
  elevationRequestStatusView,
  type ElevationRequestItem,
} from "@t3tools/client-runtime/elevation";
import {
  elevationCommandDisplay,
  elevationCommandMoreLabel,
  elevationCommandOneLine,
  type ElevationCommandDisplay,
} from "@t3tools/client-runtime/elevation-command";
import { scopeThreadRef } from "@t3tools/client-runtime/environment";
import type { EnvironmentId, OrchestrationV2ProjectedTurnItem } from "@t3tools/contracts";
import * as Result from "effect/Result";
import {
  CheckIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  ClockIcon,
  FileDiffIcon,
  MinusIcon,
  ShieldIcon,
  SmartphoneIcon,
  TriangleAlertIcon,
  XIcon,
} from "lucide-react";
import { use, useState } from "react";

import { useDiffPanelStore } from "../../diffPanelStore";
import { useRightPanelStore } from "../../rightPanelStore";
import { useEnvironments } from "../../state/environments";
import { elevation } from "../../state/elevation";
import { ElevationAgentMark, useElevationAgent } from "../elevation/ElevationAgentMark";
import {
  ElevationComparisonCode,
  ElevationTechnicalDetails,
} from "../elevation/ElevationRequestDetails";
import { useElevationDeny } from "../elevation/useElevationDeny";
import { Button } from "../ui/button";
import { TimelineRowActivityCtx } from "./timelineRowContext";
import { WorkLogDetails, WorkLogRow } from "./WorkLog";

const STATUS_ICONS = {
  pending: ShieldIcon,
  approved: CheckIcon,
  done: CheckIcon,
  denied: XIcon,
  expired: ClockIcon,
  cancelled: MinusIcon,
} as const;

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
 * Matches the phone's card: the headline, then who and where, the command, and the checkout's
 * uncommitted changes. Web can't sign, so approving happens on the phone; Deny works here.
 */
export function ElevationRequestCard(props: {
  readonly environmentId: EnvironmentId;
  readonly item: ElevationRequestItem;
  readonly visibility: OrchestrationV2ProjectedTurnItem["visibility"];
}) {
  const { item } = props;
  const { activeTurnInProgress, latestRunId } = use(TimelineRowActivityCtx);
  const runActive = activeTurnInProgress && item.runId !== null && item.runId === latestRunId;
  const status = elevationRequestStatusView(item, { finished: !runActive });
  const [expanded, setExpanded] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const { view, signed, decoded } = itemView(item);
  const command = elevationCommandDisplay(signed);
  if (status.kind === "pending" && props.visibility === "local") {
    return (
      <PendingElevationRequest
        environmentId={props.environmentId}
        item={item}
        view={view}
        command={command}
        decoded={decoded}
      />
    );
  }
  const Icon = STATUS_ICONS[status.kind];
  const oneLine = elevationCommandOneLine(command);
  if (status.kind === "pending") {
    return (
      <WorkLogRow
        data-v2-item-type={item.type}
        icon={<Icon className="size-3.5 text-icon-muted" aria-hidden />}
        label={
          <>
            {status.label} <code className="font-mono text-muted-foreground">{oneLine}</code>
          </>
        }
      />
    );
  }
  return (
    <WorkLogRow
      data-v2-item-type={item.type}
      icon={<Icon className="size-3.5 text-icon-muted" aria-hidden />}
      label={
        <>
          {status.label} <code className="font-mono text-muted-foreground">{oneLine}</code>
        </>
      }
      trailing={
        <span className="shrink-0 text-xs text-muted-foreground tabular-nums">{status.time}</span>
      }
      aria-expanded={expanded}
      onClick={() => setExpanded((current) => !current)}
    >
      {expanded ? (
        <WorkLogDetails>
          <div className="flex min-w-0 flex-col gap-1.5 text-xs">
            <AskedLine
              environmentId={props.environmentId}
              threadId={item.threadId}
              explanation={item.explanation}
            />
            <code className="block font-mono break-all whitespace-pre-wrap text-foreground">
              {command.lines.join("\n")}
            </code>
            <p className="text-muted-foreground">{status.how}</p>
            {status.detail ? <p className="text-muted-foreground">{status.detail}</p> : null}
            <button
              type="button"
              aria-expanded={detailsOpen}
              className="flex items-center gap-1 self-start text-muted-foreground hover:text-foreground"
              onClick={(event) => {
                event.stopPropagation();
                setDetailsOpen((open) => !open);
              }}
            >
              Details
              {view.warnings.length > 0 ? (
                <TriangleAlertIcon className="size-3 shrink-0" aria-hidden />
              ) : null}
              <ChevronDownIcon
                className={detailsOpen ? "size-3 shrink-0 rotate-180" : "size-3 shrink-0"}
                aria-hidden
              />
            </button>
            {detailsOpen ? <ElevationTechnicalDetails view={view} /> : null}
          </div>
        </WorkLogDetails>
      ) : null}
    </WorkLogRow>
  );
}

/** "Claude: “reason”", or whichever of the two is known. */
function AskedLine(props: {
  readonly environmentId: EnvironmentId;
  readonly threadId: ElevationRequestItem["threadId"];
  readonly explanation: string | null;
}) {
  const name = useElevationAgent(props.environmentId, props.threadId)?.name ?? null;
  const reason = elevationReason(props.explanation);
  const text = reason === null ? name : name === null ? `“${reason}”` : `${name}: “${reason}”`;
  return text === null ? null : <p className="break-words text-muted-foreground">{text}</p>;
}

function PendingElevationRequest(props: {
  readonly environmentId: EnvironmentId;
  readonly item: ElevationRequestItem;
  readonly view: ReturnType<typeof itemView>["view"];
  readonly command: ElevationCommandDisplay;
  readonly decoded: ReturnType<typeof itemView>["decoded"];
}) {
  const { item, view } = props;
  const canRespond = useAtomValue(elevation.respond.permissionAtom(props.environmentId));
  const deny = useElevationDeny();
  const { environments } = useEnvironments();
  const hasAgent = useElevationAgent(props.environmentId, item.threadId) !== null;
  const machine =
    environments.find((environment) => environment.environmentId === props.environmentId)?.label ??
    view.host;
  const enroll = view.enroll;
  // No payload was built: the reason leads, else the command the server mirrored.
  const reason = elevationReason(item.explanation);
  const headline =
    props.decoded !== null
      ? elevationHeadline({ explanation: item.explanation, decoded: props.decoded })
      : reason !== null
        ? { text: `“${reason}”`, command: false }
        : { text: props.command.collapsed, command: true };
  return (
    <div
      data-v2-item-type={item.type}
      className="flex min-w-0 flex-col gap-2 rounded-xl border border-border/60 bg-card p-4"
    >
      {headline.command ? (
        <CommandLine command={props.command} lead />
      ) : (
        <p className="text-sm font-medium break-words text-foreground">{headline.text}</p>
      )}
      <p className="flex min-w-0 items-center gap-1.5 text-xs text-muted-foreground">
        {hasAgent ? (
          <>
            <ElevationAgentMark environmentId={props.environmentId} threadId={item.threadId} />
            <span aria-hidden>·</span>
          </>
        ) : null}
        <span className="truncate">{machine}</span>
      </p>
      {enroll ? (
        <ElevationComparisonCode publicKey={enroll.publicKey} />
      ) : headline.command ? null : (
        <CommandLine command={props.command} />
      )}
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

/** Whitespace-collapsed, two rows at most; hidden text expands on click. */
function CommandLine(props: {
  readonly command: ElevationCommandDisplay;
  readonly lead?: boolean;
}) {
  const { command } = props;
  const [open, setOpen] = useState(false);
  const more = elevationCommandMoreLabel(command);
  const expandable = more !== null;
  const text = (
    <>
      <code
        className={
          open
            ? "block font-mono break-all whitespace-pre-wrap"
            : "line-clamp-2 font-mono break-all"
        }
      >
        {open ? command.lines.join("\n") : command.collapsed}
      </code>
      {expandable && !open ? <span className="text-muted-foreground">{more}</span> : null}
    </>
  );
  // A quiet box, as on the phone.
  const className = props.lead
    ? "flex min-w-0 flex-col gap-0.5 rounded-lg border border-border/60 bg-muted/40 px-2.5 py-1.5 text-left text-sm text-foreground"
    : "flex min-w-0 flex-col gap-0.5 rounded-lg border border-border/60 bg-muted/40 px-2.5 py-1.5 text-left text-xs text-foreground/80";
  return expandable ? (
    <button
      type="button"
      aria-expanded={open}
      className={className}
      onClick={() => setOpen((current) => !current)}
    >
      {text}
    </button>
  ) : (
    <div aria-label="Command" className={className}>
      {text}
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
