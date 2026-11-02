import { useAtomValue } from "@effect/atom-react";
import {
  ELEVATION_APPROVE_ON_PHONE,
  elevationAgoRefreshMs,
  elevationRequestSource,
  elevationSeriesLine,
  type ElevationEndedView,
  type ElevationRequestFact,
  type ElevationWarningView,
} from "@t3tools/client-runtime/elevation";
import type { ElevationCommandDisplay } from "@t3tools/client-runtime/elevation-command";
import { scopeThreadRef } from "@t3tools/client-runtime/environment";
import type {
  ElevationPendingRequest,
  ElevationRequestId,
  ElevationRequestSeries,
  EnvironmentId,
  ThreadId,
} from "@t3tools/contracts";
import {
  CheckIcon,
  ChevronRightIcon,
  ClockIcon,
  FileDiffIcon,
  MinusIcon,
  RotateCwIcon,
  SmartphoneIcon,
  XIcon,
} from "lucide-react";
import { useEffect, useState } from "react";

import { cn } from "~/lib/utils";
import { useDiffPanelStore } from "../../diffPanelStore";
import { useRightPanelStore } from "../../rightPanelStore";
import { useEnvironment } from "../../state/environments";
import { elevation } from "../../state/elevation";
import { Button } from "../ui/button";
import { ElevationAgentMark, type ElevationAgentView } from "./ElevationAgentMark";
import { ElevationComparisonCode, ElevationRequestFactLines } from "./ElevationRequestDetails";
import { useElevationDeny } from "./useElevationDeny";

export function DisclosureChevron(props: { readonly open: boolean }) {
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

/** The current time, kept fresh enough for an "ago" measured from `since`. */
function useElevationNow(since: number | null): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (since === null) return;
    const timer = setTimeout(() => setNow(Date.now()), elevationAgoRefreshMs(since, now));
    return () => clearTimeout(timer);
  }, [since, now]);
  return now;
}

/** "2nd request this turn · first approved 4 s ago", from the second request of a turn on. */
function ElevationSeriesLine(props: {
  readonly series: ElevationRequestSeries;
  readonly threadId: ThreadId | null;
}) {
  const now = useElevationNow(props.series.first.resolvedAt?.epochMilliseconds ?? null);
  const line = elevationSeriesLine(props.series, props.threadId, now);
  return (
    // Wraps rather than cuts: the end of the line says how the first one went.
    <p className="flex min-w-0 items-start gap-1.5 text-xs text-muted-foreground">
      <RotateCwIcon className="mt-0.5 size-3 shrink-0" aria-hidden />
      <span className="min-w-0 break-words">
        <span className="font-medium text-foreground">{line.ordinal}</span>
        {line.rest}
      </span>
    </p>
  );
}

/**
 * A pending request as a card that leads with words, never the command, like the phone's. Web
 * can't sign, so approving happens on the phone; Deny works here.
 */
export function ElevationPendingCard(props: {
  readonly environmentId: EnvironmentId;
  readonly requestId: ElevationRequestId;
  readonly threadId: ThreadId | null;
  readonly explanation: string | null;
  readonly agent: ElevationAgentView | null;
  readonly headline: string;
  readonly enrollKey: Uint8Array | null;
  /** Null when the payload couldn't be read; `decodeFailure` says why. */
  readonly command: ElevationCommandDisplay | null;
  readonly facts: readonly ElevationRequestFact[];
  readonly warnings: readonly ElevationWarningView[];
  readonly decodeFailure: string | null;
  readonly changes: ElevationPendingRequest["changes"] | null;
  readonly series?: ElevationRequestSeries | undefined;
  readonly raisedByT3?: boolean | undefined;
  /** Under a header that names the machine, which the card then leaves out. */
  readonly inMachineSection?: boolean;
  /** How the request ended, said in place of Deny while the card settles. */
  readonly ended?: ElevationEndedView | null;
  readonly dataItemType?: string;
}) {
  const { agent } = props;
  const canRespond = useAtomValue(elevation.respond.permissionAtom(props.environmentId));
  const deny = useElevationDeny();
  const machine = useEnvironment(props.environmentId)?.label ?? null;
  const source = elevationRequestSource({
    explanation: props.explanation,
    threadId: props.threadId,
    raisedByT3: props.raisedByT3,
    machine: props.inMachineSection ? null : machine,
  });
  const mark = source.agentMark ? agent : null;
  return (
    <div
      data-v2-item-type={props.dataItemType}
      className="flex min-w-0 flex-col gap-2 rounded-xl border border-border/60 bg-card p-4"
    >
      <div className="flex min-w-0 flex-col gap-1">
        <p className="line-clamp-3 text-sm font-semibold break-words text-foreground">
          {props.headline}
        </p>
        {props.series ? (
          <ElevationSeriesLine series={props.series} threadId={props.threadId} />
        ) : null}
      </div>
      {mark !== null || source.parts.length > 0 ? (
        <p className="flex min-w-0 items-center gap-1.5 text-xs text-muted-foreground">
          {mark !== null ? <ElevationAgentMark agent={mark} named={source.agentNamed} /> : null}
          {mark !== null && source.agentNamed && source.parts.length > 0 ? (
            <span aria-hidden>·</span>
          ) : null}
          {source.parts.length > 0 ? (
            <span className="truncate">{source.parts.join(" · ")}</span>
          ) : null}
        </p>
      ) : null}
      {props.enrollKey !== null ? (
        <ElevationComparisonCode publicKey={props.enrollKey} />
      ) : props.command !== null ? (
        <CommandDisclosure command={props.command} facts={props.facts} warnings={props.warnings} />
      ) : null}
      {props.decodeFailure !== null ? (
        <p className="text-xs text-muted-foreground">{props.decodeFailure}</p>
      ) : null}
      {props.changes && props.threadId !== null ? (
        <ChangesPointer
          environmentId={props.environmentId}
          threadId={props.threadId}
          changes={props.changes}
        />
      ) : null}
      {props.ended ? (
        <EndedLine ended={props.ended} />
      ) : (
        <>
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
                void deny.run({ environmentId: props.environmentId, requestId: props.requestId })
              }
            >
              Deny
            </Button>
          </div>
        </>
      )}
    </div>
  );
}

const ENDED_ICONS = {
  approved: CheckIcon,
  denied: XIcon,
  expired: ClockIcon,
  cancelled: MinusIcon,
} as const;

/** Sits at the Deny row's height, so the card doesn't move until it leaves. */
function EndedLine(props: { readonly ended: ElevationEndedView }) {
  const Icon = ENDED_ICONS[props.ended.kind];
  return (
    <p
      role="status"
      className="flex min-h-7 min-w-0 items-center gap-1.5 text-xs text-foreground sm:min-h-6"
    >
      <Icon className="size-3.5 shrink-0" aria-hidden />
      <span className="truncate">{props.ended.text}</span>
    </p>
  );
}

/** The short command in up to two quiet rows; opens to the full command and non-default facts. */
function CommandDisclosure(props: {
  readonly command: ElevationCommandDisplay;
  readonly facts: readonly ElevationRequestFact[];
  readonly warnings: readonly ElevationWarningView[];
}) {
  const { command } = props;
  const [open, setOpen] = useState(false);
  const full = command.lines.join("\n");
  const expandable = full !== command.short || props.facts.length > 0 || props.warnings.length > 0;
  const line = (
    <code className="line-clamp-2 min-w-0 font-mono wrap-anywhere">{command.short}</code>
  );
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
  readonly threadId: ThreadId;
  readonly changes: NonNullable<ElevationPendingRequest["changes"]>;
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
