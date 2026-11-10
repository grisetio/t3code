import { useAtomValue } from "@effect/atom-react";
import {
  ELEVATION_APPROVE_ON_PHONE,
  elevationAgoRefreshMs,
  elevationRequestSource,
  elevationSeriesLine,
  type ElevationEndedView,
  type ElevationApproverHere,
  type ElevationRequestFact,
  type ElevationWarningView,
} from "@t3tools/client-runtime/elevation";
import type { ElevationCommandDisplay } from "@t3tools/client-runtime/elevation-command";
import { scopeThreadRef } from "@t3tools/client-runtime/environment";
import type {
  ElevationKeyId,
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
  FingerprintIcon,
  MinusIcon,
  RotateCwIcon,
  SmartphoneIcon,
  XIcon,
} from "lucide-react";
import { useNavigate } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";

import { cn } from "~/lib/utils";
import { useDiffPanelStore } from "../../diffPanelStore";
import { useRightPanelStore } from "../../rightPanelStore";
import { useEnvironment } from "../../state/environments";
import { elevation } from "../../state/elevation";
import { useElevationApprover } from "../../state/elevationApprover";
import { Button } from "../ui/button";
import { ElevationAgentMark, type ElevationAgentView } from "./ElevationAgentMark";
import { ElevationComparisonCode, ElevationRequestFactLines } from "./ElevationRequestDetails";
import { useElevationSidebarStore } from "./elevationSidebarStore";
import { useElevationRespond } from "./useElevationRespond";

/** How long "✓ Approved on Pixel" stays before the card leaves, as on the phone. */
export const ELEVATION_SETTLE_MS = 500;
/** The card's collapse once it has said how its request ended. */
export const ELEVATION_COLLAPSE_MS = 250;

// The phone's curves, tuned on a 120 Hz screen: steeper ones move a card's height by tens of px in
// one frame and read as a jump. Each runs once, as a CSS transition, inside a one-row grid whose
// row eases between 0fr and 1fr, so the card's natural height needs no measuring.
/** Growing in: quick at first, then settling into place (ease-out quad). */
export const ELEVATION_ARRIVE_CLASS =
  "grid-rows-[1fr] [transition:grid-template-rows_260ms_cubic-bezier(0.5,1,0.89,1),opacity_260ms_cubic-bezier(0.5,1,0.89,1)] starting:grid-rows-[0fr] starting:opacity-0";
/** Closing up: gathers speed, then slows into its end (CSS `ease`). The card fades faster than it closes. */
export const ELEVATION_COLLAPSE_CLASS =
  "grid-rows-[0fr] opacity-0 [transition:grid-template-rows_250ms_ease,opacity_150ms_ease]";
/** A settled row opening on the collapse's curve, so the two heights move as one. */
export const ELEVATION_ROW_GROW_CLASS =
  "grid-rows-[1fr] [transition:grid-template-rows_250ms_ease] starting:grid-rows-[0fr]";

const SET_UP_HERE: Record<ElevationApproverHere["kind"], string> = {
  phone: "Set up this phone",
  mac: "Set up this Mac",
  browser: "Set up this browser",
};

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
 * A pending request as a card that leads with words, never the command, like the phone's. Where
 * this client holds a key the machine accepts, it approves here; otherwise approving happens on
 * the phone, and Deny works here.
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
  /** The exact bytes an approval signs and the keys that may sign them; null when unreadable. */
  readonly signable: ElevationSignable | null;
  /** How the request ended, said in place of Deny while the card settles. */
  readonly ended?: ElevationEndedView | null;
  readonly dataItemType?: string;
}) {
  const { agent } = props;
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
      <ElevationCardActions
        environmentId={props.environmentId}
        requestId={props.requestId}
        signable={props.signable}
        enroll={props.enrollKey !== null}
        ended={props.ended ?? null}
      />
    </div>
  );
}

export interface ElevationSignable {
  readonly bytes: Uint8Array;
  readonly keyIds: readonly ElevationKeyId[];
}

/**
 * Deny and Approve where this client's key may sign; "Approve on your phone" and Deny otherwise,
 * with why this client can't approve, or a way to set it up. Cancelling the passkey or Touch ID
 * prompt denies, as on the phone.
 */
function ElevationCardActions(props: {
  readonly environmentId: EnvironmentId;
  readonly requestId: ElevationRequestId;
  readonly signable: ElevationSignable | null;
  readonly enroll: boolean;
  readonly ended: ElevationEndedView | null;
}) {
  const { environmentId, requestId, signable } = props;
  const canRespond = useAtomValue(elevation.respond.permissionAtom(environmentId));
  const respond = useElevationRespond();
  const approver = useElevationApprover(environmentId);
  const navigate = useNavigate();
  const requestSetup = useElevationSidebarStore((state) => state.requestSetup);
  const [answered, setAnswered] = useState<"approved" | "denied" | null>(null);
  const [signing, setSigning] = useState(false);
  const prompt = useRef<AbortController | null>(null);
  const endedElsewhere = props.ended !== null;
  // Another device answered while the prompt was open: close it, and the line says who.
  useEffect(() => {
    if (endedElsewhere) prompt.current?.abort();
  }, [endedElsewhere]);
  useEffect(() => () => prompt.current?.abort(), []);

  const keyId = approver?.keyId ?? null;
  const signsHere = keyId !== null && signable !== null && signable.keyIds.includes(keyId);
  const reason = approver?.unavailableReason ?? null;
  // Adding a device is approved by one already set up, so it never offers to set this one up.
  const offerSetup = approver !== null && !signsHere && reason === null && !props.enroll;

  const answer = async (decision: "approve" | "deny") => {
    if (decision === "deny" || approver === null || keyId === null || signable === null) {
      const outcome = await respond.run(environmentId, {
        requestId,
        decision: "deny",
        ...(signsHere && keyId !== null ? { keyId } : {}),
      });
      if (outcome === "answered") setAnswered("denied");
      return;
    }
    const controller = new AbortController();
    prompt.current = controller;
    setSigning(true);
    respond.setError(null);
    let signed;
    try {
      signed = await approver.sign(signable.bytes, controller.signal);
    } catch (error) {
      if (!controller.signal.aborted) {
        respond.setError(error instanceof Error ? error.message : "Could not approve. Try again.");
      }
      return;
    } finally {
      prompt.current = null;
      setSigning(false);
    }
    if (controller.signal.aborted) return;
    const outcome = await respond.run(
      environmentId,
      signed === null
        ? { requestId, decision: "deny", keyId }
        : { requestId, decision: "approve", ...signed },
    );
    if (outcome === "answered") setAnswered(signed === null ? "denied" : "approved");
  };

  if (answered === "approved") return <EndedLine ended={{ kind: "approved", text: "Approved" }} />;
  if (answered === "denied") return <EndedLine ended={{ kind: "denied", text: "Denied" }} />;
  // An answer of ours in flight finishes first; the server reports a lost race as such.
  if (props.ended !== null && !respond.pending) return <EndedLine ended={props.ended} />;
  const busy = !canRespond || signing || respond.pending;
  return (
    <>
      {respond.error ? (
        <p role="alert" className="text-xs text-destructive">
          {respond.error}
        </p>
      ) : null}
      {signsHere && reason === null ? (
        <div className="flex min-w-0 items-center justify-end gap-2">
          <Button
            type="button"
            size="xs"
            variant="outline"
            disabled={busy}
            onClick={() => void answer("deny")}
          >
            Deny
          </Button>
          <Button type="button" size="xs" disabled={busy} onClick={() => void answer("approve")}>
            <FingerprintIcon aria-hidden />
            Approve
          </Button>
        </div>
      ) : (
        <div className="flex min-w-0 items-center justify-between gap-2">
          <p className="flex min-w-0 items-center gap-1.5 text-xs text-muted-foreground">
            <SmartphoneIcon className="size-3.5 shrink-0" aria-hidden />
            <span className="shrink-0">{ELEVATION_APPROVE_ON_PHONE}</span>
            {signsHere && reason !== null ? (
              <>
                <span aria-hidden>·</span>
                <span className="truncate">{reason}</span>
              </>
            ) : offerSetup ? (
              <>
                <span aria-hidden>·</span>
                <button
                  type="button"
                  className="truncate underline decoration-muted-foreground/45 underline-offset-2 hover:text-foreground"
                  onClick={() => {
                    requestSetup(environmentId);
                    void navigate({ to: "/settings/device-approval" });
                  }}
                >
                  {SET_UP_HERE[approver.kind]}
                </button>
              </>
            ) : null}
          </p>
          <Button
            type="button"
            size="xs"
            variant="ghost-muted"
            disabled={busy}
            onClick={() => void answer("deny")}
          >
            Deny
          </Button>
        </div>
      )}
    </>
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
