import { useAtomValue } from "@effect/atom-react";
import {
  ELEVATION_APPROVE_ON_PHONE,
  decodeElevationRequestPayload,
  elevationDecodeFailureMessage,
  elevationRequestFallbackView,
  elevationRequestStatusView,
  type ElevationRequestItem,
} from "@t3tools/client-runtime/elevation";
import {
  elevationCommandDisplay,
  elevationCommandMoreLabel,
  type ElevationCommandDisplay,
} from "@t3tools/client-runtime/elevation-command";
import { scopeThreadRef } from "@t3tools/client-runtime/environment";
import {
  escapeElevationDisplayText,
  type EnvironmentId,
  type OrchestrationV2ProjectedTurnItem,
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
import { useState } from "react";

import { useDiffPanelStore } from "../../diffPanelStore";
import {
  applyProviderInstanceSettings,
  deriveProviderInstanceEntries,
} from "../../providerInstances";
import { useRightPanelStore } from "../../rightPanelStore";
import { useQuietThreadShell } from "../../state/entities";
import { useEnvironments } from "../../state/environments";
import { elevation } from "../../state/elevation";
import { EMPTY_SERVER_PROVIDERS, serverEnvironment } from "../../state/server";
import { ElevationRequestDetails } from "../elevation/ElevationRequestDetails";
import { useElevationDeny } from "../elevation/useElevationDeny";
import { Button } from "../ui/button";
import { ProviderInstanceIcon } from "./ProviderInstanceIcon";
import { WorkLogDetails, WorkLogRow } from "./WorkLog";

const STATUS_ICONS = {
  pending: ShieldIcon,
  approved: CheckIcon,
  denied: XIcon,
  expired: ClockIcon,
  cancelled: MinusIcon,
} as const;

function itemView(item: ElevationRequestItem) {
  // Unsigned fallbacks never claim to be an enrollment.
  const fallback = { ...elevationRequestFallbackView(item), enroll: null };
  if (item.payload === null) {
    return { view: fallback, argv: item.argv, problem: null };
  }
  const decoded = decodeElevationRequestPayload(item.payload);
  return Result.isSuccess(decoded)
    ? { view: decoded.success.view, argv: decoded.success.payload.command.argv, problem: null }
    : {
        view: fallback,
        argv: item.argv,
        problem: elevationDecodeFailureMessage(decoded.failure),
      };
}

/**
 * Matches the phone's card: the agent's reason leads, then who and where, one
 * quiet command line, and the checkout's uncommitted changes. Web can't sign,
 * so approving happens on the phone; Deny works here.
 */
export function ElevationRequestCard(props: {
  readonly environmentId: EnvironmentId;
  readonly item: ElevationRequestItem;
  readonly visibility: OrchestrationV2ProjectedTurnItem["visibility"];
}) {
  const { item } = props;
  const status = elevationRequestStatusView(item);
  const [expanded, setExpanded] = useState(false);
  const { view, argv, problem } = itemView(item);
  const command = elevationCommandDisplay({ agentCommand: item.agentCommand, commandArgv: argv });
  const reason = item.explanation ? escapeElevationDisplayText(item.explanation) : null;
  if (status.kind === "pending" && props.visibility === "local") {
    return (
      <PendingElevationRequest
        environmentId={props.environmentId}
        item={item}
        view={view}
        command={command}
        reason={reason}
        problem={problem}
      />
    );
  }
  const Icon = STATUS_ICONS[status.kind];
  const detail =
    status.kind === "pending"
      ? null
      : (status.detail ?? (status.kind === "expired" ? "Nobody approved it in time." : null));
  return (
    <WorkLogRow
      data-v2-item-type={item.type}
      icon={<Icon className="size-3.5 text-icon-muted" aria-hidden />}
      label={
        <>
          {status.label} · {command.lines[0]}
        </>
      }
      aria-expanded={expanded}
      onClick={() => setExpanded((current) => !current)}
    >
      {expanded ? (
        <WorkLogDetails>
          {reason ? <p className="text-xs text-foreground/80">“{reason}”</p> : null}
          {detail ? <p className="text-xs text-muted-foreground">{detail}</p> : null}
          <ElevationRequestDetails view={view} explanation={null} />
        </WorkLogDetails>
      ) : null}
    </WorkLogRow>
  );
}

function PendingElevationRequest(props: {
  readonly environmentId: EnvironmentId;
  readonly item: ElevationRequestItem;
  readonly view: ReturnType<typeof itemView>["view"];
  readonly command: ElevationCommandDisplay;
  readonly reason: string | null;
  readonly problem: string | null;
}) {
  const { item, view, reason } = props;
  const canRespond = useAtomValue(elevation.respond.permissionAtom(props.environmentId));
  const deny = useElevationDeny();
  const { environments } = useEnvironments();
  const [showDetails, setShowDetails] = useState(false);
  const machine =
    environments.find((environment) => environment.environmentId === props.environmentId)?.label ??
    view.host;
  const enroll = view.enroll;
  return (
    <div
      data-v2-item-type={item.type}
      className="flex min-w-0 flex-col gap-2 rounded-xl border border-border/60 bg-card p-4"
    >
      {enroll ? (
        <p className="text-sm font-medium text-foreground">Add device {enroll.label}</p>
      ) : reason ? (
        <p className="text-sm font-medium break-words text-foreground">“{reason}”</p>
      ) : (
        <CommandLine command={props.command} lead />
      )}
      <p className="flex min-w-0 items-center gap-1.5 text-xs text-muted-foreground">
        <AgentMark environmentId={props.environmentId} threadId={item.threadId} />
        <span aria-hidden>·</span>
        <span className="truncate">{machine}</span>
      </p>
      {reason || enroll ? <CommandLine command={props.command} /> : null}
      {item.changes ? (
        <ChangesPointer
          environmentId={props.environmentId}
          threadId={item.threadId}
          changes={item.changes}
        />
      ) : null}
      {props.problem ? <p className="text-xs text-destructive">{props.problem}</p> : null}
      {view.warnings.length > 0 || enroll || showDetails ? (
        <ElevationRequestDetails view={view} explanation={null} />
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
        <div className="flex shrink-0 items-center gap-1">
          {view.warnings.length > 0 || enroll ? null : (
            <Button
              type="button"
              size="xs"
              variant="ghost-muted"
              aria-expanded={showDetails}
              onClick={() => setShowDetails((open) => !open)}
            >
              Details
            </Button>
          )}
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
    </div>
  );
}

/** First line, two rows at most; a long command expands on click. */
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
        {open ? command.lines.join("\n") : command.lines[0]}
      </code>
      {expandable && !open ? <span className="text-muted-foreground">{more}</span> : null}
    </>
  );
  const className = props.lead
    ? "flex min-w-0 flex-col gap-0.5 text-left text-sm text-foreground"
    : "flex min-w-0 flex-col gap-0.5 text-left text-xs text-foreground/80";
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

function AgentMark(props: {
  readonly environmentId: EnvironmentId;
  readonly threadId: ElevationRequestItem["threadId"];
}) {
  const shell = useQuietThreadShell(scopeThreadRef(props.environmentId, props.threadId));
  const providers =
    useAtomValue(serverEnvironment.providersValueAtom(props.environmentId)) ??
    EMPTY_SERVER_PROVIDERS;
  const settings = useAtomValue(serverEnvironment.settingsValueAtom(props.environmentId));
  if (shell === null) return null;
  const instanceId = shell.runtime?.providerInstanceId ?? shell.modelSelection.instanceId;
  const derived = deriveProviderInstanceEntries(providers);
  const entries = settings ? applyProviderInstanceSettings(derived, settings, null) : derived;
  const entry = entries.find((candidate) => candidate.instanceId === instanceId);
  if (entry === undefined) return null;
  return (
    <span className="inline-flex min-w-0 items-center gap-1">
      <ProviderInstanceIcon
        driverKind={entry.driverKind}
        displayName={entry.displayName}
        accentColor={entry.accentColor}
        acpRegistryAgentId={entry.acpRegistryAgentId}
        acpRegistryIconUrl={entry.acpRegistryIconUrl}
        size="compact"
      />
      <span className="truncate">{shell.runtime?.providerName ?? entry.displayName}</span>
    </span>
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
