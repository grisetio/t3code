import { useAtomValue } from "@effect/atom-react";
import {
  ELEVATION_APPROVE_ON_PHONE,
  decodeElevationRequestPayload,
  elevationDecodeFailureMessage,
  elevationRequestFallbackView,
  elevationRequestStatusView,
  type ElevationRequestItem,
} from "@t3tools/client-runtime/elevation";
import type { EnvironmentId, OrchestrationV2ProjectedTurnItem } from "@t3tools/contracts";
import * as Result from "effect/Result";
import { CheckIcon, ClockIcon, MinusIcon, ShieldIcon, SmartphoneIcon, XIcon } from "lucide-react";
import { useState } from "react";

import { ElevationRequestDetails } from "../elevation/ElevationRequestDetails";
import { useElevationDeny } from "../elevation/useElevationDeny";
import { elevation } from "../../state/elevation";
import { Button } from "../ui/button";
import { WorkLogDetails, WorkLogRow } from "./WorkLog";

const STATUS_ICONS = {
  pending: ShieldIcon,
  approved: CheckIcon,
  denied: XIcon,
  expired: ClockIcon,
  cancelled: MinusIcon,
} as const;

function itemView(item: ElevationRequestItem) {
  if (item.payload === null) return { view: elevationRequestFallbackView(item), problem: null };
  const decoded = decodeElevationRequestPayload(item.payload);
  return Result.isSuccess(decoded)
    ? { view: decoded.success.view, problem: null }
    : {
        view: elevationRequestFallbackView(item),
        problem: elevationDecodeFailureMessage(decoded.failure),
      };
}

export function ElevationRequestCard(props: {
  readonly environmentId: EnvironmentId;
  readonly item: ElevationRequestItem;
  readonly visibility: OrchestrationV2ProjectedTurnItem["visibility"];
}) {
  const { item } = props;
  const status = elevationRequestStatusView(item);
  const [expanded, setExpanded] = useState(false);
  const { view, problem } = itemView(item);
  if (status.kind === "pending" && props.visibility === "local") {
    return (
      <PendingElevationRequest
        environmentId={props.environmentId}
        item={item}
        view={view}
        problem={problem}
      />
    );
  }
  const Icon = STATUS_ICONS[status.kind];
  return (
    <WorkLogRow
      data-v2-item-type={item.type}
      icon={<Icon className="size-3.5 text-icon-muted" aria-hidden />}
      label={
        <>
          sudo {view.commandArgv.join(" ")} · {status.label}
        </>
      }
      aria-expanded={expanded}
      onClick={() => setExpanded((current) => !current)}
    >
      {expanded ? (
        <WorkLogDetails>
          {status.kind !== "pending" && status.detail ? (
            <p className="text-xs text-muted-foreground">{status.detail}</p>
          ) : null}
          <ElevationRequestDetails view={view} explanation={item.explanation} />
        </WorkLogDetails>
      ) : null}
    </WorkLogRow>
  );
}

function PendingElevationRequest(props: {
  readonly environmentId: EnvironmentId;
  readonly item: ElevationRequestItem;
  readonly view: ReturnType<typeof itemView>["view"];
  readonly problem: string | null;
}) {
  const canRespond = useAtomValue(elevation.respond.permissionAtom(props.environmentId));
  const deny = useElevationDeny();
  return (
    <div
      data-v2-item-type={props.item.type}
      className="flex min-w-0 flex-col gap-3 rounded-xl border border-border/60 bg-card p-4"
    >
      <p className="text-sm font-medium text-foreground">
        The agent wants to run a command as root
      </p>
      {props.problem ? <p className="text-xs text-destructive">{props.problem}</p> : null}
      <ElevationRequestDetails view={props.view} explanation={props.item.explanation} />
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
            void deny.run({ environmentId: props.environmentId, requestId: props.item.requestId })
          }
        >
          Deny
        </Button>
      </div>
    </div>
  );
}
