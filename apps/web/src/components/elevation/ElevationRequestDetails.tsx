import { sha256 } from "@noble/hashes/sha2";
import {
  ELEVATION_EXPLANATION_LABEL,
  type ElevationRequestView,
} from "@t3tools/client-runtime/elevation";
import { elevationComparisonCode, escapeElevationDisplayText } from "@t3tools/contracts";
import { TriangleAlertIcon } from "lucide-react";

/**
 * What a sudo request will do, from the payload. Every string arrives escaped,
 * the argv is shown whole with one entry per line, and warnings come first.
 */
export function ElevationRequestDetails(props: {
  readonly view: Pick<ElevationRequestView, "host" | "runAs" | "commandArgv" | "cwd" | "warnings"> &
    Partial<Pick<ElevationRequestView, "user" | "runAsGroup" | "resolvedPath" | "enroll">>;
  readonly explanation: string | null;
}) {
  const { view } = props;
  return (
    <div className="flex min-w-0 flex-col gap-2 text-xs">
      {view.enroll ? (
        <p className="text-sm font-medium text-foreground">
          Add device {view.enroll.label} · code{" "}
          <span className="font-mono tracking-wider">
            {elevationComparisonCode(sha256(view.enroll.publicKey))}
          </span>
        </p>
      ) : null}
      {view.warnings.length > 0 ? (
        <ul className="flex flex-col gap-1 text-destructive">
          {view.warnings.map((warning, index) => (
            <ElevationWarningLine key={`${warning.code}:${index}`} message={warning.message} />
          ))}
        </ul>
      ) : null}
      <ol
        aria-label="Command"
        className="flex min-w-0 flex-col rounded-md bg-muted/40 px-2.5 py-1.5 font-mono text-foreground"
      >
        {view.commandArgv.map((arg, index) => (
          <li key={index} className="break-all whitespace-pre-wrap">
            {arg}
          </li>
        ))}
      </ol>
      <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-0.5 text-muted-foreground">
        <dt>Runs as</dt>
        <dd className="break-all text-foreground">
          {view.user ? `${view.user} → ` : ""}
          {view.runAs}
          {view.runAsGroup ? ` (group ${view.runAsGroup})` : ""}
        </dd>
        <dt>Host</dt>
        <dd className="break-all text-foreground">{view.host}</dd>
        <dt>Directory</dt>
        <dd className="break-all font-mono text-foreground">{view.cwd}</dd>
        {view.resolvedPath ? (
          <>
            <dt>Program</dt>
            <dd className="break-all font-mono text-foreground">{view.resolvedPath}</dd>
          </>
        ) : null}
      </dl>
      {props.explanation ? (
        <div className="flex min-w-0 flex-col gap-0.5">
          <p className="text-muted-foreground">{ELEVATION_EXPLANATION_LABEL}</p>
          <p className="break-words whitespace-pre-wrap text-foreground/80">
            {escapeElevationDisplayText(props.explanation)}
          </p>
        </div>
      ) : null}
    </div>
  );
}

function ElevationWarningLine({ message }: { readonly message: string }) {
  return (
    <li className="flex min-w-0 items-start gap-1.5">
      <TriangleAlertIcon className="mt-px size-3.5 shrink-0" aria-hidden />
      <span className="min-w-0 break-words">{message}</span>
    </li>
  );
}
