import { sha256 } from "@noble/hashes/sha2";
import type { ElevationRequestView } from "@t3tools/client-runtime/elevation";
import { elevationComparisonCode } from "@t3tools/contracts";
import { TriangleAlertIcon } from "lucide-react";

/**
 * The technical side of a request, behind a resolved row's Details: module warnings, who it ran
 * as, where, and which program. Every string arrives escaped.
 */
export function ElevationTechnicalDetails(props: {
  readonly view: Pick<ElevationRequestView, "host" | "runAs" | "cwd" | "warnings"> &
    Partial<Pick<ElevationRequestView, "user" | "runAsGroup" | "resolvedPath">>;
}) {
  const { view } = props;
  return (
    <div className="flex min-w-0 flex-col gap-2 text-xs text-muted-foreground">
      {view.warnings.length > 0 ? (
        <ul className="flex flex-col gap-1">
          {view.warnings.map((warning, index) => (
            // oxlint-disable-next-line react/no-array-index-key -- Warnings can repeat and have no local state.
            <li key={`${warning.code}:${index}`} className="flex min-w-0 items-start gap-1.5">
              <TriangleAlertIcon className="mt-px size-3.5 shrink-0" aria-hidden />
              <span className="min-w-0 break-words">{warning.message}</span>
            </li>
          ))}
        </ul>
      ) : null}
      <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-0.5">
        <dt>Runs as</dt>
        <dd className="break-all text-foreground">
          {view.user ? `${view.user} → ` : ""}
          {view.runAs}
          {view.runAsGroup ? ` (group ${view.runAsGroup})` : ""}
        </dd>
        <dt>Machine</dt>
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
    </div>
  );
}

/** The code both phones show for a new key; matching codes mean it is the same key. */
export function ElevationComparisonCode(props: { readonly publicKey: Uint8Array }) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5 rounded-lg bg-muted/40 px-3 py-2">
      <span className="font-mono text-lg tracking-widest text-foreground">
        {elevationComparisonCode(sha256(props.publicKey))}
      </span>
      <span className="text-xs text-muted-foreground">
        Approve only if the new phone shows this same code.
      </span>
    </div>
  );
}
