import { sha256 } from "@noble/hashes/sha2";
import type { ElevationRequestFact, ElevationWarningView } from "@t3tools/client-runtime/elevation";
import { elevationComparisonCode } from "@t3tools/contracts";
import { TriangleAlertIcon } from "lucide-react";

/** Module warnings, then Runs as and Directory where they differ from the default. */
export function ElevationRequestFactLines(props: {
  readonly facts: readonly ElevationRequestFact[];
  readonly warnings: readonly ElevationWarningView[];
}) {
  return (
    <>
      {props.warnings.map((warning) => (
        <p
          key={`${warning.code}:${warning.message}`}
          className="flex min-w-0 items-start gap-1.5 text-muted-foreground"
        >
          <TriangleAlertIcon className="mt-px size-3.5 shrink-0" aria-hidden />
          <span className="min-w-0 break-words">{warning.message}</span>
        </p>
      ))}
      {props.facts.map((fact) => (
        <p key={fact.label} className="min-w-0 break-all text-muted-foreground">
          {fact.label} <span className={fact.mono ? "font-mono" : undefined}>{fact.value}</span>
        </p>
      ))}
    </>
  );
}

/** The code both devices show for a new key; matching codes mean it is the same key. */
export function ElevationComparisonCode(props: { readonly publicKey: Uint8Array }) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5 rounded-lg bg-muted/40 px-3 py-2">
      <span className="font-mono text-lg tracking-widest text-foreground">
        {elevationComparisonCode(sha256(props.publicKey))}
      </span>
      <span className="text-xs text-muted-foreground">
        Approve only if the new device shows this same code.
      </span>
    </div>
  );
}
