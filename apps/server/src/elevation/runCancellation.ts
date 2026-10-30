import type { RunId } from "@t3tools/contracts";
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";

/**
 * Lets the effect worker cancel a run's pending device approvals without
 * depending on ElevationService, which itself depends on the orchestrator.
 * Servers without device approval keep the no-op default.
 */
export class ElevationRunCancellation extends Context.Reference<{
  readonly cancelRun: (runId: RunId) => Effect.Effect<void>;
}>("t3/elevation/ElevationRunCancellation", {
  defaultValue: () => ({ cancelRun: () => Effect.void }),
}) {}
