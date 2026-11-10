import { elevationFailureMessage } from "@t3tools/client-runtime/elevation";
import {
  isAtomCommandInterrupted,
  squashAtomCommandFailure,
} from "@t3tools/client-runtime/state/runtime";
import type { ElevationRespondInput, EnvironmentId } from "@t3tools/contracts";
import { useState } from "react";

import { elevation } from "../../state/elevation";
import { useAtomCommand } from "../../state/use-atom-command";

/** Another device answered first, or the request ended: the card says how, not an error. */
const isRaceLost = (failure: unknown) =>
  typeof failure === "object" &&
  failure !== null &&
  "reason" in failure &&
  (failure.reason === "already_resolved" || failure.reason === "not_found");

/**
 * Sends an approval or a deny. Resolves "answered" once the server took it, "raced" when the
 * request had already ended, and "failed" after setting `error`.
 */
export function useElevationRespond() {
  const respond = useAtomCommand(elevation.respond, "answer device approval");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async (
    environmentId: EnvironmentId,
    input: ElevationRespondInput,
  ): Promise<"answered" | "raced" | "failed"> => {
    setPending(true);
    setError(null);
    const result = await respond({ environmentId, input }).finally(() => setPending(false));
    if (result._tag === "Success") return "answered";
    if (isAtomCommandInterrupted(result)) return "failed";
    const failure = squashAtomCommandFailure(result);
    if (isRaceLost(failure)) return "raced";
    setError(
      elevationFailureMessage(
        failure,
        input.decision === "deny" ? "Could not deny. Try again." : "Could not approve. Try again.",
      ),
    );
    return "failed";
  };
  return { run, pending, error, setError };
}
