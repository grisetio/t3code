import { elevationFailureMessage } from "@t3tools/client-runtime/elevation";
import {
  isAtomCommandInterrupted,
  squashAtomCommandFailure,
} from "@t3tools/client-runtime/state/runtime";
import type { ElevationRequestId, EnvironmentId } from "@t3tools/contracts";
import { useState } from "react";

import { elevation } from "../../state/elevation";
import { useAtomCommand } from "../../state/use-atom-command";

/** Web can't sign in v1, so its only answer is a deny. */
export function useElevationDeny() {
  const respond = useAtomCommand(elevation.respond, "deny device approval");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async (target: {
    readonly environmentId: EnvironmentId;
    readonly requestId: ElevationRequestId;
  }) => {
    setPending(true);
    setError(null);
    const result = await respond({
      environmentId: target.environmentId,
      input: { requestId: target.requestId, decision: "deny" },
    }).finally(() => setPending(false));
    if (result._tag === "Failure" && !isAtomCommandInterrupted(result)) {
      setError(
        elevationFailureMessage(squashAtomCommandFailure(result), "Could not deny. Try again."),
      );
    }
  };
  return { run, pending, error };
}
