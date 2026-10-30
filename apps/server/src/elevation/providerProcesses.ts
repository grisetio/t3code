import * as HostProcess from "@t3tools/shared/HostProcess";
import { ProviderProcesses, type ProviderProcess } from "@t3tools/shared/ProviderProcesses";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";

import { processStartTime } from "./native.ts";

export const layer = Layer.effect(
  ProviderProcesses,
  Effect.gen(function* () {
    const host = { platform: yield* HostProcess.Platform, arch: yield* HostProcess.Architecture };
    const entries = new Set<ProviderProcess>();
    return {
      register: ({ pid, threadId }) => {
        const entry: ProviderProcess = {
          pid,
          threadId,
          startTime: processStartTime(host, pid, { onlyIfLoaded: true }),
        };
        entries.add(entry);
        return () => {
          entries.delete(entry);
        };
      },
      list: () => [...entries],
    };
  }),
);
