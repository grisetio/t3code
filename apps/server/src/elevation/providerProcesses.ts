import { ProviderProcesses, type ProviderProcess } from "@t3tools/shared/ProviderProcesses";
import * as Layer from "effect/Layer";

import { processStartTime } from "./native.ts";

export const layer = Layer.sync(ProviderProcesses, () => {
  const entries = new Set<ProviderProcess>();
  return {
    register: ({ pid, threadId }) => {
      const entry: ProviderProcess = {
        pid,
        threadId,
        startTime: processStartTime(pid, { onlyIfLoaded: true }),
      };
      entries.add(entry);
      return () => {
        entries.delete(entry);
      };
    },
    list: () => [...entries],
  };
});
