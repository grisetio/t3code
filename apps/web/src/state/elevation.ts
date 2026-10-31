import { createElevationAtoms } from "@t3tools/client-runtime/state/elevation";

import { connectionAtomRuntime } from "../connection/runtime";
import { environmentServerConfigsAtom } from "./server";

export const elevation = createElevationAtoms(connectionAtomRuntime, {
  environmentServerConfigsAtom,
});
