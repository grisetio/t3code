import type { EnvironmentId } from "@t3tools/contracts";
import { Atom } from "effect/reactivity";

import { appAtomRegistry } from "../../state/atom-registry";

/**
 * The machine whose key "Set up again" asked to replace. Settings opens the re-key sheet for it
 * on arrival, so the prompt leads straight to the fingerprint instead of to a page to search.
 */
export const deviceApprovalRekeyAtom = Atom.make<EnvironmentId | null>(null).pipe(
  Atom.keepAlive,
  Atom.withLabel("mobile:device-approval-rekey"),
);

export function requestDeviceApprovalRekey(environmentId: EnvironmentId): void {
  appAtomRegistry.set(deviceApprovalRekeyAtom, environmentId);
}

export function clearDeviceApprovalRekey(): void {
  appAtomRegistry.set(deviceApprovalRekeyAtom, null);
}
