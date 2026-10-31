import type { PendingElevationRequest } from "@t3tools/client-runtime/state/elevation";
import type { EnvironmentId, ElevationRequestId } from "@t3tools/contracts";
import { Atom } from "effect/reactivity";

import { appAtomRegistry } from "../../state/atom-registry";

export interface ElevationApprovalTarget {
  readonly environmentId: EnvironmentId;
  readonly requestId: ElevationRequestId;
}

/** The request the approval sheet shows. The feed card, banner and push all open it here. */
export const elevationApprovalTargetAtom = Atom.make<ElevationApprovalTarget | null>(null).pipe(
  Atom.keepAlive,
  Atom.withLabel("mobile:elevation-approval-target"),
);

export function openElevationApproval(target: ElevationApprovalTarget): void {
  appAtomRegistry.set(elevationApprovalTargetAtom, target);
}

export function closeElevationApproval(): void {
  appAtomRegistry.set(elevationApprovalTargetAtom, null);
}

/**
 * Relay pushes only carry the thread link. A tap remembers the thread so the
 * sheet opens once that thread's pending request arrives over the socket.
 */
export interface ElevationNotificationIntent {
  readonly environmentId: string;
  readonly threadId: string;
  readonly tappedAt: number;
}

const NOTIFICATION_INTENT_TTL_MS = 2 * 60_000;

export const elevationNotificationIntentAtom = Atom.make<ElevationNotificationIntent | null>(
  null,
).pipe(Atom.keepAlive, Atom.withLabel("mobile:elevation-notification-intent"));

export function rememberElevationNotificationTap(deepLink: string, tappedAt: number): void {
  const match = /^\/threads\/([^/]+)\/([^/]+)$/.exec(deepLink);
  if (!match?.[1] || !match[2]) return;
  appAtomRegistry.set(elevationNotificationIntentAtom, {
    environmentId: decodeURIComponent(match[1]),
    threadId: decodeURIComponent(match[2]),
    tappedAt,
  });
}

/**
 * The request a tapped push was about: pending in that thread and created
 * before the tap, so a later request never opens on its own.
 */
export function pendingRequestForNotificationIntent(
  intent: ElevationNotificationIntent,
  pending: readonly PendingElevationRequest[],
  now: number,
): PendingElevationRequest | "expired" | null {
  if (now - intent.tappedAt > NOTIFICATION_INTENT_TTL_MS) return "expired";
  return (
    pending.findLast(
      (entry) =>
        entry.environmentId === intent.environmentId &&
        entry.request.threadId === intent.threadId &&
        entry.request.createdAt.epochMilliseconds <= intent.tappedAt,
    ) ?? null
  );
}
