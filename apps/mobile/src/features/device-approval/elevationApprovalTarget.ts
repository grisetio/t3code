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

export function parseElevationNotificationTap(
  deepLink: string,
  tappedAt: number,
): ElevationNotificationIntent | null {
  const match = /^\/threads\/([^/]+)\/([^/]+)$/.exec(deepLink);
  if (!match?.[1] || !match[2]) return null;
  return {
    environmentId: decodeURIComponent(match[1]),
    threadId: decodeURIComponent(match[2]),
    tappedAt,
  };
}

export function rememberElevationNotificationTap(deepLink: string, tappedAt: number): void {
  const intent = parseElevationNotificationTap(deepLink, tappedAt);
  if (intent !== null) appAtomRegistry.set(elevationNotificationIntentAtom, intent);
}

/** A sudo push opened over the lock screen; the app shows only that request until it ends. */
export interface ElevationLockScreenSession {
  readonly intent: ElevationNotificationIntent;
  /** Android's lock screen hides notification content, so the card hides the request too. */
  readonly hideContent: boolean;
}

export const elevationLockScreenAtom = Atom.make<ElevationLockScreenSession | null>(null).pipe(
  Atom.keepAlive,
  Atom.withLabel("mobile:elevation-lock-screen"),
);

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

/**
 * Requests this phone denied in this session. A deny records no device on the server, so the
 * resolved row learns "on this phone" from here.
 */
const deniedHere = new Set<ElevationRequestId>();

export function rememberDeniedHere(requestId: ElevationRequestId): void {
  deniedHere.add(requestId);
}

export function wasDeniedHere(requestId: ElevationRequestId): boolean {
  return deniedHere.has(requestId);
}

/**
 * A request this phone raised itself and answers in its own flow, such as the sudo behind
 * "Remove this phone". The banner, sheet and push skip it so it never shows twice.
 */
export interface ClaimedElevationRequest {
  readonly environmentId: EnvironmentId;
  readonly matches: (entry: PendingElevationRequest) => boolean;
}

export const claimedElevationRequestAtom = Atom.make<ClaimedElevationRequest | null>(null).pipe(
  Atom.keepAlive,
  Atom.withLabel("mobile:elevation-claimed-request"),
);

export function isClaimedElevationRequest(
  claim: ClaimedElevationRequest | null,
  entry: PendingElevationRequest,
): boolean {
  return claim !== null && claim.environmentId === entry.environmentId && claim.matches(entry);
}
