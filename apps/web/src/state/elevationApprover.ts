import type { ElevationApproverHere } from "@t3tools/client-runtime/elevation";
import type {
  ElevationKeyId,
  ElevationSignedResponse,
  ElevationWebauthnBinding,
  EnvironmentId,
} from "@t3tools/contracts";
import { useSyncExternalStore } from "react";

import { macApproverSource } from "./elevationApproverMac";

/**
 * Something on this client that approves sudo: the desktop's Touch ID key, or this browser's
 * passkey. A Mac and a browser enroll unattested, so an enrolled device or the password admits
 * the key (docs/internals/device-approval.md).
 */
export interface ElevationApprover {
  readonly kind: "mac" | "browser";
  /** This device's key on the machine; null until it is set up there. */
  readonly keyId: ElevationKeyId | null;
  /** Why it can't approve or set up now, such as "Touch ID needs the lid open"; null when it can. */
  readonly unavailableReason: string | null;
  /**
   * The label to enroll it under: its model ("MacBook Pro", "Chrome on Mac"), with the computer's
   * name only when `existing` already has that label (`uniqueElevationApproverLabel`).
   */
  readonly label: (existing: ReadonlyArray<string>) => string;
  /**
   * Signs the payload's exact bytes as `es256-der` (Mac) or `webauthn-es256` (browser). Null when
   * the user cancelled, which counts as Deny. The signal aborts when another device answers.
   */
  readonly sign: (
    payloadBytes: Uint8Array,
    signal: AbortSignal,
  ) => Promise<ElevationSignedResponse | null>;
  /**
   * Makes the key for "Add device": an SPKI DER public key, plus the passkey's site for a browser.
   * Null when the user cancelled.
   */
  readonly createKey: (signal: AbortSignal) => Promise<{
    readonly publicKey: string;
    readonly webauthn?: ElevationWebauthnBinding;
  } | null>;
  /** Forgets this device's key on the machine, after the helper has revoked it. */
  readonly forget: () => Promise<void>;
}

/**
 * One per kind of approver; the desktop and the browser each add theirs to `SOURCES`.
 * `get` returns the same object until something about it changes, as `useSyncExternalStore`
 * requires.
 */
export interface ElevationApproverSource {
  readonly subscribe: (listener: () => void) => () => void;
  readonly get: (environmentId: EnvironmentId) => ElevationApprover | null;
}

const SOURCES: ReadonlyArray<ElevationApproverSource> = [macApproverSource];

const subscribe = (listener: () => void) => {
  const unsubscribes = SOURCES.map((source) => source.subscribe(listener));
  return () => {
    for (const unsubscribe of unsubscribes) unsubscribe();
  };
};

/** The approver this client offers on a machine, or null where only a phone approves. */
export function useElevationApprover(environmentId: EnvironmentId): ElevationApprover | null {
  return useSyncExternalStore(subscribe, () =>
    SOURCES.reduce<ElevationApprover | null>(
      (found, source) => found ?? source.get(environmentId),
      null,
    ),
  );
}

/** This client's approver where it has a key, so rows say "Approved on this Mac". */
export function useElevationApproverHere(
  environmentId: EnvironmentId,
): ElevationApproverHere | null {
  const approver = useElevationApprover(environmentId);
  return approver === null || approver.keyId === null
    ? null
    : { kind: approver.kind, keyId: approver.keyId };
}
