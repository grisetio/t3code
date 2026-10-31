import { useAtomValue } from "@effect/atom-react";
import { elevationKeyAlias } from "@t3tools/client-runtime/elevation";
import type { PendingElevationRequest } from "@t3tools/client-runtime/state/elevation";
import { useNavigation } from "@react-navigation/native";
import * as Base64Url from "effect/encoding/Base64Url";
import * as SecureStore from "expo-secure-store";
import { useEffect, useRef } from "react";
import { AppState, Platform, ScrollView } from "react-native";

import * as Dialog from "../../components/ui/Dialog";
import { Sheet } from "../../components/ui/Sheet";
import { appAtomRegistry } from "../../state/atom-registry";
import { elevation } from "../../state/elevation";
import { environmentPresentations } from "../../state/presentation";
import {
  androidLockScreen,
  clearAndroidSudoApprovals,
  setAndroidSudoApprovalMachines,
  subscribeAndroidSudoApprovalOpens,
} from "../agent-awareness/androidNotifications";
import { approvalHaptic } from "./approvalHaptics";
import { ElevationApprovalCard } from "./ElevationApprovalCard";
import {
  closeElevationApproval,
  elevationApprovalTargetAtom,
  elevationLockScreenAtom,
  elevationNotificationIntentAtom,
  openElevationApproval,
  parseElevationNotificationTap,
  pendingRequestForNotificationIntent,
  rememberElevationNotificationTap,
} from "./elevationApprovalTarget";
import { deviceApprovalKeys } from "./deviceApprovalKeys";
import { deviceApprovalSigner } from "./deviceApprovalSigner";

// A request created this recently is arriving now, not found on reconnect.
const ARRIVAL_WINDOW_MS = 10_000;

/** One soft tick per request as it arrives, wherever it shows. */
function useArrivalHaptic(pending: readonly PendingElevationRequest[]): void {
  const seen = useRef(new Set<string>());
  useEffect(() => {
    const now = Date.now();
    for (const entry of pending) {
      const { requestId, createdAt } = entry.request;
      if (seen.current.has(requestId)) continue;
      seen.current.add(requestId);
      if (
        AppState.currentState === "active" &&
        now - createdAt.epochMilliseconds < ARRIVAL_WINDOW_MS
      ) {
        approvalHaptic("arrival");
      }
    }
  }, [pending]);
}

/** Keeps the native push handler's machine names current, and opens tapped sudo pushes. */
function useSudoApprovalPushes(pending: readonly PendingElevationRequest[]): void {
  const presentations = useAtomValue(environmentPresentations.presentationsAtom);
  useEffect(() => {
    if (Platform.OS !== "android") return;
    setAndroidSudoApprovalMachines(
      Object.fromEntries(
        [...presentations].map(([environmentId, presentation]) => [
          environmentId,
          presentation.entry.target.label,
        ]),
      ),
    );
  }, [presentations]);

  // Startup is empty before it connects, so only clear once requests were seen and then left.
  const hadPending = useRef(false);
  useEffect(() => {
    if (pending.length > 0) hadPending.current = true;
    else if (hadPending.current) {
      hadPending.current = false;
      clearAndroidSudoApprovals();
    }
  }, [pending.length]);

  useEffect(
    () =>
      subscribeAndroidSudoApprovalOpens((open) => {
        const tappedAt = Date.now();
        const intent = parseElevationNotificationTap(open.path, tappedAt);
        if (intent === null) return;
        if (open.lockScreen) {
          appAtomRegistry.set(elevationLockScreenAtom, {
            intent,
            hideContent: androidLockScreen.hidesSensitiveContent(),
          });
        } else {
          rememberElevationNotificationTap(open.path, tappedAt);
        }
      }),
    [],
  );
}

const reenrollAskedKey = (alias: string) =>
  `t3-elevation-relock.${Base64Url.encode(new TextEncoder().encode(alias))}`;

/**
 * Keys from earlier builds required an unlocked phone, so they can't approve from the lock
 * screen. Asks once per key to set the phone up again, which replaces the key.
 */
function useLockScreenReenrollPrompt(): void {
  const presentations = useAtomValue(environmentPresentations.presentationsAtom);
  // Over the lock screen only the request's card may show; ask once the phone is unlocked.
  const lockScreen = useAtomValue(elevationLockScreenAtom);
  const navigation = useNavigation();
  const asked = useRef(false);
  useEffect(() => {
    if (asked.current || lockScreen !== null || !deviceApprovalSigner.isPresent()) return;
    let cancelled = false;
    void (async () => {
      for (const [environmentId, presentation] of presentations) {
        const record = await deviceApprovalKeys.read(environmentId);
        if (record === null || cancelled) continue;
        const alias = elevationKeyAlias(environmentId, record.user);
        const storageKey = reenrollAskedKey(alias);
        const [present, unlockedOnly, alreadyAsked] = await Promise.all([
          deviceApprovalSigner.hasKey(alias).catch(() => false),
          deviceApprovalSigner.signsWhileLocked(alias).then(
            (signs) => !signs,
            () => false,
          ),
          SecureStore.getItemAsync(storageKey),
        ]);
        if (cancelled || asked.current || !present || !unlockedOnly || alreadyAsked !== null) {
          continue;
        }
        if (androidLockScreen.isShowingOver()) return;
        asked.current = true;
        await SecureStore.setItemAsync(storageKey, "1");
        Dialog.confirm({
          title: "Approve from the lock screen",
          message: `Set this phone up again for ${presentation.entry.target.label} so one fingerprint approves while the phone is locked.`,
          cancelText: "Not now",
          confirmText: "Set up again",
          onConfirm: () =>
            navigation.navigate("SettingsSheet", {
              screen: "SettingsContent",
              params: { screen: "SettingsDeviceApproval" },
            }),
        });
        return;
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [lockScreen, navigation, presentations]);
}

/**
 * Shows the approval sheet for whichever request was opened, and opens the
 * request a tapped push was about once it reaches this phone.
 */
export function ElevationApprovalHost() {
  const pending = useAtomValue(elevation.pendingAcrossEnvironmentsAtom);
  const target = useAtomValue(elevationApprovalTargetAtom);
  const intent = useAtomValue(elevationNotificationIntentAtom);
  useArrivalHaptic(pending);
  useSudoApprovalPushes(pending);
  useLockScreenReenrollPrompt();

  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- consumes a tapped push once its request reaches this phone and opens its sheet
  useEffect(() => {
    if (intent === null) return;
    const match = pendingRequestForNotificationIntent(intent, pending, Date.now());
    if (match === null) return;
    appAtomRegistry.set(elevationNotificationIntentAtom, null);
    if (match !== "expired") {
      openElevationApproval({
        environmentId: match.environmentId,
        requestId: match.request.requestId,
      });
    }
  }, [intent, pending]);

  const entry =
    target === null
      ? undefined
      : pending.find(
          (candidate) =>
            candidate.environmentId === target.environmentId &&
            candidate.request.requestId === target.requestId,
        );
  // Answered here, elsewhere, or expired: the request left the pending list.
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- clears the open-sheet atom when its request is answered elsewhere or expires
  useEffect(() => {
    if (target !== null && entry === undefined) closeElevationApproval();
  }, [target, entry]);

  if (entry === undefined) return null;
  const { environmentId, request, decoded } = entry;
  return (
    <Sheet title="Approval needed" onClose={closeElevationApproval}>
      <ScrollView
        nestedScrollEnabled
        className="flex-1"
        contentInsetAdjustmentBehavior={Platform.OS === "ios" ? "automatic" : "never"}
        contentContainerClassName="px-5 pt-3 pb-8"
      >
        <ElevationApprovalCard
          key={request.requestId}
          inline={false}
          request={{
            environmentId,
            requestId: request.requestId,
            threadId: request.threadId,
            decoded,
            explanation: request.explanation,
            changes: request.changes,
          }}
          openChanges={(open) => {
            closeElevationApproval();
            open();
          }}
        />
      </ScrollView>
    </Sheet>
  );
}
