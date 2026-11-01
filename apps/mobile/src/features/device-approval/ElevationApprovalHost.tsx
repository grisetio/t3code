import { useAtomValue } from "@effect/atom-react";
import type { PendingElevationRequest } from "@t3tools/client-runtime/state/elevation";
import { StackActions, useNavigation } from "@react-navigation/native";
import * as Base64Url from "effect/encoding/Base64Url";
import * as SecureStore from "expo-secure-store";
import { useEffect, useRef } from "react";
import { AppState, Platform } from "react-native";

import * as Dialog from "../../components/ui/Dialog";
import { appAtomRegistry } from "../../state/atom-registry";
import { elevation } from "../../state/elevation";
import { environmentPresentations } from "../../state/presentation";
import {
  androidLockScreen,
  clearAndroidSudoApprovals,
  setAndroidSudoApprovalMachines,
  setAndroidSudoPendingThreads,
  subscribeAndroidSudoApprovalOpens,
} from "../agent-awareness/androidNotifications";
import {
  encodeThreadDeepLink,
  threadDeepLinkOnScreen,
} from "../agent-awareness/notificationPayload";
import { useAdaptiveWorkspaceLayout } from "../layout/adaptive-workspace-context";
import { useSelectWorkspaceTab } from "../workspace/useSelectWorkspaceTab";
import { approvalHaptic } from "./approvalHaptics";
import {
  claimedElevationRequestAtom,
  closeElevationApproval,
  elevationApprovalTargetAtom,
  elevationListHighlightAtom,
  isClaimedElevationRequest,
  elevationLockScreenAtom,
  elevationNotificationIntentAtom,
  openElevationApproval,
  parseElevationNotificationTap,
  pendingRequestForNotificationIntent,
  rememberElevationNotificationTap,
} from "./elevationApprovalTarget";
import { requestDeviceApprovalRekey } from "./deviceApprovalRekey";
import { deviceApprovalKeys } from "./deviceApprovalKeys";
import { deviceApprovalSigner } from "./deviceApprovalSigner";

// A request created this recently is arriving now, not found on reconnect.
const ARRIVAL_WINDOW_MS = 10_000;

/** One soft tick per request as it arrives, wherever it shows. */
function useArrivalHaptic(pending: readonly PendingElevationRequest[]): void {
  const seen = useRef(new Set<string>());
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- fires one haptic per newly arrived request
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

/**
 * Keeps the native push handler's machine names current, tells it which threads have a request
 * waiting so their pushes don't repeat what the app shows, and opens tapped sudo pushes.
 */
function useSudoApprovalPushes(pending: readonly PendingElevationRequest[]): void {
  const presentations = useAtomValue(environmentPresentations.presentationsAtom);
  const threadPaths = pending
    .flatMap(({ environmentId, request }) =>
      request.threadId === null
        ? []
        : [encodeThreadDeepLink({ environmentId, threadId: request.threadId })],
    )
    .join("\n");
  // Reported only while the app is in front: in the background the push is the only entry.
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- mirrors the threads with pending sudo into the native push handler while the app is in front
  useEffect(() => {
    if (Platform.OS !== "android") return;
    const report = (state: string | null | undefined) =>
      setAndroidSudoPendingThreads(
        state === "active" && threadPaths !== "" ? threadPaths.split("\n") : [],
      );
    report(AppState.currentState);
    const subscription = AppState.addEventListener("change", report);
    return () => subscription.remove();
  }, [threadPaths]);
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- mirrors environment labels into the native push handler
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
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- clears the native sudo notifications once pending requests are gone
  useEffect(() => {
    if (pending.length > 0) hadPending.current = true;
    else if (hadPending.current) {
      hadPending.current = false;
      clearAndroidSudoApprovals();
    }
  }, [pending.length]);

  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- subscribes to native sudo notification taps while mounted
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
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- reads key state from the native keystore and shows the re-enroll dialog once
  useEffect(() => {
    if (asked.current || lockScreen !== null || !deviceApprovalSigner.isPresent()) return;
    let cancelled = false;
    void (async () => {
      for (const [environmentId, presentation] of presentations) {
        const record = await deviceApprovalKeys.read(environmentId);
        if (record === null || cancelled) continue;
        const { alias } = record;
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
          onConfirm: () => {
            requestDeviceApprovalRekey(environmentId);
            navigation.navigate("SettingsDeviceApproval");
          },
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
 * The threads list, where requests no thread claims wait: the sidebar in a split view, otherwise
 * the Threads tab at the root of the stack.
 */
function useOpenThreadsList(): () => void {
  const { layout, revealPrimarySidebar } = useAdaptiveWorkspaceLayout();
  const selectTab = useSelectWorkspaceTab();
  return () => {
    selectTab("threads");
    if (layout.usesSplitView) revealPrimarySidebar();
  };
}

/**
 * Opens whichever request was opened from the banner, a push or the lock screen: its thread,
 * which ends at the request's card, or the threads list, which holds requests no thread claims.
 */
export function ElevationApprovalHost(props: { readonly pathname: string }) {
  const allPending = useAtomValue(elevation.pendingAcrossEnvironmentsAtom);
  const claim = useAtomValue(claimedElevationRequestAtom);
  const pending =
    claim === null
      ? allPending
      : allPending.filter((entry) => !isClaimedElevationRequest(claim, entry));
  const target = useAtomValue(elevationApprovalTargetAtom);
  const intent = useAtomValue(elevationNotificationIntentAtom);
  const navigation = useNavigation();
  const openThreadsList = useOpenThreadsList();
  useArrivalHaptic(pending);
  useSudoApprovalPushes(pending);
  useLockScreenReenrollPrompt();

  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- consumes a tapped push once its request reaches this phone and opens it
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
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- moves an opened request to its thread's card, or to the threads list when no thread claims it
  useEffect(() => {
    if (target === null) return;
    closeElevationApproval();
    // Answered elsewhere, or expired: the request left the pending list.
    if (entry === undefined) return;
    const { threadId } = entry.request;
    if (threadId === null) {
      appAtomRegistry.set(elevationListHighlightAtom, target);
      openThreadsList();
      return;
    }
    const link = encodeThreadDeepLink({ environmentId: entry.environmentId, threadId });
    // Pushed, so Back returns to wherever the request was opened from.
    if (link !== threadDeepLinkOnScreen(props.pathname)) {
      navigation.dispatch(
        StackActions.push("Thread", {
          environmentId: String(entry.environmentId),
          threadId: String(threadId),
        }),
      );
    }
  }, [target, entry, navigation, openThreadsList, props.pathname]);

  return null;
}
