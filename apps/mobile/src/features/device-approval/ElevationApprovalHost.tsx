import { useAtomValue } from "@effect/atom-react";
import type { PendingElevationRequest } from "@t3tools/client-runtime/state/elevation";
import { StackActions, useNavigation } from "@react-navigation/native";
import * as Base64Url from "effect/encoding/Base64Url";
import * as SecureStore from "expo-secure-store";
import { useEffect, useRef, useState } from "react";
import { AppState, Modal, Platform, ScrollView, View } from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";

import * as Dialog from "../../components/ui/Dialog";
import { SheetHeader } from "../../components/ui/SheetHeader";
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
import { approvalHaptic } from "./approvalHaptics";
import { ElevationApprovalCard } from "./ElevationApprovalCard";
import {
  claimedElevationRequestAtom,
  closeElevationApproval,
  elevationApprovalTargetAtom,
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
import { ELEVATION_SETTLE_MS } from "./elevationApproval";
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
            navigation.navigate("SettingsSheet", {
              screen: "SettingsContent",
              params: { screen: "SettingsDeviceApproval" },
            });
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
 * Opens whichever request was opened from the banner, a push or the lock screen: its thread,
 * which ends at the request's card, or a full-screen card for a request no thread owns.
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
  const lockScreen = useAtomValue(elevationLockScreenAtom);
  const navigation = useNavigation();
  useArrivalHaptic(pending);
  useSudoApprovalPushes(pending);
  useLockScreenReenrollPrompt();

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

  // Approved here: the request may leave the list before the answer returns, and "✓ Approved"
  // stays a moment after it does.
  const [held, setHeld] = useState<PendingElevationRequest | null>(null);
  const [settled, setSettled] = useState(false);
  useEffect(() => {
    if (!settled) return;
    const timer = setTimeout(() => {
      setHeld(null);
      setSettled(false);
      closeElevationApproval();
    }, ELEVATION_SETTLE_MS);
    return () => clearTimeout(timer);
  }, [settled]);

  const entry =
    held ??
    (target === null
      ? undefined
      : pending.find(
          (candidate) =>
            candidate.environmentId === target.environmentId &&
            candidate.request.requestId === target.requestId,
        ));
  const threadId = entry?.request.threadId ?? null;
  useEffect(() => {
    // Answered elsewhere, or expired: the request left the pending list.
    if (target !== null && entry === undefined) closeElevationApproval();
    if (entry === undefined || threadId === null || held !== null) return;
    closeElevationApproval();
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
  }, [target, entry, threadId, held, navigation, props.pathname]);

  // A Modal is its own window and would draw above the lock-screen cover, over the keyguard.
  if (entry === undefined || threadId !== null || lockScreen !== null) return null;
  return (
    <ThreadlessElevationRequest
      entry={entry}
      onApproving={(active) => setHeld(active ? entry : null)}
      onApproved={() => setSettled(true)}
    />
  );
}

/** A request no thread owns, such as one the server raised, on a full screen of its own. */
function ThreadlessElevationRequest(props: {
  readonly entry: PendingElevationRequest;
  readonly onApproving: (active: boolean) => void;
  readonly onApproved: () => void;
}) {
  const insets = useSafeAreaInsets();
  const { environmentId, request, decoded } = props.entry;
  return (
    <Modal
      visible
      animationType="slide"
      presentationStyle="fullScreen"
      statusBarTranslucent
      onRequestClose={closeElevationApproval}
    >
      <View className="flex-1 bg-background" style={{ paddingTop: insets.top }}>
        <SheetHeader presentation="inline" title="Admin request" onClose={closeElevationApproval} />
        <ScrollView
          className="flex-1"
          contentInsetAdjustmentBehavior={Platform.OS === "ios" ? "automatic" : "never"}
          contentContainerClassName="px-5 pt-3"
          contentContainerStyle={{ paddingBottom: insets.bottom + 24 }}
        >
          <ElevationApprovalCard
            key={request.requestId}
            request={{
              environmentId,
              requestId: request.requestId,
              threadId: null,
              decoded,
              explanation: request.explanation,
              changes: request.changes,
            }}
            onApproving={props.onApproving}
            onAnswered={(decision) => {
              if (decision === "approve") props.onApproved();
              else closeElevationApproval();
            }}
          />
        </ScrollView>
      </View>
    </Modal>
  );
}
