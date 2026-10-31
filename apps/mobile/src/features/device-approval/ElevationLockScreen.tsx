import { useAtomValue } from "@effect/atom-react";
import { useEffect, useRef, useState } from "react";
import { BackHandler, Modal, View } from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";

import { SymbolView } from "../../components/ui/AppSymbol";
import { AppText as Text } from "../../components/ui/AppText";
import { Button } from "../../components/ui/Button";
import { appAtomRegistry } from "../../state/atom-registry";
import { elevation } from "../../state/elevation";
import { androidLockScreen } from "../agent-awareness/androidNotifications";
import { ElevationApprovalCard } from "./ElevationApprovalCard";
import {
  elevationLockScreenAtom,
  openElevationApproval,
  pendingRequestForNotificationIntent,
} from "./elevationApprovalTarget";

// Matches the sheet: the approved state settles before the card goes away.
const SETTLE_MS = 750;
// The request normally arrives with the connection; past this it was answered or expired.
const ARRIVAL_TIMEOUT_MS = 15_000;

function leaveLockScreen(): void {
  appAtomRegistry.set(elevationLockScreenAtom, null);
  androidLockScreen.leave();
}

/**
 * A sudo push opened from the lock screen. The app is showing over the lock screen only for this
 * request, so this covers everything else and leaves as soon as the request is answered or gone.
 */
export function ElevationLockScreen() {
  const session = useAtomValue(elevationLockScreenAtom);
  if (session === null) return null;
  return <LockScreenRequest key={session.intent.tappedAt} />;
}

function LockScreenRequest() {
  const session = useAtomValue(elevationLockScreenAtom);
  const pending = useAtomValue(elevation.pendingAcrossEnvironmentsAtom);
  const insets = useSafeAreaInsets();
  const [now] = useState(() => Date.now());
  const shownRequest = useRef<string | null>(null);
  const [waitedOut, setWaitedOut] = useState(false);
  useEffect(() => {
    const timer = setTimeout(() => setWaitedOut(true), ARRIVAL_TIMEOUT_MS);
    return () => clearTimeout(timer);
  }, []);
  const match =
    session === null ? null : pendingRequestForNotificationIntent(session.intent, pending, now);

  useEffect(() => {
    const subscription = BackHandler.addEventListener("hardwareBackPress", () => {
      leaveLockScreen();
      return true;
    });
    return () => subscription.remove();
  }, []);

  // Answered on another device, or expired: nothing is left to show.
  const requestId = match !== null && match !== "expired" ? match.request.requestId : null;
  useEffect(() => {
    if (requestId !== null) shownRequest.current = requestId;
    else if (shownRequest.current !== null) leaveLockScreen();
  }, [requestId]);

  if (session === null) return null;

  const unlock = async (then?: () => void) => {
    if (!(await androidLockScreen.requestUnlock())) return;
    appAtomRegistry.set(elevationLockScreenAtom, null);
    if (then) then();
    else if (match !== null && match !== "expired") {
      openElevationApproval({
        environmentId: match.environmentId,
        requestId: match.request.requestId,
      });
    }
  };

  return (
    <Modal visible animationType="fade" statusBarTranslucent onRequestClose={leaveLockScreen}>
      <View
        className="flex-1 justify-end gap-4 bg-background px-4"
        style={{ paddingTop: insets.top + 16, paddingBottom: insets.bottom + 16 }}
      >
        <View className="flex-row items-center gap-1.5 self-center">
          <SymbolView
            name={{ ios: "lock", android: "lock" }}
            size={12}
            tintColorClassName="accent-icon"
          />
          <Text className="text-xs text-foreground-muted">Locked</Text>
        </View>
        <View className="gap-4 rounded-[20px] border border-border bg-card-alt p-4">
          {match !== null && match !== "expired" ? (
            <ElevationApprovalCard
              inline={false}
              request={{
                environmentId: match.environmentId,
                requestId: match.request.requestId,
                threadId: match.request.threadId,
                decoded: match.decoded,
                explanation: match.request.explanation,
                agentCommand: match.request.agentCommand,
                changes: match.request.changes,
              }}
              {...(session.hideContent ? { hidden: { onUnlock: () => void unlock() } } : {})}
              onAnswered={() => setTimeout(leaveLockScreen, SETTLE_MS)}
              openChanges={(open) => void unlock(open)}
            />
          ) : (
            <>
              <Text className="text-base text-foreground">
                {match === "expired" || waitedOut
                  ? "This request isn't waiting anymore."
                  : "Getting the request…"}
              </Text>
              <Button label="Close" tone="secondary" fullWidth onPress={leaveLockScreen} />
            </>
          )}
        </View>
      </View>
    </Modal>
  );
}
