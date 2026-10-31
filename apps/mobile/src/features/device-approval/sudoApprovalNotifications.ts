import { requireOptionalNativeModule } from "expo";
import { useEffect, useState } from "react";
import { AppState, Linking, Platform } from "react-native";

// The Android "Sudo approvals" channel is the notification setting; T3 keeps
// no copy. iOS has no channels, so the row is Android-only for now.

type ChannelState = "on" | "off" | "app_off" | "missing";

interface NativeSudoApprovalChannel {
  state(): ChannelState;
  openSettings(): boolean;
}

const native =
  Platform.OS === "android"
    ? requireOptionalNativeModule<NativeSudoApprovalChannel>("T3SudoApprovalChannel")
    : null;

export function supportsSudoApprovalNotifications(): boolean {
  return native !== null;
}

function readOn(): boolean | null {
  if (native === null) return null;
  const state = native.state();
  return state === "on" || state === "missing";
}

/**
 * On or off, re-read whenever the app returns to the foreground, since the
 * user changes it in Android's settings. A channel not created yet starts on.
 */
export function useSudoApprovalNotificationsOn(): boolean | null {
  const [on, setOn] = useState(readOn);
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- re-reads the Android channel setting when the app returns to the foreground
  useEffect(() => {
    if (native === null) return;
    const subscription = AppState.addEventListener("change", (state) => {
      if (state === "active") setOn(readOn());
    });
    return () => subscription.remove();
  }, []);
  return on;
}

export async function openSudoApprovalNotificationSettings(): Promise<void> {
  if (!native?.openSettings()) await Linking.openSettings();
}
