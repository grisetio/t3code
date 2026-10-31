import * as Haptics from "expo-haptics";
import { Platform } from "react-native";

export type ApprovalHaptic = "arrival" | "approved" | "denied" | "done" | "setupComplete";

// Android's standard constants follow the system haptics setting. CONFIRM and REJECT need API 30
// and the segment ticks API 34; older versions get the closest earlier constant.
function androidHaptic(kind: ApprovalHaptic, api: number): Haptics.AndroidHaptics {
  switch (kind) {
    case "arrival":
      return api >= 34
        ? Haptics.AndroidHaptics.Segment_Frequent_Tick
        : Haptics.AndroidHaptics.Clock_Tick;
    case "done":
      return api >= 34 ? Haptics.AndroidHaptics.Segment_Tick : Haptics.AndroidHaptics.Clock_Tick;
    case "approved":
    case "setupComplete":
      return api >= 30 ? Haptics.AndroidHaptics.Confirm : Haptics.AndroidHaptics.Context_Click;
    case "denied":
      return api >= 30 ? Haptics.AndroidHaptics.Reject : Haptics.AndroidHaptics.Keyboard_Tap;
  }
}

export function approvalHaptic(kind: ApprovalHaptic): void {
  const done =
    Platform.OS === "android"
      ? Haptics.performAndroidHapticsAsync(androidHaptic(kind, Number(Platform.Version)))
      : kind === "approved" || kind === "setupComplete"
        ? Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success)
        : kind === "denied"
          ? Haptics.notificationAsync(Haptics.NotificationFeedbackType.Warning)
          : Haptics.selectionAsync();
  // Haptics are best effort; a phone without a vibrator rejects.
  void done.catch(() => undefined);
}
