import * as Haptics from "expo-haptics";
import { Platform } from "react-native";

/** The success confirm for setup and a repair that checked out (FLOW: haptics). */
export function confirmHaptic(): void {
  void (
    Platform.OS === "android"
      ? Haptics.performAndroidHapticsAsync(Haptics.AndroidHaptics.Confirm)
      : Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success)
  ).catch(() => undefined);
}
