import Constants from "expo-constants";
import { requireOptionalNativeModule } from "expo";
import { Linking, Platform } from "react-native";

interface AndroidAgentNotifications {
  configure(deviceId: string, userId: string, scheme: string, ongoingEnabled: boolean): void;
  clear(): void;
  setThreadOnScreen?(path: string | null): void;
  openLiveUpdateSettings?(): boolean;
  showShowcaseActivity?(scheme: string, data: Record<string, string>): void;
  setSudoApprovalMachines?(machines: Record<string, string>): void;
  clearSudoApprovals?(): void;
  consumeSudoApprovalOpen?(): SudoApprovalOpen | null;
  isOverLockScreen?(): boolean;
  lockScreenHidesSensitiveContent?(): boolean;
  leaveLockScreen?(): void;
  requestUnlock?(): Promise<boolean>;
  addListener?(event: "onSudoApprovalOpened", listener: () => void): { remove(): void };
}

/** A tapped sudo approval push. */
export interface SudoApprovalOpen {
  /** `/threads/<environmentId>/<threadId>`, URI-encoded. */
  readonly path: string;
  /** Opened from the lock screen, so the app is showing over it. */
  readonly lockScreen: boolean;
}

const native =
  Platform.OS === "android"
    ? requireOptionalNativeModule<AndroidAgentNotifications>("T3AgentNotifications")
    : null;

export function supportsAndroidAgentNotifications(): boolean {
  return typeof native?.configure === "function" && typeof native?.clear === "function";
}

function appScheme(): string {
  const scheme = Constants.expoConfig?.scheme;
  return (Array.isArray(scheme) ? scheme[0] : scheme) ?? "t3code";
}

export function configureAndroidAgentNotifications(
  deviceId: string,
  userId: string,
  ongoingEnabled: boolean,
): void {
  native?.configure?.(deviceId, userId, appScheme(), ongoingEnabled);
}

export function showAndroidShowcaseAgentActivity(data: Record<string, string>): boolean {
  if (!native?.showShowcaseActivity) return false;
  native.showShowcaseActivity(appScheme(), data);
  return true;
}

export function clearAndroidAgentNotifications(): void {
  native?.clear?.();
}

export function setAndroidThreadOnScreen(path: string | null): void {
  native?.setThreadOnScreen?.(path);
}

export function supportsAndroidLiveUpdateSettings(): boolean {
  return Platform.OS === "android" && Number(Platform.Version) >= 36;
}

export async function openAndroidLiveUpdateSettings(): Promise<void> {
  if (!native?.openLiveUpdateSettings?.()) {
    await Linking.openSettings();
  }
}

/** Machine names as named on this phone, which sudo approval pushes show. */
export function setAndroidSudoApprovalMachines(machines: Record<string, string>): void {
  native?.setSudoApprovalMachines?.(machines);
}

export function clearAndroidSudoApprovals(): void {
  native?.clearSudoApprovals?.();
}

/** Calls `onOpen` for each tapped sudo push, including the one that started the app. */
export function subscribeAndroidSudoApprovalOpens(
  onOpen: (open: SudoApprovalOpen) => void,
): () => void {
  if (!native?.consumeSudoApprovalOpen) return () => {};
  const consume = () => {
    const open = native.consumeSudoApprovalOpen?.();
    if (open) onOpen(open);
  };
  const subscription = native.addListener?.("onSudoApprovalOpened", consume);
  consume();
  return () => subscription?.remove();
}

export const androidLockScreen = {
  isShowingOver: (): boolean => native?.isOverLockScreen?.() ?? false,
  /** Unreadable or unsupported counts as hidden. */
  hidesSensitiveContent: (): boolean => native?.lockScreenHidesSensitiveContent?.() ?? true,
  /** Stops showing over the lock screen and returns to it if the phone is still locked. */
  leave: (): void => native?.leaveLockScreen?.(),
  requestUnlock: (): Promise<boolean> => native?.requestUnlock?.() ?? Promise.resolve(false),
};
