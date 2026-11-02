import { useAtomValue } from "@effect/atom-react";
import {
  ELEVATION_CANT_APPROVE_HERE,
  elevationFailureMessage,
  type ElevationPasswordWords,
} from "@t3tools/client-runtime/elevation";
import {
  deviceApprovalCheckOwner,
  deviceApprovalFailingChecks,
  deviceApprovalFixSheetText,
  deviceApprovalState,
  deviceApprovalTurnOff,
  planDeviceApprovalFix,
  type DeviceApprovalFixPlan,
  type DeviceApprovalRepairAttempt,
  type DeviceApprovalState,
} from "@t3tools/client-runtime/elevation-fix";
import {
  environmentSupportsDeviceApproval,
  type PendingElevationRequest,
} from "@t3tools/client-runtime/state/elevation";
import {
  isAtomCommandInterrupted,
  squashAtomCommandFailure,
  type AtomCommandResult,
} from "@t3tools/client-runtime/state/runtime";
import {
  resolveEnvironmentMachineKind,
  type ElevationCheck,
  type ElevationStatus,
  type EnvironmentId,
} from "@t3tools/contracts";
import * as Result from "effect/Result";
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { Platform, Pressable, View } from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { useResolveClassNames } from "uniwind";

import { ENVIRONMENT_MACHINE_SYMBOLS } from "../../components/EnvironmentMachineSymbol";
import { AppText as Text, AppTextInput as TextInput } from "../../components/ui/AppText";
import { SymbolView, type AppSymbolName } from "../../components/ui/AppSymbol";
import { Button } from "../../components/ui/Button";
import * as Dialog from "../../components/ui/Dialog";
import { ListActionRow } from "../../components/ui/ListActionRow";
import { ListRowLayout } from "../../components/ui/ListRowLayout";
import { RowPressable } from "../../components/ui/RowPressable";
import { ScreenScrollView as ScrollView } from "../../components/ui/ScreenScrollView";
import { Sheet } from "../../components/ui/Sheet";
import { cn } from "../../lib/cn";
import { appAtomRegistry } from "../../state/atom-registry";
import { elevation } from "../../state/elevation";
import { useEnvironments } from "../../state/environments";
import { useEnvironmentQuery } from "../../state/query";
import { useAtomCommand } from "../../state/use-atom-command";
import { SettingsRow } from "../settings/components/SettingsRow";
import { SettingsScreen } from "../settings/components/SettingsScreen";
import { SettingsSection } from "../settings/components/SettingsSection";
import { approvalHaptic } from "./approvalHaptics";
import {
  confirmPhoneKey,
  createPhoneKey,
  discardPhoneKey,
  type PhoneKey,
} from "./deviceApprovalEnrollment";
import { deviceApprovalKeys, type DeviceApprovalKeyRecord } from "./deviceApprovalKeys";
import { clearDeviceApprovalRekey, deviceApprovalRekeyAtom } from "./deviceApprovalRekey";
import {
  deviceApprovalSigner,
  deviceApprovalSignerErrorCode,
  deviceApprovalSignerErrorMessage,
} from "./deviceApprovalSigner";
import { DeviceApprovalSetupFlow } from "./DeviceApprovalSetupFlow";
import { useElevationPasswordWords } from "./ElevationApprovalCard";
import { prepareElevationSigning, removeThisPhoneMessage } from "./elevationApproval";
import { claimedElevationRequestAtom } from "./elevationApprovalTarget";
import { formatDeviceUse } from "./settings-device-dates";
import {
  openSudoApprovalNotificationSettings,
  useSudoApprovalNotificationsOn,
} from "./sudoApprovalNotifications";
import { useDeviceApprovalAgentHandoff } from "./useDeviceApprovalAgentHandoff";

const STATE_LABELS = { on: "On", needs_fixing: "Needs fixing", off: "Off" } as const;
// Long enough to read "T3 couldn't fix this one" before the thread opens.
const HANDOFF_NOTICE_MS = 1400;
// "✓ Removed" stays this long before the row goes.
const REMOVED_MS = 600;
const FINGERPRINT = { ios: "touchid", android: "fingerprint" } as const;
const REKEY_SHEET = { kind: "rekey" } as const;

interface SetupTarget {
  readonly environmentId: EnvironmentId;
  readonly machine: string;
  readonly status: ElevationStatus;
}

export function SettingsDeviceApprovalRouteScreen() {
  const insets = useSafeAreaInsets();
  const { environments } = useEnvironments();
  const [setup, setSetup] = useState<SetupTarget | null>(null);
  const supported = environments.filter((environment) =>
    environmentSupportsDeviceApproval(environment.serverConfig),
  );
  // The Notifications row only matters once some machine has device approval on.
  const [onSomewhere, setOnSomewhere] = useState<ReadonlySet<EnvironmentId>>(() => new Set());
  const reportState = useCallback((environmentId: EnvironmentId, state: DeviceApprovalState) => {
    setOnSomewhere((current) => {
      if (current.has(environmentId) === (state !== "off")) return current;
      const next = new Set(current);
      if (state === "off") next.delete(environmentId);
      else next.add(environmentId);
      return next;
    });
  }, []);
  return (
    <SettingsScreen title="Device approval">
      {setup !== null ? (
        <DeviceApprovalSetupFlow
          environmentId={setup.environmentId}
          machine={setup.machine}
          status={setup.status}
          onClose={() => setSetup(null)}
        />
      ) : (
        <ScrollView
          contentInsetAdjustmentBehavior="automatic"
          showsVerticalScrollIndicator={false}
          className="flex-1"
          contentContainerClassName="gap-4 px-5 pt-4"
          contentContainerStyle={{ paddingBottom: Math.max(insets.bottom, 18) + 18 }}
        >
          {supported.length === 0 ? (
            <Text className="text-sm text-foreground-muted">
              No connected machine offers device approval.
            </Text>
          ) : (
            <>
              {supported.map((environment) => (
                <EnvironmentDeviceApproval
                  key={environment.environmentId}
                  environmentId={environment.environmentId}
                  // The phone's own name for the machine, never the server's.
                  machine={environment.label}
                  icon={
                    ENVIRONMENT_MACHINE_SYMBOLS[
                      resolveEnvironmentMachineKind(environment.serverConfig)
                    ]
                  }
                  onSetUp={setSetup}
                  onState={reportState}
                />
              ))}
              {supported.some((environment) => onSomewhere.has(environment.environmentId)) ? (
                <NotificationsRow />
              ) : null}
            </>
          )}
        </ScrollView>
      )}
    </SettingsScreen>
  );
}

/** Mirrors Android's "Sudo approvals" channel; the switch itself lives in Android's settings. */
function NotificationsRow() {
  const on = useSudoApprovalNotificationsOn();
  if (on === null) return null;
  return (
    <SettingsSection>
      <SettingsRow
        icon="bell.badge"
        label="Notifications"
        value={on ? "On" : "Off · Requests show only in the app"}
        onPress={() => void openSudoApprovalNotificationSettings()}
      />
    </SettingsSection>
  );
}

function useKeyRecord(environmentId: EnvironmentId) {
  const [record, setRecord] = useState<DeviceApprovalKeyRecord | null | undefined>(undefined);
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- reads this environment's key record from the native keystore
  useEffect(() => {
    let cancelled = false;
    void deviceApprovalKeys.read(environmentId).then((value) => {
      if (!cancelled) setRecord(value);
    });
    return () => {
      cancelled = true;
    };
  }, [environmentId]);
  return [record, setRecord] as const;
}

function EnvironmentDeviceApproval(props: {
  readonly environmentId: EnvironmentId;
  readonly machine: string;
  readonly icon: AppSymbolName;
  readonly onSetUp: (target: SetupTarget) => void;
  readonly onState: (environmentId: EnvironmentId, state: DeviceApprovalState) => void;
}) {
  const status = useEnvironmentQuery(
    elevation.status({ environmentId: props.environmentId, input: {} }),
  );
  if (status.data === null) {
    return (
      <SettingsSection>
        <ListRowLayout
          icon={props.icon}
          label={props.machine}
          description={status.error ?? "Checking this machine…"}
        />
        {status.error === null ? null : (
          <ListActionRow icon="arrow.clockwise" label="Retry" onPress={status.refresh} />
        )}
      </SettingsSection>
    );
  }
  return (
    <DeviceApprovalGroup
      environmentId={props.environmentId}
      machine={props.machine}
      icon={props.icon}
      status={status.data}
      onSetUp={props.onSetUp}
      onState={props.onState}
    />
  );
}

type Phase = "idle" | "checking" | "handoff";

type KeySheet =
  | { readonly kind: "fix"; readonly plan: Extract<DeviceApprovalFixPlan, { kind: "repair" }> }
  | typeof REKEY_SHEET;

function DeviceApprovalGroup(props: {
  readonly environmentId: EnvironmentId;
  readonly machine: string;
  readonly icon: AppSymbolName;
  readonly status: ElevationStatus;
  readonly onSetUp: (target: SetupTarget) => void;
  readonly onState: (environmentId: EnvironmentId, state: DeviceApprovalState) => void;
}) {
  const { environmentId, machine, status, onState } = props;
  const [record, setRecord] = useKeyRecord(environmentId);
  const [phase, setPhase] = useState<Phase>("idle");
  const [keySheet, setKeySheet] = useState<KeySheet | null>(null);
  const [turningOff, setTurningOff] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  // "Used today" only needs the day, so the time the page opened is enough.
  const [now] = useState(Date.now);
  const handoff = useDeviceApprovalAgentHandoff();
  const revoke = useAtomCommand(elevation.revoke, "revoke device approval key");
  const canInstall = useAtomValue(elevation.install.permissionAtom(environmentId));
  const canEnroll = useAtomValue(elevation.enroll.permissionAtom(environmentId));
  const canRevoke = useAtomValue(elevation.revoke.permissionAtom(environmentId));
  const canUninstall = useAtomValue(elevation.uninstall.permissionAtom(environmentId));
  const rekeyRequested = useAtomValue(deviceApprovalRekeyAtom) === environmentId;
  const signerPresent = deviceApprovalSigner.isPresent();
  const words = useElevationPasswordWords(environmentId, machine);

  const phoneRecord = record && record.user === status.user ? record : null;
  const phone = { keyId: phoneRecord?.keyId ?? null };
  const state = status.supported ? deviceApprovalState(status, phone) : "off";
  const thisDevice = status.devices.find((device) => device.keyId === phoneRecord?.keyId);
  const canRepair = signerPresent && status.user !== undefined && canInstall && canEnroll;
  const turnOff = deviceApprovalTurnOff(status);

  const forgetThisPhone = async () => {
    if (phoneRecord !== null) await discardPhoneKey(phoneRecord.alias);
    await deviceApprovalKeys.remove(environmentId);
    setRecord(null);
  };

  const removal = useRemoveThisPhone({
    environmentId,
    machine,
    otherApprovers: status.devices
      .filter((device) => device.keyId !== phoneRecord?.keyId)
      .map((device) => device.label),
    record: phoneRecord,
    onRemoved: () => {
      setDetailsOpen(false);
      void forgetThisPhone();
    },
  });

  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- reports this machine's state to the screen's header row
  useEffect(() => onState(environmentId, state), [environmentId, onState, state]);

  // "Set up again" from the lock-screen prompt lands here and goes straight to the fingerprint.
  // The request stays in its atom while the sheet is open, so the sheet is derived from it.
  const rekeyOpen = rekeyRequested && phoneRecord !== null && canRepair;
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- drops a lock-screen rekey request this phone can't act on once its key record is known
  useEffect(() => {
    if (rekeyRequested && record !== undefined && !rekeyOpen) clearDeviceApprovalRekey();
  }, [rekeyRequested, record, rekeyOpen]);
  // Leaving the page drops the request, so the sheet doesn't reopen on a later visit.
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- drops the pending rekey request when the page unmounts
  useEffect(() => clearDeviceApprovalRekey, []);
  const sheet = keySheet ?? (rekeyOpen ? REKEY_SHEET : null);
  const closeSheet = () => {
    setKeySheet(null);
    if (rekeyRequested) clearDeviceApprovalRekey();
  };

  if (!status.supported) {
    return (
      <SettingsSection
        footer={status.unsupportedReason ?? "Agents' sudo keeps asking for the password here."}
      >
        <MachineRow icon={props.icon} machine={machine} trail="Off" />
      </SettingsSection>
    );
  }

  const setUp = () => props.onSetUp({ environmentId, machine, status });

  const handOff = (current: ElevationStatus, repair: DeviceApprovalRepairAttempt | null) =>
    handoff({
      purpose: "fix",
      environmentId,
      machine,
      status: current,
      failing: deviceApprovalFailingChecks(current, phone),
      repair,
    });

  const fix = () => {
    const plan = planDeviceApprovalFix(status, phone, { canRepair });
    switch (plan.kind) {
      case "none":
        return;
      case "agent":
        return void handOff(status, null);
      case "phone":
        return Dialog.alert("This phone can't repair it", ELEVATION_CANT_APPROVE_HERE);
      case "repair":
        return setKeySheet({ kind: "fix", plan });
    }
  };

  const startTurnOff = () =>
    turnOff === "uninstall"
      ? Dialog.confirm({
          title: "Turn off device approval?",
          message: `Agents' sudo on ${machine} will ask for the password again, and every phone stops approving there.`,
          confirmText: "Turn off",
          destructive: true,
          onConfirm: () => setTurningOff(true),
        })
      : Dialog.confirm({
          title: "Turn off device approval?",
          message: `Its setup on ${machine} comes from config outside T3, so an agent removes it there.`,
          confirmText: "Ask an agent",
          destructive: true,
          onConfirm: () =>
            void handoff({
              purpose: "turn_off",
              environmentId,
              machine,
              status,
              failing: [],
              repair: null,
            }),
        });

  const revokeOther = (keyId: string, label: string) =>
    Dialog.confirm({
      title: `Remove ${label}?`,
      message: `It will no longer approve sudo on ${machine}.`,
      confirmText: "Remove",
      destructive: true,
      onConfirm: () =>
        void (async () => {
          setBusy(keyId);
          setError(null);
          const result = await revoke({ environmentId, input: { keyId } }).finally(() =>
            setBusy(null),
          );
          if (result._tag !== "Success") setError(failureText(result));
        })(),
    });

  /** After T3's repair: done if the checks pass, otherwise an agent takes it with the diagnosis. */
  const afterRepair = (
    current: ElevationStatus,
    nextPhone: { readonly keyId: string | null },
    repair: DeviceApprovalRepairAttempt,
    expectedAgent: boolean,
  ) => {
    const remaining = deviceApprovalFailingChecks(current, nextPhone);
    if (remaining.length === 0 && current.ready) {
      setPhase("idle");
      approvalHaptic("setupComplete");
      return;
    }
    const plan = planDeviceApprovalFix(current, nextPhone, { canRepair });
    const next = {
      purpose: "fix" as const,
      environmentId,
      machine,
      status: current,
      failing: remaining,
      repair,
    };
    // Only the parts already meant for an agent remain: continue straight on.
    if (expectedAgent && plan.kind === "agent" && repair.error === null) {
      setPhase("idle");
      void handoff(next);
      return;
    }
    setPhase("handoff");
    setTimeout(() => {
      setPhase("idle");
      void handoff(next);
    }, HANDOFF_NOTICE_MS);
  };

  const offLine = `Approve agents' sudo on ${machine} with this phone.`;
  const canSetUp = signerPresent && status.user !== undefined;
  const addThisPhone = state === "on" && thisDevice === undefined && canSetUp;
  const footer =
    state === "off"
      ? canSetUp
        ? offLine
        : offReason(signerPresent)
      : addThisPhone
        ? offLine
        : state === "on" && thisDevice !== undefined
          ? `Agents' sudo on ${machine} waits for your fingerprint on this phone.`
          : undefined;
  const description =
    phase === "checking"
      ? "Checking…"
      : phase === "handoff"
        ? "T3 couldn't fix this one, so an agent will."
        : state === "needs_fixing"
          ? "Agents' sudo will ask for the password"
          : undefined;
  const checks = status.checks.filter((check) => !(check.id === "devices" && check.ok));
  // Removing runs the root-owned helper; without it the helper check in Details says why.
  const canRemove =
    status.helperInstalled && thisDevice !== undefined && phoneRecord !== null && signerPresent;
  const otherDevices = status.devices.filter((device) => device.keyId !== thisDevice?.keyId);

  return (
    <>
      <SettingsSection footer={footer}>
        <MachineRow
          icon={props.icon}
          machine={machine}
          trail={STATE_LABELS[state]}
          description={description}
          warn={state === "needs_fixing"}
        />
        {phase !== "idle" ? null : state === "off" ? (
          canSetUp ? (
            <ListActionRow
              icon={FINGERPRINT}
              label="Set up"
              disabled={!canInstall}
              onPress={setUp}
            />
          ) : null
        ) : state === "needs_fixing" ? (
          <ListActionRow icon="hammer" label="Fix" onPress={fix} />
        ) : addThisPhone ? (
          <ListActionRow icon="plus" label="Add this phone" disabled={!canEnroll} onPress={setUp} />
        ) : null}
        {state === "off" ? null : (
          <>
            <DetailsRow open={detailsOpen} onPress={() => setDetailsOpen((open) => !open)} />
            {detailsOpen ? (
              <View className="pb-2">
                {checks.map((check) => (
                  <CheckLine key={check.id} check={check} />
                ))}
              </View>
            ) : null}
            {turnOff !== null ? (
              <ListActionRow
                icon="slash.circle"
                label="Turn off"
                tone="danger"
                disabled={turnOff === "uninstall" && !canUninstall}
                onPress={startTurnOff}
              />
            ) : null}
          </>
        )}
      </SettingsSection>
      {state === "off" || thisDevice === undefined ? null : (
        // Remove sits with the row it removes, apart from the phones it leaves approving.
        <SettingsSection title="This phone">
          <ListRowLayout
            icon="iphone"
            label={thisDevice.label}
            description={formatDeviceUse(thisDevice, now)}
          />
          {canRemove ? (
            removal.phase === "removed" ? (
              <ListRowLayout icon="checkmark" label="Removed" />
            ) : (
              <ListActionRow
                icon="trash"
                label="Remove this phone"
                tone="danger"
                disabled={!canRevoke || busy !== null}
                loading={removal.phase === "waiting" && !removal.needsPassword}
                onPress={removal.confirm}
              />
            )
          ) : null}
        </SettingsSection>
      )}
      {state === "off" || otherDevices.length === 0 ? null : (
        <SettingsSection title={thisDevice === undefined ? "Phones" : "Other phones"}>
          {otherDevices.map((device) =>
            status.helperInstalled ? (
              <ListActionRow
                key={device.keyId}
                icon="iphone"
                label={device.label}
                description={formatDeviceUse(device, now)}
                disabled={!canRevoke || busy !== null}
                loading={busy === device.keyId}
                onPress={() => revokeOther(device.keyId, device.label)}
              />
            ) : (
              <ListRowLayout
                key={device.keyId}
                icon="iphone"
                label={device.label}
                description={formatDeviceUse(device, now)}
              />
            ),
          )}
        </SettingsSection>
      )}
      {(error ?? removal.error) !== null && !removal.needsPassword ? (
        <Text accessibilityRole="alert" className="px-4 text-sm text-danger-foreground">
          {error ?? removal.error}
        </Text>
      ) : null}
      {sheet !== null && status.user !== undefined ? (
        <KeySheetView
          environmentId={environmentId}
          machine={machine}
          words={words}
          user={status.user}
          status={status}
          record={phoneRecord}
          sheet={sheet}
          onClose={closeSheet}
          onStarted={() => {
            closeSheet();
            setDetailsOpen(false);
            setPhase("checking");
          }}
          onRecord={setRecord}
          onFinished={(current, nextPhone, repair) =>
            afterRepair(current, nextPhone, repair, sheet.kind === "fix" && sheet.plan.agentAfter)
          }
        />
      ) : null}
      {removal.needsPassword && phoneRecord !== null ? (
        <RemovePasswordSheet
          machine={machine}
          words={words}
          busy={removal.phase === "waiting"}
          error={removal.error}
          onClose={removal.dismissPassword}
          onSubmit={removal.removeWithPassword}
        />
      ) : null}
      {turningOff ? (
        <TurnOffSheet
          environmentId={environmentId}
          machine={machine}
          words={words}
          onClose={() => setTurningOff(false)}
          onTurnedOff={() => {
            setTurningOff(false);
            setDetailsOpen(false);
            void forgetThisPhone();
          }}
        />
      ) : null}
    </>
  );
}

const offReason = (signerPresent: boolean) =>
  signerPresent
    ? "Update T3 on this machine to set up device approval from here."
    : ELEVATION_CANT_APPROVE_HERE;

function MachineRow(props: {
  readonly icon: AppSymbolName;
  readonly machine: string;
  readonly trail: string;
  readonly description?: string;
  readonly warn?: boolean;
}) {
  return (
    <ListRowLayout
      icon={props.icon}
      label={props.machine}
      description={props.description}
      detail={props.trail}
      accessory={
        props.warn ? (
          <SymbolView
            name="exclamationmark.triangle"
            size={18}
            tintColorClassName="accent-warning-foreground"
            type="monochrome"
          />
        ) : undefined
      }
    />
  );
}

function DetailsRow(props: { readonly open: boolean; readonly onPress: () => void }) {
  const rippleStyle = useResolveClassNames("bg-subtle-strong");
  return (
    <RowPressable
      accessibilityRole="button"
      accessibilityLabel="Details"
      accessibilityState={{ expanded: props.open }}
      onPress={props.onPress}
      android_ripple={{ color: rippleStyle.backgroundColor }}
      unstable_pressDelay={Platform.OS === "android" ? 50 : undefined}
      className="bg-grouped-card"
    >
      <ListRowLayout
        icon="info.circle"
        label="Details"
        accessory={
          <SymbolView
            name={props.open ? "chevron.up" : "chevron.down"}
            size={16}
            tintColorClassName="accent-chevron"
            type="monochrome"
            weight="semibold"
          />
        }
      />
    </RowPressable>
  );
}

/** One line per check; a tap shows the whole sentence when its path doesn't fit. */
function CheckLine(props: { readonly check: ElevationCheck }) {
  const { check } = props;
  const [full, setFull] = useState(false);
  const owner = check.ok ? null : deviceApprovalCheckOwner(check);
  const text = owner === null ? check.message : `${check.message} · ${owner}`;
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={check.ok ? text : `Failing: ${text}`}
      accessibilityState={{ expanded: full }}
      onPress={() => setFull((value) => !value)}
      className="flex-row items-start gap-3 px-4 py-1.5"
    >
      <View className="size-6 items-center justify-center">
        <SymbolView
          name={check.ok ? "checkmark" : "xmark"}
          size={14}
          tintColorClassName={
            check.ok ? "accent-adaptive-emerald-600" : "accent-warning-foreground"
          }
          type="monochrome"
        />
      </View>
      <Text
        textRole="footnote"
        selectable={full}
        numberOfLines={full ? undefined : 1}
        ellipsizeMode="middle"
        className="min-w-0 flex-1 pt-0.5 text-foreground-muted"
      >
        {text}
      </Text>
    </Pressable>
  );
}

function failureReason(result: AtomCommandResult<unknown, unknown>): string | null {
  if (result._tag !== "Failure") return null;
  const failure = squashAtomCommandFailure(result);
  return typeof failure === "object" &&
    failure !== null &&
    "reason" in failure &&
    typeof failure.reason === "string"
    ? failure.reason
    : null;
}

const failureText = (result: AtomCommandResult<unknown, unknown>) =>
  result._tag !== "Failure" || isAtomCommandInterrupted(result)
    ? null
    : elevationFailureMessage(squashAtomCommandFailure(result), "Something went wrong.");

/**
 * Android's titled Sheet adds an app bar with its own back arrow, a second tone and a second way
 * out next to the grabber; a Material bottom sheet carries its heading in the content instead.
 * iOS keeps the native header, whose close button is the sheet's only way out.
 */
function PasswordSheet(props: {
  readonly title: string;
  readonly onClose: () => void;
  readonly children: ReactNode;
}) {
  const android = Platform.OS === "android";
  return (
    <Sheet title={android ? undefined : props.title} onClose={props.onClose}>
      <View className={cn("gap-4 px-5 pb-8", android ? "pt-1" : "pt-3")}>
        {android ? (
          <Text accessibilityRole="header" className="text-xl font-t3-medium text-foreground">
            {props.title}
          </Text>
        ) : null}
        {props.children}
      </View>
    </Sheet>
  );
}

function PasswordField(props: {
  readonly words: ElevationPasswordWords;
  readonly value: string;
  readonly onChange: (value: string) => void;
  readonly editable: boolean;
}) {
  return (
    <TextInput
      accessibilityLabel={props.words.password}
      placeholder={props.words.password}
      value={props.value}
      onChangeText={props.onChange}
      editable={props.editable}
      secureTextEntry
      autoCorrect={false}
      autoCapitalize="none"
      autoComplete="off"
      textContentType="none"
      importantForAutofill="no"
    />
  );
}

/** The sudo the helper runs to revoke this phone's own key, which this phone answers itself. */
function isOwnRevokeRequest(entry: PendingElevationRequest, user: string, keyId: string) {
  if (entry.request.threadId !== null || !Result.isSuccess(entry.decoded)) return false;
  const tail = entry.decoded.success.payload.command.argv.slice(-5);
  return ["revoke", "--user", user, "--key-id", keyId].every((arg, index) => tail[index] === arg);
}

/**
 * Remove this phone: the confirm, then the fingerprint, then "Removed". Revoking runs the helper
 * through sudo, which this phone approves with the key it is removing; the request is claimed so
 * it doesn't also show as a banner. Without a phone to approve, the machine's password does.
 */
function useRemoveThisPhone(props: {
  readonly environmentId: EnvironmentId;
  readonly machine: string;
  /** Keys that still approve once this phone's is gone. */
  readonly otherApprovers: readonly string[];
  readonly record: DeviceApprovalKeyRecord | null;
  readonly onRemoved: () => void;
}) {
  const { environmentId, machine, record } = props;
  const revoke = useAtomCommand(elevation.revoke, "remove this phone");
  const respond = useAtomCommand(elevation.respond, "answer sudo request");
  const pending = useAtomValue(elevation.pendingAcrossEnvironmentsAtom);
  const [phase, setPhase] = useState<"idle" | "waiting" | "removed">("idle");
  const [needsPassword, setNeedsPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const answered = useRef(new Set<string>());
  const cancelled = useRef(false);

  const own =
    record === null
      ? undefined
      : pending.find(
          (entry) =>
            entry.environmentId === environmentId &&
            isOwnRevokeRequest(entry, record.user, record.keyId),
        );
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- signs this phone's own removal request with the native keystore once it arrives
  useEffect(() => {
    if (phase !== "waiting" || own === undefined || record === null) return;
    const { requestId } = own.request;
    if (answered.current.has(requestId) || !Result.isSuccess(own.decoded)) return;
    answered.current.add(requestId);
    const prepared = prepareElevationSigning({
      requestId,
      decoded: own.decoded.success,
      key: record,
      machine,
      headline: "Remove this phone",
    });
    if (!prepared.ok) return;
    const { signing } = prepared;
    void (async () => {
      try {
        const { signature } = await deviceApprovalSigner.sign(
          signing.alias,
          signing.payloadB64url,
          {
            title: "Remove this phone",
            subtitle: machine,
          },
        );
        await respond({ environmentId, input: signing.respond(signature) });
      } catch (cause) {
        // Cancel is a plain cancel; the deny ends the helper's sudo at once.
        const code = deviceApprovalSignerErrorCode(cause);
        cancelled.current = true;
        if (code !== "cancelled" && code !== "declined") {
          setError(deviceApprovalSignerErrorMessage(code));
        }
        await respond({ environmentId, input: { requestId, decision: "deny" } });
      }
    })();
  }, [environmentId, machine, own, phase, record, respond]);

  const remove = async (password: string | null) => {
    if (record === null) return;
    setError(null);
    cancelled.current = false;
    setPhase("waiting");
    if (password === null) {
      appAtomRegistry.set(claimedElevationRequestAtom, {
        environmentId,
        matches: (entry) => isOwnRevokeRequest(entry, record.user, record.keyId),
      });
    }
    const result = await revoke({
      environmentId,
      input: { keyId: record.keyId, ...(password === null ? {} : { password }) },
    }).finally(() => appAtomRegistry.set(claimedElevationRequestAtom, null));
    if (result._tag === "Success") {
      approvalHaptic("approved");
      setNeedsPassword(false);
      setPhase("removed");
      setTimeout(() => {
        setPhase("idle");
        props.onRemoved();
      }, REMOVED_MS);
      return;
    }
    setPhase("idle");
    if (failureReason(result) === "password_required") setNeedsPassword(true);
    else if (!cancelled.current) setError(failureText(result));
  };

  return {
    phase,
    needsPassword,
    error,
    confirm: () =>
      Dialog.confirm({
        title: "Remove this phone?",
        message: removeThisPhoneMessage(machine, props.otherApprovers),
        confirmText: "Remove",
        destructive: true,
        onConfirm: () => void remove(null),
      }),
    removeWithPassword: (password: string) => void remove(password),
    dismissPassword: () => {
      setNeedsPassword(false);
      setError(null);
    },
  };
}

/** Only when no phone can approve the removal; the confirm already happened. */
function RemovePasswordSheet(props: {
  readonly machine: string;
  readonly words: ElevationPasswordWords;
  readonly busy: boolean;
  readonly error: string | null;
  readonly onClose: () => void;
  readonly onSubmit: (password: string) => void;
}) {
  const [password, setPassword] = useState("");
  return (
    <PasswordSheet title="Remove this phone" onClose={props.onClose}>
      <Text className="text-sm text-foreground-muted">
        No phone can approve this, so {props.machine} needs your {props.words.shortPassword}.
      </Text>
      <PasswordField
        words={props.words}
        value={password}
        onChange={setPassword}
        editable={!props.busy}
      />
      {props.error !== null ? (
        <Text accessibilityRole="alert" className="text-sm text-danger-foreground">
          {props.error}
        </Text>
      ) : null}
      <Button
        label="Remove"
        tone="destructive"
        fullWidth
        loading={props.busy}
        disabled={props.busy || password === ""}
        onPress={() => {
          props.onSubmit(password);
          setPassword("");
        }}
      />
    </PasswordSheet>
  );
}

/** Turn off what T3 installed, with the machine's password; the machine's sudo goes back to normal. */
function TurnOffSheet(props: {
  readonly environmentId: EnvironmentId;
  readonly machine: string;
  readonly words: ElevationPasswordWords;
  readonly onClose: () => void;
  readonly onTurnedOff: () => void;
}) {
  const uninstall = useAtomCommand(elevation.uninstall, "turn off device approval");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setBusy(true);
    setError(null);
    const result = await uninstall({
      environmentId: props.environmentId,
      input: { password },
    }).finally(() => {
      setBusy(false);
      setPassword("");
    });
    if (result._tag === "Success") props.onTurnedOff();
    else setError(failureText(result));
  };

  return (
    <PasswordSheet title="Turn off device approval" onClose={props.onClose}>
      <Text className="text-sm text-foreground-muted">
        {props.machine} needs your {props.words.shortPassword} to turn it off.
      </Text>
      <PasswordField words={props.words} value={password} onChange={setPassword} editable={!busy} />
      {error !== null ? (
        <Text accessibilityRole="alert" className="text-sm text-danger-foreground">
          {error}
        </Text>
      ) : null}
      <Button
        label="Turn off"
        tone="destructive"
        fullWidth
        loading={busy}
        disabled={busy || password === ""}
        onPress={() => void submit()}
      />
    </PasswordSheet>
  );
}

/**
 * A new key from this phone, approved by the machine's password. Fix uses `install` when T3's config
 * parts need rewriting (it adds the key it is given) or `enroll` when only the key is missing;
 * "Set up again" replaces the key the same way. The fingerprint proves the new key first, and the
 * previous key, if the machine still lists it, is revoked so it doesn't linger.
 */
function KeySheetView(props: {
  readonly environmentId: EnvironmentId;
  readonly machine: string;
  readonly words: ElevationPasswordWords;
  readonly user: string;
  readonly status: ElevationStatus;
  readonly record: DeviceApprovalKeyRecord | null;
  readonly sheet: KeySheet;
  readonly onClose: () => void;
  readonly onStarted: () => void;
  readonly onRecord: (record: DeviceApprovalKeyRecord) => void;
  readonly onFinished: (
    status: ElevationStatus,
    phone: { readonly keyId: string | null },
    repair: DeviceApprovalRepairAttempt,
  ) => void;
}) {
  const { environmentId, machine, status, sheet, words } = props;
  const install = useAtomCommand(elevation.install, "repair device approval");
  const enroll = useAtomCommand(elevation.enroll, "add device approval key");
  const revoke = useAtomCommand(elevation.revoke, "revoke device approval key");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);
  // A key the fingerprint already confirmed survives a mistyped password.
  const confirmedKey = useRef<PhoneKey | null>(null);
  const useInstall = sheet.kind === "fix" && sheet.plan.install;
  const text =
    sheet.kind === "fix"
      ? deviceApprovalFixSheetText(sheet.plan, machine, words)
      : {
          message: `Enter your ${words.shortPassword} to set this phone up again for ${machine}.`,
          action: "Set up again",
        };

  const close = () => {
    if (confirmedKey.current !== null) void discardPhoneKey(confirmedKey.current.record.alias);
    props.onClose();
  };

  const submit = async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    const ran: string[] = [];
    const attempt = async () => {
      let key = confirmedKey.current;
      if (key === null) {
        const created = await createPhoneKey(environmentId, props.user, props.record);
        // Outside the try: the React Compiler cannot lower conditionals inside one.
        const title = sheet.kind === "fix" ? "Fix device approval" : "Set up device approval";
        try {
          await confirmPhoneKey(created, { title, subtitle: machine });
        } catch (cause) {
          await discardPhoneKey(created.record.alias);
          throw cause;
        }
        key = created;
        confirmedKey.current = created;
      }
      const result = useInstall
        ? await install({ environmentId, input: { password, device: key.device } })
        : await enroll({ environmentId, input: { device: key.device, password } });
      if (failureReason(result) === "wrong_password") {
        setError(`The ${words.password} was not accepted.`);
        return;
      }
      confirmedKey.current = null;
      props.onStarted();
      ran.push(useInstall ? "install" : "enroll");
      if (result._tag !== "Success") {
        await discardPhoneKey(key.record.alias);
        props.onFinished(
          status,
          { keyId: props.record?.keyId ?? null },
          { ran, error: failureText(result) },
        );
        return;
      }
      await deviceApprovalKeys.write(environmentId, key.record);
      props.onRecord(key.record);
      let current =
        "type" in result.value
          ? "status" in result.value
            ? result.value.status
            : status
          : result.value;
      const previous = props.record;
      if (previous !== null && previous.alias !== key.record.alias) {
        await discardPhoneKey(previous.alias);
      }
      if (
        previous !== null &&
        previous.keyId !== key.record.keyId &&
        current.devices.some((device) => device.keyId === previous.keyId)
      ) {
        const revoked = await revoke({ environmentId, input: { keyId: previous.keyId, password } });
        ran.push("revoke");
        if (revoked._tag === "Success") current = revoked.value;
      }
      props.onFinished(current, { keyId: key.record.keyId }, { ran, error: null });
    };
    try {
      await attempt();
    } catch (cause) {
      const code = deviceApprovalSignerErrorCode(cause);
      if (code !== "cancelled" && code !== "declined") {
        setError(deviceApprovalSignerErrorMessage(code));
      }
    }
    // After the catch rather than in `finally`, which the React Compiler cannot lower.
    inFlight.current = false;
    setBusy(false);
  };

  return (
    <PasswordSheet
      title={sheet.kind === "fix" ? "Fix device approval" : "Set up this phone again"}
      onClose={close}
    >
      <Text className="text-sm text-foreground-muted">{text.message}</Text>
      <PasswordField words={words} value={password} onChange={setPassword} editable={!busy} />
      {error !== null ? (
        <Text accessibilityRole="alert" className="text-sm text-danger-foreground">
          {error}
        </Text>
      ) : null}
      <Button
        label={text.action}
        icon={FINGERPRINT}
        tone="primary"
        fullWidth
        loading={busy}
        disabled={busy || password === ""}
        onPress={() => void submit()}
      />
    </PasswordSheet>
  );
}
