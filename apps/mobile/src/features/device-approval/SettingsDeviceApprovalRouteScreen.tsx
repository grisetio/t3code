import { useAtomValue } from "@effect/atom-react";
import { elevationFailureMessage } from "@t3tools/client-runtime/elevation";
import {
  deviceApprovalFailingChecks,
  deviceApprovalFixSheetText,
  deviceApprovalInstalled,
  deviceApprovalState,
  planDeviceApprovalFix,
  type DeviceApprovalFixPlan,
  type DeviceApprovalRepairAttempt,
} from "@t3tools/client-runtime/elevation-fix";
import { environmentSupportsDeviceApproval } from "@t3tools/client-runtime/state/elevation";
import {
  isAtomCommandInterrupted,
  squashAtomCommandFailure,
  type AtomCommandResult,
} from "@t3tools/client-runtime/state/runtime";
import type { ElevationDevice, ElevationStatus, EnvironmentId } from "@t3tools/contracts";
import { useEffect, useRef, useState } from "react";
import { Pressable, View } from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";

import { AppText as Text, AppTextInput as TextInput } from "../../components/ui/AppText";
import { SymbolView } from "../../components/ui/AppSymbol";
import { Button } from "../../components/ui/Button";
import * as Dialog from "../../components/ui/Dialog";
import { ListActionRow } from "../../components/ui/ListActionRow";
import { ScreenScrollView as ScrollView } from "../../components/ui/ScreenScrollView";
import { Sheet } from "../../components/ui/Sheet";
import { elevation } from "../../state/elevation";
import { useEnvironments } from "../../state/environments";
import { useEnvironmentQuery } from "../../state/query";
import { useAtomCommand } from "../../state/use-atom-command";
import { SettingsScreen } from "../settings/components/SettingsScreen";
import { SettingsSection } from "../settings/components/SettingsSection";
import { confirmHaptic } from "./confirmHaptic";
import { createPhoneKey } from "./deviceApprovalEnrollment";
import { deviceApprovalKeys, type DeviceApprovalKeyRecord } from "./deviceApprovalKeys";
import {
  deviceApprovalSigner,
  deviceApprovalSignerErrorCode,
  deviceApprovalSignerErrorMessage,
} from "./deviceApprovalSigner";
import { DeviceApprovalSetupFlow } from "./DeviceApprovalSetupFlow";
import {
  openSudoApprovalNotificationSettings,
  useSudoApprovalNotificationsOn,
} from "./sudoApprovalNotifications";
import { useDeviceApprovalAgentHandoff } from "./useDeviceApprovalAgentHandoff";

const STATE_LABELS = { on: "On", needs_fixing: "Needs fixing", off: "Off" } as const;
// Long enough to read "T3 couldn't fix this one" before the thread opens.
const HANDOFF_NOTICE_MS = 1400;

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
          contentContainerClassName="gap-6 px-5 pt-4"
          contentContainerStyle={{ paddingBottom: Math.max(insets.bottom, 18) + 18 }}
        >
          {supported.length === 0 ? (
            <Text className="text-sm text-foreground-muted">
              No connected environment offers device approval.
            </Text>
          ) : (
            <>
              {supported.map((environment) => (
                <EnvironmentDeviceApproval
                  key={environment.environmentId}
                  environmentId={environment.environmentId}
                  // The phone's own name for the machine, never the server's.
                  machine={environment.label}
                  onSetUp={setSetup}
                />
              ))}
              <NotificationsRow />
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
      <ListActionRow
        label="Notifications"
        description={on ? undefined : "Requests show only in the app"}
        detail={on ? "On" : "Off"}
        onPress={() => void openSudoApprovalNotificationSettings()}
      />
    </SettingsSection>
  );
}

function useKeyRecord(environmentId: EnvironmentId) {
  const [record, setRecord] = useState<DeviceApprovalKeyRecord | null | undefined>(undefined);
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
  readonly onSetUp: (target: SetupTarget) => void;
}) {
  const status = useEnvironmentQuery(
    elevation.status({ environmentId: props.environmentId, input: {} }),
  );
  if (status.data === null) {
    return (
      <SettingsSection>
        <View className="gap-2 p-4">
          <Text className="text-base text-foreground">{props.machine}</Text>
          <Text className="text-sm text-foreground-muted">
            {status.error ?? "Checking this machine…"}
          </Text>
          {status.error === null ? null : (
            <Button label="Retry" tone="secondary" onPress={status.refresh} />
          )}
        </View>
      </SettingsSection>
    );
  }
  return (
    <DeviceApprovalGroup
      environmentId={props.environmentId}
      machine={props.machine}
      status={status.data}
      onSetUp={props.onSetUp}
    />
  );
}

type Phase = "idle" | "checking" | "handoff";

function DeviceApprovalGroup(props: {
  readonly environmentId: EnvironmentId;
  readonly machine: string;
  readonly status: ElevationStatus;
  readonly onSetUp: (target: SetupTarget) => void;
}) {
  const { environmentId, machine, status } = props;
  const [record, setRecord] = useKeyRecord(environmentId);
  const [phase, setPhase] = useState<Phase>("idle");
  const [fixSheet, setFixSheet] = useState<Extract<
    DeviceApprovalFixPlan,
    { kind: "repair" }
  > | null>(null);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const handoff = useDeviceApprovalAgentHandoff();
  const canInstall = useAtomValue(elevation.install.permissionAtom(environmentId));
  const canEnroll = useAtomValue(elevation.enroll.permissionAtom(environmentId));
  const signerPresent = deviceApprovalSigner.isPresent();

  if (!status.supported) {
    return (
      <SettingsSection>
        <HeaderRow machine={machine} trail="Off" warn={false} />
        <Body
          text={status.unsupportedReason ?? "Agents' sudo keeps asking for the password here."}
        />
      </SettingsSection>
    );
  }

  const phoneRecord = record && record.user === status.user ? record : null;
  const phone = { keyId: phoneRecord?.keyId ?? null };
  const state = deviceApprovalState(status, phone);
  const thisDevice = status.devices.find((device) => device.keyId === phoneRecord?.keyId);
  const canRepair = signerPresent && status.user !== undefined && canInstall && canEnroll;
  const setUp = () => props.onSetUp({ environmentId, machine, status });

  const handOff = (current: ElevationStatus, repair: DeviceApprovalRepairAttempt | null) =>
    handoff({
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
        return Dialog.alert(
          "This phone can't repair it",
          "Approving needs the T3 app on Android with a fingerprint sensor.",
        );
      case "repair":
        return setFixSheet(plan);
    }
  };

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
      confirmHaptic();
      return;
    }
    const plan = planDeviceApprovalFix(current, nextPhone, { canRepair });
    // Only the parts already meant for an agent remain: continue straight on.
    if (expectedAgent && plan.kind === "agent" && repair.error === null) {
      setPhase("idle");
      void handoff({ environmentId, machine, status: current, failing: remaining, repair });
      return;
    }
    setPhase("handoff");
    setTimeout(() => {
      setPhase("idle");
      void handoff({ environmentId, machine, status: current, failing: remaining, repair });
    }, HANDOFF_NOTICE_MS);
  };

  return (
    <>
      <SettingsSection>
        <HeaderRow machine={machine} trail={STATE_LABELS[state]} warn={state === "needs_fixing"} />
        {state === "off" ? (
          signerPresent && status.user !== undefined ? (
            <Body
              text="Approve agents' sudo on this Mac with this phone."
              action={{ label: "Set up", disabled: !canInstall, onPress: setUp }}
            />
          ) : (
            <Body text={offReason(signerPresent)} />
          )
        ) : phase === "checking" ? (
          <Body text="Checking…" />
        ) : phase === "handoff" ? (
          <Body text="T3 couldn't fix this one, so an agent will." />
        ) : state === "needs_fixing" ? (
          <Body
            text="Agents' sudo will ask for the password"
            action={{ label: "Fix", onPress: fix }}
          />
        ) : thisDevice === undefined && signerPresent && status.user !== undefined ? (
          <Body
            text="Approve agents' sudo on this Mac with this phone."
            action={{ label: "Add this phone", disabled: !canEnroll, onPress: setUp }}
          />
        ) : null}
        <DetailsToggle open={detailsOpen} onPress={() => setDetailsOpen((open) => !open)} />
        {detailsOpen ? (
          <DeviceApprovalDetails
            environmentId={environmentId}
            machine={machine}
            status={status}
            thisDevice={thisDevice}
            record={phoneRecord}
            onRemoved={() => setRecord(null)}
          />
        ) : null}
      </SettingsSection>
      {fixSheet !== null ? (
        <FixSheet
          environmentId={environmentId}
          machine={machine}
          status={status}
          record={phoneRecord}
          plan={fixSheet}
          onClose={() => setFixSheet(null)}
          onStarted={() => {
            setFixSheet(null);
            setDetailsOpen(false);
            setPhase("checking");
          }}
          onRecord={setRecord}
          onFinished={(current, nextPhone, repair) =>
            afterRepair(current, nextPhone, repair, fixSheet.agentAfter)
          }
        />
      ) : null}
    </>
  );
}

const offReason = (signerPresent: boolean) =>
  signerPresent
    ? "Update T3 on this machine to set up device approval from here."
    : "Approving needs the T3 app on Android with a fingerprint sensor.";

function HeaderRow(props: {
  readonly machine: string;
  readonly trail: string;
  readonly warn: boolean;
}) {
  return (
    <View className="min-h-14 flex-row items-center gap-3 px-4 py-3">
      <Text textRole="body" className="min-w-0 flex-1 text-foreground" numberOfLines={1}>
        {props.machine}
      </Text>
      <Text
        textRole="body"
        className={props.warn ? "text-warning-foreground" : "text-foreground-muted"}
      >
        {props.trail}
      </Text>
    </View>
  );
}

function Body(props: {
  readonly text: string;
  readonly action?: {
    readonly label: string;
    readonly disabled?: boolean;
    readonly onPress: () => void;
  };
}) {
  return (
    <View className="flex-row items-center gap-3 px-4 pb-3">
      <Text className="min-w-0 flex-1 text-sm text-foreground-muted">{props.text}</Text>
      {props.action ? (
        <Button
          label={props.action.label}
          tone="primary"
          disabled={props.action.disabled}
          onPress={props.action.onPress}
        />
      ) : null}
    </View>
  );
}

function DetailsToggle(props: { readonly open: boolean; readonly onPress: () => void }) {
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityState={{ expanded: props.open }}
      onPress={props.onPress}
      className="min-h-12 flex-row items-center gap-3 border-t border-border px-4 py-3"
    >
      <Text textRole="body" className="flex-1 text-foreground">
        Details
      </Text>
      <SymbolView
        name={props.open ? "chevron.up" : "chevron.down"}
        size={16}
        tintColorClassName="accent-icon"
        type="monochrome"
      />
    </Pressable>
  );
}

const SECURITY_LEVEL_LABELS: Record<ElevationDevice["securityLevel"], string> = {
  strongbox: "StrongBox",
  tee: "TEE",
  software: "Software (development)",
};

const formatDate = (value: { readonly epochMilliseconds: number }) =>
  new Date(value.epochMilliseconds).toLocaleDateString();

/** Checks, paths and devices: what an agent or a curious user needs, kept out of the normal path. */
function DeviceApprovalDetails(props: {
  readonly environmentId: EnvironmentId;
  readonly machine: string;
  readonly status: ElevationStatus;
  readonly thisDevice: ElevationDevice | undefined;
  readonly record: DeviceApprovalKeyRecord | null;
  readonly onRemoved: () => void;
}) {
  const { environmentId, status, thisDevice, record } = props;
  const revoke = useAtomCommand(elevation.revoke, "revoke device approval key");
  const uninstall = useAtomCommand(elevation.uninstall, "turn off device approval");
  const canRevoke = useAtomValue(elevation.revoke.permissionAtom(environmentId));
  const canUninstall = useAtomValue(elevation.uninstall.permissionAtom(environmentId));
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const installed = deviceApprovalInstalled(status);

  const run = async (label: string, action: () => Promise<AtomCommandResult<unknown, unknown>>) => {
    setBusy(label);
    setError(null);
    try {
      const result = await action();
      if (result._tag === "Success") return true;
      if (!isAtomCommandInterrupted(result)) {
        setError(
          elevationFailureMessage(squashAtomCommandFailure(result), "Something went wrong."),
        );
      }
      return false;
    } finally {
      setBusy(null);
    }
  };

  // The last phone takes the whole setup with it, so agents' sudo goes back to the password.
  const lastPhone = thisDevice !== undefined && status.devices.length === 1;
  const removeThisPhone = async () => {
    if (thisDevice === undefined || record === null) return;
    const removed = await run("remove", () =>
      lastPhone
        ? uninstall({ environmentId, input: {} })
        : revoke({ environmentId, input: { keyId: thisDevice.keyId } }),
    );
    if (!removed) return;
    await deviceApprovalSigner.deleteKey(record.alias).catch(() => undefined);
    await deviceApprovalKeys.remove(environmentId);
    props.onRemoved();
  };

  return (
    <View className="gap-3 px-4 pb-4">
      {status.checks.map((check) => (
        <View key={check.id} className="flex-row items-start gap-2">
          <SymbolView
            name={check.ok ? "checkmark" : "xmark"}
            size={14}
            tintColorClassName={check.ok ? "accent-success-foreground" : "accent-danger-foreground"}
            type="monochrome"
          />
          <Text selectable className="min-w-0 flex-1 text-sm text-foreground-muted">
            {check.message}
          </Text>
        </View>
      ))}
      {status.setupOutsideT3 ? (
        <Text className="text-sm text-foreground-muted">
          Some parts were set up outside T3; turning off leaves them in place.
        </Text>
      ) : null}
      {status.devices.map((device) => (
        <View key={device.keyId} className="flex-row items-center gap-3">
          <View className="min-w-0 flex-1 gap-0.5">
            <Text className="text-sm text-foreground">
              {device.keyId === thisDevice?.keyId ? `${device.label} (this phone)` : device.label}
            </Text>
            <Text className="text-xs text-foreground-muted">
              {SECURITY_LEVEL_LABELS[device.securityLevel]} · Added {formatDate(device.enrolledAt)}
              {device.lastUsedAt === null ? "" : ` · Last used ${formatDate(device.lastUsedAt)}`}
            </Text>
          </View>
          {device.keyId !== thisDevice?.keyId && status.helperInstalled ? (
            <Button
              label="Revoke"
              tone="text"
              disabled={!canRevoke || busy !== null}
              loading={busy === `revoke:${device.keyId}`}
              onPress={() =>
                Dialog.confirm({
                  title: `Revoke ${device.label}?`,
                  message: `It will no longer approve sudo on ${props.machine}.`,
                  confirmText: "Revoke",
                  destructive: true,
                  onConfirm: () =>
                    void run(`revoke:${device.keyId}`, () =>
                      revoke({ environmentId, input: { keyId: device.keyId } }),
                    ),
                })
              }
            />
          ) : null}
        </View>
      ))}
      {error !== null ? (
        <Text accessibilityRole="alert" className="text-sm text-danger-foreground">
          {error}
        </Text>
      ) : null}
      {/* Removing runs the root-owned helper; without it the helper check above says why. */}
      {status.helperInstalled && thisDevice !== undefined ? (
        <Button
          label="Remove this phone"
          tone="danger"
          disabled={!(lastPhone ? canUninstall : canRevoke) || busy !== null}
          loading={busy === "remove"}
          onPress={() =>
            Dialog.confirm({
              title: "Remove this phone?",
              message: `Agents' sudo on ${props.machine} will ask for the password again.`,
              confirmText: "Remove",
              destructive: true,
              onConfirm: () => void removeThisPhone(),
            })
          }
        />
      ) : null}
      {status.helperInstalled && installed && thisDevice === undefined ? (
        <Button
          label="Turn off"
          tone="danger"
          disabled={!canUninstall || busy !== null}
          loading={busy === "uninstall"}
          onPress={() =>
            Dialog.confirm({
              title: "Turn off device approval?",
              message: `Agents' sudo on ${props.machine} will ask for the password again. A phone that's set up approves this.`,
              confirmText: "Turn off",
              destructive: true,
              onConfirm: () => void run("uninstall", () => uninstall({ environmentId, input: {} })),
            })
          }
        />
      ) : null}
    </View>
  );
}

/**
 * T3's own repair: the Mac password approves a fresh key from this phone,
 * through `install` when T3's config parts need rewriting (it adds the key it
 * is given) or `enroll` when only the key is missing. The previous key, if the
 * machine still lists it, is revoked so it doesn't linger.
 */
function FixSheet(props: {
  readonly environmentId: EnvironmentId;
  readonly machine: string;
  readonly status: ElevationStatus;
  readonly record: DeviceApprovalKeyRecord | null;
  readonly plan: Extract<DeviceApprovalFixPlan, { kind: "repair" }>;
  readonly onClose: () => void;
  readonly onStarted: () => void;
  readonly onRecord: (record: DeviceApprovalKeyRecord) => void;
  readonly onFinished: (
    status: ElevationStatus,
    phone: { readonly keyId: string | null },
    repair: DeviceApprovalRepairAttempt,
  ) => void;
}) {
  const { environmentId, status, plan } = props;
  const install = useAtomCommand(elevation.install, "repair device approval");
  const enroll = useAtomCommand(elevation.enroll, "add device approval key");
  const revoke = useAtomCommand(elevation.revoke, "revoke device approval key");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);
  const text = deviceApprovalFixSheetText(plan, props.machine);

  const failureText = (result: AtomCommandResult<unknown, unknown>) =>
    result._tag !== "Failure" || isAtomCommandInterrupted(result)
      ? null
      : elevationFailureMessage(squashAtomCommandFailure(result), "Something went wrong.");
  const wrongPassword = (result: AtomCommandResult<unknown, unknown>) => {
    if (result._tag !== "Failure") return false;
    const failure = squashAtomCommandFailure(result);
    return (
      typeof failure === "object" &&
      failure !== null &&
      "reason" in failure &&
      failure.reason === "wrong_password"
    );
  };

  const submit = async () => {
    if (inFlight.current || status.user === undefined) return;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    const ran: string[] = [];
    try {
      const key = await createPhoneKey(environmentId, status.user);
      const result = plan.install
        ? await install({ environmentId, input: { password, device: key.device } })
        : await enroll({ environmentId, input: { device: key.device, password } });
      if (wrongPassword(result)) {
        setError("The Mac password was not accepted.");
        return;
      }
      props.onStarted();
      ran.push(plan.install ? "install" : "enroll");
      if (result._tag !== "Success") {
        props.onFinished(
          status,
          { keyId: props.record?.keyId ?? null },
          {
            ran,
            error: failureText(result),
          },
        );
        return;
      }
      await deviceApprovalKeys.write(environmentId, key.record);
      props.onRecord(key.record);
      let current = "status" in result.value ? result.value.status : status;
      const previous = props.record?.keyId;
      if (
        previous !== undefined &&
        previous !== key.record.keyId &&
        current.devices.some((device) => device.keyId === previous)
      ) {
        const revoked = await revoke({ environmentId, input: { keyId: previous, password } });
        ran.push("revoke");
        if (revoked._tag === "Success") current = revoked.value;
      }
      props.onFinished(current, { keyId: key.record.keyId }, { ran, error: null });
    } catch (cause) {
      const code = deviceApprovalSignerErrorCode(cause);
      if (code !== "cancelled") setError(deviceApprovalSignerErrorMessage(code));
    } finally {
      inFlight.current = false;
      setBusy(false);
      setPassword("");
    }
  };

  return (
    <Sheet title="Fix device approval" onClose={props.onClose}>
      <View className="gap-4 px-5 pt-3 pb-8">
        <Text className="text-sm text-foreground-muted">{text.message}</Text>
        <TextInput
          accessibilityLabel="Mac password"
          placeholder="Mac password"
          value={password}
          onChangeText={setPassword}
          editable={!busy}
          secureTextEntry
          autoCorrect={false}
          autoCapitalize="none"
          autoComplete="off"
          textContentType="none"
          importantForAutofill="no"
        />
        {error !== null ? (
          <Text accessibilityRole="alert" className="text-sm text-danger-foreground">
            {error}
          </Text>
        ) : null}
        <Button
          label={text.action}
          tone="primary"
          fullWidth
          loading={busy}
          disabled={busy || password === ""}
          onPress={() => void submit()}
        />
      </View>
    </Sheet>
  );
}
