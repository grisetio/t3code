import { useAtomValue } from "@effect/atom-react";
import {
  ELEVATION_CANT_APPROVE_HERE,
  elevationFailureMessage,
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
import type { ElevationDevice, ElevationStatus, EnvironmentId } from "@t3tools/contracts";
import * as Result from "effect/Result";
import { useCallback, useEffect, useRef, useState } from "react";
import { Pressable, View } from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";

import { AppText as Text, AppTextInput as TextInput } from "../../components/ui/AppText";
import { SymbolView } from "../../components/ui/AppSymbol";
import { Button } from "../../components/ui/Button";
import * as Dialog from "../../components/ui/Dialog";
import { ListActionRow } from "../../components/ui/ListActionRow";
import { ScreenScrollView as ScrollView } from "../../components/ui/ScreenScrollView";
import { Sheet } from "../../components/ui/Sheet";
import { appAtomRegistry } from "../../state/atom-registry";
import { elevation } from "../../state/elevation";
import { useEnvironments } from "../../state/environments";
import { useEnvironmentQuery } from "../../state/query";
import { useAtomCommand } from "../../state/use-atom-command";
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
import { prepareElevationSigning } from "./elevationApproval";
import { claimedElevationRequestAtom } from "./elevationApprovalTarget";
import {
  openSudoApprovalNotificationSettings,
  useSudoApprovalNotificationsOn,
} from "./sudoApprovalNotifications";
import { useDeviceApprovalAgentHandoff } from "./useDeviceApprovalAgentHandoff";

const STATE_LABELS = { on: "On", needs_fixing: "Needs fixing", off: "Off" } as const;
// Long enough to read "T3 couldn't fix this one" before the thread opens.
const HANDOFF_NOTICE_MS = 1400;
// "✓ Removed" stays this long before the sheet closes.
const REMOVED_MS = 600;
const FINGERPRINT = { ios: "touchid", android: "fingerprint" } as const;

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
          contentContainerClassName="gap-6 px-5 pt-4"
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
  readonly onSetUp: (target: SetupTarget) => void;
  readonly onState: (environmentId: EnvironmentId, state: DeviceApprovalState) => void;
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
      onState={props.onState}
    />
  );
}

type Phase = "idle" | "checking" | "handoff";

type KeySheet =
  | { readonly kind: "fix"; readonly plan: Extract<DeviceApprovalFixPlan, { kind: "repair" }> }
  | { readonly kind: "rekey" };

function DeviceApprovalGroup(props: {
  readonly environmentId: EnvironmentId;
  readonly machine: string;
  readonly status: ElevationStatus;
  readonly onSetUp: (target: SetupTarget) => void;
  readonly onState: (environmentId: EnvironmentId, state: DeviceApprovalState) => void;
}) {
  const { environmentId, machine, status, onState } = props;
  const [record, setRecord] = useKeyRecord(environmentId);
  const [phase, setPhase] = useState<Phase>("idle");
  const [keySheet, setKeySheet] = useState<KeySheet | null>(null);
  const [removing, setRemoving] = useState(false);
  const [turningOff, setTurningOff] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const handoff = useDeviceApprovalAgentHandoff();
  const canInstall = useAtomValue(elevation.install.permissionAtom(environmentId));
  const canEnroll = useAtomValue(elevation.enroll.permissionAtom(environmentId));
  const rekeyRequested = useAtomValue(deviceApprovalRekeyAtom) === environmentId;
  const signerPresent = deviceApprovalSigner.isPresent();

  const phoneRecord = record && record.user === status.user ? record : null;
  const phone = { keyId: phoneRecord?.keyId ?? null };
  const state = status.supported ? deviceApprovalState(status, phone) : "off";
  const thisDevice = status.devices.find((device) => device.keyId === phoneRecord?.keyId);
  const canRepair = signerPresent && status.user !== undefined && canInstall && canEnroll;
  const turnOff = deviceApprovalTurnOff(status);

  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- reports this machine's state to the screen's header row
  useEffect(() => onState(environmentId, state), [environmentId, onState, state]);

  // "Set up again" from the lock-screen prompt lands here and goes straight to the fingerprint.
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- consumes the one-shot rekey request from the lock-screen prompt
  useEffect(() => {
    if (!rekeyRequested || record === undefined) return;
    clearDeviceApprovalRekey();
    // oxlint-disable-next-line react/set-state-in-effect -- Opens the rekey sheet once the request and this phone's key record are both known.
    if (phoneRecord !== null && canRepair) setKeySheet({ kind: "rekey" });
  }, [rekeyRequested, record, phoneRecord, canRepair]);

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

  const startTurnOff = () => {
    if (turnOff === "uninstall") return setTurningOff(true);
    Dialog.confirm({
      title: "Turn off device approval?",
      message: `Its setup on ${machine} comes from config outside T3, so an agent removes it there.`,
      confirmText: "Continue",
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
  };

  const forgetThisPhone = async () => {
    if (phoneRecord !== null) await discardPhoneKey(phoneRecord.alias);
    await deviceApprovalKeys.remove(environmentId);
    setRecord(null);
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

  return (
    <>
      <SettingsSection>
        <HeaderRow machine={machine} trail={STATE_LABELS[state]} warn={state === "needs_fixing"} />
        {state === "off" ? (
          signerPresent && status.user !== undefined ? (
            <Body
              text={offLine}
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
            text={offLine}
            action={{ label: "Add this phone", disabled: !canEnroll, onPress: setUp }}
          />
        ) : null}
        {state === "off" ? null : (
          <>
            <DetailsToggle open={detailsOpen} onPress={() => setDetailsOpen((open) => !open)} />
            {detailsOpen ? (
              <DeviceApprovalDetails
                environmentId={environmentId}
                machine={machine}
                status={status}
                thisDevice={thisDevice}
                canRemove={phoneRecord !== null && signerPresent}
                turnOff={turnOff}
                onRemove={() => setRemoving(true)}
                onTurnOff={startTurnOff}
              />
            ) : null}
          </>
        )}
      </SettingsSection>
      {keySheet !== null && status.user !== undefined ? (
        <KeySheetView
          environmentId={environmentId}
          machine={machine}
          user={status.user}
          status={status}
          record={phoneRecord}
          sheet={keySheet}
          onClose={() => setKeySheet(null)}
          onStarted={() => {
            setKeySheet(null);
            setDetailsOpen(false);
            setPhase("checking");
          }}
          onRecord={setRecord}
          onFinished={(current, nextPhone, repair) =>
            afterRepair(
              current,
              nextPhone,
              repair,
              keySheet.kind === "fix" && keySheet.plan.agentAfter,
            )
          }
        />
      ) : null}
      {removing && phoneRecord !== null && thisDevice !== undefined ? (
        <RemovePhoneSheet
          environmentId={environmentId}
          machine={machine}
          record={phoneRecord}
          onClose={() => setRemoving(false)}
          onRemoved={() => {
            setRemoving(false);
            setDetailsOpen(false);
            void forgetThisPhone();
          }}
        />
      ) : null}
      {turningOff ? (
        <TurnOffSheet
          environmentId={environmentId}
          machine={machine}
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
  readonly canRemove: boolean;
  readonly turnOff: "uninstall" | "agent" | null;
  readonly onRemove: () => void;
  readonly onTurnOff: () => void;
}) {
  const { environmentId, status, thisDevice } = props;
  const revoke = useAtomCommand(elevation.revoke, "revoke device approval key");
  const canRevoke = useAtomValue(elevation.revoke.permissionAtom(environmentId));
  const canUninstall = useAtomValue(elevation.uninstall.permissionAtom(environmentId));
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = async (label: string, action: () => Promise<AtomCommandResult<unknown, unknown>>) => {
    setBusy(label);
    setError(null);
    const result = await action().finally(() => setBusy(null));
    if (result._tag === "Success") return true;
    if (!isAtomCommandInterrupted(result)) {
      setError(elevationFailureMessage(squashAtomCommandFailure(result), "Something went wrong."));
    }
    return false;
  };

  return (
    <View className="gap-3 px-4 pb-4">
      {status.checks.map((check) => {
        const owner = check.ok ? null : deviceApprovalCheckOwner(check);
        return (
          <View key={check.id} className="flex-row items-start gap-2">
            <SymbolView
              name={check.ok ? "checkmark" : "xmark"}
              size={14}
              tintColorClassName={
                check.ok ? "accent-success-foreground" : "accent-warning-foreground"
              }
              type="monochrome"
            />
            <View className="min-w-0 flex-1 gap-0.5">
              <Text selectable className="text-sm text-foreground-muted">
                {check.message}
                {owner === null ? "" : ` · ${owner}`}
              </Text>
              {check.path === undefined ? null : (
                <Text selectable className="font-mono text-xs text-foreground-muted">
                  {check.path}
                </Text>
              )}
            </View>
          </View>
        );
      })}
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
      {status.helperInstalled && thisDevice !== undefined && props.canRemove ? (
        <Button
          label="Remove this phone"
          tone="danger"
          disabled={!canRevoke || busy !== null}
          onPress={props.onRemove}
        />
      ) : null}
      {props.turnOff !== null ? (
        <Button
          label="Turn off"
          tone="text"
          disabled={(props.turnOff === "uninstall" && !canUninstall) || busy !== null}
          onPress={props.onTurnOff}
        />
      ) : null}
    </View>
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

function PasswordField(props: {
  readonly value: string;
  readonly onChange: (value: string) => void;
  readonly editable: boolean;
}) {
  return (
    <TextInput
      accessibilityLabel="Mac password"
      placeholder="Mac password"
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
 * Remove this phone: the confirm sheet, then the fingerprint, then "Removed". Revoking runs the
 * helper through sudo, which this phone approves with the key it is removing; the request is
 * claimed so it doesn't also show as a banner. Without a phone to approve, the Mac password does.
 */
function RemovePhoneSheet(props: {
  readonly environmentId: EnvironmentId;
  readonly machine: string;
  readonly record: DeviceApprovalKeyRecord;
  readonly onClose: () => void;
  readonly onRemoved: () => void;
}) {
  const { environmentId, machine, record } = props;
  const revoke = useAtomCommand(elevation.revoke, "remove this phone");
  const respond = useAtomCommand(elevation.respond, "answer sudo request");
  const pending = useAtomValue(elevation.pendingAcrossEnvironmentsAtom);
  const [phase, setPhase] = useState<"confirm" | "waiting" | "removed">("confirm");
  const [needsPassword, setNeedsPassword] = useState(false);
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const answered = useRef(new Set<string>());
  const cancelled = useRef(false);

  const own = pending.find(
    (entry) =>
      entry.environmentId === environmentId && isOwnRevokeRequest(entry, record.user, record.keyId),
  );
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- signs this phone's own removal request with the native keystore once it arrives
  useEffect(() => {
    if (phase !== "waiting" || own === undefined) return;
    const { requestId } = own.request;
    if (answered.current.has(requestId) || !Result.isSuccess(own.decoded)) return;
    answered.current.add(requestId);
    const prepared = prepareElevationSigning({
      requestId,
      decoded: own.decoded.success,
      key: record,
      machine,
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

  const remove = async () => {
    setError(null);
    cancelled.current = false;
    setPhase("waiting");
    const withPassword = needsPassword && password !== "";
    if (!withPassword) {
      appAtomRegistry.set(claimedElevationRequestAtom, {
        environmentId,
        matches: (entry) => isOwnRevokeRequest(entry, record.user, record.keyId),
      });
    }
    const result = await revoke({
      environmentId,
      input: { keyId: record.keyId, ...(withPassword ? { password } : {}) },
    }).finally(() => {
      setPassword("");
      appAtomRegistry.set(claimedElevationRequestAtom, null);
    });
    if (result._tag === "Success") {
      approvalHaptic("approved");
      setPhase("removed");
      setTimeout(props.onRemoved, REMOVED_MS);
      return;
    }
    setPhase("confirm");
    const reason = failureReason(result);
    if (reason === "password_required") setNeedsPassword(true);
    else if (!cancelled.current) setError(failureText(result));
  };

  return (
    <Sheet title="Remove this phone?" onClose={props.onClose}>
      <View className="gap-4 px-5 pt-3 pb-8">
        <Text className="text-sm text-foreground-muted">
          {needsPassword
            ? `No phone can approve this, so ${machine} needs your Mac password.`
            : `Agents' sudo on ${machine} will ask for the password again.`}
        </Text>
        {needsPassword ? (
          <PasswordField value={password} onChange={setPassword} editable={phase === "confirm"} />
        ) : null}
        {error !== null ? (
          <Text accessibilityRole="alert" className="text-sm text-danger-foreground">
            {error}
          </Text>
        ) : null}
        <View className="flex-row gap-2">
          <View className="flex-1">
            <Button
              label="Cancel"
              tone="secondary"
              fullWidth
              disabled={phase !== "confirm"}
              onPress={props.onClose}
            />
          </View>
          <View className="flex-1">
            <Button
              label={phase === "removed" ? "Removed" : "Remove"}
              icon={phase === "removed" ? "checkmark" : needsPassword ? undefined : FINGERPRINT}
              tone="primary"
              fullWidth
              loading={phase === "waiting"}
              disabled={phase !== "confirm" || (needsPassword && password === "")}
              onPress={() => void remove()}
            />
          </View>
        </View>
      </View>
    </Sheet>
  );
}

/** Turn off what T3 installed, with the Mac password; the machine's sudo goes back to normal. */
function TurnOffSheet(props: {
  readonly environmentId: EnvironmentId;
  readonly machine: string;
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
    <Sheet title="Turn off device approval?" onClose={props.onClose}>
      <View className="gap-4 px-5 pt-3 pb-8">
        <Text className="text-sm text-foreground-muted">
          Agents' sudo on {props.machine} will ask for the password again, and every phone stops
          approving there.
        </Text>
        <PasswordField value={password} onChange={setPassword} editable={!busy} />
        {error !== null ? (
          <Text accessibilityRole="alert" className="text-sm text-danger-foreground">
            {error}
          </Text>
        ) : null}
        <Button
          label="Turn off"
          tone="danger"
          fullWidth
          loading={busy}
          disabled={busy || password === ""}
          onPress={() => void submit()}
        />
      </View>
    </Sheet>
  );
}

/**
 * A new key from this phone, approved by the Mac password. Fix uses `install` when T3's config
 * parts need rewriting (it adds the key it is given) or `enroll` when only the key is missing;
 * "Set up again" replaces the key the same way. The fingerprint proves the new key first, and the
 * previous key, if the machine still lists it, is revoked so it doesn't linger.
 */
function KeySheetView(props: {
  readonly environmentId: EnvironmentId;
  readonly machine: string;
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
  const { environmentId, machine, status, sheet } = props;
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
      ? deviceApprovalFixSheetText(sheet.plan, machine)
      : {
          message: `Enter your Mac password to set this phone up again for ${machine}.`,
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
        try {
          await confirmPhoneKey(created, {
            title: sheet.kind === "fix" ? "Fix device approval" : "Set up device approval",
            subtitle: machine,
          });
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
        setError("The Mac password was not accepted.");
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
    <Sheet
      title={sheet.kind === "fix" ? "Fix device approval" : "Set up this phone again"}
      onClose={close}
    >
      <View className="gap-4 px-5 pt-3 pb-8">
        <Text className="text-sm text-foreground-muted">{text.message}</Text>
        <PasswordField value={password} onChange={setPassword} editable={!busy} />
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
      </View>
    </Sheet>
  );
}
