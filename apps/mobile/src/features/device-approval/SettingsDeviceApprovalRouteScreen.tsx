import { useAtomValue } from "@effect/atom-react";
import { elevationFailureMessage, elevationKeyAlias } from "@t3tools/client-runtime/elevation";
import { environmentSupportsDeviceApproval } from "@t3tools/client-runtime/state/elevation";
import {
  isAtomCommandInterrupted,
  squashAtomCommandFailure,
  type AtomCommandResult,
} from "@t3tools/client-runtime/state/runtime";
import type {
  ElevationCheck,
  ElevationDevice,
  ElevationEnrollmentDevice,
  ElevationStatus,
  EnvironmentId,
} from "@t3tools/contracts";
import * as Base64Url from "effect/encoding/Base64Url";
import * as Result from "effect/Result";
import * as Clipboard from "expo-clipboard";
import * as ExpoCrypto from "expo-crypto";
import * as Device from "expo-device";
import { useEffect, useRef, useState } from "react";
import { View } from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";

import { AppText as Text, AppTextInput as TextInput } from "../../components/ui/AppText";
import { Button } from "../../components/ui/Button";
import * as Dialog from "../../components/ui/Dialog";
import { ListActionRow } from "../../components/ui/ListActionRow";
import { ListRowLayout } from "../../components/ui/ListRowLayout";
import { ScreenScrollView as ScrollView } from "../../components/ui/ScreenScrollView";
import { elevation } from "../../state/elevation";
import { useEnvironments } from "../../state/environments";
import { useEnvironmentQuery } from "../../state/query";
import { useAtomCommand } from "../../state/use-atom-command";
import { SettingsScreen } from "../settings/components/SettingsScreen";
import { SettingsSection } from "../settings/components/SettingsSection";
import { deviceApprovalKeys, type DeviceApprovalKeyRecord } from "./deviceApprovalKeys";
import {
  deviceApprovalSigner,
  DeviceApprovalSignerError,
  deviceApprovalSignerErrorCode,
  deviceApprovalSignerErrorMessage,
} from "./deviceApprovalSigner";
import { useComparisonCode } from "./ElevationRequestDetails";

const SECURITY_LEVEL_LABELS: Record<ElevationDevice["securityLevel"], string> = {
  strongbox: "StrongBox",
  tee: "TEE",
  software: "Software (development)",
};

const formatDate = (value: { readonly epochMilliseconds: number }) =>
  new Date(value.epochMilliseconds).toLocaleDateString();

const deviceLabel = () => (Device.modelName ?? "Android phone").trim().slice(0, 64);

export function SettingsDeviceApprovalRouteScreen() {
  const insets = useSafeAreaInsets();
  const { environments } = useEnvironments();
  const supported = environments.filter((environment) =>
    environmentSupportsDeviceApproval(environment.serverConfig),
  );
  return (
    <SettingsScreen title="Device approval">
      <ScrollView
        contentInsetAdjustmentBehavior="automatic"
        showsVerticalScrollIndicator={false}
        className="flex-1"
        contentContainerClassName="gap-6 px-5 pt-4"
        contentContainerStyle={{ paddingBottom: Math.max(insets.bottom, 18) + 18 }}
      >
        <Text className="text-sm text-foreground-muted">
          Approve an agent's sudo with your fingerprint, one command per approval.
        </Text>
        {supported.length === 0 ? (
          <Text className="text-sm text-foreground-muted">
            No connected environment offers device approval.
          </Text>
        ) : (
          supported.map((environment) => (
            <EnvironmentDeviceApproval
              key={environment.environmentId}
              environmentId={environment.environmentId}
              title={environment.label}
            />
          ))
        )}
      </ScrollView>
    </SettingsScreen>
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
  readonly title: string;
}) {
  const status = useEnvironmentQuery(
    elevation.status({ environmentId: props.environmentId, input: {} }),
  );
  return (
    <SettingsSection title={props.title}>
      {status.data === null ? (
        <View className="gap-2 rounded-2xl bg-grouped-card p-4">
          <Text className="text-sm text-foreground-muted">
            {status.error ?? "Checking this machine…"}
          </Text>
          {status.error === null ? null : (
            <Button label="Retry" tone="secondary" onPress={status.refresh} />
          )}
        </View>
      ) : (
        <DeviceApprovalStatus
          environmentId={props.environmentId}
          status={status.data}
          refreshing={status.isPending}
          onRefresh={status.refresh}
        />
      )}
    </SettingsSection>
  );
}

type SudoAction = (password: string | undefined) => Promise<AtomCommandResult<unknown, unknown>>;

function DeviceApprovalStatus(props: {
  readonly environmentId: EnvironmentId;
  readonly status: ElevationStatus;
  readonly refreshing: boolean;
  readonly onRefresh: () => void;
}) {
  const { environmentId, status } = props;
  const install = useAtomCommand(elevation.install, "set up device approval");
  const enroll = useAtomCommand(elevation.enroll, "add device approval key");
  const revoke = useAtomCommand(elevation.revoke, "revoke device approval key");
  const uninstall = useAtomCommand(elevation.uninstall, "turn off device approval");
  const canInstall = useAtomValue(elevation.install.permissionAtom(environmentId));
  const canEnroll = useAtomValue(elevation.enroll.permissionAtom(environmentId));
  const canRevoke = useAtomValue(elevation.revoke.permissionAtom(environmentId));
  const canUninstall = useAtomValue(elevation.uninstall.permissionAtom(environmentId));
  const test = useAtomCommand(elevation.test, "test device approval");
  const canTest = useAtomValue(elevation.test.permissionAtom(environmentId));
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<ElevationCheck | null>(null);
  const [record, setRecord] = useKeyRecord(environmentId);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [terminalCommand, setTerminalCommand] = useState<string | null>(null);
  const [newKey, setNewKey] = useState<Uint8Array | null>(null);
  const comparisonCode = useComparisonCode(newKey);
  const inFlight = useRef(false);

  if (!status.supported) {
    return (
      <StaticRow
        label="Not supported on this machine"
        description={status.unsupportedReason ?? "Agent sudo keeps asking for the password here."}
      />
    );
  }

  const installed = status.ownsApprovals || status.devices.length > 0;
  const thisDevice =
    record && record.user === status.user
      ? status.devices.find((device) => device.keyId === record.keyId)
      : undefined;
  const sudoPassword = password === "" ? undefined : password;

  /** Runs one setup change; the sudo password, if any, is used once and cleared. */
  const run = async (label: string, action: () => Promise<boolean>) => {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(label);
    setError(null);
    try {
      if (await action()) setPassword("");
    } catch (cause) {
      const code = deviceApprovalSignerErrorCode(cause);
      if (code !== "cancelled") setError(deviceApprovalSignerErrorMessage(code));
    } finally {
      inFlight.current = false;
      setBusy(null);
      setNewKey(null);
    }
  };
  const succeeded = (result: AtomCommandResult<unknown, unknown>) => {
    if (result._tag === "Success") return true;
    if (!isAtomCommandInterrupted(result)) {
      setError(elevationFailureMessage(squashAtomCommandFailure(result), "Something went wrong."));
    }
    return false;
  };
  /** The live check: only a real approval proves sudo reaches device approval. */
  const runTest = async () => {
    setTesting(true);
    setTestResult(null);
    setError(null);
    try {
      const result = await test({ environmentId, input: {} });
      if (result._tag === "Success") setTestResult(result.value);
      else succeeded(result);
    } finally {
      setTesting(false);
    }
  };
  const sudo = (label: string, action: SudoAction, after?: () => Promise<void>) =>
    run(label, async () => {
      if (!succeeded(await action(sudoPassword))) return false;
      await after?.();
      return true;
    });

  /**
   * Creates this phone's key and sends it with its attestation. The first
   * phone installs; later ones are added and approved by an enrolled phone or
   * the password. A previous key under the same alias is replaced, which is how
   * a key invalidated by a fingerprint change is recovered.
   */
  const setUpThisPhone = (replacing: DeviceApprovalKeyRecord | null) =>
    run(installed ? "enroll" : "install", async () => {
      const user = status.user;
      if (user === undefined) return false;
      const challenge = Base64Url.encode(ExpoCrypto.getRandomBytes(32));
      const alias = elevationKeyAlias(environmentId, user);
      const key = await deviceApprovalSigner.generateKey(alias, challenge);
      const [leaf, ...rest] = key.attestationChain;
      if (leaf === undefined) throw new DeviceApprovalSignerError("failed");
      const label = deviceLabel();
      const device: ElevationEnrollmentDevice = {
        label,
        publicKey: key.publicKeySpki,
        challenge,
        attestationChain: [leaf, ...rest],
      };
      const nextRecord = { alias, keyId: key.keyId, user, label };
      if (!installed) {
        const result = await install({
          environmentId,
          input: { password: sudoPassword ?? null, device },
        });
        if (!succeeded(result)) return false;
        // Either way the key is this phone's now; the command enrolls it once run.
        await deviceApprovalKeys.write(environmentId, nextRecord);
        setRecord(nextRecord);
        if (result._tag === "Success" && result.value.type === "terminal_command") {
          setTerminalCommand(result.value.command);
        } else {
          void runTest();
        }
        return true;
      }
      const publicKey = Base64Url.decode(key.publicKeySpki);
      if (Result.isSuccess(publicKey)) setNewKey(publicKey.success);
      const enrolled = await enroll({
        environmentId,
        input: { device, ...(sudoPassword === undefined ? {} : { password: sudoPassword }) },
      });
      if (!succeeded(enrolled)) return false;
      await deviceApprovalKeys.write(environmentId, nextRecord);
      setRecord(nextRecord);
      if (replacing !== null && replacing.keyId !== key.keyId) {
        succeeded(
          await revoke({
            environmentId,
            input: {
              keyId: replacing.keyId,
              ...(sudoPassword === undefined ? {} : { password: sudoPassword }),
            },
          }),
        );
      }
      void runTest();
      return true;
    });

  const removeThisPhone = (current: DeviceApprovalKeyRecord) =>
    sudo(
      "remove",
      (password) =>
        revoke({
          environmentId,
          input: { keyId: current.keyId, ...(password === undefined ? {} : { password }) },
        }),
      async () => {
        await deviceApprovalSigner.deleteKey(current.alias).catch(() => undefined);
        await deviceApprovalKeys.remove(environmentId);
        setRecord(null);
      },
    );

  const signerPresent = deviceApprovalSigner.isPresent();
  const statusLabel = status.ready ? "Ready" : installed ? "Needs attention" : "Not set up";
  return (
    <>
      <View className="gap-2 rounded-2xl bg-grouped-card p-4">
        <Text className="font-t3-bold text-base text-foreground">{statusLabel}</Text>
        <Text className="text-sm text-foreground-muted">
          {status.ready
            ? "An agent's sudo on this machine waits for approval on a phone."
            : "Agent sudo asks for the password as usual."}
        </Text>
        {status.checks.map((check) => (
          <Text
            key={check.id}
            className={`text-sm ${check.ok ? "text-foreground-muted" : "text-danger-foreground"}`}
          >
            {check.ok ? "✓" : "✗"} {check.message}
          </Text>
        ))}
        {status.setupOutsideT3 ? (
          <Text className="text-sm text-foreground-muted">
            Some parts were set up outside T3; turning off leaves them in place.
          </Text>
        ) : null}
        <Button
          label="Check again"
          tone="secondary"
          disabled={props.refreshing}
          onPress={props.onRefresh}
        />
      </View>

      {installed ? (
        <View className="gap-2">
          <View className="overflow-hidden rounded-2xl">
            <ListActionRow
              icon="checkmark.circle"
              label="Test"
              description={
                testing
                  ? "Waiting for approval on a phone…"
                  : "Runs sudo -n true on this machine for a phone to approve."
              }
              disabled={!canTest || testing || busy !== null}
              onPress={() => void runTest()}
            />
          </View>
          {testResult !== null ? (
            <Text
              className={`text-sm ${testResult.ok ? "text-foreground-muted" : "text-danger-foreground"}`}
            >
              {testResult.ok ? "✓" : "✗"} {testResult.message}
            </Text>
          ) : null}
        </View>
      ) : null}

      {!installed && status.plannedChanges.length > 0 ? (
        <View className="gap-1 rounded-2xl bg-grouped-card p-4">
          <Text className="text-sm text-foreground-muted">Setup will change:</Text>
          {status.plannedChanges.map((change) => (
            <Text key={change.path} className="text-sm text-foreground">
              <Text className="font-mono text-sm text-foreground">{change.path}</Text> ·{" "}
              {change.summary}
            </Text>
          ))}
        </View>
      ) : null}

      <View className="gap-2">
        <TextInput
          accessibilityLabel="sudo password"
          placeholder="sudo password (optional)"
          value={password}
          onChangeText={setPassword}
          editable={busy === null}
          secureTextEntry
          autoCorrect={false}
          autoCapitalize="none"
          autoComplete="off"
          textContentType="none"
          importantForAutofill="no"
        />
        <Text className="text-xs text-foreground-muted">
          {installed
            ? "Changes are approved on an enrolled phone, or with this password."
            : "Without it, setup gives you a command to paste into a terminal on this machine."}{" "}
          The password goes to the server once and is never stored.
        </Text>
      </View>

      {busy === "enroll" && comparisonCode !== null ? (
        <View className="gap-1 rounded-2xl bg-grouped-card p-4">
          <Text className="text-sm text-foreground-muted">
            {sudoPassword === undefined
              ? "Approve on a phone that's already set up. It must show this code:"
              : "This phone's code:"}
          </Text>
          <Text selectable className="font-mono text-2xl tracking-widest text-foreground">
            {comparisonCode}
          </Text>
        </View>
      ) : null}

      {terminalCommand !== null ? (
        <View className="gap-2 rounded-2xl bg-grouped-card p-4">
          <Text className="text-sm text-foreground-muted">
            Run this in a terminal on this machine, then tap Check again:
          </Text>
          <Text selectable className="font-mono text-sm text-foreground">
            {terminalCommand}
          </Text>
          <Button
            label="Copy command"
            tone="secondary"
            onPress={() => void Clipboard.setStringAsync(terminalCommand)}
          />
        </View>
      ) : null}

      {error !== null ? (
        <Text accessibilityRole="alert" className="text-sm text-danger-foreground">
          {error}
        </Text>
      ) : null}

      <View className="overflow-hidden rounded-2xl">
        {!signerPresent ? (
          <StaticRow
            icon="iphone"
            label="This phone can't approve"
            description="Approving needs the T3 app on Android with a fingerprint sensor."
          />
        ) : status.user === undefined ? (
          <StaticRow
            icon="iphone"
            label="Update T3 on this machine"
            description="This server doesn't say which user it approves for yet."
          />
        ) : thisDevice !== undefined && record ? (
          <>
            <ListActionRow
              icon="iphone"
              label="Set up this phone again"
              description="Use this if a fingerprint change broke this phone's key."
              disabled={!canEnroll || busy !== null}
              loading={busy === "enroll"}
              onPress={() => void setUpThisPhone(record)}
            />
            <ListActionRow
              icon="minus"
              tone="danger"
              label="Remove this device"
              description="Revokes this phone's key on this machine and deletes it."
              disabled={!canRevoke || busy !== null}
              loading={busy === "remove"}
              onPress={() =>
                Dialog.confirm({
                  title: "Remove this device?",
                  message: "This phone will no longer approve sudo on this machine.",
                  confirmText: "Remove",
                  destructive: true,
                  onConfirm: () => void removeThisPhone(record),
                })
              }
            />
          </>
        ) : (
          <ListActionRow
            icon="iphone"
            label={installed ? "Add this phone" : "Set up on this machine"}
            description={
              installed
                ? "Creates a key on this phone. An enrolled phone or the password approves it."
                : "Creates a key on this phone and installs approval on this machine."
            }
            disabled={(installed ? !canEnroll : !canInstall) || busy !== null}
            loading={busy === "install" || busy === "enroll"}
            onPress={() => void setUpThisPhone(record ?? null)}
          />
        )}
      </View>

      {status.devices.length > 0 ? (
        <View className="overflow-hidden rounded-2xl">
          {status.devices.map((device) => (
            <ListActionRow
              key={device.keyId}
              icon="iphone"
              label={
                device.keyId === thisDevice?.keyId ? `${device.label} (this phone)` : device.label
              }
              description={`${SECURITY_LEVEL_LABELS[device.securityLevel]} · Added ${formatDate(device.enrolledAt)}${
                device.lastUsedAt === null ? "" : ` · Last used ${formatDate(device.lastUsedAt)}`
              }`}
              detail="Revoke"
              disabled={!canRevoke || busy !== null}
              loading={busy === `revoke:${device.keyId}`}
              onPress={() =>
                Dialog.confirm({
                  title: `Revoke ${device.label}?`,
                  message: "It will no longer approve sudo on this machine.",
                  confirmText: "Revoke",
                  destructive: true,
                  onConfirm: () =>
                    void sudo(`revoke:${device.keyId}`, (password) =>
                      revoke({
                        environmentId,
                        input: {
                          keyId: device.keyId,
                          ...(password === undefined ? {} : { password }),
                        },
                      }),
                    ),
                })
              }
            />
          ))}
        </View>
      ) : null}

      {installed ? (
        <View className="overflow-hidden rounded-2xl">
          <ListActionRow
            icon="xmark"
            tone="danger"
            label="Turn off"
            description="Restores the files T3 changed; agent sudo asks for the password again."
            disabled={!canUninstall || busy !== null}
            loading={busy === "uninstall"}
            onPress={() =>
              Dialog.confirm({
                title: "Turn off device approval?",
                confirmText: "Turn off",
                destructive: true,
                onConfirm: () =>
                  void sudo("uninstall", (password) =>
                    uninstall({
                      environmentId,
                      input: password === undefined ? {} : { password },
                    }),
                  ),
              })
            }
          />
        </View>
      ) : null}
    </>
  );
}

function StaticRow(props: {
  readonly icon?: "iphone";
  readonly label: string;
  readonly description?: string;
}) {
  return (
    <View className="overflow-hidden rounded-2xl bg-grouped-card">
      <ListRowLayout icon={props.icon} label={props.label} description={props.description} />
    </View>
  );
}
