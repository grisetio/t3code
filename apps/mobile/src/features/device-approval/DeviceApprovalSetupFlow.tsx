import { useAtomValue } from "@effect/atom-react";
import { elevationFailureMessage } from "@t3tools/client-runtime/elevation";
import {
  isAtomCommandInterrupted,
  squashAtomCommandFailure,
  type AtomCommandResult,
} from "@t3tools/client-runtime/state/runtime";
import type { ElevationStatus, EnvironmentId } from "@t3tools/contracts";
import * as Clipboard from "expo-clipboard";
import { useRef, useState, type ReactNode } from "react";
import { View } from "react-native";

import { AppText as Text, AppTextInput as TextInput } from "../../components/ui/AppText";
import { SymbolView } from "../../components/ui/AppSymbol";
import { Button } from "../../components/ui/Button";
import { elevation } from "../../state/elevation";
import { useAtomCommand } from "../../state/use-atom-command";
import {
  confirmPhoneKey,
  createPhoneKey,
  discardPhoneKey,
  type PhoneKey,
} from "./deviceApprovalEnrollment";
import { deviceApprovalKeys } from "./deviceApprovalKeys";
import {
  deviceApprovalSignerErrorCode,
  deviceApprovalSignerErrorMessage,
} from "./deviceApprovalSigner";
import { useComparisonCode } from "./ElevationRequestDetails";
import { approvalHaptic } from "./approvalHaptics";

type Step = "intro" | "approve" | "terminal" | "done";

// Long enough to see "✓ Confirmed" before the password step slides in.
const CONFIRMED_MS = 500;

/**
 * Setup from the phone (FLOW moment 4): the phone creates its key and the fingerprint proves it
 * can use it, the Mac password approves the first phone once, and an enrolled phone approves a
 * later one. No checks or paths here; Details has them.
 */
export function DeviceApprovalSetupFlow(props: {
  readonly environmentId: EnvironmentId;
  readonly machine: string;
  readonly status: ElevationStatus;
  readonly onClose: () => void;
}) {
  const { environmentId, machine, status } = props;
  const install = useAtomCommand(elevation.install, "set up device approval");
  const enroll = useAtomCommand(elevation.enroll, "add device approval key");
  const canInstall = useAtomValue(elevation.install.permissionAtom(environmentId));
  const canEnroll = useAtomValue(elevation.enroll.permissionAtom(environmentId));
  const installed = status.ownsApprovals || status.devices.length > 0;
  // A later phone is approved by one already set up; with none, only the password can.
  const otherPhoneApproves = installed && status.devices.length > 0;
  const [step, setStep] = useState<Step>("intro");
  const [key, setKey] = useState<PhoneKey | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [password, setPassword] = useState("");
  const [usePassword, setUsePassword] = useState(!otherPhoneApproves);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [terminalCommand, setTerminalCommand] = useState<string | null>(null);
  const comparisonCode = useComparisonCode(otherPhoneApproves ? (key?.publicKey ?? null) : null);
  const inFlight = useRef(false);
  const stepNumber = step === "intro" ? 1 : step === "done" ? 3 : 2;

  const guarded = async (action: () => Promise<void>) => {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (cause) {
      const code = deviceApprovalSignerErrorCode(cause);
      if (code !== "cancelled") setError(deviceApprovalSignerErrorMessage(code));
    }
    // After the catch rather than in `finally`, which the React Compiler cannot lower.
    inFlight.current = false;
    setBusy(false);
  };
  const succeeded = (result: AtomCommandResult<unknown, unknown>) => {
    if (result._tag === "Success") return true;
    if (!isAtomCommandInterrupted(result)) {
      setError(elevationFailureMessage(squashAtomCommandFailure(result), "Something went wrong."));
    }
    return false;
  };
  // The key this phone had before, if any; it stays until the new one is accepted.
  const previous = useRef<string | null>(null);
  const keep = async (phoneKey: PhoneKey) => {
    await deviceApprovalKeys.write(environmentId, phoneKey.record);
    if (previous.current !== null && previous.current !== phoneKey.record.alias) {
      await discardPhoneKey(previous.current);
    }
  };
  const finish = async (phoneKey: PhoneKey) => {
    await keep(phoneKey);
    setPassword("");
    setStep("done");
    approvalHaptic("setupComplete");
  };

  const createKey = () =>
    guarded(async () => {
      if (status.user === undefined) return;
      const current = await deviceApprovalKeys.read(environmentId);
      previous.current = current?.alias ?? null;
      const created = await createPhoneKey(environmentId, status.user, current);
      try {
        await confirmPhoneKey(created, { title: "Set up device approval", subtitle: machine });
      } catch (cause) {
        // Cancel is a plain cancel: the new key goes, and the intro stays.
        await discardPhoneKey(created.record.alias);
        throw cause;
      }
      approvalHaptic("approved");
      setKey(created);
      setConfirmed(true);
      await new Promise((resolve) => setTimeout(resolve, CONFIRMED_MS));
      setStep("approve");
    });

  const close = () => {
    // A key the machine never accepted is useless; the previous key, if any, still works.
    if (key !== null && (step === "intro" || step === "approve")) {
      void discardPhoneKey(key.record.alias);
    }
    props.onClose();
  };

  const approve = (sudoPassword: string | null) =>
    guarded(async () => {
      if (key === null) return;
      if (!installed) {
        const result = await install({
          environmentId,
          input: { password: sudoPassword, device: key.device },
        });
        if (!succeeded(result) || result._tag !== "Success") return;
        if (result.value.type === "terminal_command") {
          // The key is this phone's once the command runs.
          await keep(key);
          setTerminalCommand(result.value.command);
          setStep("terminal");
          return;
        }
        await finish(key);
        return;
      }
      const result = await enroll({
        environmentId,
        input: { device: key.device, ...(sudoPassword === null ? {} : { password: sudoPassword }) },
      });
      if (succeeded(result)) await finish(key);
    });

  return (
    <View className="flex-1 gap-5 px-5 pt-4">
      <View className="flex-row items-center justify-between">
        <Button label="Cancel" tone="text" disabled={busy} onPress={close} />
        <Text className="text-sm text-foreground-muted">{stepNumber} of 3</Text>
      </View>

      {step === "intro" ? (
        <StepBody
          icon={FINGERPRINT}
          title={`Use this phone to approve admin actions on ${machine}`}
          body="When an agent there needs sudo, it asks here and you approve with your fingerprint."
        >
          <Button
            label={confirmed ? "Confirmed" : "Continue"}
            icon={confirmed ? "checkmark" : FINGERPRINT}
            tone="primary"
            fullWidth
            loading={busy && !confirmed}
            disabled={
              busy ||
              confirmed ||
              status.user === undefined ||
              !(installed ? canEnroll : canInstall)
            }
            onPress={() => void createKey()}
          />
        </StepBody>
      ) : null}

      {step === "approve" && usePassword ? (
        <StepBody
          icon="laptopcomputer"
          title="Enter your Mac password, once"
          body={`${machine} needs it one time to trust this phone.`}
        >
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
          <Text className="text-xs text-foreground-muted">
            If Touch ID appears on the Mac, choose Cancel. Setup continues here.
          </Text>
          <Button
            label={busy ? "Checking with the Mac…" : "Continue"}
            tone="primary"
            fullWidth
            disabled={busy || password === ""}
            onPress={() => void approve(password)}
          />
          {installed ? null : (
            <Button
              label="Use a terminal command instead"
              tone="text"
              disabled={busy}
              onPress={() => void approve(null)}
            />
          )}
        </StepBody>
      ) : null}

      {step === "approve" && !usePassword ? (
        <StepBody
          icon="iphone"
          title="Approve this phone on your other phone"
          body={`A phone already set up for ${machine} gets the request. It must show this code:`}
        >
          <Text selectable className="font-mono text-2xl tracking-widest text-foreground">
            {comparisonCode ?? " "}
          </Text>
          <Button
            label={busy ? "Waiting for your other phone…" : "Send the request"}
            tone="primary"
            fullWidth
            disabled={busy}
            onPress={() => void approve(null)}
          />
          <Button
            label="Use your Mac password instead"
            tone="text"
            disabled={busy}
            onPress={() => setUsePassword(true)}
          />
        </StepBody>
      ) : null}

      {step === "terminal" && terminalCommand !== null ? (
        <StepBody
          icon="terminal"
          title="Run this on the Mac"
          body="Paste it into a terminal there. It asks for your Mac password once."
        >
          <Text selectable className="font-mono text-sm text-foreground">
            {terminalCommand}
          </Text>
          <Button
            label="Copy command"
            tone="secondary"
            fullWidth
            onPress={() => void Clipboard.setStringAsync(terminalCommand)}
          />
          <Button label="Done" tone="primary" fullWidth onPress={props.onClose} />
        </StepBody>
      ) : null}

      {step === "done" ? (
        <StepBody
          icon="checkmark.circle"
          title="Done"
          body={`The next time an agent runs sudo on ${machine}, it will ask here.`}
        >
          <Button label="Done" tone="primary" fullWidth onPress={props.onClose} />
        </StepBody>
      ) : null}

      {error !== null ? (
        <Text accessibilityRole="alert" className="text-sm text-danger-foreground">
          {error}
        </Text>
      ) : null}
    </View>
  );
}

const FINGERPRINT = { ios: "touchid", android: "fingerprint" } as const;

function StepBody(props: {
  readonly icon: "laptopcomputer" | "iphone" | "terminal" | "checkmark.circle" | typeof FINGERPRINT;
  readonly title: string;
  readonly body: string;
  readonly children: ReactNode;
}) {
  return (
    <View className="gap-4">
      <SymbolView name={props.icon} size={32} tintColorClassName="accent-icon" type="monochrome" />
      <Text className="font-t3-bold text-xl text-foreground">{props.title}</Text>
      <Text className="text-sm text-foreground-muted">{props.body}</Text>
      {props.children}
    </View>
  );
}
