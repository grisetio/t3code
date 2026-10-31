import { useAtomValue } from "@effect/atom-react";
import { elevationFailureMessage } from "@t3tools/client-runtime/elevation";
import { environmentSupportsDeviceApproval } from "@t3tools/client-runtime/state/elevation";
import {
  isAtomCommandInterrupted,
  squashAtomCommandFailure,
  type AtomCommandResult,
} from "@t3tools/client-runtime/state/runtime";
import type {
  ElevationCheck,
  ElevationDevice,
  ElevationStatus,
  EnvironmentId,
} from "@t3tools/contracts";
import { CheckIcon, XIcon } from "lucide-react";
import { useId, useState, type FormEvent } from "react";

import { useEnvironments } from "../../state/environments";
import { elevation } from "../../state/elevation";
import { useEnvironmentQuery } from "../../state/query";
import { useAtomCommand } from "../../state/use-atom-command";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { SettingsPageContainer, SettingsRow, SettingsSection } from "./settingsLayout";

const SECURITY_LEVEL_LABELS: Record<ElevationDevice["securityLevel"], string> = {
  strongbox: "StrongBox",
  tee: "TEE",
  software: "Software (development)",
};

function formatDate(value: { readonly epochMilliseconds: number }) {
  return new Date(value.epochMilliseconds).toLocaleDateString();
}

export function DeviceApprovalSettings() {
  const { environments } = useEnvironments();
  const supported = environments.filter((environment) =>
    environmentSupportsDeviceApproval(environment.serverConfig),
  );
  return (
    <SettingsPageContainer>
      {supported.length === 0 ? (
        <p className="px-3 text-sm text-muted-foreground sm:px-4">
          No connected machine offers device approval.
        </p>
      ) : (
        supported.map((environment) => (
          <EnvironmentDeviceApproval
            key={environment.environmentId}
            environmentId={environment.environmentId}
            title={supported.length === 1 ? "Device approval" : environment.label}
          />
        ))
      )}
    </SettingsPageContainer>
  );
}

function EnvironmentDeviceApproval(props: {
  readonly environmentId: EnvironmentId;
  readonly title: string;
}) {
  const status = useEnvironmentQuery(
    elevation.status({ environmentId: props.environmentId, input: {} }),
  );
  return (
    <SettingsSection id="device-approval" title={props.title}>
      {status.data === null ? (
        <SettingsRow
          title={status.error === null ? "Checking this machine…" : "Couldn't check this machine"}
          description={status.error ?? undefined}
          control={
            status.error === null ? null : (
              <Button variant="outline" size="xs" onClick={status.refresh}>
                Retry
              </Button>
            )
          }
        />
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

function DeviceApprovalStatus(props: {
  readonly environmentId: EnvironmentId;
  readonly status: ElevationStatus;
  readonly refreshing: boolean;
  readonly onRefresh: () => void;
}) {
  const { status } = props;
  if (!status.supported) {
    return (
      <SettingsRow
        title="Not supported on this machine"
        description={status.unsupportedReason ?? "Agent sudo keeps asking for the password here."}
      />
    );
  }
  const installed = status.ownsApprovals || status.devices.length > 0;
  return (
    <>
      <SettingsRow
        title={status.ready ? "Ready" : installed ? "Needs attention" : "Not set up"}
        description={
          status.ready
            ? "An agent's sudo waits for approval on your phone, one command per approval."
            : "Agent sudo asks for the password as usual."
        }
        status={
          <Badge variant={status.ready ? "success" : installed ? "warning" : "secondary"}>
            {status.ready ? "Ready" : installed ? "Incomplete" : "Off"}
          </Badge>
        }
        control={
          <Button variant="outline" size="xs" disabled={props.refreshing} onClick={props.onRefresh}>
            Check again
          </Button>
        }
      >
        {status.checks.length > 0 ? (
          <ul className="flex flex-col gap-1 text-xs">
            {status.checks.map((check) => (
              <li key={check.id}>
                <CheckLine check={check} />
              </li>
            ))}
          </ul>
        ) : null}
      </SettingsRow>
      {installed ? <TestRow environmentId={props.environmentId} /> : <SetUpRow status={status} />}
      {status.devices.map((device) => (
        <DeviceRow key={device.keyId} environmentId={props.environmentId} device={device} />
      ))}
      {status.setupOutsideT3 ? (
        <SettingsRow
          title="Other parts were set up outside T3"
          description="Turning device approval off leaves them in place."
        />
      ) : null}
      {installed ? (
        <TurnOffRow environmentId={props.environmentId} phoneFirst={status.devices.length > 0} />
      ) : null}
    </>
  );
}

function CheckLine(props: { readonly check: ElevationCheck }) {
  return (
    <span className="flex min-w-0 items-start gap-1.5">
      {props.check.ok ? (
        <CheckIcon className="mt-px size-3.5 shrink-0 text-success" aria-label="Passed" />
      ) : (
        <XIcon className="mt-px size-3.5 shrink-0 text-destructive" aria-label="Failed" />
      )}
      <span className="min-w-0 break-words text-muted-foreground">{props.check.message}</span>
    </span>
  );
}

/** The live half of verification: only a real approval proves sudo reaches the module. */
function TestRow(props: { readonly environmentId: EnvironmentId }) {
  const test = useAtomCommand(elevation.test, "test device approval");
  const canTest = useAtomValue(elevation.test.permissionAtom(props.environmentId));
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<ElevationCheck | null>(null);
  const [error, setError] = useState<string | null>(null);
  const onTest = async () => {
    setRunning(true);
    setResult(null);
    setError(null);
    const outcome = await test({ environmentId: props.environmentId, input: {} }).finally(() =>
      setRunning(false),
    );
    if (outcome._tag === "Success") setResult(outcome.value);
    else if (!isAtomCommandInterrupted(outcome)) {
      setError(elevationFailureMessage(squashAtomCommandFailure(outcome), "The test didn't run."));
    }
  };
  return (
    <SettingsRow
      title="Test"
      description={
        running
          ? "Waiting for approval on your phone…"
          : "Runs sudo -n true on this machine for your phone to approve."
      }
      control={
        <Button
          variant="outline"
          size="xs"
          disabled={!canTest || running}
          onClick={() => void onTest()}
        >
          Test
        </Button>
      }
    >
      {result !== null ? (
        <div className="text-xs">
          <CheckLine check={result} />
        </div>
      ) : null}
      {error !== null ? (
        <p role="alert" className="text-xs text-destructive">
          {error}
        </p>
      ) : null}
    </SettingsRow>
  );
}

function SetUpRow(props: { readonly status: ElevationStatus }) {
  return (
    <SettingsRow
      title="Set up on this machine"
      description="Start setup in the T3 app on your Android phone, under Settings → Device approval. The phone creates its key, then you enter the sudo password once or paste a command into a terminal here. Setup trusts this account: anything running as you, including an agent, could change what it installs, the same as typing your sudo password into T3."
    >
      {props.status.plannedChanges.length > 0 ? (
        <div className="flex flex-col gap-1 text-xs">
          <p className="text-muted-foreground">Setup will change:</p>
          <ul className="flex flex-col gap-0.5">
            {props.status.plannedChanges.map((change) => (
              <li key={change.path} className="min-w-0 break-words">
                <code className="font-mono text-foreground">{change.path}</code>
                <span className="text-muted-foreground"> · {change.summary}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </SettingsRow>
  );
}

function DeviceRow(props: {
  readonly environmentId: EnvironmentId;
  readonly device: ElevationDevice;
}) {
  const { device } = props;
  const revoke = useAtomCommand(elevation.revoke, "revoke device approval key");
  const canRevoke = useAtomValue(elevation.revoke.permissionAtom(props.environmentId));
  const [confirming, setConfirming] = useState(false);
  return (
    <SettingsRow
      title={device.label}
      description={`${SECURITY_LEVEL_LABELS[device.securityLevel]} · Added ${formatDate(device.enrolledAt)}${
        device.lastUsedAt === null ? "" : ` · Last used ${formatDate(device.lastUsedAt)}`
      }`}
      control={
        confirming ? null : (
          <Button
            variant="outline"
            size="xs"
            disabled={!canRevoke}
            onClick={() => setConfirming(true)}
          >
            Revoke
          </Button>
        )
      }
    >
      {confirming ? (
        <SudoConfirmForm
          actionLabel="Revoke"
          phoneFirst
          onCancel={() => setConfirming(false)}
          run={(password) =>
            revoke({
              environmentId: props.environmentId,
              input: { keyId: device.keyId, ...(password === undefined ? {} : { password }) },
            })
          }
        />
      ) : null}
    </SettingsRow>
  );
}

function TurnOffRow(props: {
  readonly environmentId: EnvironmentId;
  readonly phoneFirst: boolean;
}) {
  const uninstall = useAtomCommand(elevation.uninstall, "turn off device approval");
  const canUninstall = useAtomValue(elevation.uninstall.permissionAtom(props.environmentId));
  const [confirming, setConfirming] = useState(false);
  return (
    <SettingsRow
      title="Turn off"
      description="Restores the PAM and sudoers files T3 changed; agent sudo asks for the password again."
      control={
        confirming ? null : (
          <Button
            variant="destructive-outline"
            size="xs"
            disabled={!canUninstall}
            onClick={() => setConfirming(true)}
          >
            Turn off
          </Button>
        )
      }
    >
      {confirming ? (
        <SudoConfirmForm
          actionLabel="Turn off"
          phoneFirst={props.phoneFirst}
          onCancel={() => setConfirming(false)}
          run={(password) =>
            uninstall({
              environmentId: props.environmentId,
              input: password === undefined ? {} : { password },
            })
          }
        />
      ) : null}
    </SettingsRow>
  );
}

/**
 * These changes run through sudo, so either a phone approves them or the
 * user gives the password here. With a phone enrolled, the phone comes first:
 * a password typed here passes through the server, which agents share.
 */
export function SudoConfirmForm(props: {
  readonly actionLabel: string;
  readonly phoneFirst: boolean;
  readonly onCancel: () => void;
  readonly run: (password: string | undefined) => Promise<AtomCommandResult<unknown, unknown>>;
}) {
  const inputId = useId();
  const [password, setPassword] = useState("");
  const [usePassword, setUsePassword] = useState(!props.phoneFirst);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    const result = await props
      .run(password === "" ? undefined : password)
      .finally(() => setSubmitting(false));
    if (result._tag === "Success") {
      setPassword("");
      props.onCancel();
    } else if (!isAtomCommandInterrupted(result)) {
      setError(elevationFailureMessage(squashAtomCommandFailure(result), "Something went wrong."));
    }
  };
  return (
    <form className="flex flex-col gap-2" autoComplete="off" onSubmit={(e) => void onSubmit(e)}>
      {usePassword ? (
        <label htmlFor={inputId} className="text-xs text-muted-foreground">
          Approve on your phone, or enter the sudo password. The password goes through the T3 server
          to sudo once and is never stored.
        </label>
      ) : (
        <p className="text-xs text-muted-foreground">Approve on your phone.</p>
      )}
      <div className="flex min-w-0 items-center gap-2">
        {usePassword ? (
          <Input
            id={inputId}
            type="password"
            autoComplete="off"
            placeholder="sudo password (optional)"
            value={password}
            disabled={submitting}
            onChange={(event) => setPassword(event.currentTarget.value)}
          />
        ) : null}
        <Button type="submit" size="sm" variant="destructive" disabled={submitting}>
          {submitting && password === "" ? "Waiting for your phone…" : props.actionLabel}
        </Button>
        <Button
          type="button"
          size="sm"
          variant="ghost"
          disabled={submitting}
          onClick={props.onCancel}
        >
          Cancel
        </Button>
        {usePassword ? null : (
          <Button
            type="button"
            size="sm"
            variant="link"
            disabled={submitting}
            onClick={() => setUsePassword(true)}
          >
            Use the sudo password instead
          </Button>
        )}
      </div>
      {error ? (
        <p role="alert" className="text-xs text-destructive">
          {error}
        </p>
      ) : null}
    </form>
  );
}
