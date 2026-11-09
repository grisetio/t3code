import { useAtomValue } from "@effect/atom-react";
import {
  ELEVATION_TOUCH_ID_HINT,
  elevationApproverDescription,
  elevationDeviceKind,
  elevationFailureMessage,
  elevationPasswordWords,
  type ElevationPasswordWords,
  elevationSudoApproval,
} from "@t3tools/client-runtime/elevation";
import {
  deviceApprovalCheckOwner,
  deviceApprovalFailingChecks,
  deviceApprovalState,
  deviceApprovalTurnOff,
  planDeviceApprovalFix,
} from "@t3tools/client-runtime/elevation-fix";
import { environmentSupportsDeviceApproval } from "@t3tools/client-runtime/state/elevation";
import {
  isAtomCommandInterrupted,
  squashAtomCommandFailure,
  type AtomCommandResult,
} from "@t3tools/client-runtime/state/runtime";
import type {
  ElevationApproverKind,
  ElevationCheck,
  ElevationDevice,
  ElevationStatus,
  EnvironmentId,
} from "@t3tools/contracts";
import {
  CheckIcon,
  ChevronDownIcon,
  GlobeIcon,
  LaptopIcon,
  SmartphoneIcon,
  XIcon,
  type LucideIcon,
} from "lucide-react";
import { useId, useState, type FormEvent } from "react";

import { useEnvironments } from "../../state/environments";
import { elevation } from "../../state/elevation";
import { useElevationApprover } from "../../state/elevationApprover";
import { useEnvironmentQuery } from "../../state/query";
import { useAtomCommand } from "../../state/use-atom-command";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { SettingsPageContainer, SettingsRow, SettingsSection } from "./settingsLayout";
import { ThisDeviceApproval } from "./ThisDeviceApproval";
import { useDeviceApprovalAgentHandoff } from "./useDeviceApprovalAgentHandoff";

const APPROVER_ICONS: Record<ElevationApproverKind, LucideIcon> = {
  phone: SmartphoneIcon,
  mac: LaptopIcon,
  browser: GlobeIcon,
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
            machine={environment.label}
            words={elevationPasswordWords(
              environment.serverConfig?.environment.platform.os,
              environment.label,
            )}
          />
        ))
      )}
    </SettingsPageContainer>
  );
}

function EnvironmentDeviceApproval(props: {
  readonly environmentId: EnvironmentId;
  readonly machine: string;
  readonly words: ElevationPasswordWords;
}) {
  const status = useEnvironmentQuery(
    elevation.status({ environmentId: props.environmentId, input: {} }),
  );
  return (
    <SettingsSection id="device-approval" title={props.machine}>
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
          machine={props.machine}
          words={props.words}
          status={status.data}
        />
      )}
    </SettingsSection>
  );
}

const STATE_BADGES = {
  on: { label: "On", variant: "success" },
  needs_fixing: { label: "Needs fixing", variant: "warning" },
  off: { label: "Off", variant: "secondary" },
} as const;

function DeviceApprovalStatus(props: {
  readonly environmentId: EnvironmentId;
  readonly machine: string;
  readonly words: ElevationPasswordWords;
  readonly status: ElevationStatus;
}) {
  const { status } = props;
  const handoff = useDeviceApprovalAgentHandoff();
  const approver = useElevationApprover(props.environmentId);
  const [fixNote, setFixNote] = useState<string | null>(null);
  const [detailsOpen, setDetailsOpen] = useState(false);
  if (!status.supported) {
    return (
      <SettingsRow
        title={props.machine}
        description={status.unsupportedReason ?? "Agents' sudo keeps asking for the password here."}
        status={<Badge variant={STATE_BADGES.off.variant}>{STATE_BADGES.off.label}</Badge>}
      />
    );
  }
  // Web holds no phone key, and every repair T3 does itself sends one.
  const state = deviceApprovalState(status, null);
  const approval = elevationSudoApproval(status);
  const turnOff = deviceApprovalTurnOff(status);
  const badge = STATE_BADGES[state];
  const fix = () => {
    const plan = planDeviceApprovalFix(status, null, { canRepair: false });
    if (plan.kind === "phone") {
      setFixNote("Fix this from your phone: open T3, then Settings → Device approval.");
    } else if (plan.kind === "agent") {
      setFixNote(null);
      void handoff({
        purpose: "fix",
        environmentId: props.environmentId,
        machine: props.machine,
        status,
        failing: deviceApprovalFailingChecks(status, null),
      });
    }
  };
  return (
    <>
      <SettingsRow
        title={props.machine}
        description={
          state === "on"
            ? undefined
            : state === "needs_fixing"
              ? "Agents' sudo will ask for the password"
              : (status.setupUnavailableReason ??
                (approver === null
                  ? `Approve agents' sudo on ${props.machine} with your phone. Set it up in the T3 app on Android, under Settings → Device approval.`
                  : undefined))
        }
        status={<Badge variant={badge.variant}>{badge.label}</Badge>}
        control={
          state === "needs_fixing" ? (
            <Button size="xs" onClick={fix}>
              Fix
            </Button>
          ) : null
        }
      >
        {fixNote !== null ? <p className="text-xs text-muted-foreground">{fixNote}</p> : null}
      </SettingsRow>
      {approver === null ? null : (
        <ThisDeviceApproval
          environmentId={props.environmentId}
          machine={props.machine}
          words={props.words}
          status={status}
          approver={approver}
        />
      )}
      {state === "off"
        ? null
        : status.devices
            .filter((device) => device.keyId !== approver?.keyId)
            .map((device) => (
              <DeviceRow
                key={device.keyId}
                environmentId={props.environmentId}
                device={device}
                revocable={status.helperInstalled}
                words={props.words}
              />
            ))}
      {state === "off" ? null : (
        <SettingsRow
          title="Details"
          control={
            <Button
              variant="ghost"
              size="icon-xs"
              aria-label="Details"
              aria-expanded={detailsOpen}
              onClick={() => setDetailsOpen((open) => !open)}
            >
              <ChevronDownIcon className={detailsOpen ? "rotate-180" : undefined} aria-hidden />
            </Button>
          }
        >
          {detailsOpen && status.checks.length > 0 ? (
            <ul className="flex flex-col gap-1 text-xs">
              {status.checks.map((check) => (
                <li key={check.id}>
                  <CheckLine check={check} />
                </li>
              ))}
            </ul>
          ) : null}
        </SettingsRow>
      )}
      {detailsOpen && turnOff === "uninstall" ? (
        <TurnOffRow
          environmentId={props.environmentId}
          machine={props.machine}
          words={props.words}
          phoneFirst={status.devices.length > 0}
          passwordRequired={approval.passwordRequired}
        />
      ) : null}
      {detailsOpen && turnOff === "agent" ? (
        <SettingsRow
          title="Turn off"
          description={`Its setup on ${props.machine} comes from config outside T3, so an agent removes it there.`}
          control={
            <Button
              variant="destructive-outline"
              size="xs"
              onClick={() =>
                void handoff({
                  purpose: "turn_off",
                  environmentId: props.environmentId,
                  machine: props.machine,
                  status,
                  failing: [],
                })
              }
            >
              Turn off
            </Button>
          }
        />
      ) : null}
    </>
  );
}

function CheckLine(props: { readonly check: ElevationCheck }) {
  const { check } = props;
  const owner = check.ok ? null : deviceApprovalCheckOwner(check);
  return (
    <span className="flex min-w-0 items-start gap-1.5">
      {check.ok ? (
        <CheckIcon className="mt-px size-3.5 shrink-0 text-success" aria-label="Passed" />
      ) : (
        <XIcon className="mt-px size-3.5 shrink-0 text-warning" aria-label="Failed" />
      )}
      <span className="flex min-w-0 flex-col break-words text-muted-foreground">
        <span>
          {check.message}
          {owner === null ? "" : ` · ${owner}`}
        </span>
        {check.path === undefined ? null : (
          <code className="font-mono break-all">{check.path}</code>
        )}
      </span>
    </span>
  );
}

/** Another approver: a phone, a Mac's Touch ID or a browser's passkey. */
function DeviceRow(props: {
  readonly environmentId: EnvironmentId;
  readonly device: ElevationDevice;
  readonly revocable: boolean;
  readonly words: ElevationPasswordWords;
}) {
  const { device } = props;
  const revoke = useAtomCommand(elevation.revoke, "revoke device approval key");
  const canRevoke = useAtomValue(elevation.revoke.permissionAtom(props.environmentId));
  const [confirming, setConfirming] = useState(false);
  const Icon = APPROVER_ICONS[elevationDeviceKind(device)];
  return (
    <SettingsRow
      title={
        <span className="flex min-w-0 items-center gap-2">
          <Icon className="size-3.5 shrink-0 text-muted-foreground" aria-hidden />
          <span className="truncate">{device.label}</span>
        </span>
      }
      description={`${elevationApproverDescription(device)} · Added ${formatDate(device.enrolledAt)}${
        device.lastUsedAt === null ? "" : ` · Last used ${formatDate(device.lastUsedAt)}`
      }`}
      control={
        confirming || !props.revocable ? null : (
          <Button
            variant="destructive-outline"
            size="xs"
            disabled={!canRevoke}
            onClick={() => setConfirming(true)}
          >
            Remove
          </Button>
        )
      }
    >
      {confirming ? (
        <SudoConfirmForm
          actionLabel="Remove"
          words={props.words}
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
  readonly machine: string;
  readonly words: ElevationPasswordWords;
  readonly phoneFirst: boolean;
  readonly passwordRequired: boolean;
}) {
  const uninstall = useAtomCommand(elevation.uninstall, "turn off device approval");
  const canUninstall = useAtomValue(elevation.uninstall.permissionAtom(props.environmentId));
  const [confirming, setConfirming] = useState(false);
  return (
    <SettingsRow
      title="Turn off"
      description={`Agents' sudo on ${props.machine} asks for the password again, and every device stops approving there.`}
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
          words={props.words}
          phoneFirst={props.phoneFirst}
          passwordRequired={props.passwordRequired}
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
 * With none enrolled, only the password can approve.
 */
export function SudoConfirmForm(props: {
  readonly actionLabel: string;
  readonly words: ElevationPasswordWords;
  readonly phoneFirst: boolean;
  readonly passwordRequired?: boolean;
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
          {props.passwordRequired
            ? `No phone is enrolled to approve this, so enter the ${props.words.password}.`
            : `Approve on your phone, or enter the ${props.words.password}.`}{" "}
          The password goes through the T3 server to sudo once and is never stored.
          {props.words.touchId ? ` ${ELEVATION_TOUCH_ID_HINT}` : null}
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
            placeholder={
              props.passwordRequired ? props.words.password : `${props.words.password} (optional)`
            }
            value={password}
            disabled={submitting}
            onChange={(event) => setPassword(event.currentTarget.value)}
          />
        ) : null}
        <Button
          type="submit"
          size="sm"
          variant="destructive"
          disabled={submitting || (props.passwordRequired === true && password === "")}
        >
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
            Use the {props.words.password} instead
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
