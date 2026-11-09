import { useAtomValue } from "@effect/atom-react";
import { sha256 } from "@noble/hashes/sha2";
import {
  ELEVATION_TOUCH_ID_HINT,
  elevationFailureMessage,
  uniqueElevationApproverLabel,
  type ElevationPasswordWords,
} from "@t3tools/client-runtime/elevation";
import { deviceApprovalSetupChanges } from "@t3tools/client-runtime/elevation-fix";
import type { PendingElevationRequest } from "@t3tools/client-runtime/state/elevation";
import {
  isAtomCommandInterrupted,
  squashAtomCommandFailure,
  type AtomCommandResult,
} from "@t3tools/client-runtime/state/runtime";
import {
  decodeElevationBase64Url,
  elevationComparisonCode,
  type ElevationEnrollmentDevice,
  type ElevationSignedResponse,
  type ElevationStatus,
  type EnvironmentId,
} from "@t3tools/contracts";
import * as Result from "effect/Result";
import { CheckIcon, GlobeIcon, LaptopIcon } from "lucide-react";
import { useEffect, useId, useRef, useState, type FormEvent } from "react";

import { useStableCallback } from "../../hooks/useStableCallback";
import { elevation } from "../../state/elevation";
import type { ElevationApprover } from "../../state/elevationApprover";
import { useAtomCommand } from "../../state/use-atom-command";
import { useElevationSidebarStore } from "../elevation/elevationSidebarStore";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { SettingsRow } from "./settingsLayout";

const HERE = {
  mac: {
    badge: "This Mac",
    icon: LaptopIcon,
    offer: "Approve here with Touch ID.",
    key: "Touch ID",
  },
  browser: {
    badge: "This browser",
    icon: GlobeIcon,
    offer: "Approve here with a passkey.",
    key: "Passkey on this device",
  },
} as const;

interface NewKey {
  readonly device: ElevationEnrollmentDevice;
  readonly publicKey: Uint8Array;
}

type Step =
  | { readonly kind: "idle" }
  | { readonly kind: "creating" }
  /** Another approver gets the "Add device" request and compares the code. */
  | { readonly kind: "elsewhere"; readonly key: NewKey }
  | { readonly kind: "password"; readonly key: NewKey }
  | { readonly kind: "terminal"; readonly command: string }
  | { readonly kind: "added"; readonly first: boolean }
  | { readonly kind: "confirm-remove" }
  | { readonly kind: "removing" };

const IDLE: Step = { kind: "idle" };

const message = (error: unknown, fallback: string) =>
  error instanceof Error && error.message !== "" ? error.message : fallback;

const failureReason = (result: AtomCommandResult<unknown, unknown>) => {
  if (result._tag === "Success" || isAtomCommandInterrupted(result)) return null;
  const failure = squashAtomCommandFailure(result);
  return typeof failure === "object" && failure !== null && "reason" in failure
    ? failure.reason
    : null;
};

/** The "Add device" sudo for this device's own new key, which another approver answers. */
function isOwnEnrollRequest(entry: PendingElevationRequest, publicKey: Uint8Array) {
  if (!Result.isSuccess(entry.decoded)) return false;
  const enroll = entry.decoded.success.view.enroll;
  return (
    enroll !== null &&
    enroll.publicKey.length === publicKey.length &&
    enroll.publicKey.every((byte, index) => byte === publicKey[index])
  );
}

/** The sudo the helper runs to revoke this device's own key, which this device answers itself. */
function isOwnRevokeRequest(entry: PendingElevationRequest, user: string, keyId: string) {
  if (entry.request.threadId !== null || !Result.isSuccess(entry.decoded)) return false;
  const tail = entry.decoded.success.payload.command.argv.slice(-5);
  return ["revoke", "--user", user, "--key-id", keyId].every((arg, index) => tail[index] === arg);
}

/**
 * This Mac or this browser as an approver of one machine: Set up, then Remove. A new key is
 * unattested, so an approver already set up confirms it by its comparison code, or the
 * machine's password admits it once; with nothing set up yet, that password also turns device
 * approval on.
 */
export function ThisDeviceApproval(props: {
  readonly environmentId: EnvironmentId;
  readonly machine: string;
  readonly words: ElevationPasswordWords;
  readonly status: ElevationStatus;
  readonly approver: ElevationApprover;
}) {
  const { environmentId, machine, words, status, approver } = props;
  const { user } = status;
  const install = useAtomCommand(elevation.install, "set up device approval");
  const enroll = useAtomCommand(elevation.enroll, "add device approval key");
  const revoke = useAtomCommand(elevation.revoke, "remove this device");
  const respond = useAtomCommand(elevation.respond, "answer sudo request");
  const canInstall = useAtomValue(elevation.install.permissionAtom(environmentId));
  const canEnroll = useAtomValue(elevation.enroll.permissionAtom(environmentId));
  const canRevoke = useAtomValue(elevation.revoke.permissionAtom(environmentId));
  const pending = useAtomValue(elevation.pendingAcrossEnvironmentsAtom).filter(
    (entry) => entry.environmentId === environmentId,
  );
  const claim = useElevationSidebarStore((state) => state.claim);
  const [step, setStep] = useState<Step>(IDLE);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // A new key whose "Add device" request was abandoned; it is denied once it shows up.
  const [abandoned, setAbandoned] = useState<Uint8Array | null>(null);
  const prompt = useRef<AbortController | null>(null);
  // Bumped when the user leaves a wait, so a late result of that wait is ignored.
  const attempt = useRef(0);
  const answeredRevoke = useRef<string | null>(null);
  const deniedAbandoned = useRef<string | null>(null);
  const declined = useRef(false);
  useEffect(() => () => prompt.current?.abort(), []);

  const here = HERE[approver.kind];
  const installed = status.ownsApprovals || status.devices.length > 0;
  const enrolled =
    approver.keyId === null
      ? undefined
      : status.devices.find((device) => device.keyId === approver.keyId);
  const others = status.devices.filter((device) => device.keyId !== approver.keyId);
  const othersApprove = installed && others.length > 0;
  const otherName = others.length === 1 ? (others[0]?.label ?? "") : "another device";
  const changes = installed ? [] : deviceApprovalSetupChanges(status.plannedChanges);
  const blocked = changes.some((change) => change.blocked);
  const setupBlockedReason =
    approver.unavailableReason ?? (installed ? null : (status.setupUnavailableReason ?? null));
  const canSetUp =
    setupBlockedReason === null &&
    !blocked &&
    user !== undefined &&
    (installed ? canEnroll : canInstall);

  const failed = (result: AtomCommandResult<unknown, unknown>) => {
    if (result._tag !== "Success" && !isAtomCommandInterrupted(result)) {
      setError(elevationFailureMessage(squashAtomCommandFailure(result), "Something went wrong."));
    }
  };
  // A key the machine never accepted can't approve; forgetting it keeps "Set up" honest.
  const abandon = (key: NewKey | null) => {
    attempt.current += 1;
    if (key !== null) setAbandoned(key.publicKey);
    void approver.forget();
  };

  const enrollElsewhere = async (key: NewKey) => {
    const id = ++attempt.current;
    const result = await enroll({ environmentId, input: { device: key.device } });
    if (attempt.current !== id) return;
    if (result._tag === "Success") {
      setStep({ kind: "added", first: false });
      return;
    }
    failed(result);
    void approver.forget();
    setStep(IDLE);
  };

  const start = useStableCallback(async () => {
    if (user === undefined) return;
    setError(null);
    setAbandoned(null);
    setStep({ kind: "creating" });
    const controller = new AbortController();
    prompt.current = controller;
    let created: Awaited<ReturnType<ElevationApprover["createKey"]>>;
    try {
      created = await approver.createKey(controller.signal, { name: `${user} on ${machine}` });
    } catch (cause) {
      setError(message(cause, "This device couldn't make a key."));
      setStep(IDLE);
      return;
    } finally {
      prompt.current = null;
    }
    const publicKey = created === null ? null : decodeElevationBase64Url(created.publicKey);
    if (created === null || publicKey === null) {
      setStep(IDLE);
      return;
    }
    const key: NewKey = {
      publicKey,
      device: {
        label: uniqueElevationApproverLabel(
          approver.label,
          approver.computerName,
          status.devices.map((device) => device.label),
        ),
        publicKey: created.publicKey,
        ...(created.webauthn === undefined ? {} : { webauthn: created.webauthn }),
      },
    };
    if (othersApprove) {
      setStep({ kind: "elsewhere", key });
      await enrollElsewhere(key);
    } else {
      setStep({ kind: "password", key });
    }
  });

  const submitPassword = async (key: NewKey, password: string | null) => {
    setBusy(true);
    setError(null);
    try {
      if (!installed) {
        const result = await install({ environmentId, input: { password, device: key.device } });
        if (result._tag !== "Success") return failed(result);
        // The key is this device's once the command runs.
        if (result.value.type === "terminal_command") {
          setStep({ kind: "terminal", command: result.value.command });
        } else {
          setStep({ kind: "added", first: true });
        }
        return;
      }
      if (password === null) return;
      const result = await enroll({ environmentId, input: { device: key.device, password } });
      if (result._tag === "Success") setStep({ kind: "added", first: others.length === 0 });
      else failed(result);
    } finally {
      setBusy(false);
    }
  };

  const remove = async () => {
    if (approver.keyId === null) return;
    setError(null);
    declined.current = false;
    setStep({ kind: "removing" });
    const result = await revoke({ environmentId, input: { keyId: approver.keyId } });
    if (result._tag === "Success") {
      await approver.forget();
      setStep(IDLE);
      return;
    }
    if (!declined.current) {
      setError(
        failureReason(result) === "password_required"
          ? `${machine} asked for the password; remove this device from your phone instead.`
          : elevationFailureMessage(squashAtomCommandFailure(result), "Something went wrong."),
      );
    }
    setStep(IDLE);
  };

  // This device answers its own removal with the key it removes; Cancel there keeps it.
  const { keyId, sign } = approver;
  const ownRevoke =
    step.kind === "removing" && user !== undefined && keyId !== null
      ? pending.find((entry) => isOwnRevokeRequest(entry, user, keyId))
      : undefined;
  useEffect(() => {
    if (ownRevoke === undefined || !Result.isSuccess(ownRevoke.decoded) || keyId === null) return;
    const { requestId } = ownRevoke.request;
    if (answeredRevoke.current === requestId) return;
    answeredRevoke.current = requestId;
    const bytes = ownRevoke.decoded.success.bytes;
    const controller = new AbortController();
    prompt.current = controller;
    void (async () => {
      let signed: ElevationSignedResponse | null = null;
      try {
        signed = await sign(bytes, controller.signal);
        if (signed === null) declined.current = true;
      } catch (cause) {
        setError(message(cause, "This device couldn't sign."));
        declined.current = true;
      } finally {
        prompt.current = null;
      }
      if (controller.signal.aborted) return;
      // A deny ends the helper's sudo at once, so the revoke call returns.
      await respond({
        environmentId,
        input:
          signed === null
            ? { requestId, decision: "deny", keyId }
            : { requestId, decision: "approve", ...signed },
      });
    })();
  }, [answeredRevoke, ownRevoke, keyId, sign, environmentId, respond]);

  const abandonedRequest =
    abandoned === null ? undefined : pending.find((entry) => isOwnEnrollRequest(entry, abandoned));
  useEffect(() => {
    if (abandonedRequest === undefined) return;
    const { requestId } = abandonedRequest.request;
    if (deniedAbandoned.current === requestId) return;
    deniedAbandoned.current = requestId;
    void respond({ environmentId, input: { requestId, decision: "deny" } });
  }, [abandonedRequest, environmentId, respond]);

  const claimEnroll = step.kind === "elsewhere" ? step.key.publicKey : abandoned;
  const claimRevoke = step.kind === "removing" ? approver.keyId : null;
  useEffect(() => {
    if (claimEnroll === null && claimRevoke === null) return;
    claim(
      (entry) =>
        entry.environmentId === environmentId &&
        ((claimEnroll !== null && isOwnEnrollRequest(entry, claimEnroll)) ||
          (claimRevoke !== null &&
            user !== undefined &&
            isOwnRevokeRequest(entry, user, claimRevoke))),
    );
    return () => claim(null);
  }, [claim, claimEnroll, claimRevoke, environmentId, user]);

  const setupRequested = useElevationSidebarStore(
    (state) => state.setupRequested === environmentId,
  );
  const requestSetup = useElevationSidebarStore((state) => state.requestSetup);
  useEffect(() => {
    if (!setupRequested || enrolled !== undefined || !canSetUp) return;
    requestSetup(null);
    void start();
  }, [setupRequested, enrolled, canSetUp, requestSetup, start]);

  const Icon = here.icon;
  const settingUp =
    step.kind === "creating" || step.kind === "elsewhere" || step.kind === "password";
  const description =
    enrolled !== undefined
      ? `${here.key} · Added ${new Date(enrolled.enrolledAt.epochMilliseconds).toLocaleDateString()}`
      : (setupBlockedReason ?? here.offer);
  return (
    <SettingsRow
      title={
        <span className="flex min-w-0 items-center gap-2">
          <Icon className="size-3.5 shrink-0 text-muted-foreground" aria-hidden />
          <span className="truncate">{enrolled?.label ?? approver.label}</span>
          <Badge variant="secondary">{here.badge}</Badge>
        </span>
      }
      description={description}
      control={
        enrolled !== undefined ? (
          step.kind === "confirm-remove" || step.kind === "removing" ? null : (
            <Button
              variant="destructive-outline"
              size="xs"
              disabled={!canRevoke || !status.helperInstalled}
              onClick={() => setStep({ kind: "confirm-remove" })}
            >
              Remove
            </Button>
          )
        ) : settingUp || step.kind === "terminal" ? null : (
          <Button variant="outline" size="xs" disabled={!canSetUp} onClick={() => void start()}>
            Set up
          </Button>
        )
      }
    >
      {step.kind === "elsewhere" ? (
        <div className="flex flex-col gap-2 text-xs text-muted-foreground">
          <span>Approve on {otherName} if it shows the same code:</span>
          <span className="font-mono text-lg tracking-widest text-foreground">
            {elevationComparisonCode(sha256(step.key.publicKey))}
          </span>
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <Button
              type="button"
              size="sm"
              variant="ghost"
              onClick={() => {
                abandon(step.key);
                setStep(IDLE);
              }}
            >
              Cancel
            </Button>
            <Button
              type="button"
              size="sm"
              variant="link"
              onClick={() => {
                const { key } = step;
                attempt.current += 1;
                setAbandoned(key.publicKey);
                setStep({ kind: "password", key });
              }}
            >
              Use your {words.password} instead
            </Button>
          </div>
        </div>
      ) : null}
      {step.kind === "password" ? (
        <PasswordStep
          words={words}
          firstSetup={!installed}
          busy={busy}
          onSubmit={(password) => void submitPassword(step.key, password)}
          onTerminal={() => void submitPassword(step.key, null)}
          onCancel={() => {
            abandon(null);
            setStep(IDLE);
          }}
        />
      ) : null}
      {changes.length > 0 && enrolled === undefined && step.kind !== "terminal" ? (
        <SetupChanges machine={machine} changes={changes} blocked={blocked} />
      ) : null}
      {step.kind === "terminal" ? (
        <TerminalStep
          machine={words.machine}
          shortPassword={words.shortPassword}
          command={step.command}
          onDone={() => setStep(IDLE)}
        />
      ) : null}
      {step.kind === "added" && enrolled !== undefined ? (
        <p className="flex items-center gap-1.5 text-xs text-foreground">
          <CheckIcon className="size-3.5 shrink-0 text-success" aria-hidden />
          Admin requests from agents now come here{step.first ? "" : " too"}.
        </p>
      ) : null}
      {step.kind === "confirm-remove" || step.kind === "removing" ? (
        <div className="flex flex-col gap-2 text-xs text-muted-foreground">
          <span>
            {here.badge} stops approving on {machine}.
            {others.length === 1
              ? ` ${otherName} still can.`
              : others.length > 1
                ? " Your other devices still can."
                : ""}
          </span>
          <div className="flex min-w-0 items-center gap-2">
            <Button
              type="button"
              size="sm"
              variant="destructive"
              disabled={step.kind === "removing"}
              onClick={() => void remove()}
            >
              Remove
            </Button>
            <Button
              type="button"
              size="sm"
              variant="ghost"
              disabled={step.kind === "removing"}
              onClick={() => setStep(IDLE)}
            >
              Cancel
            </Button>
          </div>
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

/** The machine's password, once: it admits this key, and on first setup turns approval on. */
function PasswordStep(props: {
  readonly words: ElevationPasswordWords;
  readonly firstSetup: boolean;
  readonly busy: boolean;
  readonly onSubmit: (password: string) => void;
  readonly onTerminal: () => void;
  readonly onCancel: () => void;
}) {
  const inputId = useId();
  const [password, setPassword] = useState("");
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (password === "") return;
    props.onSubmit(password);
    setPassword("");
  };
  return (
    <form className="flex flex-col gap-2" autoComplete="off" onSubmit={submit}>
      <label htmlFor={inputId} className="text-xs text-muted-foreground">
        Enter your {props.words.password}, once. The password goes through the T3 server to sudo
        once and is never stored.
        {props.words.touchId ? ` ${ELEVATION_TOUCH_ID_HINT}` : null}
      </label>
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <Input
          id={inputId}
          type="password"
          autoComplete="off"
          placeholder={props.words.password}
          value={password}
          disabled={props.busy}
          onChange={(event) => setPassword(event.currentTarget.value)}
        />
        <Button type="submit" size="sm" disabled={props.busy || password === ""}>
          Continue
        </Button>
        <Button
          type="button"
          size="sm"
          variant="ghost"
          disabled={props.busy}
          onClick={props.onCancel}
        >
          Cancel
        </Button>
        {props.firstSetup ? (
          <Button
            type="button"
            size="sm"
            variant="link"
            disabled={props.busy}
            onClick={props.onTerminal}
          >
            Use a terminal command instead
          </Button>
        ) : null}
      </div>
    </form>
  );
}

/** What first setup writes, before anything is written, as the phone shows it. */
function SetupChanges(props: {
  readonly machine: string;
  readonly changes: ReturnType<typeof deviceApprovalSetupChanges>;
  readonly blocked: boolean;
}) {
  return (
    <div className="flex flex-col gap-1 text-xs text-muted-foreground">
      <span className="text-foreground">What changes on {props.machine}</span>
      <ul className="flex flex-col gap-1">
        {props.changes.map((change) => (
          <li key={change.path} className={change.blocked ? "text-warning" : undefined}>
            {change.summary} <code className="font-mono break-all">{change.path}</code>
          </li>
        ))}
      </ul>
      <span>
        {props.blocked
          ? "Setup can't change a file safely, so it changes nothing."
          : "Turn off restores these files."}
      </span>
    </div>
  );
}

function TerminalStep(props: {
  readonly machine: string;
  readonly shortPassword: string;
  readonly command: string;
  readonly onDone: () => void;
}) {
  return (
    <div className="flex flex-col gap-2 text-xs text-muted-foreground">
      <span>
        Run this on {props.machine}. Paste it into a terminal there; it asks for your{" "}
        {props.shortPassword} once.
      </span>
      <code className="block font-mono break-all whitespace-pre-wrap text-foreground">
        {props.command}
      </code>
      <div className="flex items-center gap-2">
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={() => void navigator.clipboard.writeText(props.command)}
        >
          Copy command
        </Button>
        <Button type="button" size="sm" onClick={props.onDone}>
          Done
        </Button>
      </div>
    </div>
  );
}
