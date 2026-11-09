import { RegistryContext } from "@effect/atom-react";
import { sha256 } from "@noble/hashes/sha2";
import { elevationPasswordWords } from "@t3tools/client-runtime/elevation";
import type { PendingElevationRequest } from "@t3tools/client-runtime/state/elevation";
import {
  decodeElevationBase64Url,
  elevationComparisonCode,
  ElevationKeyId,
  ElevationRequestId,
  EnvironmentId,
  type ElevationDevice,
  type ElevationStatus,
} from "@t3tools/contracts";
import * as DateTime from "effect/DateTime";
import * as Result from "effect/Result";
import { AsyncResult, AtomRegistry, type Atom } from "effect/reactivity";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vite-plus/test";
import { userEvent } from "vite-plus/test/browser";

import type { ElevationApprover } from "../../state/elevationApprover";

const testState = vi.hoisted(() => ({
  commands: {
    install: vi.fn(),
    enroll: vi.fn(),
    revoke: vi.fn(),
    respond: vi.fn(),
  } as Record<string, ReturnType<typeof vi.fn>>,
  pending: null as unknown as Atom.Writable<readonly PendingElevationRequest[]>,
}));

vi.mock(import("../../state/elevation"), async () => {
  const { Atom } = await import("effect/reactivity");
  const allowed = Atom.make(true);
  testState.pending = Atom.make<readonly PendingElevationRequest[]>([]);
  const command = (name: string) => ({ name, permissionAtom: () => allowed });
  return {
    elevation: {
      install: command("install"),
      enroll: command("enroll"),
      revoke: command("revoke"),
      respond: command("respond"),
      pendingAcrossEnvironmentsAtom: testState.pending,
    },
  } as never;
});
vi.mock(import("../../state/use-atom-command"), async (original) => ({
  ...(await original()),
  useAtomCommand: ((command: { name: string }) => testState.commands[command.name]) as never,
}));
vi.mock(import("./settingsLayout"), async (original) => ({
  ...(await original()),
  // The real row reads settings scope and write permission from live environment state.
  SettingsRow: (({
    title,
    description,
    control,
    children,
  }: {
    title: ReactNode;
    description?: ReactNode;
    control?: ReactNode;
    children?: ReactNode;
  }) => (
    <div>
      <h3>{title}</h3>
      <p>{description}</p>
      {control}
      {children}
    </div>
  )) as never,
}));

import { render } from "../../../test/render";
import { enrollThisBrowser, virtualAuthenticator } from "../../../test/virtualPasskey";
import { browserElevationApproverSource } from "../../state/browserElevationApprover";
import { useElevationApprover } from "../../state/elevationApprover";
import { ThisDeviceApproval } from "./ThisDeviceApproval";

const environmentId = EnvironmentId.make("env-settings");
const words = elevationPasswordWords("linux", "oracle");
const enrolledAt = DateTime.makeUnsafe("2026-11-02T10:00:00Z");
const phone: ElevationDevice = {
  keyId: ElevationKeyId.make("cGhvbmUta2V5LWlkLTAwMA"),
  label: "Galaxy Z Fold",
  securityLevel: "strongbox",
  kind: "phone",
  enrolledAt,
  lastUsedAt: null,
};
const on: ElevationStatus = {
  user: "kgriset",
  supported: true,
  ready: true,
  ownsApprovals: true,
  setupOutsideT3: false,
  helperInstalled: true,
  checks: [],
  plannedChanges: [],
  devices: [phone],
};
const off: ElevationStatus = {
  ...on,
  ready: false,
  ownsApprovals: false,
  helperInstalled: false,
  devices: [],
  plannedChanges: [{ path: "/etc/pam.d/sudo", summary: "add T3's approval line" }],
};

function setup() {
  for (const command of Object.values(testState.commands)) command.mockReset();
  testState.commands.respond?.mockResolvedValue(AsyncResult.success(undefined));
  return AtomRegistry.make();
}

/** A command result the test settles when it is ready. */
function deferred() {
  let resolve: (value: unknown) => void = () => {};
  const promise = new Promise((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function Harness(props: {
  readonly status: ElevationStatus;
  readonly approver?: ElevationApprover;
}) {
  const approver = useElevationApprover(environmentId);
  const shown = props.approver ?? approver;
  return shown === null ? null : (
    <ThisDeviceApproval
      environmentId={environmentId}
      machine="oracle"
      words={words}
      status={props.status}
      approver={shown}
      autoStart={false}
    />
  );
}

const harness = (
  registry: AtomRegistry.AtomRegistry,
  status: ElevationStatus,
  approver?: ElevationApprover,
) => (
  <RegistryContext.Provider value={registry}>
    <Harness status={status} {...(approver === undefined ? {} : { approver })} />
  </RegistryContext.Provider>
);

const thisBrowser = (keyId: ElevationKeyId): ElevationDevice => ({
  keyId,
  label: "Chrome on Mac",
  securityLevel: "software",
  kind: "browser",
  enrolledAt,
  lastUsedAt: null,
});

/** The key this browser keeps for the machine, as the card and Settings read it. */
const storedKeyId = () => browserElevationApproverSource.get(environmentId)?.keyId ?? null;

/** The pending request the helper's sudo raises, as the client decodes it. */
function pendingRequest(
  requestId: string,
  payload: { argv?: readonly string[]; enrollKey?: Uint8Array },
): PendingElevationRequest {
  return {
    environmentId,
    request: { requestId: ElevationRequestId.make(requestId), threadId: null } as never,
    decoded: Result.succeed({
      bytes: new TextEncoder().encode(requestId),
      payload: { command: { argv: payload.argv ?? [] } },
      view: {
        enroll:
          payload.enrollKey === undefined
            ? null
            : { label: "Chrome on Mac", publicKey: payload.enrollKey },
      },
    }) as never,
  };
}

describe("ThisDeviceApproval", () => {
  it("sets this browser up when a phone confirms the same code", async () => {
    const registry = setup();
    await using _authenticator = await virtualAuthenticator(environmentId);
    const enrolled = deferred();
    testState.commands.enroll?.mockReturnValue(enrolled.promise);
    await using screen = await render(harness(registry, on));
    await expect.element(screen.getByText("Approve here with a passkey.")).toBeVisible();
    await userEvent.click(screen.getByRole("button", { name: "Set up" }));

    await expect
      .element(screen.getByText("Approve on Galaxy Z Fold if it shows the same code:"))
      .toBeVisible();
    const { device } = testState.commands.enroll?.mock.lastCall?.[0].input;
    expect(device).toMatchObject({
      label: "Chrome on Mac",
      webauthn: { rpId: "localhost", origin: window.location.origin },
    });
    expect(device.webauthn.authenticatorData).toEqual(expect.any(String));
    const publicKey = decodeElevationBase64Url(device.publicKey) ?? new Uint8Array();
    await expect
      .element(screen.getByText(elevationComparisonCode(sha256(publicKey))))
      .toBeVisible();

    enrolled.resolve(AsyncResult.success(undefined));
    const keyId = ElevationKeyId.make(storedKeyId() ?? "");
    await screen.rerender(harness(registry, { ...on, devices: [phone, thisBrowser(keyId)] }));
    await expect
      .element(screen.getByText("Admin requests from agents now come here too."))
      .toBeVisible();
    await expect.element(screen.getByRole("button", { name: "Remove" })).toBeVisible();
  });

  it("turns approval on with the machine's password when nothing approves yet", async () => {
    const registry = setup();
    await using _authenticator = await virtualAuthenticator(environmentId);
    testState.commands.install?.mockResolvedValue(
      AsyncResult.success({ type: "installed", status: off }),
    );
    await using screen = await render(harness(registry, off));
    await expect.element(screen.getByText("What changes on oracle")).toBeVisible();
    await userEvent.click(screen.getByRole("button", { name: "Set up" }));
    await userEvent.type(screen.getByPlaceholder("oracle password"), "hunter2");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    expect(testState.commands.install?.mock.lastCall?.[0].input).toMatchObject({
      password: "hunter2",
      device: { label: "Chrome on Mac" },
    });
    const keyId = ElevationKeyId.make(storedKeyId() ?? "");
    await screen.rerender(harness(registry, { ...on, devices: [thisBrowser(keyId)] }));
    await expect
      .element(screen.getByText("Admin requests from agents now come here."))
      .toBeVisible();
  });

  it("denies its own Add device request and forgets the key when setup is cancelled", async () => {
    const registry = setup();
    await using _authenticator = await virtualAuthenticator(environmentId);
    testState.commands.enroll?.mockReturnValue(deferred().promise);
    await using screen = await render(harness(registry, on));
    await userEvent.click(screen.getByRole("button", { name: "Set up" }));
    await expect.element(screen.getByRole("button", { name: "Cancel" })).toBeVisible();
    const { device } = testState.commands.enroll?.mock.lastCall?.[0].input;
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));

    registry.set(testState.pending, [
      pendingRequest("req-enroll", {
        enrollKey: decodeElevationBase64Url(device.publicKey) ?? new Uint8Array(),
      }),
    ]);
    await vi.waitFor(() =>
      expect(testState.commands.respond?.mock.lastCall?.[0].input).toEqual({
        requestId: "req-enroll",
        decision: "deny",
      }),
    );
    await expect.element(screen.getByRole("button", { name: "Set up" })).toBeEnabled();
  });

  it("removes this browser by approving its own revoke with the passkey", async () => {
    const registry = setup();
    await using _authenticator = await virtualAuthenticator(environmentId);
    const { keyId } = await enrollThisBrowser(environmentId);
    const revoked = deferred();
    testState.commands.revoke?.mockReturnValue(revoked.promise);
    await using screen = await render(
      harness(registry, { ...on, devices: [phone, thisBrowser(keyId)] }),
    );
    await userEvent.click(screen.getByRole("button", { name: "Remove" }));
    await expect
      .element(screen.getByText("This browser stops approving on oracle. Galaxy Z Fold still can."))
      .toBeVisible();
    await userEvent.click(screen.getByRole("button", { name: "Remove" }));
    expect(testState.commands.revoke?.mock.lastCall?.[0].input).toEqual({ keyId });

    registry.set(testState.pending, [
      pendingRequest("req-revoke", {
        argv: ["/usr/local/libexec/t3-elevation", "revoke", "--user", "kgriset", "--key-id", keyId],
      }),
    ]);
    await vi.waitFor(() =>
      expect(testState.commands.respond?.mock.lastCall?.[0].input).toMatchObject({
        requestId: "req-revoke",
        decision: "approve",
        keyId,
        alg: "webauthn-es256",
      }),
    );
    revoked.resolve(AsyncResult.success(undefined));
    await vi.waitFor(() => expect(storedKeyId()).toBeNull());
  });

  it("disables Set up and says why where this browser can't hold a passkey", async () => {
    const registry = setup();
    const safari: ElevationApprover = {
      kind: "browser",
      label: "Safari on Mac",
      keyId: null,
      unavailableReason:
        "Safari only saves passkeys that sync to your other devices, so it can't approve.",
      sign: vi.fn(),
      createKey: vi.fn(),
      forget: vi.fn(),
    };
    await using screen = await render(harness(registry, on, safari));
    await expect.element(screen.getByText(/Safari only saves passkeys that sync/)).toBeVisible();
    await expect.element(screen.getByRole("button", { name: "Set up" })).toBeDisabled();
  });
});
