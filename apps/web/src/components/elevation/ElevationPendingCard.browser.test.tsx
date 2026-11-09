import {
  ElevationError,
  ElevationKeyId,
  ElevationRequestId,
  EnvironmentId,
  type ElevationRespondInput,
} from "@t3tools/contracts";
import * as Cause from "effect/Cause";
import { AsyncResult } from "effect/reactivity";
import { describe, expect, it, vi } from "vite-plus/test";
import { commands, userEvent } from "vite-plus/test/browser";

import type { ElevationApprover } from "../../state/elevationApprover";

const testState = vi.hoisted(() => ({
  respond: vi.fn(),
  approver: null as ElevationApprover | null,
}));

vi.mock(import("../../state/elevation"), async () => {
  const { Atom } = await import("effect/reactivity");
  const allowed = Atom.make(true);
  return { elevation: { respond: { permissionAtom: () => allowed } } } as never;
});
vi.mock(import("../../state/use-atom-command"), async (original) => ({
  ...(await original()),
  useAtomCommand: (() => testState.respond) as never,
}));
vi.mock(import("../../state/environments"), async (original) => ({
  ...(await original()),
  useEnvironment: (() => ({ label: "oracle" })) as never,
}));
// A Mac approver stands in where a browser can't reach the state under test.
vi.mock(import("../../state/elevationApprover"), async (original) => {
  const actual = await original();
  return {
    ...actual,
    useElevationApprover: (environmentId: EnvironmentId) => {
      const real = actual.useElevationApprover(environmentId);
      return testState.approver ?? real;
    },
  };
});

import { render } from "../../../test/render";
import { enrollThisBrowser, virtualAuthenticator } from "../../../test/virtualPasskey";
import { ElevationPendingCard, type ElevationSignable } from "./ElevationPendingCard";

const environmentId = EnvironmentId.make("env-card");
const requestId = ElevationRequestId.make("req-card");
const bytes = new TextEncoder().encode('{"requestId":"req-card"}');
const PHONE_KEY = ElevationKeyId.make("cGhvbmUta2V5LWlkLTAwMA");

function setup() {
  testState.respond.mockReset();
  testState.respond.mockResolvedValue(AsyncResult.success(undefined));
  testState.approver = null;
}

function card(
  props: {
    readonly signable?: ElevationSignable | null;
    readonly enrollKey?: Uint8Array | null;
    readonly ended?: { kind: "approved"; text: string } | null;
  } = {},
) {
  return (
    <ElevationPendingCard
      environmentId={environmentId}
      requestId={requestId}
      threadId={null}
      explanation="Restart the deploy service"
      agent={null}
      headline="“Restart the deploy service”"
      enrollKey={props.enrollKey ?? null}
      command={null}
      facts={[]}
      warnings={[]}
      decodeFailure={null}
      changes={null}
      signable={props.signable === undefined ? { bytes, keyIds: [PHONE_KEY] } : props.signable}
      ended={props.ended ?? null}
    />
  );
}

const respondedWith = () =>
  testState.respond.mock.lastCall?.[0] as
    | { environmentId: EnvironmentId; input: ElevationRespondInput }
    | undefined;

describe("ElevationPendingCard", () => {
  it("approves with this browser's passkey where the machine accepts its key", async () => {
    setup();
    await using _authenticator = await virtualAuthenticator(environmentId);
    const { keyId } = await enrollThisBrowser(environmentId);
    await using screen = await render(card({ signable: { bytes, keyIds: [PHONE_KEY, keyId] } }));
    await userEvent.click(screen.getByRole("button", { name: "Approve" }));
    await expect.element(screen.getByRole("button", { name: "Approved" })).toBeVisible();
    expect(respondedWith()).toMatchObject({
      environmentId,
      input: { requestId, decision: "approve", keyId, alg: "webauthn-es256" },
    });
    expect(screen.getByRole("button", { name: "Deny" }).query()).toBeNull();
  });

  it("denies, naming this browser, when the passkey prompt is cancelled", async () => {
    setup();
    await using _authenticator = await virtualAuthenticator(environmentId);
    const { keyId } = await enrollThisBrowser(environmentId);
    await commands.setVirtualAuthenticator({ userVerified: false });
    await using screen = await render(card({ signable: { bytes, keyIds: [keyId] } }));
    await userEvent.click(screen.getByRole("button", { name: "Approve" }));
    await expect.element(screen.getByText("Denied")).toBeVisible();
    expect(respondedWith()?.input).toEqual({ requestId, decision: "deny", keyId });
  });

  it("closes the prompt when another device answers, and says who did", async () => {
    setup();
    await using _authenticator = await virtualAuthenticator(environmentId);
    const { keyId } = await enrollThisBrowser(environmentId);
    await commands.setVirtualAuthenticator({ presence: false });
    const signable = { bytes, keyIds: [keyId] };
    await using screen = await render(card({ signable }));
    await userEvent.click(screen.getByRole("button", { name: "Approve" }));
    await expect.element(screen.getByRole("button", { name: "Approve" })).toBeDisabled();
    await screen.rerender(
      card({ signable, ended: { kind: "approved", text: "Approved on Galaxy Z Fold" } }),
    );
    await expect.element(screen.getByText("Approved on Galaxy Z Fold")).toBeVisible();
    expect(screen.getByRole("alert").query()).toBeNull();
    expect(testState.respond).not.toHaveBeenCalled();
  });

  it("shows the card's outcome, not an error, when its approval lost the race", async () => {
    setup();
    testState.respond.mockResolvedValue(
      AsyncResult.failure(Cause.fail(new ElevationError({ reason: "already_resolved" }))),
    );
    await using screen = await render(card());
    await userEvent.click(screen.getByRole("button", { name: "Deny" }));
    expect(respondedWith()?.input).toEqual({ requestId, decision: "deny" });
    await screen.rerender(card({ ended: { kind: "approved", text: "Approved on Galaxy Z Fold" } }));
    await expect.element(screen.getByText("Approved on Galaxy Z Fold")).toBeVisible();
    expect(screen.getByRole("alert").query()).toBeNull();
  });

  it("offers to set this browser up where it isn't an approver, except on Add device", async () => {
    setup();
    await using screen = await render(card());
    await expect.element(screen.getByText("Approve on your phone")).toBeVisible();
    await expect.element(screen.getByRole("button", { name: "Set up this browser" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Approve" }).query()).toBeNull();

    await screen.rerender(card({ enrollKey: new Uint8Array(65) }));
    await expect.element(screen.getByText("Approve on your phone")).toBeVisible();
    expect(screen.getByRole("button", { name: "Set up this browser" }).query()).toBeNull();
  });

  it("goes back to the phone, saying why, when this Mac's key can't sign now", async () => {
    setup();
    const keyId = ElevationKeyId.make("bWFjLWtleS1pZC0wMDAwMA");
    testState.approver = {
      kind: "mac",
      label: "MacBook Pro",
      keyId,
      unavailableReason: "Touch ID needs the lid open",
      sign: vi.fn(),
      createKey: vi.fn(),
      forget: vi.fn(),
    };
    await using screen = await render(card({ signable: { bytes, keyIds: [keyId] } }));
    await expect.element(screen.getByText("Touch ID needs the lid open")).toBeVisible();
    expect(screen.getByRole("button", { name: "Approve" }).query()).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Deny" }));
    expect(respondedWith()?.input).toEqual({ requestId, decision: "deny", keyId });
  });
});
