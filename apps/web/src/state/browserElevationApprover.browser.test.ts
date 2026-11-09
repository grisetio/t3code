import {
  decodeElevationBase64Url,
  elevationWebauthnRegistrationRefusal,
  EnvironmentId,
} from "@t3tools/contracts";
import { describe, expect, it } from "vite-plus/test";
import { commands } from "vite-plus/test/browser";

import {
  enrollThisBrowser,
  verifyBrowserApproval,
  virtualAuthenticator,
} from "../../test/virtualPasskey";
import {
  browserApproverLabel,
  browserApproverUnavailableReason,
  browserElevationApproverSource,
} from "./browserElevationApprover";

const environmentId = EnvironmentId.make("env-passkey");
const payload = new TextEncoder().encode('{"requestId":"req-1"}');
const CHROME_MAC =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";
const SAFARI_MAC =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15";

describe("browserElevationApproverSource", () => {
  it("makes a device-bound passkey whose approvals the module would accept", async () => {
    await using _authenticator = await virtualAuthenticator(environmentId);
    const created = await enrollThisBrowser(environmentId);
    expect(created.webauthn).toMatchObject({
      rpId: "localhost",
      origin: window.location.origin,
    });
    const authenticatorData = decodeElevationBase64Url(created.webauthn?.authenticatorData ?? "");
    const credentialId = decodeElevationBase64Url(created.webauthn?.credentialId ?? "");
    expect(
      elevationWebauthnRegistrationRefusal({
        authenticatorData: authenticatorData ?? new Uint8Array(),
        rpIdHash: new Uint8Array(
          await crypto.subtle.digest("SHA-256", new TextEncoder().encode("localhost")),
        ),
        credentialId: credentialId ?? new Uint8Array(),
      }),
    ).toBeNull();

    const signed = await browserElevationApproverSource
      .get(environmentId)
      ?.sign(payload, new AbortController().signal);
    expect(signed).toMatchObject({ keyId: created.keyId, alg: "webauthn-es256" });
    expect(
      await verifyBrowserApproval({
        publicKey: created.publicKey,
        payload,
        signed: signed ?? expect.fail("no signature"),
      }),
    ).toEqual({
      type: "webauthn.get",
      origin: window.location.origin,
      challengeMatches: true,
      userVerified: true,
      backupEligible: false,
      signatureValid: true,
    });
  });

  it("refuses a passkey that can sync, and keeps no binding for it", async () => {
    await using _authenticator = await virtualAuthenticator(environmentId, {
      backupEligible: true,
    });
    const approver = browserElevationApproverSource.get(environmentId);
    await expect(
      approver?.createKey(new AbortController().signal, { name: "kgriset on oracle" }),
    ).rejects.toThrow("That passkey syncs to your other devices.");
    expect(browserElevationApproverSource.get(environmentId)?.keyId).toBeNull();
  });

  it("reads a failed verification as a cancel, which the card sends as Deny", async () => {
    await using _authenticator = await virtualAuthenticator(environmentId);
    await enrollThisBrowser(environmentId);
    await commands.setVirtualAuthenticator({ userVerified: false });
    const signed = await browserElevationApproverSource
      .get(environmentId)
      ?.sign(payload, new AbortController().signal);
    expect(signed).toBeNull();
  });

  it("closes the prompt when its signal aborts", async () => {
    await using _authenticator = await virtualAuthenticator(environmentId);
    await enrollThisBrowser(environmentId);
    await commands.setVirtualAuthenticator({ presence: false });
    const controller = new AbortController();
    const signing = browserElevationApproverSource
      .get(environmentId)
      ?.sign(payload, controller.signal);
    controller.abort();
    expect(await signing).toBeNull();
  });
});

describe("browserApproverUnavailableReason", () => {
  const page = {
    hostname: "oracle.tail1234.ts.net",
    origin: "https://oracle.tail1234.ts.net",
    secureContext: true,
    webauthn: true,
    userAgent: CHROME_MAC,
  };

  it("approves from Chrome on an https name or localhost", () => {
    expect(browserApproverUnavailableReason(page)).toBeNull();
    expect(
      browserApproverUnavailableReason({
        ...page,
        hostname: "localhost",
        origin: "http://localhost:5733",
      }),
    ).toBeNull();
  });

  it("names the secure address it needs on a LAN IP or the desktop's own origin", () => {
    const insecure = /Passkeys need a secure address/;
    expect(
      browserApproverUnavailableReason({
        ...page,
        hostname: "192.168.1.20",
        origin: "http://192.168.1.20:3773",
        secureContext: false,
      }),
    ).toMatch(insecure);
    // An IP is no valid rpId even over https.
    expect(
      browserApproverUnavailableReason({
        ...page,
        hostname: "192.168.1.20",
        origin: "https://192.168.1.20",
      }),
    ).toMatch(insecure);
    expect(
      browserApproverUnavailableReason({ ...page, hostname: "app", origin: "t3code://app" }),
    ).toMatch(insecure);
  });

  it("says Safari can't approve, since it only saves passkeys that sync", () => {
    expect(browserApproverUnavailableReason({ ...page, userAgent: SAFARI_MAC })).toBe(
      "Safari only saves passkeys that sync to your other devices, so it can't approve.",
    );
  });
});

describe("browserApproverLabel", () => {
  it("names the browser and its OS, like a phone's model name", () => {
    expect(browserApproverLabel(CHROME_MAC)).toBe("Chrome on Mac");
    expect(browserApproverLabel(SAFARI_MAC)).toBe("Safari on Mac");
    expect(
      browserApproverLabel(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0",
      ),
    ).toBe("Edge on Windows");
  });
});
