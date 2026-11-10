import { describe, expect, it } from "@effect/vitest";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";

import vectorsJson from "../test-vectors/device-approval.json" with { type: "json" };

import {
  decodeElevationBase64Url,
  decodeElevationPayload,
  ElevationDevice,
  ElevationEnrollmentDevice,
  ElevationError,
  ElevationStatus,
  elevationComparisonCode,
  elevationKeyIdFromSpkiSha256,
  elevationPasskeyProvider,
  elevationWebauthnAaguid,
  elevationWebauthnRegistrationRefusal,
  elevationWebauthnSite,
  escapeElevationDisplayText,
  parseElevationEnrollCommand,
} from "./elevation.ts";

interface Vectors {
  readonly payloads: ReadonlyArray<{ name: string; payload: string; decoded: unknown }>;
  readonly parse: ReadonlyArray<{ name: string; payload: string; expected: string }>;
  readonly enrollParse: ReadonlyArray<{ name: string; expected: Record<string, unknown> | null }>;
  readonly displayEscaping: ReadonlyArray<{ name: string; input: string; expected: string }>;
  readonly comparisonCodes: ReadonlyArray<{ spkiDer: string; keyId: string; code: string }>;
  readonly webauthnRegistrations: ReadonlyArray<{
    name: string;
    rpId: string;
    credentialId: string;
    authenticatorData: string;
    refusal: string | null;
  }>;
}

const vectors: Vectors = vectorsJson;

const bytesOf = (base64Url: string) => {
  const bytes = decodeElevationBase64Url(base64Url);
  if (bytes === null) throw new Error(`Not base64url: ${base64Url.slice(0, 20)}`);
  return new Uint8Array(bytes);
};
const sha256 = async (bytes: Uint8Array<ArrayBuffer>) =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));

describe("elevation payload", () => {
  it.each(vectors.payloads)("decodes $name exactly as signed", ({ payload, decoded }) => {
    expect(Result.getOrThrow(decodeElevationPayload(bytesOf(payload)))).toEqual(decoded);
  });

  it.each(vectors.parse)("classifies $name as $expected", ({ payload, expected }) => {
    const result = decodeElevationPayload(bytesOf(payload));
    expect(Result.isSuccess(result) ? "ok" : result.failure).toBe(expected);
  });

  it("rejects padded or non-url base64", () => {
    expect(decodeElevationBase64Url("AAAA")).toEqual(new Uint8Array([0, 0, 0]));
    expect(decodeElevationBase64Url("AA==")).toBeNull();
    expect(decodeElevationBase64Url("A+/A")).toBeNull();
    expect(decodeElevationBase64Url("AAAAA")).toBeNull();
  });
});

describe("elevation display", () => {
  it.each(vectors.displayEscaping)("escapes $name", ({ input, expected }) => {
    expect(escapeElevationDisplayText(input)).toBe(expected);
  });

  it("escapes every default-ignorable code point", () => {
    const shownRaw: Array<string> = [];
    for (let code = 0; code <= 0x10ffff; code++) {
      const char = String.fromCodePoint(code);
      if (!/\p{Default_Ignorable_Code_Point}/u.test(char)) continue;
      if (escapeElevationDisplayText(char) === char) shownRaw.push(code.toString(16));
    }
    expect(shownRaw).toEqual([]);
  });
});

describe("elevation enrollment", () => {
  it.each(vectors.webauthnRegistrations)(
    "refuses a $name passkey registration as $refusal",
    async ({ rpId, credentialId, authenticatorData, refusal }) => {
      const rpIdHash = await sha256(new TextEncoder().encode(rpId));
      expect(
        elevationWebauthnRegistrationRefusal({
          authenticatorData: bytesOf(authenticatorData),
          rpIdHash,
          credentialId: bytesOf(credentialId),
        }),
      ).toBe(refusal);
    },
  );

  it("never reads a phone's enrollment with a bad chain as an unattested key", () => {
    const decode = Schema.decodeUnknownOption(ElevationEnrollmentDevice);
    const publicKey = vectorsJson.keys.newDevice.spkiDer;
    const challenge = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";
    expect(decode({ label: "Pixel", publicKey, challenge, attestationChain: [] })._tag).toBe(
      "None",
    );
    expect(decode({ label: "Pixel", publicKey, challenge })._tag).toBe("None");
    expect(decode({ label: "MacBook Pro", publicKey })._tag).toBe("Some");
    expect(decode({ label: "Pixel", publicKey, challenge, attestationChain: ["AAAA"] })._tag).toBe(
      "Some",
    );
  });

  it.each(vectors.comparisonCodes)(
    "derives code $code and keyId",
    async ({ spkiDer, keyId, code }) => {
      const digest = await sha256(bytesOf(spkiDer));
      expect(elevationComparisonCode(digest)).toBe(code);
      expect(elevationKeyIdFromSpkiSha256(digest)).toBe(keyId);
    },
  );

  it.each(vectors.enrollParse)("parses the enroll command in $name", async ({ name, expected }) => {
    const vector = vectors.payloads.find((candidate) => candidate.name === name)!;
    const payload = Result.getOrThrow(decodeElevationPayload(bytesOf(vector.payload)));
    const parsed = parseElevationEnrollCommand(payload);
    if (expected === null) {
      expect(parsed).toBeNull();
      return;
    }
    const { comparisonCode, ...command } = expected;
    expect(parsed).toEqual(command);
    expect(elevationComparisonCode(await sha256(bytesOf(parsed!.publicKey)))).toBe(comparisonCode);
  });

  it("treats any deviation from the helper's grammar as a plain command", () => {
    const enroll = vectors.payloads.find((candidate) => candidate.name === "enroll")!;
    const payload = Result.getOrThrow(decodeElevationPayload(bytesOf(enroll.payload)));
    const withArgv = (argv: ReadonlyArray<string>) =>
      parseElevationEnrollCommand({ ...payload, command: { ...payload.command, argv } });
    const argv = payload.command.argv;

    expect(withArgv([...argv, "--allow-dev-attestation"])?.allowDevAttestation).toBe(true);
    expect(withArgv([...argv, "--allow-dev-attestation", "--allow-test-attestation"])).toBeNull();
    expect(withArgv([...argv, "--allow-test-attestation", "--allow-test-attestation"])).toBeNull();
    expect(withArgv([...argv, "--label", "Second"])).toBeNull();
    expect(withArgv([...argv, "--bogus"])).toBeNull();
    expect(withArgv([...argv, "--user"])).toBeNull();
    expect(withArgv(["/tmp/not-the-helper", ...argv.slice(1)])).toBeNull();
    expect(withArgv(argv.filter((_, index) => index !== 8 && index !== 9))).toBeNull();
    // Unattested keys never take the attested grammar, nor it theirs.
    expect(withArgv([...argv, "--unattested"])).toBeNull();
    expect(
      withArgv([...argv, "--rp-id", "localhost", "--origin", "http://localhost:3773"]),
    ).toBeNull();
    const unattested = [...argv.slice(0, 8), "--unattested"];
    expect(withArgv(unattested)?.unattested).toBe(true);
    expect(withArgv([...unattested, "--unattested"])).toBeNull();
    expect(withArgv([...unattested, "--allow-test-attestation"])).toBeNull();
    expect(withArgv([...unattested, "--rp-id", "localhost"])).toBeNull();
    expect(
      withArgv([...unattested, "--rp-id", "localhost", "--origin", "http://localhost:3773"])?.site,
    ).toEqual({ rpId: "localhost", origin: "http://localhost:3773" });
  });

  it("binds a passkey only to an exact origin its rpId covers", () => {
    const ok = (rpId: string, origin: string) => elevationWebauthnSite(rpId, origin) !== null;
    expect(ok("app.t3.codes", "https://app.t3.codes")).toBe(true);
    expect(ok("t3.codes", "https://app.t3.codes")).toBe(true);
    expect(ok("mac.tail1234.ts.net", "https://mac.tail1234.ts.net:8443")).toBe(true);
    expect(ok("localhost", "http://localhost:3773")).toBe(true);
    expect(ok("localhost", "https://localhost")).toBe(true);
    for (const [rpId, origin] of [
      ["app.t3.codes", "https://t3.codes"],
      ["pp.t3.codes", "https://app.t3.codes"],
      ["app.t3.codes", "http://app.t3.codes"],
      ["app.t3.codes", "https://app.t3.codes/"],
      ["app.t3.codes", "https://app.t3.codes:443"],
      ["localhost", "http://localhost:80"],
      ["app.t3.codes", "https://app.t3.codes:0443"],
      ["app.t3.codes", "https://app.t3.codes:70000"],
      ["App.t3.codes", "https://App.t3.codes"],
      ["192.168.1.20", "https://192.168.1.20"],
      ["", "https://app.t3.codes"],
      ["app.t3.codes", "https://user@app.t3.codes"],
      ["app.t3.codes", "t3code://app.t3.codes"],
    ] as const) {
      expect(ok(rpId, origin), `${rpId} ${origin}`).toBe(false);
    }
  });

  // Its owner could swap a user-writable copy after approval.
  it("treats a user-writable t3-elevation as a plain command", () => {
    const enroll = vectors.payloads.find((candidate) => candidate.name === "enroll")!;
    const payload = Result.getOrThrow(decodeElevationPayload(bytesOf(enroll.payload)));
    const helper = "/home/alice/.cache/t3/t3-elevation";
    const parsed = parseElevationEnrollCommand({
      ...payload,
      command: {
        argv: [helper, ...payload.command.argv.slice(1)],
        resolvedPath: helper,
        warnings: [{ code: "user_writable_program" }],
      },
    });
    expect(parsed).toBeNull();
    // A writable folder above the installed path, as with Intel Homebrew's /usr/local/lib.
    const writableInstall = parseElevationEnrollCommand({
      ...payload,
      command: { ...payload.command, warnings: [{ code: "user_writable_program" }] },
    });
    expect(writableInstall).toBeNull();
    const elsewhere = parseElevationEnrollCommand({
      ...payload,
      command: { ...payload.command, resolvedPath: "/opt/t3/t3-elevation" },
    });
    expect(elsewhere).toBeNull();
  });
});

const decodeStatusJson = Schema.decodeUnknownSync(Schema.toCodecJson(ElevationStatus));
// The phone app 2.3.13 and older decode with their own schema, which lacks these keys; only
// optional keys were added, and no literal, so they still decode a new server's status.
const { synced: _synced, provider: _provider, ...oldDeviceFields } = ElevationDevice.fields;
const {
  allowSyncedPasskeys: _allow,
  devices: _devices,
  ...oldStatusFields
} = ElevationStatus.fields;
const decodeOldStatusJson = Schema.decodeUnknownSync(
  Schema.toCodecJson(
    Schema.Struct({ ...oldStatusFields, devices: Schema.Array(Schema.Struct(oldDeviceFields)) }),
  ),
);

describe("synced passkeys", () => {
  const registration = (name: string) =>
    bytesOf(
      vectors.webauthnRegistrations.find((vector) => vector.name === name)!.authenticatorData,
    );

  it("reads the AAGUID that names a password manager", () => {
    const bytes = registration("synced");
    expect(elevationWebauthnAaguid(bytes)).toBeNull();
    bytes.set([0xd5, 0x48, 0x82, 0x6e, 0x79, 0xb4, 0xdb, 0x40, 0xa3, 0xd8, 0x11, 0x11], 37);
    bytes.set([0x6f, 0x7e, 0x83, 0x49], 49);
    const aaguid = elevationWebauthnAaguid(bytes);
    expect(aaguid).toBe("d548826e-79b4-db40-a3d8-11116f7e8349");
    expect(elevationPasskeyProvider(aaguid)).toBe("Bitwarden");
    expect(elevationPasskeyProvider("00112233-4455-6677-8899-aabbccddeeff")).toBeNull();
    expect(elevationPasskeyProvider(undefined)).toBeNull();
  });

  it("names the provider in a refusal only when it is known", () => {
    expect(new ElevationError({ reason: "synced_passkey", provider: "1Password" }).message).toBe(
      "1Password saved this passkey and syncs it to your other devices. To use it, turn on Allow passkeys from password managers under Details, or set up again and save it to this device.",
    );
    expect(new ElevationError({ reason: "synced_passkey" }).message).toMatch(
      /^That passkey syncs to your other devices\. To use it, turn on Allow passkeys/,
    );
  });

  const device = {
    keyId: vectorsJson.keys.webauthnDevice.keyId,
    label: "Chrome on Mac",
    securityLevel: "webauthn",
    kind: "browser",
    webauthn: vectorsJson.keys.webauthnDevice.webauthn,
    enrolledAt: "2026-11-10T12:00:00.000Z",
    lastUsedAt: null,
  };
  const status = {
    user: "me",
    supported: true,
    ready: true,
    ownsApprovals: true,
    setupOutsideT3: false,
    installedByT3: true,
    helperInstalled: true,
    checks: [],
    plannedChanges: [],
  };

  it("decodes a status from a server that predates the setting", () => {
    const decoded = decodeStatusJson({
      ...status,
      devices: [device],
    });
    expect(decoded.allowSyncedPasskeys).toBeUndefined();
    expect(decoded.devices[0]?.synced).toBeUndefined();
  });

  it("keeps a new server's status decodable by clients that predate the setting", () => {
    const current = {
      ...status,
      allowSyncedPasskeys: true,
      devices: [{ ...device, synced: true, provider: "Bitwarden" }],
    };
    expect(decodeStatusJson(current).devices[0]?.provider).toBe("Bitwarden");
    expect(decodeOldStatusJson(current).devices[0]?.securityLevel).toBe("webauthn");
  });
});
