import { describe, expect, it } from "@effect/vitest";
import * as Result from "effect/Result";

import vectorsJson from "../test-vectors/device-approval.json" with { type: "json" };

import {
  decodeElevationBase64Url,
  decodeElevationPayload,
  elevationComparisonCode,
  elevationKeyIdFromSpkiSha256,
  escapeElevationDisplayText,
  parseElevationEnrollCommand,
} from "./elevation.ts";

interface Vectors {
  readonly payloads: ReadonlyArray<{ name: string; payload: string; decoded: unknown }>;
  readonly parse: ReadonlyArray<{ name: string; payload: string; expected: string }>;
  readonly enrollParse: ReadonlyArray<{ name: string; expected: Record<string, unknown> | null }>;
  readonly displayEscaping: ReadonlyArray<{ name: string; input: string; expected: string }>;
  readonly comparisonCodes: ReadonlyArray<{ spkiDer: string; keyId: string; code: string }>;
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
