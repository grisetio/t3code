import { describe, expect, it } from "vite-plus/test";
import * as Result from "effect/Result";
import * as Base64Url from "effect/encoding/Base64Url";

import {
  decodeElevationRequestPayload,
  elevationFailureMessage,
  elevationRequestFallbackView,
  elevationRequestStatusView,
} from "./elevation.ts";
import { ElevationError } from "@t3tools/contracts";

const NEW_DEVICE_SPKI =
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUadYCDOJjqGxg8vXNQpAmQeMbvHB4Y6XDNdoMDXyXn0BEFInErC1p8_wgWhUhphKlOaDHtrEbnNg-p2DSnqBoQ";

function encodePayload(command: {
  readonly argv: readonly string[];
  readonly resolvedPath: string | null;
  readonly warnings: ReadonlyArray<{ readonly code: string; readonly arg?: number }>;
}): string {
  const payload = {
    v: 1,
    kind: "sudo",
    nonce: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    issuedAt: 1793318400,
    expiresAt: 1793318500,
    host: { name: "mac‮book", machineId: "PrG9Q5lH63YpmOVmzMLgmceREYsvQFecxPfaK1Bht_k" },
    user: "kgriset",
    uid: 501,
    runAs: "root",
    runAsGroup: null,
    argv: ["sudo", ...command.argv],
    command,
    cwd: "/tmp/x\ny",
    service: "sudo",
    keyIds: ["doBaY6aYDBgHVCShPzJ3LQ"],
  };
  return Base64Url.encode(new TextEncoder().encode(JSON.stringify(payload)));
}

describe("decodeElevationRequestPayload", () => {
  it("shows every payload string escaped and warnings tied to the argument they name", () => {
    const decoded = Result.getOrThrow(
      decodeElevationRequestPayload(
        encodePayload({
          argv: ["python3", "x​.py"],
          resolvedPath: "/Users/kgriset/.local/bin/python3",
          warnings: [{ code: "user_writable_argument", arg: 1 }, { code: "some_future_warning" }],
        }),
      ),
    );
    expect(decoded.view.host).toBe("mac\\u{202E}book");
    expect(decoded.view.cwd).toBe("/tmp/x\\ny");
    expect(decoded.view.commandArgv).toEqual(["python3", "x\\u{200B}.py"]);
    expect(decoded.view.warnings.map((warning) => warning.message)).toEqual([
      "x\\u{200B}.py is a file you can write, so anything running as you could change it.",
      "Warning: some_future_warning",
    ]);
    expect(decoded.view.enroll).toBeNull();
  });

  it("recognizes the helper's enroll command so the prompt can say Add device", () => {
    const decoded = Result.getOrThrow(
      decodeElevationRequestPayload(
        encodePayload({
          argv: [
            "/usr/local/lib/t3-elevation/t3-elevation",
            "enroll",
            "--user",
            "kgriset",
            "--label",
            "Pixel‮",
            "--public-key",
            NEW_DEVICE_SPKI,
            "--challenge",
            "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
            "--allow-dev-attestation",
          ],
          resolvedPath: "/usr/local/lib/t3-elevation/t3-elevation",
          warnings: [],
        }),
      ),
    );
    expect(decoded.view.enroll?.label).toBe("Pixel\\u{202E}");
    expect(decoded.view.enroll?.allowDevAttestation).toBe(true);
    expect(decoded.view.warnings.map((warning) => warning.message)).toEqual([
      "Accepts debug builds of the T3 app.",
    ]);
    expect(Base64Url.encode(decoded.view.enroll!.publicKey)).toBe(NEW_DEVICE_SPKI);
  });

  it("flags --allow-test-attestation in the enroll argv when the module doesn't", () => {
    const decoded = Result.getOrThrow(
      decodeElevationRequestPayload(
        encodePayload({
          argv: [
            "/usr/local/lib/t3-elevation/t3-elevation",
            "enroll",
            "--user",
            "kgriset",
            "--label",
            "Pixel",
            "--public-key",
            NEW_DEVICE_SPKI,
            "--challenge",
            "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
            "--allow-test-attestation",
          ],
          resolvedPath: "/usr/local/lib/t3-elevation/t3-elevation",
          warnings: [],
        }),
      ),
    );
    expect(decoded.view.enroll?.allowTestAttestation).toBe(true);
    expect(decoded.view.warnings.map((warning) => warning.message)).toEqual([
      "Accepts emulators and test keys.",
    ]);
  });

  it("names attestation shortcuts once, whether the module or the enroll argv flags them", () => {
    const decoded = Result.getOrThrow(
      decodeElevationRequestPayload(
        encodePayload({
          argv: [
            "/usr/local/lib/t3-elevation/t3-elevation",
            "enroll",
            "--user",
            "kgriset",
            "--label",
            "Pixel",
            "--public-key",
            NEW_DEVICE_SPKI,
            "--challenge",
            "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
            "--allow-dev-attestation",
          ],
          resolvedPath: "/usr/local/lib/t3-elevation/t3-elevation",
          warnings: [{ code: "dev_attestation" }, { code: "test_attestation" }],
        }),
      ),
    );
    expect(decoded.view.warnings.map((warning) => warning.message)).toEqual([
      "Accepts debug builds of the T3 app.",
      "Accepts emulators and test keys.",
    ]);
  });

  it("names the unresolved program and attestation warnings that carry an argument index", () => {
    const decoded = Result.getOrThrow(
      decodeElevationRequestPayload(
        encodePayload({
          argv: [
            "/usr/local/lib/t3-elevation/t3-elevation",
            "enroll",
            "--user",
            "kgriset",
            "--label",
            "Pixel",
            "--public-key",
            NEW_DEVICE_SPKI,
            "--challenge",
            "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
            "--allow-dev-attestation",
          ],
          resolvedPath: null,
          warnings: [{ code: "unresolved_program" }, { code: "dev_attestation", arg: 10 }],
        }),
      ),
    );
    expect(decoded.view.warnings.map((warning) => warning.message)).toEqual([
      "Couldn't determine which program sudo will run.",
      "Accepts debug builds of the T3 app.",
    ]);
  });

  it("names the working directory and environment warnings", () => {
    const decoded = Result.getOrThrow(
      decodeElevationRequestPayload(
        encodePayload({
          argv: ["git", "clean", "-fdx"],
          resolvedPath: "/usr/bin/git",
          warnings: [{ code: "user_writable_cwd" }, { code: "user_environment" }],
        }),
      ),
    );
    expect(decoded.view.warnings.map((warning) => warning.message)).toEqual([
      "You can write to the working directory, so anything running as you could change what the command reads from it.",
      "sudo passes some of your environment variables to the command, so they could point it at your files.",
    ]);
  });

  it("refuses bytes that are not a strict payload", () => {
    expect(decodeElevationRequestPayload("not base64url!")).toEqual(Result.fail("invalid_json"));
    expect(
      decodeElevationRequestPayload(
        Base64Url.encode(new TextEncoder().encode(JSON.stringify({ v: 1, kind: "ssh" }))),
      ),
    ).toEqual(Result.fail("unknown_kind"));
  });
});

describe("elevationRequestFallbackView", () => {
  // The item mirrors sudo's argv, so `arg` would name the wrong entry.
  it("doesn't resolve warning arguments against sudo's own argv", () => {
    const view = elevationRequestFallbackView({
      argv: ["sudo", "-g", "wheel", "python3", "x.py"],
      runAs: "#0 (root)",
      cwd: "/tmp",
      host: "mac",
      warnings: [{ code: "user_writable_argument", arg: 1 }],
    });
    expect(view.warnings.map((warning) => warning.message)).toEqual([
      "An argument is a file you can write, so anything running as you could change it.",
    ]);
  });
});

describe("elevationRequestStatusView", () => {
  it("names the answering device and keeps the failure reason", () => {
    expect(
      elevationRequestStatusView({
        elevationStatus: "approved",
        resolvedBy: { deviceLabel: "Fold\n" },
      }),
    ).toEqual({ kind: "approved", label: "Approved on Fold\\n", detail: null });
    expect(
      elevationRequestStatusView({
        elevationStatus: "cancelled",
        failure: "too_large",
        resolvedBy: null,
      }),
    ).toEqual({
      kind: "cancelled",
      label: "Cancelled",
      detail: "Too long to approve on a device; use the terminal.",
    });
  });
});

describe("elevationFailureMessage", () => {
  it("passes server errors through with the helper's detail and hides anything else", () => {
    expect(
      elevationFailureMessage(
        new ElevationError({ reason: "helper_failed", detail: "visudo failed" }),
        "fallback",
      ),
    ).toBe("The device approval helper failed. visudo failed");
    expect(elevationFailureMessage(new Error("password=hunter2"), "fallback")).toBe("fallback");
  });
});
