import { describe, expect, it } from "vite-plus/test";
import * as DateTime from "effect/DateTime";
import * as Result from "effect/Result";
import * as Base64Url from "effect/encoding/Base64Url";

import {
  decodeElevationRequestPayload,
  elevationAgent,
  elevationFailureMessage,
  elevationHeadline,
  elevationNoticeText,
  elevationRequestSource,
  elevationSeriesLine,
  elevationRequestFacts,
  elevationResolvedSummary,
  elevationRequestFallbackView,
  elevationRequestStatusView,
  elevationSudoApproval,
} from "./elevation.ts";
import {
  ElevationError,
  ProviderDriverKind,
  ProviderInstanceId,
  type ServerProvider,
} from "@t3tools/contracts";

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
  const at = DateTime.makeUnsafe(Date.UTC(2026, 9, 31, 13, 18));
  const time = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" }).format(
    at.epochMilliseconds,
  );
  const ended = { updatedAt: at, completedAt: at };

  it("says it was this phone when the approving key is this phone's", () => {
    const item = {
      ...ended,
      elevationStatus: "approved" as const,
      resolvedBy: { deviceLabel: "Fold\n", keyId: "doBaY6aYDBgHVCShPzJ3LQ" },
    };
    expect(
      elevationRequestStatusView(item, { finished: false, thisKeyId: "doBaY6aYDBgHVCShPzJ3LQ" }),
    ).toEqual({
      kind: "approved",
      label: "Approved",
      time,
      how: `Approved on this phone · ${time}`,
      detail: null,
    });
    expect(elevationRequestStatusView(item, { finished: true })).toEqual({
      kind: "done",
      label: "Done",
      time,
      how: `Approved on Fold\\n · ${time} · finished`,
      detail: null,
    });
  });

  it("names the phone that denied, from the item or from this session", () => {
    const item = {
      ...ended,
      elevationStatus: "denied" as const,
      resolvedBy: { deviceLabel: "Fold", keyId: "doBaY6aYDBgHVCShPzJ3LQ" },
    };
    expect(
      elevationRequestStatusView(item, { finished: true, thisKeyId: "doBaY6aYDBgHVCShPzJ3LQ" }),
    ).toMatchObject({ label: "Denied", how: `Denied on this phone · ${time}` });
    expect(elevationRequestStatusView(item, { finished: true })).toMatchObject({
      how: `Denied on Fold · ${time}`,
    });
    expect(
      elevationRequestStatusView(
        { ...item, resolvedBy: null },
        { finished: true, deniedHere: true },
      ),
    ).toMatchObject({ how: `Denied on this phone · ${time}` });
    expect(
      elevationRequestStatusView({ ...item, resolvedBy: null }, { finished: true }),
    ).toMatchObject({ how: `Denied · ${time}` });
  });

  it("uses one expired text and keeps the failure reason", () => {
    expect(
      elevationRequestStatusView(
        { ...ended, elevationStatus: "expired", resolvedBy: null },
        { finished: true },
      ),
    ).toMatchObject({ label: "Expired", how: `Nobody approved in time · ${time}` });
    expect(
      elevationRequestStatusView(
        { ...ended, elevationStatus: "cancelled", failure: "too_large", resolvedBy: null },
        { finished: true },
      ),
    ).toEqual({
      kind: "cancelled",
      label: "Cancelled",
      time,
      how: `Cancelled · ${time}`,
      detail: "Too long to approve on a device; use the terminal.",
    });
  });
});

describe("elevationHeadline", () => {
  const decoded = decodeElevationRequestPayload(
    encodePayload({ argv: ["killall", "coreaudiod"], resolvedPath: null, warnings: [] }),
  );

  it("leads with the trimmed reason in quotes, else a fixed line that is never the command", () => {
    expect(
      elevationHeadline({ explanation: "  Restart audio\n", decoded, agentName: "Claude" }),
    ).toBe("“Restart audio”");
    expect(elevationHeadline({ explanation: "  ", decoded, agentName: "Claude" })).toBe(
      "Claude wants admin access",
    );
    expect(
      elevationHeadline({ explanation: null, decoded: Result.fail("too_large"), agentName: null }),
    ).toBe("An agent wants admin access");
  });
});

describe("elevationResolvedSummary", () => {
  it("names the reason, else the programs", () => {
    const display = { programs: ["id", "ls"], short: "id, ls" };
    expect(elevationResolvedSummary("Approved", " Restart audio ", display)).toBe(
      "Approved · Restart audio",
    );
    expect(elevationResolvedSummary("Denied", null, display)).toBe("Denied · id, ls");
  });
});

describe("elevationRequestFacts", () => {
  it("shows Runs as and Directory only where they differ from root and the checkout", () => {
    expect(elevationRequestFacts({ runAs: "root", cwd: "/w/app" }, { cwd: "/w/app/" })).toEqual([]);
    expect(
      elevationRequestFacts(
        { runAs: "postgres", runAsGroup: "staff", cwd: "/tmp" },
        { cwd: "/w/app" },
      ),
    ).toEqual([
      { label: "Runs as", value: "postgres (group staff)", mono: false },
      { label: "Directory", value: "/tmp", mono: true },
    ]);
    expect(elevationRequestFacts({ runAs: "root", cwd: "/w" }, { cwd: null })).toEqual([
      { label: "Directory", value: "/w", mono: true },
    ]);
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

describe("elevationSudoApproval", () => {
  const device = {
    keyId: "doBaY6aYDBgHVCShPzJ3LQ",
    label: "Pixel",
    securityLevel: "strongbox" as const,
    enrolledAt: DateTime.makeUnsafe(0),
    lastUsedAt: null,
  };

  it("needs the password and holds back the test until a device is enrolled", () => {
    const noDevice = elevationSudoApproval({ ownsApprovals: true, devices: [] });
    expect(noDevice.passwordRequired).toBe(true);
    expect(noDevice.testUnavailableReason).toEqual(expect.any(String));

    expect(elevationSudoApproval({ ownsApprovals: true, devices: [device] })).toEqual({
      passwordRequired: false,
      testUnavailableReason: null,
    });
  });

  it("leaves the password optional for setup, which can give a terminal command instead", () => {
    expect(elevationSudoApproval({ ownsApprovals: false, devices: [] }).passwordRequired).toBe(
      false,
    );
  });
});

describe("elevationAgent", () => {
  const claude = ProviderDriverKind.make("claudeAgent");
  const provider = (instanceId: string, displayName?: string) =>
    ({
      instanceId: ProviderInstanceId.make(instanceId),
      driver: claude,
      ...(displayName === undefined ? {} : { displayName }),
    }) as unknown as ServerProvider;

  it("names the agent from its process's driver when no thread is known", () => {
    expect(elevationAgent(null, [provider("claudeAgent", "Claude")], claude)).toMatchObject({
      driver: claude,
      instanceId: "claudeAgent",
      name: "Claude",
    });
    // Several instances run the driver: the driver's name, no instance.
    expect(
      elevationAgent(null, [provider("claudeAgent"), provider("claude-work", "Work")], claude),
    ).toMatchObject({ driver: claude, instanceId: null, name: "Claude" });
    expect(elevationAgent(null, [], undefined)).toBeNull();
  });

  it("prefers the thread's own instance over the driver", () => {
    const thread = {
      modelSelection: { instanceId: ProviderInstanceId.make("claude-work") },
      runtime: null,
    };
    expect(
      elevationAgent(thread, [provider("claudeAgent"), provider("claude-work", "Work")], claude)
        ?.name,
    ).toBe("Work");
  });
});

describe("elevationRequestSource", () => {
  it("says a request no thread claims wasn't placed, and leaves the agent to the headline", () => {
    expect(
      elevationRequestSource({
        explanation: null,
        threadId: null,
        raisedByT3: undefined,
        machine: "Killian's MacBook Pro",
      }),
    ).toEqual({ agentMark: false, parts: ["Killian's MacBook Pro", "thread not found"] });
    // In the threads list the section header names the machine.
    expect(
      elevationRequestSource({
        explanation: null,
        threadId: null,
        raisedByT3: false,
        machine: null,
      }),
    ).toEqual({ agentMark: false, parts: ["thread not found"] });
  });

  it("leads with the agent's mark under its reason, and T3 for its own sudo", () => {
    expect(
      elevationRequestSource({
        explanation: "Deploy",
        threadId: "thread:a",
        raisedByT3: undefined,
        machine: "mac",
      }),
    ).toEqual({ agentMark: true, parts: ["mac"] });
    expect(
      elevationRequestSource({
        explanation: "Test device approval",
        threadId: null,
        raisedByT3: true,
        machine: "mac",
      }),
    ).toEqual({ agentMark: false, parts: ["T3 Code", "mac"] });
  });
});

describe("elevationSeriesLine", () => {
  const at = (millis: number) => DateTime.makeUnsafe(millis);
  it("says which request this is and how long ago the first ended", () => {
    const line = (series: Parameters<typeof elevationSeriesLine>[0], threadId: string | null) => {
      const { ordinal, rest } = elevationSeriesLine(series, threadId, 10_000);
      return ordinal + rest;
    };
    expect(
      line({ ordinal: 2, first: { elevationStatus: "approved", resolvedAt: at(6_000) } }, "t"),
    ).toBe("2nd request this turn · first approved 4 s ago");
    expect(
      line({ ordinal: 3, first: { elevationStatus: "denied", resolvedAt: at(9_500) } }, null),
    ).toBe("3rd request in a few minutes · first denied just now");
    expect(line({ ordinal: 11, first: { elevationStatus: "pending" } }, "t")).toBe(
      "11th request this turn · first still waiting",
    );
  });
});

describe("elevationNoticeText", () => {
  const base = {
    headline: "“Deploying release .7 to the Mac”",
    threadId: "thread:a",
    threadTitle: "Deploy device approval .7",
    raisedByT3: undefined,
    machine: "Killian's MacBook Pro",
  };
  it("leads with the headline, then the thread and machine", () => {
    expect(elevationNoticeText({ ...base, series: undefined })).toEqual({
      title: "“Deploying release .7 to the Mac”",
      detail: "Deploy device approval .7 · Killian's MacBook Pro",
    });
  });

  it("says a repeat is one, the reason moving underneath", () => {
    expect(
      elevationNoticeText({
        ...base,
        series: { ordinal: 2, first: { elevationStatus: "approved" } },
      }),
    ).toEqual({
      title: "2nd admin request this turn",
      detail: "“Deploying release .7 to the Mac” · Killian's MacBook Pro",
    });
  });

  it("says a request no thread claims wasn't placed", () => {
    expect(
      elevationNoticeText({
        ...base,
        headline: "Claude wants admin access",
        threadId: null,
        threadTitle: null,
        series: undefined,
      }),
    ).toEqual({
      title: "Claude wants admin access",
      detail: "Killian's MacBook Pro · thread not found",
    });
  });
});
