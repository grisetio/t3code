import * as NodeCrypto from "@effect/platform-node/NodeCrypto";
import * as NodeServices from "@effect/platform-node/NodeServices";
import { assert, describe, it } from "@effect/vitest";
import {
  type HostPowerSnapshot,
  ProviderDriverKind,
  ProviderInstanceId,
  resolveProviderInstanceEnabled,
} from "@t3tools/contracts";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Layer from "effect/Layer";
import * as Path from "effect/Path";
import * as Stream from "effect/Stream";
import { HttpClient } from "effect/http";

import * as BackgroundPolicy from "../background/BackgroundPolicy.ts";
import * as HostPowerMonitor from "../background/HostPowerMonitor.ts";
import { deriveProviderInstanceConfigMap } from "../provider/ProviderInstanceRegistryHydration.ts";
import * as ServerSettings from "../serverSettings.ts";
import * as UsageLimitSources from "./UsageLimitSources.ts";
import { CODEX_ACCOUNT_USAGE_SOURCE_ID, readCodexAccountUsage } from "./codexAccountUsage.ts";

type FakeAccount = "chatgpt" | "signedOut" | "apiKey";

/**
 * A stand-in `codex` binary. It answers only the handshake and the two
 * account reads, records every method it receives, and errors on anything
 * else, so a test can prove the usage read never lists models or runs turns.
 */
const writeFakeCodex = Effect.fn("writeFakeCodex")(function* (input: {
  readonly account: FakeAccount;
  readonly rateLimitsError?: boolean;
}) {
  const fileSystem = yield* FileSystem.FileSystem;
  const path = yield* Path.Path;
  const dir = yield* fileSystem.makeTempDirectoryScoped({ prefix: "t3-codex-usage-" });
  const binaryPath = path.join(dir, "codex");
  const logPath = path.join(dir, "methods.log");
  const account =
    input.account === "chatgpt"
      ? { type: "chatgpt", email: "person@example.com", planType: "plus" }
      : input.account === "apiKey"
        ? { type: "apiKey" }
        : null;
  const script = `#!/usr/bin/env node
const fs = require("node:fs");
const readline = require("node:readline");
const config = ${JSON.stringify({ account, rateLimitsError: input.rateLimitsError ?? false, logPath })};
const write = (message) => process.stdout.write(JSON.stringify(message) + "\\n");
readline.createInterface({ input: process.stdin }).on("line", (line) => {
  const { id, method } = JSON.parse(line);
  if (method === undefined) return;
  fs.appendFileSync(config.logPath, method + "\\n");
  if (id === undefined) return;
  if (method === "initialize") {
    return write({ id, result: { userAgent: "codex-fake/1.0.0", codexHome: "/tmp", platformFamily: "unix", platformOs: "macos" } });
  }
  if (method === "account/read") {
    return write({ id, result: { account: config.account, requiresOpenaiAuth: config.account === null } });
  }
  if (method === "account/rateLimits/read" && config.rateLimitsError) {
    return write({ id, error: { code: -32603, message: "internal: token=secret-value" } });
  }
  if (method === "account/rateLimits/read") {
    return write({ id, result: {
      accountId: "acct_private",
      rateLimits: {
        limitId: "codex",
        planType: "plus",
        primary: { usedPercent: 42, windowDurationMins: 300, resetsAt: 1790000000 },
        secondary: { usedPercent: 7, windowDurationMins: 10080, resetsAt: 1790500000 },
      },
    } });
  }
  write({ id, error: { code: -32601, message: "unexpected method " + method } });
});
`;
  yield* fileSystem.writeFileString(binaryPath, script);
  yield* fileSystem.chmod(binaryPath, 0o755);
  const methods = fileSystem.readFileString(logPath).pipe(
    Effect.orElseSucceed(() => ""),
    Effect.map((text) => text.split("\n").filter((line) => line.length > 0)),
  );
  return { binaryPath, methods };
});

const READ_METHODS = ["initialize", "initialized", "account/read", "account/rateLimits/read"];

describe("readCodexAccountUsage", () => {
  it.effect("reports plan windows from a ChatGPT login without listing models or turns", () =>
    Effect.gen(function* () {
      const codex = yield* writeFakeCodex({ account: "chatgpt" });
      const snapshot = yield* readCodexAccountUsage({ binaryPath: codex.binaryPath, homePath: "" });

      assert.strictEqual(snapshot.id, CODEX_ACCOUNT_USAGE_SOURCE_ID);
      assert.strictEqual(snapshot.kind, "codex");
      assert.strictEqual(snapshot.error, undefined);
      assert.strictEqual(snapshot.accounts.length, 1);
      const [account] = snapshot.accounts;
      assert.strictEqual(account!.driver, ProviderDriverKind.make("codex"));
      assert.strictEqual(account!.plan, "ChatGPT Plus Subscription");
      assert.deepStrictEqual(
        account!.usageLimits.windows.map((window) => [window.id, window.kind, window.usedPercent]),
        [
          ["primary", "session", 42],
          ["secondary", "weekly", 7],
        ],
      );
      // The email and backend account id stay on the server.
      const published = JSON.stringify(snapshot);
      assert.notInclude(published, "person@example.com");
      assert.notInclude(published, "acct_private");
      assert.deepStrictEqual(yield* codex.methods, READ_METHODS);
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer)),
  );

  it.effect("explains a signed-out Codex and skips the usage request", () =>
    Effect.gen(function* () {
      const codex = yield* writeFakeCodex({ account: "signedOut" });
      const snapshot = yield* readCodexAccountUsage({ binaryPath: codex.binaryPath, homePath: "" });

      assert.deepStrictEqual(snapshot.accounts, []);
      assert.match(snapshot.error ?? "", /not signed in/);
      assert.deepStrictEqual(yield* codex.methods, ["initialize", "initialized", "account/read"]);
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer)),
  );

  it.effect("explains that an API-key login has no plan usage", () =>
    Effect.gen(function* () {
      const codex = yield* writeFakeCodex({ account: "apiKey" });
      const snapshot = yield* readCodexAccountUsage({ binaryPath: codex.binaryPath, homePath: "" });

      assert.deepStrictEqual(snapshot.accounts, []);
      assert.match(snapshot.error ?? "", /API key/);
      assert.notInclude(yield* codex.methods, "account/rateLimits/read");
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer)),
  );

  it.effect("keeps the raw error out of a failed usage read", () =>
    Effect.gen(function* () {
      const codex = yield* writeFakeCodex({ account: "chatgpt", rateLimitsError: true });
      const snapshot = yield* readCodexAccountUsage({ binaryPath: codex.binaryPath, homePath: "" });

      assert.deepStrictEqual(snapshot.accounts, []);
      assert.strictEqual(snapshot.error, "Codex could not read usage (JSON-RPC -32603).");
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer)),
  );

  it.effect("reports invalid Codex settings without starting a process", () =>
    Effect.gen(function* () {
      const snapshot = yield* readCodexAccountUsage({ binaryPath: 42 });

      assert.deepStrictEqual(snapshot.accounts, []);
      assert.strictEqual(snapshot.error, "The Codex provider settings are invalid.");
    }).pipe(Effect.provide(NodeServices.layer)),
  );

  it.effect("reports a missing Codex binary instead of failing", () =>
    Effect.gen(function* () {
      const snapshot = yield* readCodexAccountUsage({
        binaryPath: "/nonexistent/t3-codex-usage/codex",
        homePath: "",
      });

      assert.deepStrictEqual(snapshot.accounts, []);
      assert.strictEqual(snapshot.error, "Codex could not be started to read usage.");
    }).pipe(Effect.provide(NodeServices.layer)),
  );
});

const nominalHostPower: HostPowerSnapshot = {
  source: "unknown",
  idle: "unknown",
  idleSeconds: null,
  locked: "unknown",
  suspended: false,
  onBattery: "unknown",
  lowPowerMode: "unknown",
  thermalState: "unknown",
  stale: true,
  updatedAt: DateTime.makeUnsafe("2026-10-24T00:00:00.000Z"),
};

const layerUsageLimitSources = (settings: Parameters<typeof ServerSettings.layerTest>[0]) => {
  const layerSettings = ServerSettings.layerTest(settings);
  const layerHost = Layer.succeed(
    HostPowerMonitor.HostPowerMonitor,
    HostPowerMonitor.HostPowerMonitor.of({
      snapshot: Effect.succeed(nominalHostPower),
      report: () => Effect.void,
      streamChanges: Stream.empty,
    }),
  );
  return UsageLimitSources.layer.pipe(
    Layer.provide(BackgroundPolicy.layer.pipe(Layer.provide(layerHost))),
    Layer.provideMerge(layerSettings),
    Layer.provide(
      Layer.succeed(
        HttpClient.HttpClient,
        HttpClient.make(() => Effect.die("no hub is configured")),
      ),
    ),
    Layer.provide(NodeCrypto.layer),
    Layer.provide(NodeServices.layer),
  );
};

describe("UsageLimitSources with Codex account usage", () => {
  it.effect("publishes Codex plan limits while Codex is not an orchestration provider", () =>
    Effect.gen(function* () {
      const codex = yield* writeFakeCodex({ account: "chatgpt" });
      const settingsOverrides = {
        codexAccountUsageEnabled: true,
        providerInstances: {
          [ProviderInstanceId.make("codex")]: {
            driver: ProviderDriverKind.make("codex"),
            enabled: false,
            config: { binaryPath: codex.binaryPath },
          },
        },
      };

      yield* Effect.gen(function* () {
        const settings = yield* (yield* ServerSettings.ServerSettingsService).getSettings;
        // Orchestration has no runnable Codex instance to select.
        const codexInstance = Object.values(deriveProviderInstanceConfigMap(settings)).find(
          (instance) => instance.driver === ProviderDriverKind.make("codex"),
        );
        assert.isDefined(codexInstance);
        assert.isFalse(resolveProviderInstanceEnabled(codexInstance!));

        const sources = yield* UsageLimitSources.UsageLimitSources;
        yield* sources.refresh;
        const [snapshot] = yield* sources.current;
        assert.strictEqual(snapshot?.id, CODEX_ACCOUNT_USAGE_SOURCE_ID);
        assert.strictEqual(snapshot?.accounts[0]?.usageLimits.windows.length, 2);

        // Read-only: the usage-only source has nothing to redeem against.
        const redeem = yield* sources
          .consumeResetCredit({
            sourceId: CODEX_ACCOUNT_USAGE_SOURCE_ID,
            accountId: "codex",
            creditId: "credit",
          })
          .pipe(Effect.flip);
        assert.strictEqual(redeem._tag, "UsageLimitSourceError");
        assert.isTrue((yield* codex.methods).every((method) => READ_METHODS.includes(method)));
      }).pipe(Effect.provide(layerUsageLimitSources(settingsOverrides)));
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer)),
  );

  it.effect("publishes nothing for Codex until the setting is on", () =>
    Effect.gen(function* () {
      const sources = yield* UsageLimitSources.UsageLimitSources;
      yield* sources.refresh;
      assert.deepStrictEqual(yield* sources.current, []);
    }).pipe(
      Effect.provide(
        layerUsageLimitSources({
          providerInstances: {
            [ProviderInstanceId.make("codex")]: {
              driver: ProviderDriverKind.make("codex"),
              config: { binaryPath: "/nonexistent/t3-codex-usage/codex" },
            },
          },
        }),
      ),
    ),
  );
});
