import * as NodeServices from "@effect/platform-node/NodeServices";
import { it as effectIt } from "@effect/vitest";
import * as HostProcess from "@t3tools/shared/HostProcess";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Path from "effect/Path";
import * as Schema from "effect/Schema";
import * as Sink from "effect/Sink";
import * as Stream from "effect/Stream";
import { HttpClient, HttpClientResponse, UrlParams } from "effect/http";
import { ChildProcessSpawner } from "effect/process";
import { describe, expect, it } from "vite-plus/test";

import * as ClaudeResetCredits from "./claudeResetCredits.ts";
import { claudeUsageResponseToLimits } from "./claudeUsageLimits.ts";

const NOW = Date.parse("2026-09-22T12:00:00.000Z");
const grant = (overrides: Record<string, unknown>) => ({
  id: "grant_a",
  resets_left: 1,
  usable_now: true,
  ...overrides,
});

const writeLogin = Effect.gen(function* () {
  const fs = yield* FileSystem.FileSystem;
  const path = yield* Path.Path;
  const directory = yield* fs.makeTempDirectoryScoped();
  yield* fs.writeFileString(
    path.join(directory, ".credentials.json"),
    '{"claudeAiOauth":{"accessToken":"oauth-token"}}',
  );
  const accountConfigPath = path.join(directory, ".claude.json");
  yield* fs.writeFileString(accountConfigPath, '{"oauthAccount":{"organizationUuid":"org-1"}}');
  return { configDir: directory, accountConfigPath };
});

const respond = (status: number, body: unknown) =>
  HttpClient.make((request) =>
    Effect.succeed(HttpClientResponse.fromWeb(request, Response.json(body, { status }))),
  );
const refuseRequests = HttpClient.make(() => Effect.die("must not send a request"));

describe("claudeResetCreditsToContract", () => {
  it("counts live grants and pins the next usable one", () => {
    expect(
      ClaudeResetCredits.claudeResetCreditsToContract(
        {
          eligible: true,
          next_grant_id: "grant_a",
          grants: [
            grant({ resets_left: 2, ends_at: "2026-10-01T00:00:00Z" }),
            grant({ id: "paused", paused: true }),
            grant({ id: "expired", ends_at: "2026-09-01T00:00:00Z" }),
            grant({ id: "garbled", ends_at: "not a date" }),
            grant({ id: "date_only", ends_at: "2026-10-01" }),
            grant({ id: "impossible", ends_at: "2027-02-30T00:00:00Z" }),
            grant({ id: "empty", ends_at: "" }),
            grant({ id: "Not Valid" }),
            grant({ id: "grant_b", resets_left: 3, usable_now: false }),
          ],
        },
        NOW,
      ),
    ).toEqual({
      availableCount: 2,
      nextCreditId: "grant_a",
      nextExpiresAt: "2026-10-01T00:00:00.000Z",
    });
  });

  it("offers nothing to redeem without a usable next grant or an eligible account", () => {
    expect(
      ClaudeResetCredits.claudeResetCreditsToContract(
        { eligible: true, next_grant_id: "grant_a", grants: [grant({ usable_now: false })] },
        NOW,
      ),
    ).toEqual({ availableCount: 0 });
    expect(
      ClaudeResetCredits.claudeResetCreditsToContract({ eligible: true, grants: [grant({})] }, NOW),
    ).toEqual({
      availableCount: 0,
    });
    expect(
      ClaudeResetCredits.claudeResetCreditsToContract(
        { eligible: false, grants: [grant({})] },
        NOW,
      ),
    ).toBeUndefined();
    expect(ClaudeResetCredits.claudeResetCreditsToContract(undefined, NOW)).toBeUndefined();
  });
});

const usageBody = {
  five_hour: { utilization: 28, resets_at: "2026-09-22T15:00:00Z" },
  seven_day: { utilization: 49, resets_at: "2026-09-25T00:00:00Z" },
  limits: [
    { kind: "session", percent: 28 },
    {
      kind: "weekly_scoped",
      percent: 12,
      resets_at: "2026-09-25T00:00:00Z",
      scope: { model: { display_name: "Fable" } },
    },
  ],
  cedar_ember: { eligible: true, next_grant_id: "grant_a", grants: [grant({})] },
};

const linuxLogin = (configDir: string, environment: NodeJS.ProcessEnv = {}) => ({
  configDir,
  customConfigDir: true,
  environment,
});

/** Answers usage reads and records the bearer token each one carried. */
const recordTokens = (tokens: Array<string | undefined>) =>
  HttpClient.make((request) => {
    tokens.push(request.headers.authorization);
    return Effect.succeed(HttpClientResponse.fromWeb(request, Response.json(usageBody)));
  });

const keychain = (handler: (args: ReadonlyArray<string>) => { stdout: string; code: number }) =>
  ChildProcessSpawner.make((command) => {
    const result = handler((command as unknown as { args: ReadonlyArray<string> }).args);
    return Effect.succeed(
      ChildProcessSpawner.makeHandle({
        pid: ChildProcessSpawner.ProcessId(1),
        exitCode: Effect.succeed(ChildProcessSpawner.ExitCode(result.code)),
        isRunning: Effect.succeed(false),
        kill: () => Effect.void,
        unref: Effect.succeed(Effect.void),
        stdin: Sink.drain,
        stdout: Stream.make(new TextEncoder().encode(result.stdout)),
        stderr: Stream.empty,
        all: Stream.empty,
        getInputFd: () => Sink.drain,
        getOutputFd: () => Stream.empty,
      }),
    );
  });
const refuseSpawns = ChildProcessSpawner.make(() => Effect.die("must not read the Keychain"));

effectIt.layer(NodeServices.layer)("readClaudeOAuthUsage", (it) => {
  it.effect("reads the windows and grants with the CLI's request", () =>
    Effect.gen(function* () {
      const { configDir } = yield* writeLogin;
      const client = HttpClient.make((request) => {
        expect(request.method).toBe("GET");
        expect(request.url).toBe("https://api.anthropic.com/api/oauth/usage");
        expect(UrlParams.toString(request.urlParams)).toBe("cedar_ember=1");
        expect(request.headers.authorization).toBe("Bearer oauth-token");
        expect(request.headers["anthropic-beta"]).toBe("oauth-2025-04-20");
        expect(request.headers["user-agent"]).toBe("claude-cli/2.1.0 (external, cli)");
        return Effect.succeed(HttpClientResponse.fromWeb(request, Response.json(usageBody)));
      });
      const read = yield* ClaudeResetCredits.readClaudeOAuthUsage(
        linuxLogin(configDir),
        "2.1.0",
      ).pipe(
        Effect.provideService(HostProcess.Platform, "linux"),
        Effect.provideService(HttpClient.HttpClient, client),
      );
      expect(read?.resetCredits).toEqual({ availableCount: 1, nextCreditId: "grant_a" });
      const limits = claudeUsageResponseToLimits({
        response: read!.usage,
        checkedAt: read!.checkedAt,
      }).limits;
      expect(limits.windows.map((window) => [window.id, window.usedPercent])).toEqual([
        ["five_hour", 28],
        ["seven_day", 49],
        ["seven_day_fable", 12],
      ]);
    }),
  );

  it.effect("finds the login where the CLI keeps it, and skips expired ones", () =>
    Effect.gen(function* () {
      const tokens: Array<string | undefined> = [];
      const services: Array<string | undefined> = [];
      const keychainLogin = (expiresAt: number) =>
        keychain((args) => {
          expect(args.slice(0, 1)).toEqual(["find-generic-password"]);
          expect(args.slice(3)).toEqual(["-a", "kgriset", "-w"]);
          services.push(args[2]);
          return {
            stdout: JSON.stringify({ claudeAiOauth: { accessToken: "keychain-token", expiresAt } }),
            code: 0,
          };
        });
      const read = (
        login: ClaudeResetCredits.ClaudeLogin,
        spawner: ChildProcessSpawner.ChildProcessSpawner["Service"],
      ) =>
        ClaudeResetCredits.readClaudeOAuthUsage(login, "2.1.0").pipe(
          Effect.provideService(HostProcess.Platform, "darwin"),
          Effect.provideService(ChildProcessSpawner.ChildProcessSpawner, spawner),
          Effect.provideService(HttpClient.HttpClient, recordTokens(tokens)),
        );
      const environment = { USER: "kgriset" };
      // it.effect's TestClock starts at the epoch.
      const future = 60 * 60_000;
      yield* read(
        { configDir: "/Users/kgriset/.claude", customConfigDir: false, environment },
        keychainLogin(future),
      );
      yield* read(
        { configDir: "/Users/kgriset/.claude-work", customConfigDir: true, environment },
        keychainLogin(future),
      );
      const expired = yield* read(
        { configDir: "/Users/kgriset/.claude", customConfigDir: false, environment },
        keychainLogin(0),
      );
      yield* read(
        {
          configDir: "/Users/kgriset/.claude",
          customConfigDir: false,
          environment: { ...environment, CLAUDE_CODE_OAUTH_TOKEN: " env-token " },
        },
        refuseSpawns,
      );
      // A Keychain without the item reads as signed out.
      const missing = yield* read(
        { configDir: "/Users/kgriset/.claude", customConfigDir: false, environment },
        keychain(() => ({ stdout: "", code: 44 })),
      );
      expect(services).toEqual([
        "Claude Code-credentials",
        "Claude Code-credentials-4d256fd0",
        "Claude Code-credentials",
      ]);
      expect(tokens).toEqual([
        "Bearer keychain-token",
        "Bearer keychain-token",
        "Bearer env-token",
      ]);
      expect([expired, missing]).toEqual([undefined, undefined]);
    }),
  );

  it.effect("reads nothing from failed requests and reports a 429's retry delay", () =>
    Effect.gen(function* () {
      const { configDir } = yield* writeLogin;
      const read = (client: HttpClient.HttpClient) =>
        ClaudeResetCredits.readClaudeOAuthUsage(linuxLogin(configDir), "2.1.0").pipe(
          Effect.provideService(HostProcess.Platform, "linux"),
          Effect.provideService(HttpClient.HttpClient, client),
          Effect.result,
        );
      const limited = (headers: Record<string, string>) =>
        HttpClient.make((request) =>
          Effect.succeed(
            HttpClientResponse.fromWeb(request, new Response(null, { status: 429, headers })),
          ),
        );
      expect(yield* read(respond(401, {}))).toMatchObject({ _tag: "Success", success: undefined });
      expect(yield* read(respond(500, {}))).toMatchObject({ _tag: "Success", success: undefined });
      expect(yield* read(limited({ "retry-after": "120" }))).toMatchObject({
        _tag: "Failure",
        failure: { _tag: "ClaudeOAuthUsageRateLimited", retryAfterSeconds: 120 },
      });
      expect(yield* read(limited({}))).toMatchObject({
        failure: { retryAfterSeconds: 300 },
      });
    }),
  );
});

const ClaimBody = Schema.fromJsonString(
  Schema.Struct({ program: Schema.String, grant_id: Schema.String, request_id: Schema.String }),
);
const decodeClaimBody = Schema.decodeEffect(ClaimBody);

const consume = (client: HttpClient.HttpClient, ids = { grantId: "grant_a", requestId: "r-1" }) =>
  Effect.gen(function* () {
    const { configDir, accountConfigPath } = yield* writeLogin;
    return yield* ClaudeResetCredits.consumeClaudeResetCredit({
      login: linuxLogin(configDir),
      accountConfigPath,
      version: "2.1.0",
      ...ids,
    }).pipe(
      Effect.provideService(HostProcess.Platform, "linux"),
      Effect.provideService(HttpClient.HttpClient, client),
      Effect.result,
    );
  });

effectIt.layer(NodeServices.layer)("consumeClaudeResetCredit", (it) => {
  it.effect("claims the grant for the organization", () =>
    Effect.gen(function* () {
      const client = HttpClient.make((request) =>
        Effect.gen(function* () {
          expect(request.method).toBe("POST");
          expect(request.url).toBe(
            "https://api.anthropic.com/api/organizations/org-1/reset_rate_limits",
          );
          expect(request.headers.authorization).toBe("Bearer oauth-token");
          const body =
            request.body._tag === "Uint8Array" ? new TextDecoder().decode(request.body.body) : "";
          expect(yield* decodeClaimBody(body)).toEqual({
            program: "cedar_ember",
            grant_id: "grant_a",
            request_id: "r-1",
          });
          return HttpClientResponse.fromWeb(request, Response.json({ result: "reset" }));
        }).pipe(Effect.orDie),
      );
      expect(yield* consume(client)).toMatchObject({ _tag: "Success", success: "reset" });
    }),
  );

  it.effect("maps each answer to an outcome or a failure", () =>
    Effect.gen(function* () {
      for (const [result, outcome] of [
        ["not_limited", "nothingToReset"],
        ["already_used", "alreadyRedeemed"],
        ["ineligible", "noCredit"],
      ] as const) {
        expect(yield* consume(respond(200, { result }))).toMatchObject({ success: outcome });
      }
      for (const client of [
        respond(200, { result: "cooldown" }),
        respond(429, {}),
        respond(401, {}),
      ]) {
        const result = yield* consume(client);
        expect(result).toMatchObject({ _tag: "Failure" });
        if (result._tag === "Failure") {
          expect(ClaudeResetCredits.isSettledClaudeResetCreditFailure(result.failure)).toBe(true);
        }
      }
      for (const client of [respond(500, {}), respond(200, { result: "unavailable" })]) {
        const unanswered = yield* consume(client);
        expect(unanswered).toMatchObject({ _tag: "Failure" });
        if (unanswered._tag === "Failure") {
          expect(ClaudeResetCredits.isSettledClaudeResetCreditFailure(unanswered.failure)).toBe(
            false,
          );
        }
      }
    }),
  );

  it.effect("refuses malformed ids without sending anything", () =>
    Effect.gen(function* () {
      for (const ids of [
        { grantId: "Bad Grant", requestId: "r-1" },
        { grantId: "grant_a", requestId: "has space" },
      ]) {
        expect(yield* consume(refuseRequests, ids)).toMatchObject({ _tag: "Failure" });
      }
    }),
  );
});
