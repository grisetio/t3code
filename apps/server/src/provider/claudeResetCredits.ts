import type {
  ProviderConsumeResetCreditOutcome,
  ServerProviderResetCredits,
} from "@t3tools/contracts";
import { spawnAndCollect } from "@t3tools/provider-core/server/snapshotProbe";
import * as HostProcess from "@t3tools/shared/HostProcess";
import * as Crypto from "effect/Crypto";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Option from "effect/Option";
import * as Path from "effect/Path";
import * as Schema from "effect/Schema";
import * as Hex from "effect/encoding/Hex";
import { HttpClient, HttpClientRequest, HttpClientResponse } from "effect/http";
import * as ChildProcess from "effect/process/ChildProcess";

import { ClaudeOAuthUsage, claudeOAuthUsageToResponse } from "./claudeUsageLimits.ts";

const API_BASE = "https://api.anthropic.com";
const PROGRAM = "cedar_ember";
const GRANT_ID = /^[a-z0-9_-]{1,40}$/;
const REQUEST_ID = /^[A-Za-z0-9_-]{1,64}$/;
const COMPLETE_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

const Credentials = Schema.Struct({
  claudeAiOauth: Schema.optional(
    Schema.Struct({
      accessToken: Schema.optional(Schema.String),
      expiresAt: Schema.optional(Schema.Number),
    }),
  ),
});
const decodeCredentialsJson = Schema.decodeEffect(Schema.fromJsonString(Credentials));
const Config = Schema.Struct({
  oauthAccount: Schema.optional(
    Schema.Struct({ organizationUuid: Schema.optional(Schema.String) }),
  ),
});
const Grant = Schema.Struct({
  id: Schema.String.check(Schema.isPattern(GRANT_ID)),
  resets_left: Schema.Int.check(Schema.isGreaterThanOrEqualTo(0)),
  ends_at: Schema.optional(Schema.NullOr(Schema.String)),
  paused: Schema.optional(Schema.Boolean),
  usable_now: Schema.optional(Schema.Boolean),
});
const decodeGrant = Schema.decodeUnknownOption(Grant);
const CedarEmber = Schema.Struct({
  eligible: Schema.Boolean,
  grants: Schema.optional(Schema.Array(Schema.Unknown)),
  next_grant_id: Schema.optional(Schema.NullOr(Schema.String)),
});
const UsageResponse = Schema.Struct({
  ...ClaudeOAuthUsage.fields,
  cedar_ember: Schema.optional(Schema.NullOr(Schema.Unknown)),
});
const decodeCedarEmber = Schema.decodeUnknownOption(CedarEmber);
const ClaimResponse = Schema.Struct({
  result: Schema.Literals([
    "reset",
    "already_used",
    "not_limited",
    "cooldown",
    "ineligible",
    "unavailable",
  ]),
});

const RESET_CREDIT_FAILURES = {
  malformedCredit: "Claude returned a malformed reset credit.",
  loginUnreadable: "Claude could not read its login.",
  accountUnreadable: "Claude could not read its account.",
  signedOut: "Sign in to Claude again to redeem resets.",
  rateLimited: "Claude is rate limiting resets. Try again soon.",
  coolingDown: "Claude resets are cooling down. Try again later.",
  unconfirmed:
    "Claude could not confirm the reset. If you are still limited in a moment, try again.",
  requestFailed: "Claude could not redeem the reset.",
} as const;

class ClaudeResetCreditError extends Schema.TaggedError<ClaudeResetCreditError>()(
  "ClaudeResetCreditError",
  {
    reason: Schema.Literals(
      Object.keys(RESET_CREDIT_FAILURES) as Array<keyof typeof RESET_CREDIT_FAILURES>,
    ),
    cause: Schema.optional(Schema.Defect()),
  },
) {
  override get message(): string {
    return RESET_CREDIT_FAILURES[this.reason];
  }
}

const isClaudeResetCreditError = Schema.is(ClaudeResetCreditError);

/** Retry unanswered or unconfirmed claims with the same request ID. */
export const isSettledClaudeResetCreditFailure = (error: unknown) =>
  isClaudeResetCreditError(error) &&
  error.reason !== "requestFailed" &&
  error.reason !== "unconfirmed";

const isFutureTimestamp = (value: string, nowMs: number) => {
  if (!COMPLETE_TIMESTAMP.test(value)) return false;
  const [year, month, day] = value.slice(0, 10).split("-").map(Number);
  return (
    Date.parse(value) > nowMs && Date.UTC(year!, month! - 1, day!) <= Date.UTC(year!, month!, 0)
  );
};

export function claudeResetCreditsToContract(
  block: unknown,
  nowMs: number,
): ServerProviderResetCredits | undefined {
  const parsed = decodeCedarEmber(block);
  if (Option.isNone(parsed) || !parsed.value.eligible) return undefined;
  const live = (parsed.value.grants ?? [])
    .flatMap((raw) => Option.toArray(decodeGrant(raw)))
    .filter(
      (grant) =>
        !grant.paused &&
        grant.usable_now &&
        (grant.ends_at == null || isFutureTimestamp(grant.ends_at, nowMs)),
    );
  const next = live.find((grant) => grant.id === parsed.value.next_grant_id);
  const nextExpiresAt = next?.ends_at ? DateTime.make(next.ends_at) : Option.none();
  return {
    availableCount: next ? live.reduce((sum, grant) => sum + grant.resets_left, 0) : 0,
    ...(Option.isSome(nextExpiresAt)
      ? { nextExpiresAt: DateTime.formatIso(nextExpiresAt.value) }
      : {}),
    ...(next ? { nextCreditId: next.id } : {}),
  };
}

const readJson = Effect.fn("claudeResetCredits.readJson")(function* <S extends Schema.Top>(
  schema: S,
  file: string,
) {
  const fs = yield* FileSystem.FileSystem;
  return yield* fs.readFileString(file).pipe(
    Effect.catchTags({
      PlatformError: (error) =>
        error.reason._tag === "NotFound" ? Effect.succeed("{}") : Effect.fail(error),
    }),
    Effect.flatMap(Schema.decodeEffect(Schema.fromJsonString(schema))),
  );
});

/** Where the CLI keeps one instance's login. */
export interface ClaudeLogin {
  readonly configDir: string;
  /** The CLI suffixes its Keychain item only when CLAUDE_CONFIG_DIR is set. */
  readonly customConfigDir: boolean;
  readonly environment: NodeJS.ProcessEnv;
}

class ClaudeKeychainReadError extends Schema.TaggedError<ClaudeKeychainReadError>()(
  "ClaudeKeychainReadError",
  { exitCode: Schema.Number },
) {}

// Exit 44 is errSecItemNotFound. Without -a, a stale item for another account can win.
const readKeychainCredentials = Effect.fn("claudeResetCredits.readKeychainCredentials")(function* (
  login: ClaudeLogin,
) {
  const suffix = login.customConfigDir
    ? `-${Hex.encode(
        yield* (yield* Crypto.Crypto).digest("SHA-256", new TextEncoder().encode(login.configDir)),
      ).slice(0, 8)}`
    : "";
  const account = login.environment.USER?.trim() || (yield* HostProcess.Username) || "";
  const result = yield* spawnAndCollect(
    "security",
    ChildProcess.make("security", [
      "find-generic-password",
      "-s",
      `Claude Code-credentials${suffix}`,
      "-a",
      account,
      "-w",
    ]),
  );
  if (result.code === 44) return "{}";
  if (result.code !== 0) return yield* new ClaudeKeychainReadError({ exitCode: result.code });
  return result.stdout;
});

const readAccessToken = Effect.fn("claudeResetCredits.readAccessToken")(function* (
  login: ClaudeLogin,
) {
  const fromEnvironment = login.environment.CLAUDE_CODE_OAUTH_TOKEN?.trim();
  if (fromEnvironment) return fromEnvironment;
  const credentials =
    (yield* HostProcess.Platform) === "darwin"
      ? yield* decodeCredentialsJson(yield* readKeychainCredentials(login))
      : yield* readJson(Credentials, (yield* Path.Path).join(login.configDir, ".credentials.json"));
  const oauth = credentials.claudeAiOauth;
  // The CLI owns refresh-token rotation; refreshing here could sign it out.
  if (
    oauth?.expiresAt !== undefined &&
    oauth.expiresAt <= DateTime.toEpochMillis(yield* DateTime.now)
  ) {
    return undefined;
  }
  return oauth?.accessToken?.trim() || undefined;
});

const withClaudeHeaders = (token: string, version: string) =>
  HttpClientRequest.setHeaders({
    authorization: `Bearer ${token}`,
    "anthropic-beta": "oauth-2025-04-20",
    "user-agent": `claude-cli/${version} (external, cli)`,
  });

export class ClaudeOAuthUsageRateLimited extends Schema.TaggedError<ClaudeOAuthUsageRateLimited>()(
  "ClaudeOAuthUsageRateLimited",
  { retryAfterSeconds: Schema.Number },
) {}

const isClaudeOAuthUsageRateLimited = Schema.is(ClaudeOAuthUsageRateLimited);

const DEFAULT_RETRY_AFTER_SECONDS = 5 * 60;

/** Undefined when there is no usable login or the read failed for any reason but a 429. */
export const readClaudeOAuthUsage = Effect.fn("readClaudeOAuthUsage")(
  function* (login: ClaudeLogin, version: string) {
    const token = yield* readAccessToken(login);
    if (!token) return undefined;
    const client = yield* HttpClient.HttpClient;
    const response = yield* client.execute(
      HttpClientRequest.get(`${API_BASE}/api/oauth/usage`, {
        urlParams: { cedar_ember: "1" },
      }).pipe(withClaudeHeaders(token, version)),
    );
    if (response.status === 429) {
      const retryAfter = Number(response.headers["retry-after"]);
      return yield* new ClaudeOAuthUsageRateLimited({
        retryAfterSeconds:
          Number.isFinite(retryAfter) && retryAfter > 0
            ? Math.min(retryAfter, 60 * 60)
            : DEFAULT_RETRY_AFTER_SECONDS,
      });
    }
    const body = yield* HttpClientResponse.schemaBodyJson(UsageResponse)(
      yield* HttpClientResponse.filterStatusOk(response),
    );
    const now = yield* DateTime.now;
    return {
      checkedAt: DateTime.formatIso(now),
      usage: claudeOAuthUsageToResponse(body),
      resetCredits: claudeResetCreditsToContract(body.cedar_ember, DateTime.toEpochMillis(now)),
    };
  },
  Effect.timeout("10 seconds"),
  Effect.catchIf(
    (error) => !isClaudeOAuthUsageRateLimited(error),
    () => Effect.undefined,
  ),
);

export type ClaudeOAuthUsageRead = NonNullable<
  Effect.Success<ReturnType<typeof readClaudeOAuthUsage>>
>;

export const readClaudeOrganizationId = (accountConfigPath: string) =>
  readJson(Config, accountConfigPath).pipe(
    Effect.map((config) => config.oauthAccount?.organizationUuid?.trim() || undefined),
    Effect.orElseSucceed(() => undefined),
  );

export const claudeAccountConfigPath = Effect.fn("claudeAccountConfigPath")(function* (
  configDir: string | undefined,
) {
  const path = yield* Path.Path;
  return configDir
    ? path.join(configDir, ".claude.json")
    : path.join(yield* HostProcess.HomeDirectory, ".claude.json");
});

const CLAIM_OUTCOMES = {
  reset: "reset",
  not_limited: "nothingToReset",
  already_used: "alreadyRedeemed",
  ineligible: "noCredit",
} as const satisfies Record<string, ProviderConsumeResetCreditOutcome>;

/** requestId is the claim's idempotency key. */
export const consumeClaudeResetCredit = Effect.fn("consumeClaudeResetCredit")(function* (input: {
  readonly login: ClaudeLogin;
  readonly accountConfigPath: string;
  readonly version: string;
  readonly grantId: string;
  readonly requestId: string;
}) {
  if (!GRANT_ID.test(input.grantId) || !REQUEST_ID.test(input.requestId)) {
    return yield* new ClaudeResetCreditError({ reason: "malformedCredit" });
  }
  const token = yield* readAccessToken(input.login).pipe(
    Effect.mapError((cause) => new ClaudeResetCreditError({ reason: "loginUnreadable", cause })),
  );
  const config = yield* readJson(Config, input.accountConfigPath).pipe(
    Effect.mapError((cause) => new ClaudeResetCreditError({ reason: "accountUnreadable", cause })),
  );
  const organization = config.oauthAccount?.organizationUuid?.trim();
  if (!token || !organization) {
    return yield* new ClaudeResetCreditError({ reason: "signedOut" });
  }
  const client = yield* HttpClient.HttpClient;
  const response = yield* client
    .execute(
      HttpClientRequest.post(
        new URL(
          `/api/organizations/${encodeURIComponent(organization)}/reset_rate_limits`,
          API_BASE,
        ),
      ).pipe(
        withClaudeHeaders(token, input.version),
        HttpClientRequest.bodyJsonUnsafe({
          program: PROGRAM,
          grant_id: input.grantId,
          request_id: input.requestId,
        }),
      ),
    )
    .pipe(
      Effect.timeout("25 seconds"),
      Effect.mapError((cause) => new ClaudeResetCreditError({ reason: "requestFailed", cause })),
    );
  if (response.status === 429) {
    return yield* new ClaudeResetCreditError({ reason: "rateLimited" });
  }
  if (response.status === 401 || response.status === 403) {
    return yield* new ClaudeResetCreditError({ reason: "signedOut" });
  }
  const body = yield* HttpClientResponse.filterStatusOk(response).pipe(
    Effect.flatMap(HttpClientResponse.schemaBodyJson(ClaimResponse)),
    Effect.timeout("25 seconds"),
    Effect.mapError((cause) => new ClaudeResetCreditError({ reason: "requestFailed", cause })),
  );
  if (body.result === "cooldown") {
    return yield* new ClaudeResetCreditError({ reason: "coolingDown" });
  }
  // Unknown outcomes retain the request ID so retries address the same claim.
  if (body.result === "unavailable") {
    return yield* new ClaudeResetCreditError({ reason: "unconfirmed" });
  }
  return CLAIM_OUTCOMES[body.result];
});
