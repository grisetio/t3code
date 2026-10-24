/**
 * Usage-only Codex: the signed-in Codex account's plan limits, read through a
 * short-lived `codex app-server` while the Codex provider stays disabled. It serves
 * users who spend a ChatGPT subscription through another harness (such as Pi
 * on an OpenAI Codex model) and want the Limits view, not Codex turns.
 *
 * The read is deliberately narrow: `initialize`, `account/read`, and
 * `account/rateLimits/read`. It lists no models and starts no thread or turn,
 * and it never redeems reset credits. The account's email stays on the server.
 *
 * @module usage/codexAccountUsage
 */
import {
  CodexSettings,
  defaultInstanceIdForDriver,
  ProviderDriverKind,
  type ServerSettings,
  type UsageLimitSourceAccount,
  UsageLimitSourceId,
  type UsageLimitSourceSnapshot,
} from "@t3tools/contracts";
import * as DateTime from "effect/DateTime";
import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import * as NodeOS from "node:os";

import { codexPlanLabel, withCodexAppServerClient } from "../provider/CodexProvider.ts";
import {
  codexRateLimitsFailureMessage,
  codexRateLimitsToLimits,
} from "../provider/codexUsageLimits.ts";

export const CODEX_ACCOUNT_USAGE_SOURCE_ID = UsageLimitSourceId.make("codex-account");

const READ_TIMEOUT = Duration.seconds(15);
const CODEX_INSTANCE_ID = defaultInstanceIdForDriver(ProviderDriverKind.make("codex"));
const decodeCodexSettings = Schema.decodeUnknownOption(CodexSettings);

/**
 * The default Codex instance's stored config. Its `enabled` flag is ignored on
 * purpose: the instance can stay off for orchestration while its binary and
 * home still locate the signed-in CLI.
 */
export const codexAccountUsageConfig = (settings: ServerSettings): unknown =>
  settings.providerInstances[CODEX_INSTANCE_ID]?.config ?? {};

type CodexAccountUsageRead =
  | { readonly account: UsageLimitSourceAccount }
  | { readonly error: string };

const readAccount = Effect.fn("codexAccountUsage.readAccount")(function* (
  settings: Pick<CodexSettings, "binaryPath" | "homePath">,
  checkedAt: string,
) {
  const { client } = yield* withCodexAppServerClient({
    binaryPath: settings.binaryPath,
    homePath: settings.homePath || undefined,
    cwd: NodeOS.homedir(),
  });
  const { account } = yield* client.request("account/read", {});
  if (!account) {
    return {
      error: "Codex is not signed in on this server. Run `codex login` to show plan usage.",
    } satisfies CodexAccountUsageRead;
  }
  if (account.type !== "chatgpt") {
    return {
      error: "Codex is signed in with an API key or cloud credential, which has no plan usage.",
    } satisfies CodexAccountUsageRead;
  }
  const response = yield* client.request("account/rateLimits/read", null);
  const plan = codexPlanLabel(account.planType);
  return {
    account: {
      id: "codex",
      driver: ProviderDriverKind.make("codex"),
      ...(plan ? { plan } : {}),
      usageLimits: codexRateLimitsToLimits({
        snapshot: response.rateLimits,
        rateLimitsByLimitId: response.rateLimitsByLimitId,
        resetCredits: response.rateLimitResetCredits,
        checkedAt,
      }),
    },
  } satisfies CodexAccountUsageRead;
});

/**
 * One snapshot for the usage-only Codex account. Never fails: a missing
 * binary, a signed-out or API-key account, and a failed read each become a
 * bounded `error` line. The raw cause only reaches the debug log.
 */
export const readCodexAccountUsage = Effect.fn("codexAccountUsage.read")(function* (
  config: unknown,
) {
  const checkedAt = DateTime.formatIso(yield* DateTime.now);
  const base = {
    id: CODEX_ACCOUNT_USAGE_SOURCE_ID,
    kind: "codex",
    label: "Codex",
    checkedAt,
  } as const;
  const settings = decodeCodexSettings(config);
  if (Option.isNone(settings)) {
    const invalid: UsageLimitSourceSnapshot = {
      ...base,
      accounts: [],
      error: "The Codex provider settings are invalid.",
    };
    return invalid;
  }
  const result = yield* readAccount(settings.value, checkedAt).pipe(
    Effect.scoped,
    Effect.timeoutOption(READ_TIMEOUT),
    Effect.map(
      Option.getOrElse((): CodexAccountUsageRead => ({
        error: "Codex did not answer the usage request.",
      })),
    ),
    Effect.catch((error) =>
      Effect.logDebug("Codex account usage read failed.", { cause: error }).pipe(
        Effect.as<CodexAccountUsageRead>({ error: codexRateLimitsFailureMessage(error) }),
      ),
    ),
  );
  const snapshot: UsageLimitSourceSnapshot =
    "account" in result
      ? { ...base, accounts: [result.account] }
      : { ...base, accounts: [], error: result.error };
  return snapshot;
});
