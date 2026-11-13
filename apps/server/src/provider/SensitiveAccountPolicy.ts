import type {
  ModelSelection,
  ProviderInstanceId,
  ServerProvider,
  ThreadId,
} from "@t3tools/contracts";
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Path from "effect/Path";
import * as Schema from "effect/Schema";
import * as SqlClient from "effect/sql/SqlClient";

const SENSITIVE_PROVIDER_INSTANCES_ENV = "T3CODE_SENSITIVE_PROVIDER_INSTANCES";

export class SensitiveAccountPolicyError extends Schema.TaggedError<SensitiveAccountPolicyError>()(
  "SensitiveAccountPolicyError",
  {
    operation: Schema.String,
    cause: Schema.Defect(),
  },
) {
  override get message(): string {
    return `Could not decide which accounts may run here (${this.operation}).`;
  }
}

/**
 * The sensitive instances a thread has used. Empty means it is not locked.
 * Once locked, only these instances may run its turns or helper calls.
 */
export type SensitiveAccountLock = ReadonlySet<ProviderInstanceId>;

export interface SensitiveAccountPolicyShape {
  readonly lockForThread: (
    threadId: ThreadId,
  ) => Effect.Effect<SensitiveAccountLock, SensitiveAccountPolicyError>;
  /** The lock of every thread whose worktree contains `cwd`. */
  readonly lockForPath: (
    cwd: string,
  ) => Effect.Effect<SensitiveAccountLock, SensitiveAccountPolicyError>;
}

export class SensitiveAccountPolicy extends Context.Service<
  SensitiveAccountPolicy,
  SensitiveAccountPolicyShape
>()("t3/provider/SensitiveAccountPolicy") {}

function parseSensitiveInstanceIds(value: string | undefined): ReadonlySet<string> {
  return new Set(
    (value ?? "")
      .split(",")
      .map((entry) => entry.trim())
      .filter((entry) => entry !== ""),
  );
}

const EMPTY_LOCK: SensitiveAccountLock = new Set();

/** @public */
export const make = Effect.fn("SensitiveAccountPolicy.make")(function* (
  sensitiveInstanceIds: ReadonlySet<string>,
) {
  const sql = yield* SqlClient.SqlClient;
  const path = yield* Path.Path;

  // A thread stays locked after switching instance, and passes its lock to the forks and
  // delegated tasks started from it, which carry its context.
  const lockedThreads = (ids: ReadonlyArray<string>) => sql`
    WITH RECURSIVE used AS (
      SELECT thread_id, provider_instance_id AS instance_id
      FROM orchestration_v2_projection_threads
      WHERE ${sql.in("provider_instance_id", ids)}
      UNION
      SELECT thread_id, provider_instance_id AS instance_id
      FROM orchestration_v2_projection_runs
      WHERE ${sql.in("provider_instance_id", ids)}
    ),
    locked AS (
      SELECT thread_id, instance_id FROM used
      UNION
      SELECT child.thread_id, locked.instance_id
      FROM orchestration_v2_projection_threads child
      JOIN locked ON json_extract(child.payload_json, '$.lineage.parentThreadId') = locked.thread_id
    )
  `;

  const isInside = (child: string, parent: string) => {
    const relative = path.relative(parent, child);
    return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
  };

  const lockForThread = Effect.fn("SensitiveAccountPolicy.lockForThread")(function* (
    threadId: ThreadId,
  ) {
    const ids = [...sensitiveInstanceIds];
    if (ids.length === 0) return EMPTY_LOCK;
    const rows = yield* sql<{ readonly instanceId: string }>`
      ${lockedThreads(ids)}
      SELECT DISTINCT instance_id AS "instanceId" FROM locked WHERE thread_id = ${threadId}
    `.pipe(
      Effect.mapError(
        (cause) => new SensitiveAccountPolicyError({ operation: `thread ${threadId}`, cause }),
      ),
    );
    return new Set(rows.map((row) => row.instanceId as ProviderInstanceId)) as SensitiveAccountLock;
  });

  const lockForPath = Effect.fn("SensitiveAccountPolicy.lockForPath")(function* (cwd: string) {
    const ids = [...sensitiveInstanceIds];
    if (ids.length === 0) return EMPTY_LOCK;
    const rows = yield* sql<{ readonly instanceId: string; readonly path: string | null }>`
      ${lockedThreads(ids)}
      SELECT DISTINCT locked.instance_id AS "instanceId",
        json_extract(t.payload_json, '$.worktreePath') AS "path"
      FROM locked JOIN orchestration_v2_projection_threads t ON t.thread_id = locked.thread_id
    `.pipe(
      Effect.mapError(
        (cause) => new SensitiveAccountPolicyError({ operation: `path ${cwd}`, cause }),
      ),
    );
    const target = path.resolve(cwd);
    const lock = new Set<ProviderInstanceId>();
    for (const row of rows) {
      if (row.path !== null && row.path !== "" && isInside(target, path.resolve(row.path))) {
        lock.add(row.instanceId as ProviderInstanceId);
      }
    }
    return lock as SensitiveAccountLock;
  });

  return SensitiveAccountPolicy.of({ lockForThread, lockForPath });
});

export const layer = Layer.effect(
  SensitiveAccountPolicy,
  Effect.suspend(() =>
    make(parseSensitiveInstanceIds(process.env[SENSITIVE_PROVIDER_INSTANCES_ENV])),
  ),
);

/**
 * Moves a selection onto the lock's account: the same model when the driver matches,
 * otherwise `defaultModel` for that account. Null when no locked account is available.
 */
export function lockedSelection(
  lock: SensitiveAccountLock,
  selection: ModelSelection,
  providers: ReadonlyArray<ServerProvider>,
  defaultModel: (provider: ServerProvider) => string | undefined,
): ModelSelection | null {
  if (lock.size === 0 || lock.has(selection.instanceId)) return selection;
  const current = providers.find((provider) => provider.instanceId === selection.instanceId);
  const locked = providers.find((provider) => lock.has(provider.instanceId));
  if (locked === undefined) return null;
  if (current?.driver === locked.driver) return { ...selection, instanceId: locked.instanceId };
  const model = defaultModel(locked);
  return model === undefined ? null : { instanceId: locked.instanceId, model };
}

/** Refuses an instance a locked thread does not allow. */
export function lockRefusal(lock: SensitiveAccountLock, instanceId: string): string | null {
  if (lock.size === 0 || lock.has(instanceId as ProviderInstanceId)) return null;
  return `This thread, or the thread it was started from, has run on the sensitive account ${[...lock].join(", ")}, so it can only run there, not on ${instanceId}.`;
}
