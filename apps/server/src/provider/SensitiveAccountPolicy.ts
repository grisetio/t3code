import type {
  ModelSelection,
  ProviderInstanceId,
  ServerProvider,
  ThreadId,
} from "@t3tools/contracts";
import * as HostProcess from "@t3tools/shared/HostProcess";
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Path from "effect/Path";
import * as Schema from "effect/Schema";
import * as SqlClient from "effect/sql/SqlClient";

import * as TaskFolderStore from "../workspace/TaskFolderStore.ts";

const SENSITIVE_PROVIDER_INSTANCES_ENV = "T3CODE_SENSITIVE_PROVIDER_INSTANCES";
/** Instances that also write their own threads' helper text (titles, commit messages, ...), without a lock. */
const SELF_TEXT_GENERATION_PROVIDER_INSTANCES_ENV =
  "T3CODE_SELF_TEXT_GENERATION_PROVIDER_INSTANCES";

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
  /**
   * The lock of every thread whose worktree contains `cwd`, counting a multi-repository thread's
   * whole task folder as its worktree.
   */
  readonly lockForPath: (
    cwd: string,
  ) => Effect.Effect<SensitiveAccountLock, SensitiveAccountPolicyError>;
  /**
   * The instance that writes this thread's helper text: the thread's current instance when it is
   * one of the self text generation instances, else none. It follows the thread when it switches.
   */
  readonly textGenerationForThread: (
    threadId: ThreadId,
  ) => Effect.Effect<SensitiveAccountLock, SensitiveAccountPolicyError>;
  /**
   * The same for a call that names only a directory: the instances of the threads whose worktree
   * (or task folder) contains `cwd`, when every one of them is a self text generation instance,
   * else none.
   */
  readonly textGenerationForPath: (
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
  selfTextGenerationInstanceIds: ReadonlySet<string> = new Set(),
) {
  const sql = yield* SqlClient.SqlClient;
  const path = yield* Path.Path;
  const taskFolders = yield* TaskFolderStore.TaskFolderStore;

  // A thread stays locked after an agent or the server moves it to another instance, and
  // passes its lock to the forks and delegated tasks started from it, which carry its context.
  // A turn the user sends from a client on another instance hands the thread off and releases
  // it until it runs on a sensitive instance again.
  const lockedThreads = (ids: ReadonlyArray<string>) => sql`
    WITH RECURSIVE used AS (
      SELECT thread_id, provider_instance_id AS instance_id, 0 AS ordinal
      FROM orchestration_v2_projection_threads
      WHERE ${sql.in("provider_instance_id", ids)}
      UNION
      SELECT thread_id, provider_instance_id AS instance_id, ordinal
      FROM orchestration_v2_projection_runs
      WHERE ${sql.in("provider_instance_id", ids)}
    ),
    handoff AS (
      SELECT run.thread_id, MAX(run.ordinal) AS ordinal
      FROM orchestration_v2_projection_runs run
      JOIN orchestration_v2_projection_messages message
        ON message.message_id = json_extract(run.payload_json, '$.userMessageId')
      WHERE run.provider_instance_id IS NOT NULL
        AND NOT ${sql.in("run.provider_instance_id", ids)}
        AND json_extract(message.payload_json, '$.createdBy') = 'user'
        AND json_extract(message.payload_json, '$.creationSource') IN ('web', 'mobile')
      GROUP BY run.thread_id
    ),
    locked AS (
      SELECT used.thread_id, used.instance_id FROM used
      LEFT JOIN handoff ON handoff.thread_id = used.thread_id
      WHERE handoff.ordinal IS NULL OR used.ordinal > handoff.ordinal
      UNION
      SELECT child.thread_id, locked.instance_id
      FROM orchestration_v2_projection_threads child
      JOIN locked ON json_extract(child.payload_json, '$.lineage.parentThreadId') = locked.thread_id
      WHERE child.thread_id NOT IN (SELECT thread_id FROM handoff)
    )
  `;

  const isInside = (child: string, parent: string) => {
    const relative = path.relative(parent, child);
    return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
  };

  // A multi-repository thread's `worktreePath` is only the project folder inside its task folder;
  // the other repositories' worktrees sit beside it, so a path there stands for the project folder.
  const pathTargets = Effect.fn("SensitiveAccountPolicy.pathTargets")(function* (cwd: string) {
    const target = path.resolve(cwd);
    const taskFolder = yield* taskFolders
      .findContaining(target)
      .pipe(
        Effect.mapError(
          (cause) => new SensitiveAccountPolicyError({ operation: `path ${cwd}`, cause }),
        ),
      );
    return taskFolder === null ? [target] : [target, path.resolve(taskFolder.projectPath)];
  });
  const isInsideAny = (targets: ReadonlyArray<string>, worktreePath: string) =>
    targets.some((target) => isInside(target, path.resolve(worktreePath)));

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
    const targets = yield* pathTargets(cwd);
    const lock = new Set<ProviderInstanceId>();
    for (const row of rows) {
      if (row.path !== null && row.path !== "" && isInsideAny(targets, row.path)) {
        lock.add(row.instanceId as ProviderInstanceId);
      }
    }
    return lock as SensitiveAccountLock;
  });

  const textGenerationForThread = Effect.fn("SensitiveAccountPolicy.textGenerationForThread")(
    function* (threadId: ThreadId) {
      if (selfTextGenerationInstanceIds.size === 0) return EMPTY_LOCK;
      const rows = yield* sql<{ readonly instanceId: string | null }>`
        SELECT provider_instance_id AS "instanceId"
        FROM orchestration_v2_projection_threads WHERE thread_id = ${threadId}
      `.pipe(
        Effect.mapError(
          (cause) => new SensitiveAccountPolicyError({ operation: `thread ${threadId}`, cause }),
        ),
      );
      const instanceId = rows[0]?.instanceId;
      return instanceId != null && selfTextGenerationInstanceIds.has(instanceId)
        ? (new Set([instanceId as ProviderInstanceId]) as SensitiveAccountLock)
        : EMPTY_LOCK;
    },
  );

  const textGenerationForPath = Effect.fn("SensitiveAccountPolicy.textGenerationForPath")(
    function* (cwd: string) {
      if (selfTextGenerationInstanceIds.size === 0) return EMPTY_LOCK;
      const rows = yield* sql<{ readonly instanceId: string | null; readonly path: string | null }>`
        SELECT provider_instance_id AS "instanceId",
          json_extract(payload_json, '$.worktreePath') AS "path"
        FROM orchestration_v2_projection_threads
        WHERE json_extract(payload_json, '$.worktreePath') IS NOT NULL
      `.pipe(
        Effect.mapError(
          (cause) => new SensitiveAccountPolicyError({ operation: `path ${cwd}`, cause }),
        ),
      );
      const targets = yield* pathTargets(cwd);
      const owners = rows.filter(
        (row) => row.path !== null && row.path !== "" && isInsideAny(targets, row.path),
      );
      // A worktree shared with a thread on another instance keeps the configured model.
      if (
        owners.length === 0 ||
        !owners.every(
          (row) => row.instanceId !== null && selfTextGenerationInstanceIds.has(row.instanceId),
        )
      ) {
        return EMPTY_LOCK;
      }
      return new Set(
        owners.map((row) => row.instanceId as ProviderInstanceId),
      ) as SensitiveAccountLock;
    },
  );

  return SensitiveAccountPolicy.of({
    lockForThread,
    lockForPath,
    textGenerationForThread,
    textGenerationForPath,
  });
});

export const layer = Layer.effect(
  SensitiveAccountPolicy,
  Effect.flatMap(HostProcess.Environment, (env) =>
    make(
      parseSensitiveInstanceIds(env[SENSITIVE_PROVIDER_INSTANCES_ENV]),
      parseSensitiveInstanceIds(env[SELF_TEXT_GENERATION_PROVIDER_INSTANCES_ENV]),
    ),
  ),
).pipe(Layer.provide(TaskFolderStore.layer));

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
  return `This thread, or the thread it was started from, has run on the sensitive account ${[...lock].join(", ")}, so only the user, by sending a turn from the app, can move it to ${instanceId}.`;
}
