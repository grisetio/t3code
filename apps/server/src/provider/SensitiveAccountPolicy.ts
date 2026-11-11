import type {
  ModelSelection,
  ProviderInstanceId,
  ServerProvider,
  ThreadId,
} from "@t3tools/contracts";
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
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
 * The sensitive instances a place has used. Empty means it is not locked.
 * Once locked, only these instances may run turns or helper calls there.
 */
export type SensitiveAccountLock = ReadonlySet<ProviderInstanceId>;

export interface SensitiveAccountPolicyShape {
  readonly lockForThread: (
    threadId: ThreadId,
  ) => Effect.Effect<SensitiveAccountLock, SensitiveAccountPolicyError>;
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

interface LockedPlace {
  readonly instanceId: string;
  readonly path: string;
}

/** @public */
export const make = Effect.fn("SensitiveAccountPolicy.make")(function* (
  sensitiveInstanceIds: ReadonlySet<string>,
) {
  const sql = yield* SqlClient.SqlClient;
  const fileSystem = yield* FileSystem.FileSystem;
  const path = yield* Path.Path;

  // A project's history includes deleted threads and projects: the data stays in the repository.
  const lockedPlaces = Effect.fn("SensitiveAccountPolicy.lockedPlaces")(function* () {
    const ids = [...sensitiveInstanceIds];
    if (ids.length === 0) return [] as ReadonlyArray<LockedPlace>;
    const rows = yield* sql<{ readonly instanceId: string; readonly path: string | null }>`
        WITH used AS (
          SELECT project_id, provider_instance_id AS instance_id
          FROM orchestration_v2_projection_threads
          WHERE ${sql.in("provider_instance_id", ids)}
          UNION
          SELECT t.project_id, r.provider_instance_id AS instance_id
          FROM orchestration_v2_projection_runs r
          JOIN orchestration_v2_projection_threads t ON t.thread_id = r.thread_id
          WHERE ${sql.in("r.provider_instance_id", ids)}
        )
        SELECT used.instance_id AS "instanceId", p.workspace_root AS "path"
        FROM used JOIN projection_projects p ON p.project_id = used.project_id
        UNION
        SELECT used.instance_id AS "instanceId", json_extract(t.payload_json, '$.worktreePath') AS "path"
        FROM used JOIN orchestration_v2_projection_threads t ON t.project_id = used.project_id
      `;
    return rows.flatMap((row) =>
      row.path === null || row.path === "" ? [] : [{ instanceId: row.instanceId, path: row.path }],
    );
  });

  const isInside = (child: string, parent: string) => {
    const relative = path.relative(parent, child);
    return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
  };

  const readText = (file: string) =>
    fileSystem.readFileString(file).pipe(
      Effect.map((text) => text.trim()),
      Effect.orElseSucceed(() => null),
    );

  // Worktrees and temporary checkouts share their repository's common git directory.
  const gitCommonDirectory = Effect.fn("SensitiveAccountPolicy.gitCommonDirectory")(function* (
    start: string,
  ) {
    let directory = path.resolve(start);
    while (true) {
      const dotGit = path.join(directory, ".git");
      const info = yield* fileSystem.stat(dotGit).pipe(Effect.orElseSucceed(() => null));
      if (info?.type === "Directory") return dotGit;
      if (info?.type === "File") {
        const pointer = yield* readText(dotGit);
        const match = pointer?.match(/^gitdir:\s*(.+)$/m);
        if (!match?.[1]) return null;
        const gitDirectory = path.resolve(directory, match[1].trim());
        const common = yield* readText(path.join(gitDirectory, "commondir"));
        return common === null ? gitDirectory : path.resolve(gitDirectory, common);
      }
      const parent = path.dirname(directory);
      if (parent === directory) return null;
      directory = parent;
    }
  });

  const lockForPath = Effect.fn("SensitiveAccountPolicy.lockForPath")(
    function* (cwd: string) {
      const places = yield* lockedPlaces();
      if (places.length === 0) return EMPTY_LOCK;
      const target = path.resolve(cwd);
      const lock = new Set<ProviderInstanceId>();
      for (const place of places) {
        if (isInside(target, path.resolve(place.path))) {
          lock.add(place.instanceId as ProviderInstanceId);
        }
      }
      const targetRepository = yield* gitCommonDirectory(target);
      if (targetRepository !== null) {
        for (const place of places) {
          if (lock.has(place.instanceId as ProviderInstanceId)) continue;
          if ((yield* gitCommonDirectory(place.path)) === targetRepository) {
            lock.add(place.instanceId as ProviderInstanceId);
          }
        }
      }
      return lock as SensitiveAccountLock;
    },
    (effect, cwd) =>
      effect.pipe(
        Effect.mapError(
          (cause) => new SensitiveAccountPolicyError({ operation: `path ${cwd}`, cause }),
        ),
      ),
  );

  const lockForThread = Effect.fn("SensitiveAccountPolicy.lockForThread")(function* (
    threadId: ThreadId,
  ) {
    if (sensitiveInstanceIds.size === 0) return EMPTY_LOCK;
    const rows = yield* sql<{ readonly path: string | null }>`
          SELECT p.workspace_root AS "path"
          FROM orchestration_v2_projection_threads t
          JOIN projection_projects p ON p.project_id = t.project_id
          WHERE t.thread_id = ${threadId}
          UNION ALL
          SELECT json_extract(payload_json, '$.worktreePath') AS "path"
          FROM orchestration_v2_projection_threads
          WHERE thread_id = ${threadId}
        `.pipe(
      Effect.mapError(
        (cause) => new SensitiveAccountPolicyError({ operation: `thread ${threadId}`, cause }),
      ),
    );
    const lock = new Set<ProviderInstanceId>();
    for (const row of rows) {
      if (row.path === null || row.path === "") continue;
      for (const instanceId of yield* lockForPath(row.path)) lock.add(instanceId);
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

/** Refuses an instance a locked place does not allow. */
export function lockRefusal(lock: SensitiveAccountLock, instanceId: string): string | null {
  if (lock.size === 0 || lock.has(instanceId as ProviderInstanceId)) return null;
  return `This project has run on the sensitive account ${[...lock].join(", ")}, so it can only run there, not on ${instanceId}.`;
}
