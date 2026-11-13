import * as NodeServices from "@effect/platform-node/NodeServices";
import { assert, it } from "@effect/vitest";
import { ThreadId } from "@t3tools/contracts";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Layer from "effect/Layer";
import * as Path from "effect/Path";
import * as SqlClient from "effect/sql/SqlClient";

import * as SqlitePersistence from "../persistence/Sqlite.ts";
import * as SensitiveAccountPolicy from "./SensitiveAccountPolicy.ts";

const insertProject = (projectId: string, workspaceRoot: string) =>
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;
    yield* sql`
      INSERT INTO projection_projects (project_id, title, workspace_root, scripts_json, created_at, updated_at)
      VALUES (${projectId}, ${projectId}, ${workspaceRoot}, '[]', '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z')
    `;
  });

const insertThread = (input: {
  readonly threadId: string;
  readonly projectId: string;
  readonly instanceId: string;
  readonly worktreePath?: string;
  readonly parentThreadId?: string;
  readonly runInstanceIds?: ReadonlyArray<string>;
}) =>
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;
    const payload = JSON.stringify({
      ...(input.worktreePath === undefined ? {} : { worktreePath: input.worktreePath }),
      ...(input.parentThreadId === undefined
        ? {}
        : { lineage: { parentThreadId: input.parentThreadId } }),
    });
    yield* sql`
      INSERT INTO orchestration_v2_projection_threads (
        thread_id, project_id, title, default_provider, runtime_mode, interaction_mode,
        created_at, updated_at, payload_json, provider_instance_id
      ) VALUES (
        ${input.threadId}, ${input.projectId}, 'thread', 'claudeAgent', 'full-access', 'default',
        '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z', ${payload}, ${input.instanceId}
      )
    `;
    for (const [ordinal, instanceId] of (input.runInstanceIds ?? []).entries()) {
      yield* sql`
        INSERT INTO orchestration_v2_projection_runs (
          run_id, thread_id, ordinal, provider, status, requested_at, payload_json, provider_instance_id
        ) VALUES (
          ${`${input.threadId}-run-${ordinal}`}, ${input.threadId}, ${ordinal}, 'claudeAgent',
          'completed', '1970-01-01T00:00:00Z', '{}', ${instanceId}
        )
      `;
    }
  });

const layerTest = Layer.mergeAll(SqlitePersistence.layerMemory, NodeServices.layer);

it.layer(layerTest)("SensitiveAccountPolicy", (it) => {
  it.effect("locks a thread, its children and its worktree, not its project", () =>
    Effect.gen(function* () {
      const fs = yield* FileSystem.FileSystem;
      const path = yield* Path.Path;
      const root = yield* fs.makeTempDirectoryScoped();
      const project = path.join(root, "project");
      const worktree = path.join(root, "worktrees", "work");
      yield* fs.makeDirectory(path.join(worktree, "src"), { recursive: true });

      yield* insertProject("project", project);
      // Switched to the personal account after running on the work account.
      yield* insertThread({
        threadId: "work-thread",
        projectId: "project",
        instanceId: "claudeAgent",
        worktreePath: worktree,
        runInstanceIds: ["claudeWork"],
      });
      yield* insertThread({
        threadId: "work-child",
        projectId: "project",
        instanceId: "claudeAgent",
        parentThreadId: "work-thread",
      });
      yield* insertThread({
        threadId: "personal-thread",
        projectId: "project",
        instanceId: "claudeAgent",
      });

      const unlocked = yield* SensitiveAccountPolicy.make(new Set());
      assert.deepStrictEqual(
        [...(yield* unlocked.lockForThread(ThreadId.make("work-thread")))],
        [],
      );
      assert.deepStrictEqual([...(yield* unlocked.lockForPath(worktree))], []);

      const policy = yield* SensitiveAccountPolicy.make(new Set(["claudeWork"]));
      for (const threadId of ["work-thread", "work-child"]) {
        assert.deepStrictEqual(
          [...(yield* policy.lockForThread(ThreadId.make(threadId)))],
          ["claudeWork"],
          threadId,
        );
      }
      assert.deepStrictEqual(
        [...(yield* policy.lockForThread(ThreadId.make("personal-thread")))],
        [],
      );
      for (const cwd of [worktree, path.join(worktree, "src")]) {
        assert.deepStrictEqual([...(yield* policy.lockForPath(cwd))], ["claudeWork"], cwd);
      }
      assert.deepStrictEqual([...(yield* policy.lockForPath(project))], []);
      assert.strictEqual(SensitiveAccountPolicy.lockRefusal(new Set(), "claudeAgent"), null);
      assert.notStrictEqual(
        SensitiveAccountPolicy.lockRefusal(
          yield* policy.lockForThread(ThreadId.make("work-child")),
          "claudeAgent",
        ),
        null,
      );
    }),
  );
});
