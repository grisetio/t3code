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
  readonly runInstanceIds?: ReadonlyArray<
    | string
    | { readonly instanceId: string; readonly createdBy: string; readonly creationSource: string }
  >;
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
    for (const [index, run] of (input.runInstanceIds ?? []).entries()) {
      const ordinal = index + 1;
      const runId = `${input.threadId}-run-${ordinal}`;
      const instanceId = typeof run === "string" ? run : run.instanceId;
      const messageId = `${runId}-message`;
      yield* sql`
        INSERT INTO orchestration_v2_projection_runs (
          run_id, thread_id, ordinal, provider, status, requested_at, payload_json, provider_instance_id
        ) VALUES (
          ${runId}, ${input.threadId}, ${ordinal}, 'claudeAgent', 'completed', '1970-01-01T00:00:00Z',
          ${JSON.stringify({ userMessageId: messageId })}, ${instanceId}
        )
      `;
      const sender = typeof run === "string" ? { createdBy: "agent", creationSource: "mcp" } : run;
      yield* sql`
        INSERT INTO orchestration_v2_projection_messages (
          message_id, thread_id, run_id, role, streaming, created_at, updated_at, payload_json
        ) VALUES (
          ${messageId}, ${input.threadId}, ${runId}, 'user', 0, '1970-01-01T00:00:00Z',
          '1970-01-01T00:00:00Z',
          ${JSON.stringify({ createdBy: sender.createdBy, creationSource: sender.creationSource })}
        )
      `;
    }
  });

const fromApp = (instanceId: string) =>
  ({ instanceId, createdBy: "user", creationSource: "mobile" }) as const;

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
      // A side chat forked from the delegated task: the lock passes down every level.
      yield* insertThread({
        threadId: "work-side-chat",
        projectId: "project",
        instanceId: "claudeAgent",
        parentThreadId: "work-child",
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
      for (const threadId of ["work-thread", "work-child", "work-side-chat"]) {
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

  it.effect("releases a thread the user moves off the sensitive instance from the app", () =>
    Effect.gen(function* () {
      yield* insertProject("handoff-project", "/handoff-project");
      yield* insertThread({
        threadId: "handed-off",
        projectId: "handoff-project",
        instanceId: "claudeAgent",
        runInstanceIds: ["claudeWork", fromApp("claudeAgent"), "claudeAgent"],
      });
      yield* insertThread({
        threadId: "handed-off-child",
        projectId: "handoff-project",
        instanceId: "claudeAgent",
        parentThreadId: "handed-off",
      });
      yield* insertThread({
        threadId: "back-on-work",
        projectId: "handoff-project",
        instanceId: "claudeWork",
        runInstanceIds: ["claudeWork", fromApp("claudeAgent"), fromApp("claudeWork")],
      });
      // An agent's turn, or the user's own turn on the sensitive instance, is no handoff.
      yield* insertThread({
        threadId: "moved-by-agent",
        projectId: "handoff-project",
        instanceId: "claudeAgent",
        runInstanceIds: [fromApp("claudeWork"), "claudeAgent"],
      });
      yield* insertThread({
        threadId: "work-parent",
        projectId: "handoff-project",
        instanceId: "claudeWork",
        runInstanceIds: ["claudeWork"],
      });
      yield* insertThread({
        threadId: "child-handed-off",
        projectId: "handoff-project",
        instanceId: "claudeAgent",
        parentThreadId: "work-parent",
        runInstanceIds: [fromApp("claudeAgent")],
      });

      const policy = yield* SensitiveAccountPolicy.make(new Set(["claudeWork"]));
      const lockOf = (threadId: string) =>
        policy.lockForThread(ThreadId.make(threadId)).pipe(Effect.map((lock) => [...lock]));
      assert.deepStrictEqual(yield* lockOf("handed-off"), []);
      assert.deepStrictEqual(yield* lockOf("handed-off-child"), []);
      assert.deepStrictEqual(yield* lockOf("back-on-work"), ["claudeWork"]);
      assert.deepStrictEqual(yield* lockOf("moved-by-agent"), ["claudeWork"]);
      assert.deepStrictEqual(yield* lockOf("work-parent"), ["claudeWork"]);
      assert.deepStrictEqual(yield* lockOf("child-handed-off"), []);
    }),
  );

  it.effect(
    "writes helper text on a self text generation instance only while the thread runs there",
    () =>
      Effect.gen(function* () {
        const fs = yield* FileSystem.FileSystem;
        const path = yield* Path.Path;
        const root = yield* fs.makeTempDirectoryScoped();
        const localTree = path.join(root, "worktrees", "local");
        const sharedTree = path.join(root, "worktrees", "shared");
        yield* fs.makeDirectory(path.join(localTree, "src"), { recursive: true });
        yield* fs.makeDirectory(sharedTree, { recursive: true });

        yield* insertProject("self-project", path.join(root, "self-project"));
        yield* insertThread({
          threadId: "local-thread",
          projectId: "self-project",
          instanceId: "claudeLocal",
          worktreePath: localTree,
        });
        // Ran on the local model, then switched to the cloud: no lock, its text follows it.
        yield* insertThread({
          threadId: "switched-thread",
          projectId: "self-project",
          instanceId: "claudeAgent",
          runInstanceIds: ["claudeLocal"],
        });
        yield* insertThread({
          threadId: "shared-local",
          projectId: "self-project",
          instanceId: "claudeLocal",
          worktreePath: sharedTree,
        });
        yield* insertThread({
          threadId: "shared-cloud",
          projectId: "self-project",
          instanceId: "claudeAgent",
          worktreePath: sharedTree,
        });

        const off = yield* SensitiveAccountPolicy.make(new Set());
        assert.deepStrictEqual(
          [...(yield* off.textGenerationForThread(ThreadId.make("local-thread")))],
          [],
        );

        const policy = yield* SensitiveAccountPolicy.make(new Set(), new Set(["claudeLocal"]));
        assert.deepStrictEqual(
          [...(yield* policy.textGenerationForThread(ThreadId.make("local-thread")))],
          ["claudeLocal"],
        );
        assert.deepStrictEqual(
          [...(yield* policy.textGenerationForThread(ThreadId.make("switched-thread")))],
          [],
        );
        assert.deepStrictEqual(
          [...(yield* policy.lockForThread(ThreadId.make("local-thread")))],
          [],
        );
        assert.deepStrictEqual(
          [...(yield* policy.textGenerationForPath(path.join(localTree, "src")))],
          ["claudeLocal"],
        );
        assert.deepStrictEqual([...(yield* policy.textGenerationForPath(sharedTree))], []);
        assert.deepStrictEqual([...(yield* policy.textGenerationForPath(root))], []);
      }),
  );
});
