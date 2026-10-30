import type { SDKUserMessage } from "@anthropic-ai/claude-agent-sdk";
import { assert, it } from "@effect/vitest";
import * as NodeServices from "@effect/platform-node/NodeServices";
import {
  ClaudeSettings,
  CommandId,
  EventId,
  MessageId,
  ProjectId,
  ProviderDriverKind,
  ProviderThreadId,
  ThreadId,
  TurnItemId,
} from "@t3tools/contracts";
import * as Crypto from "effect/Crypto";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Layer from "effect/Layer";
import * as Path from "effect/Path";
import * as Schema from "effect/Schema";
import * as Stream from "effect/Stream";
import * as IdAllocator from "@t3tools/provider-core/server/IdAllocator";
import * as McpProviderSessions from "@t3tools/provider-core/server/McpProviderSessions";
import * as SqlitePersistence from "../persistence/Sqlite.ts";
import * as ClaudeAdapterV2 from "./Adapters/ClaudeAdapterV2.ts";
import * as EffectWorker from "./EffectWorker.ts";
import * as Orchestrator from "./Orchestrator.ts";
import { shouldPrepareLegacyImportHandoff } from "./Orchestrator.ts";
import * as ProjectionStore from "./ProjectionStore.ts";
import * as ProviderAdapterRegistry from "./ProviderAdapterRegistry.ts";
import * as ProviderReplayHarness from "./testkit/ProviderReplayHarness.ts";
import { CLAUDE_MODEL_SELECTION } from "./testkit/fixtures/shared.ts";

const claudeSettings = Schema.decodeSync(ClaudeSettings)({});

it("reissues imported context until a V2 run completes", () => {
  assert.isTrue(
    shouldPrepareLegacyImportHandoff({
      historyOrigin: "v1_import",
      hasCompletedRun: false,
      legacyImportItemCount: 2,
    }),
  );
  assert.isFalse(
    shouldPrepareLegacyImportHandoff({
      historyOrigin: "v1_import",
      hasCompletedRun: true,
      legacyImportItemCount: 2,
    }),
  );
  assert.isFalse(
    shouldPrepareLegacyImportHandoff({
      historyOrigin: undefined,
      hasCompletedRun: false,
      legacyImportItemCount: 2,
    }),
  );
  assert.isFalse(
    shouldPrepareLegacyImportHandoff({
      historyOrigin: "v1_import",
      hasCompletedRun: false,
      legacyImportItemCount: 0,
    }),
  );
});

it.effect.each([
  "available",
  "missing",
  "empty",
  "unreadable",
  "other-profile",
  "relative-profile",
  "app-only",
] as const)("starts imported Claude history without duplicate replay, native history=%s", (state) =>
  Effect.scoped(
    Effect.gen(function* () {
      const fileSystem = yield* FileSystem.FileSystem;
      const path = yield* Path.Path;
      const configDir = yield* fileSystem.makeTempDirectoryScoped({
        prefix: "t3-import-resume-",
      });
      const projectDir = path.join(configDir, "projects", "original-workspace");
      yield* fileSystem.makeDirectory(projectDir, { recursive: true });
      const transcriptPath = path.join(projectDir, "synthetic-session.jsonl");
      if (state === "available" || state === "relative-profile")
        yield* fileSystem.writeFileString(
          transcriptPath,
          '{"type":"assistant","message":{"role":"assistant","content":"Imported answer"}}\n',
        );
      if (state === "empty")
        yield* fileSystem.writeFileString(transcriptPath, '{"type":"cost-state"}\n');
      if (state === "unreadable") yield* fileSystem.makeDirectory(transcriptPath);
      if (state === "other-profile") {
        const otherProject = path.join(
          configDir,
          "other-profile",
          "projects",
          "original-workspace",
        );
        yield* fileSystem.makeDirectory(otherProject, { recursive: true });
        yield* fileSystem.writeFileString(
          path.join(otherProject, "synthetic-session.jsonl"),
          '{"type":"assistant","message":{"role":"assistant","content":"Different profile"}}\n',
        );
      }
      const queries: Array<ClaudeAdapterV2.ClaudeAgentSdkQueryOpenInput> = [];
      const prompts: Array<SDKUserMessage> = [];
      const adapter = yield* ClaudeAdapterV2.makeClaudeAdapterV2({
        instanceId: CLAUDE_MODEL_SELECTION.instanceId,
        settings: claudeSettings,
        environment: { CLAUDE_CONFIG_DIR: state === "relative-profile" ? "." : configDir },
        attachmentsDir: configDir,
        fileSystem,
        path,
        crypto: yield* Crypto.Crypto,
        idAllocator: yield* IdAllocator.IdAllocatorV2,
        queryRunner: {
          allocateSessionId: Effect.succeed("fresh-native-session"),
          open: (input) =>
            Effect.sync(() => {
              queries.push(input);
              return {
                messages: Stream.never,
                offer: (message) =>
                  Effect.sync(() => {
                    prompts.push(message);
                  }),
                setModel: () => Effect.void,
                applyFlagSettings: () => Effect.void,
                setPermissionMode: () => Effect.void,
                backgroundTasks: () => Effect.succeed(false),
                stopTask: () => Effect.void,
                interrupt: Effect.void,
                close: Effect.void,
              };
            }),
          forkSession: () => Effect.die("Unexpected native fork in offline import test"),
          subagentLaunchToolUseId: () => Effect.succeed(null),
          assertComplete: Effect.void,
        },
      });
      const databaseLayer = SqlitePersistence.layerMemory;
      const layer = Layer.mergeAll(
        ProjectionStore.layer.pipe(Layer.provide(databaseLayer)),
        ProviderReplayHarness.layerWithRegistry(
          { name: "imported-session-handoff", runtimePolicyOverride: { cwd: configDir } },
          ProviderAdapterRegistry.layerFromAdapters([adapter]),
          { databaseLayer, runEffectWorker: false },
        ),
      );
      yield* Effect.gen(function* () {
        const orchestrator = yield* Orchestrator.OrchestratorV2;
        const projections = yield* ProjectionStore.ProjectionStoreV2;
        const worker = yield* EffectWorker.OrchestrationEffectWorkerV2;
        const threadId = ThreadId.make("import:claudeAgent:synthetic-session");
        const providerThreadId = ProviderThreadId.make("imported-provider-thread");
        const driver = ProviderDriverKind.make("claudeAgent");
        const bound = state !== "app-only";
        const now = yield* DateTime.now;
        yield* orchestrator.dispatch({
          type: "thread.create",
          commandId: CommandId.make("create-imported"),
          threadId,
          projectId: ProjectId.make("imported-project"),
          title: "Imported session",
          modelSelection: CLAUDE_MODEL_SELECTION,
          runtimeMode: "full-access",
          interactionMode: "default",
          branch: null,
          worktreePath: null,
          createdBy: "system",
          creationSource: "server",
        });
        const { thread } = yield* projections.getThreadProjection(threadId);
        yield* projections.apply({
          id: EventId.make("imported-thread"),
          type: "thread.created",
          threadId,
          occurredAt: now,
          payload: {
            ...thread,
            historyOrigin: "v1_import",
            activeProviderThreadId: bound ? providerThreadId : null,
          },
        });
        if (bound)
          yield* projections.apply({
            id: EventId.make("imported-binding"),
            type: "provider-thread.updated",
            threadId,
            occurredAt: now,
            payload: {
              id: providerThreadId,
              driver,
              providerInstanceId: CLAUDE_MODEL_SELECTION.instanceId,
              providerSessionId: null,
              appThreadId: threadId,
              ownerNodeId: null,
              nativeThreadRef: { driver, nativeId: "synthetic-session", strength: "strong" },
              nativeConversationHeadRef: null,
              status: "idle",
              firstRunOrdinal: null,
              lastRunOrdinal: null,
              handoffIds: [],
              forkedFrom: null,
              createdAt: now,
              updatedAt: now,
            },
          });
        yield* projections.apply({
          id: EventId.make("imported-history"),
          type: "turn-item.updated",
          threadId,
          occurredAt: now,
          payload: {
            id: TurnItemId.make("imported-answer"),
            threadId,
            runId: null,
            nodeId: null,
            providerThreadId: null,
            providerTurnId: null,
            nativeItemRef: null,
            parentItemId: null,
            ordinal: 1,
            status: "completed",
            title: null,
            startedAt: now,
            completedAt: now,
            updatedAt: now,
            type: "assistant_message",
            messageId: MessageId.make("imported-answer"),
            text: "Imported answer that must not be silently discarded.",
            streaming: false,
          },
        });
        yield* orchestrator.dispatch({
          type: "message.dispatch",
          commandId: CommandId.make("continue-imported"),
          threadId,
          messageId: MessageId.make("continue-imported"),
          text: "Continue.",
          attachments: [],
          dispatchMode: { type: "start_immediately" },
          createdBy: "user",
          creationSource: "web",
        });
        yield* worker.drain();
        const projection = yield* projections.getThreadProjection(threadId);
        assert.lengthOf(queries, 1);
        assert.lengthOf(prompts, 1);
        assert.equal(projection.runs[0]?.status, "running");
        const resumed = state === "available" || state === "relative-profile";
        assert.equal(queries[0]?.options.resume, resumed ? "synthetic-session" : undefined);
        assert.equal(queries[0]?.options.sessionId, resumed ? undefined : "fresh-native-session");
        assert.lengthOf(projection.contextHandoffs, resumed ? 0 : 1);
        const prompt = JSON.stringify(prompts[0]?.message.content);
        assert.include(prompt, "Continue.");
        if (resumed) {
          assert.notInclude(prompt, "Imported answer");
          assert.notInclude(prompt, "Historical");
        } else {
          assert.equal(
            prompt.split("Imported answer that must not be silently discarded.").length - 1,
            1,
          );
          assert.equal(projection.contextHandoffs[0]?.delivery?.status, "inline");
        }
      }).pipe(Effect.provide(layer));
    }),
  ).pipe(
    Effect.provide(
      Layer.mergeAll(NodeServices.layer, IdAllocator.layer, McpProviderSessions.layer),
    ),
  ),
);
