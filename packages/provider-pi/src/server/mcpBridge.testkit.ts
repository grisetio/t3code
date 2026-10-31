// @effect-diagnostics nodeBuiltinImport:off -- Executes the shipped Pi extension at its native JavaScript boundary.
import * as NodeModule from "node:module";
import * as NodePath from "node:path";
import * as NodeVM from "node:vm";
import { PI_T3_MCP_EXTENSION_SOURCE } from "./mcpExtensionSource.ts";

interface RegisteredTool {
  readonly name: string;
  readonly description: string;
  readonly parameters: unknown;
  readonly outputSchema?: unknown;
  readonly exposure?: string;
  readonly promptSnippet?: string;
  readonly promptGuidelines?: ReadonlyArray<string>;
  readonly execute: (
    id: string,
    args: Record<string, unknown>,
    signal?: AbortSignal,
  ) => Promise<{
    readonly content: ReadonlyArray<{
      readonly type: string;
      readonly text?: string;
      readonly data?: string;
      readonly mimeType?: string;
    }>;
    readonly structuredContent?: unknown;
    readonly isError?: boolean;
  }>;
}

type AgentStartHook = (
  event: {
    systemPrompt: string;
    systemPromptOptions?: { sections?: Record<string, string> | null; forceSystemPrompt?: string };
  },
  ctx: {
    cwd?: string;
    model?: { api: string };
    ui: { notify: (message: string, severity: string) => void };
  },
) => Promise<{ systemPrompt: string } | undefined>;

interface PiBashOptions {
  /** Where the active `bash` comes from; Pi's own unless another extension replaced it. */
  readonly sourcePath?: string;
  readonly settings?: { readonly shellCommandPrefix?: string; readonly shellPath?: string };
}

export async function loadMcpBridge(
  options: {
    readonly modern?: boolean;
    readonly result?: unknown;
    readonly toolSearchAvailable?: boolean;
    readonly toolSearchDisabled?: boolean;
    readonly allowsTool?: (name: string) => boolean;
    readonly runtimeMode?: string;
    readonly inputSchema?: Record<string, unknown>;
    readonly deviceApproval?: boolean;
    readonly bash?: PiBashOptions;
  } = {},
) {
  const handlers = new Map<string, AgentStartHook>();
  const bashBuilds: Array<{ readonly cwd: string; readonly options: unknown }> = [];
  const bashRuns: Array<Record<string, unknown>> = [];
  const tools: RegisteredTool[] = [];
  const requests: Array<{ readonly method: string; readonly params?: unknown }> = [];
  let activeTools = ["read"];
  let bridgeSourcePath = "/fixture/pi-t3-extension.ts";
  const transports: Array<{
    readonly url: string;
    readonly authorization: string;
    readonly signal: AbortSignal | undefined;
  }> = [];
  const servers: Array<{ readonly name: string; readonly config: Record<string, unknown> }> = [];
  const catalog = [
    {
      name: "orchestrator_capabilities",
      description: "Discover available providers and models.",
      annotations: { readOnlyHint: true },
    },
    { name: "delegate_task", description: "Delegate work to another agent." },
    {
      name: "task_status",
      description: "Check delegated work.",
      annotations: { readOnlyHint: false },
    },
    { name: "preview_snapshot", description: "Inspect the collaborative browser." },
  ].map((tool) => ({
    ...tool,
    inputSchema: options.inputSchema ?? { type: "object", properties: {} },
    outputSchema: { type: "object", properties: { count: { type: "number" } } },
  }));
  const source = NodeModule.stripTypeScriptTypes(
    PI_T3_MCP_EXTENSION_SOURCE.replace(/^import .*;$/gm, "").replace(
      "export default async function",
      "async function",
    ),
  );
  await NodeVM.runInNewContext(`${source}\nt3McpExtension(pi)`, {
    process: {
      env: {
        T3_MCP_URL: "http://fixture.invalid/mcp",
        T3_MCP_BEARER_TOKEN: "fixture-token",
        T3_PI_MCP_EXTENSION_PATH: "/fixture/pi-t3-extension.ts",
        T3_PI_RUNTIME_MODE: options.runtimeMode,
        T3_PI_DEVICE_APPROVAL: options.deviceApproval === true ? "1" : undefined,
      },
    },
    AbortSignal,
    NodePath,
    Type: {
      Unsafe: (schema: unknown) => schema,
      Object: (properties: Record<string, unknown>) => ({ type: "object", properties }),
      Optional: (schema: Record<string, unknown>) => ({ ...schema, optional: true }),
      String: (schema: Record<string, unknown>) => ({ type: "string", ...schema }),
    },
    PiCodingAgent: {
      createBashToolDefinition: (cwd: string, bashOptions: unknown) => {
        bashBuilds.push({ cwd, options: bashOptions });
        return {
          name: "bash",
          label: "bash",
          description: "Execute a bash command.",
          parameters: { type: "object", properties: { command: { type: "string" } } },
          execute: async (_id: string, params: Record<string, unknown>) => {
            bashRuns.push(params);
            return { content: [{ type: "text", text: "ran" }] };
          },
        };
      },
    },
    fetch: async (
      url: string,
      transport: { body: string; headers: Record<string, string>; signal?: AbortSignal },
    ) => {
      transport.signal?.throwIfAborted();
      transports.push({
        url,
        authorization: transport.headers.authorization!,
        signal: transport.signal,
      });
      const request = JSON.parse(transport.body) as {
        id: number;
        method: string;
        params?: unknown;
      };
      requests.push(request);
      const result =
        request.method === "tools/list"
          ? { tools: catalog }
          : request.method === "tools/call"
            ? (options.result ?? { content: [{ type: "text", text: "browser snapshot" }] })
            : {};
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: request.id, result }), {
        headers: { "content-type": "application/json" },
      });
    },
    pi: {
      // Pi runs every handler for an event; keep the last result like its prompt chain.
      on: (name: string, handler: AgentStartHook) => {
        const previous = handlers.get(name);
        handlers.set(
          name,
          previous === undefined
            ? handler
            : async (event, ctx) => {
                const first = await previous(event, ctx);
                return (await handler(event, ctx)) ?? first;
              },
        );
      },
      getSettings: () => options.bash?.settings ?? {},
      registerTool: (tool: RegisteredTool) => {
        if (options.allowsTool && !options.allowsTool(tool.name)) return;
        const index = tools.findIndex((current) => current.name === tool.name);
        if (index === -1) tools.push(tool);
        else tools[index] = tool;
      },
      getActiveTools: () => activeTools,
      setActiveTools: (names: string[]) => {
        activeTools = names.filter((name) => options.allowsTool?.(name) ?? true);
      },
      getAllTools: () => [
        ...tools.map((tool) => ({ name: tool.name, sourceInfo: { path: bridgeSourcePath } })),
        ...(options.bash !== undefined && !tools.some((tool) => tool.name === "bash")
          ? [{ name: "bash", sourceInfo: { path: options.bash.sourcePath ?? "builtin:bash" } }]
          : []),
        ...(options.toolSearchAvailable &&
        !options.toolSearchDisabled &&
        (options.allowsTool?.("tool_search") ?? true)
          ? [{ name: "tool_search", sourceInfo: { path: "builtin:tool-search" } }]
          : []),
      ],
      ...(options.modern
        ? {
            registerMcpServer: (name: string, config: Record<string, unknown>) =>
              servers.push({ name, config }),
            unregisterMcpServer: () => servers.splice(0),
          }
        : {}),
    },
  });
  return {
    handlers,
    tools,
    setBridgeSourcePath: (path: string) => {
      bridgeSourcePath = path;
    },
    requests,
    bashBuilds,
    bashRuns,
    servers,
    transports,
    getActiveTools: () => activeTools,
    restoreActiveTools: (names: string[]) => {
      activeTools = names;
    },
  };
}
