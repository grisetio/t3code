import { describe, expect, it } from "@effect/vitest";
import { NodeId, RunId, ThreadId } from "@t3tools/contracts";

import { attribute, type LiveRun } from "./attribution.ts";
import type { ChainEntry } from "./protocol.ts";

const server = { pid: 100, startTime: 5000 };
const entry = (pid: number, argv: ReadonlyArray<string> | null, startTime = 6000): ChainEntry => ({
  pid,
  ppid: 0,
  startTime,
  exe: null,
  argv,
  argvTruncated: false,
});
const serverEntry = entry(server.pid, ["node", "t3"], server.startTime);
const run = (
  name: string,
  commands: ReadonlyArray<{
    readonly text: string;
    readonly explanation?: string;
    readonly running?: boolean;
  }>,
): LiveRun => ({
  threadId: ThreadId.make(`thread:${name}`),
  runId: RunId.make(`run:${name}`),
  rootNodeId: NodeId.make(`node:${name}`),
  commands: commands.map((command) => ({
    text: command.text,
    explanation: command.explanation ?? null,
    running: command.running ?? true,
  })),
});

// Measured: Claude wraps each Bash call, and its bash stays as sudo's parent.
const claudeBash = (command: string) => [
  "/bin/bash",
  "-c",
  `source /tmp/snapshot.sh && eval '${command.replaceAll("'", `'\\''`)}' < /dev/null && pwd -P >| /tmp/cwd`,
];

describe("attribute", () => {
  it("leaves a sudo that doesn't descend from this server to the password", () => {
    expect(
      attribute({
        hello: { argv: ["sudo", "ls"], chain: [entry(7, ["zsh"]), entry(1, ["launchd"])] },
        server,
        liveRuns: [run("a", [{ text: "sudo ls" }])],
        providerProcesses: [],
        serverSudos: [],
      }),
    ).toEqual({ type: "not_mine" });
  });

  it("treats a reused server pid with another start time as a different process", () => {
    expect(
      attribute({
        hello: { argv: ["sudo", "ls"], chain: [entry(server.pid, ["node"], 1)] },
        server,
        liveRuns: [run("a", [{ text: "sudo ls" }])],
        providerProcesses: [],
        serverSudos: [],
      }),
    ).toEqual({ type: "not_mine" });
  });

  it("says not_mine when no run is live", () => {
    expect(
      attribute({
        hello: {
          argv: ["sudo", "ls"],
          chain: [entry(200, claudeBash("sudo ls")), entry(150, ["claude"]), serverEntry],
        },
        server,
        liveRuns: [],
        providerProcesses: [{ pid: 150, startTime: 6000, threadId: "thread:a" }],
        serverSudos: [],
      }),
    ).toEqual({ type: "not_mine" });
  });

  it("matches a Claude command through its bash wrapper and keeps the description", () => {
    const a = run("a", [{ text: "sudo nix-collect-garbage -d", explanation: "Free disk space" }]);
    const b = run("b", [{ text: "pnpm test" }]);
    expect(
      attribute({
        hello: {
          argv: ["sudo", "nix-collect-garbage", "-d"],
          chain: [
            entry(200, claudeBash("sudo nix-collect-garbage -d")),
            entry(150, ["claude"]),
            serverEntry,
          ],
        },
        server,
        liveRuns: [b, a],
        providerProcesses: [],
        serverSudos: [],
      }),
    ).toEqual({
      type: "mine",
      run: a,
      explanation: "Free disk space",
      command: "sudo nix-collect-garbage -d",
    });
  });

  it("keeps the reason of a background command whose tool call already returned", () => {
    const background = run("a", [
      { text: "sleep 1; sudo cat /dev/null", explanation: "Run a test request", running: false },
      { text: "pnpm dev", explanation: "Start the dev server" },
    ]);
    const hello = {
      argv: ["sudo", "cat", "/dev/null"],
      chain: [
        entry(200, claudeBash("sleep 1; sudo cat /dev/null")),
        entry(150, ["claude"]),
        serverEntry,
      ],
    };
    expect(
      attribute({
        hello,
        server,
        liveRuns: [background],
        providerProcesses: [{ pid: 150, startTime: 6000, threadId: "thread:a" }],
        serverSudos: [],
      }),
    ).toEqual({
      type: "mine",
      run: background,
      explanation: "Run a test request",
      command: "sleep 1; sudo cat /dev/null",
    });
    // A running call wins over a finished one with the same sudo.
    const script = run("a", [
      { text: "sudo cat /dev/null", explanation: "Older call", running: false },
      { text: "./check.sh", explanation: "Run the checks" },
    ]);
    expect(
      attribute({
        hello: {
          argv: ["sudo", "cat", "/dev/null"],
          chain: [
            entry(210, ["/bin/sh", "./check.sh"]),
            entry(200, claudeBash("./check.sh")),
            entry(150, ["claude"]),
            serverEntry,
          ],
        },
        server,
        liveRuns: [script],
        providerProcesses: [{ pid: 150, startTime: 6000, threadId: "thread:a" }],
        serverSudos: [],
      }),
    ).toEqual({ type: "mine", run: script, explanation: "Run the checks", command: "./check.sh" });
  });

  it("matches a lone sudo zsh exec'd under Codex's shared app-server by its own argv", () => {
    const a = run("a", [{ text: "cargo build" }]);
    const b = run("b", [{ text: "sudo apt-get update", explanation: "Refresh packages" }]);
    expect(
      attribute({
        hello: {
          argv: ["sudo", "apt-get", "update"],
          chain: [entry(300, ["codex", "app-server"]), serverEntry],
        },
        server,
        liveRuns: [a, b],
        providerProcesses: [{ pid: 300, startTime: 6000, threadId: null }],
        serverSudos: [],
      }),
    ).toEqual({
      type: "mine",
      run: b,
      explanation: "Refresh packages",
      command: "sudo apt-get update",
    });
  });

  it("matches a sudo inside a longer Codex shell command", () => {
    const a = run("a", [{ text: "sudo systemctl restart nginx && curl localhost" }]);
    expect(
      attribute({
        hello: {
          argv: ["sudo", "systemctl", "restart", "nginx"],
          chain: [
            entry(310, ["/bin/zsh", "-lc", "sudo systemctl restart nginx && curl localhost"]),
            entry(300, ["codex", "app-server"]),
            serverEntry,
          ],
        },
        server,
        liveRuns: [a, run("b", [{ text: "ls" }])],
        providerProcesses: [{ pid: 300, startTime: 6000, threadId: null }],
        serverSudos: [],
      }),
    ).toEqual({
      type: "mine",
      run: a,
      explanation: null,
      command: "sudo systemctl restart nginx && curl localhost",
    });
  });

  it("matches the shell wrapper when sudo runs from a script the command started", () => {
    const a = run("a", [{ text: "./install.sh --system" }]);
    expect(
      attribute({
        hello: {
          argv: ["sudo", "cp", "unit", "/etc/systemd/system/"],
          chain: [
            entry(320, ["/bin/sh", "./install.sh", "--system"]),
            entry(310, ["/bin/zsh", "-lc", "./install.sh --system"]),
            entry(300, ["codex", "app-server"]),
            serverEntry,
          ],
        },
        server,
        liveRuns: [a, run("b", [{ text: "ls" }])],
        providerProcesses: [{ pid: 300, startTime: 6000, threadId: null }],
        serverSudos: [],
      }),
    ).toEqual({ type: "mine", run: a, explanation: null, command: "./install.sh --system" });
  });

  it("shows a banner without a thread when two threads of a shared process run the same text", () => {
    expect(
      attribute({
        hello: {
          argv: ["sudo", "apt-get", "update"],
          chain: [entry(300, ["codex", "app-server"]), serverEntry],
        },
        server,
        liveRuns: [
          run("a", [{ text: "sudo apt-get update" }]),
          run("b", [{ text: "sudo apt-get update" }]),
        ],
        providerProcesses: [{ pid: 300, startTime: 6000, threadId: null }],
        serverSudos: [],
      }),
    ).toEqual({ type: "mine", run: null, explanation: null });
  });

  it("falls back to the provider process spawned for one thread", () => {
    const a = run("a", []);
    expect(
      attribute({
        hello: {
          argv: ["sudo", "make", "install"],
          chain: [entry(200, ["make"]), entry(150, ["claude"]), serverEntry],
        },
        server,
        liveRuns: [run("b", [{ text: "ls" }]), a],
        providerProcesses: [{ pid: 150, startTime: 6000, threadId: "thread:a" }],
        serverSudos: [],
      }),
    ).toEqual({ type: "mine", run: a, explanation: null });
  });

  it("ignores a registered pid whose start time no longer matches", () => {
    expect(
      attribute({
        hello: {
          argv: ["sudo", "make", "install"],
          chain: [entry(200, ["make"]), entry(150, ["vim"], 9999), serverEntry],
        },
        server,
        liveRuns: [run("a", [])],
        providerProcesses: [{ pid: 150, startTime: 6000, threadId: "thread:a" }],
        serverSudos: [],
      }),
    ).toEqual({ type: "not_mine" });
  });

  it("leaves the integrated terminal to the password", () => {
    expect(
      attribute({
        hello: {
          argv: ["sudo", "ls"],
          chain: [entry(400, ["-zsh"]), serverEntry],
        },
        server,
        liveRuns: [run("a", [{ text: "pnpm dev" }])],
        providerProcesses: [{ pid: 300, startTime: 6000, threadId: null }],
        serverSudos: [],
      }),
    ).toEqual({ type: "not_mine" });
  });

  it("claims only the sudo calls this server spawned itself", () => {
    const own = { argv: ["sudo", "-n", "true"], explanation: "Test device approval" };
    expect(
      attribute({
        hello: { argv: ["/usr/bin/sudo", "-n", "true"], chain: [serverEntry] },
        server,
        liveRuns: [],
        providerProcesses: [],
        serverSudos: [own],
      }),
    ).toEqual({ type: "mine", run: null, explanation: "Test device approval", serverSudo: own });
    expect(
      attribute({
        hello: { argv: ["sudo", "-S", "-k", "-p", "", "true"], chain: [serverEntry] },
        server,
        liveRuns: [run("a", [{ text: "sudo -S -k -p true" }])],
        providerProcesses: [],
        serverSudos: [own],
      }),
    ).toEqual({ type: "not_mine" });
  });
});
