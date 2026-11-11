import { describe, expect, it } from "@effect/vitest";
import { NodeId, RunId, ThreadId, TurnItemId } from "@t3tools/contracts";

import { attribute, sudoProgram, type LiveRun } from "./attribution.ts";
import type { ChainEntry } from "./protocol.ts";

const server = { pid: 100, startTime: 5000 };
const now = 1_000_000;
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
    readonly finishedAt?: number;
  }>,
): LiveRun => ({
  threadId: ThreadId.make(`thread:${name}`),
  runId: RunId.make(`run:${name}`),
  rootNodeId: NodeId.make(`node:${name}`),
  commands: commands.map((command, index) => ({
    id: TurnItemId.make(`item:${name}:${index}`),
    text: command.text,
    explanation: command.explanation ?? null,
    finishedAt: command.finishedAt ?? null,
  })),
  backgroundWork: false,
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
        now,
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
        now,
        liveRuns: [run("a", [{ text: "sudo ls" }])],
        providerProcesses: [],
        serverSudos: [],
      }),
    ).toEqual({ type: "not_mine" });
  });

  it("claims a background command's sudo after its run ended, and nothing foreign", () => {
    const providerProcesses = [
      { pid: 150, startTime: 6000, threadId: "thread:a", driver: null },
    ] as const;
    expect(
      attribute({
        hello: {
          argv: ["sudo", "ls"],
          chain: [entry(200, claudeBash("sudo ls")), entry(150, ["claude"]), serverEntry],
        },
        server,
        now,
        liveRuns: [],
        providerProcesses,
        serverSudos: [],
      }),
    ).toEqual({ type: "mine", run: null, explanation: null });
    expect(
      attribute({
        hello: { argv: ["sudo", "ls"], chain: [entry(400, ["-zsh"]), serverEntry] },
        server,
        now,
        liveRuns: [],
        providerProcesses,
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
        now,
        liveRuns: [b, a],
        providerProcesses: [],
        serverSudos: [],
      }),
    ).toEqual({
      type: "mine",
      run: a,
      explanation: "Free disk space",
      command: "sudo nix-collect-garbage -d",
      commandItemId: TurnItemId.make("item:a:0"),
    });
  });

  it("keeps the reason of a background command whose tool call already returned", () => {
    const background = run("a", [
      {
        text: "sleep 1; sudo cat /dev/null",
        explanation: "Run a test request",
        finishedAt: now - 1000,
      },
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
        now,
        liveRuns: [background],
        providerProcesses: [{ pid: 150, startTime: 6000, threadId: "thread:a", driver: null }],
        serverSudos: [],
      }),
    ).toEqual({
      type: "mine",
      run: background,
      explanation: "Run a test request",
      command: "sleep 1; sudo cat /dev/null",
      commandItemId: TurnItemId.make("item:a:0"),
    });
    // A running call wins over a finished one with the same sudo.
    const script = run("a", [
      { text: "sudo cat /dev/null", explanation: "Older call", finishedAt: now - 500 },
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
        now,
        liveRuns: [script],
        providerProcesses: [{ pid: 150, startTime: 6000, threadId: "thread:a", driver: null }],
        serverSudos: [],
      }),
    ).toEqual({ type: "mine", run: script, explanation: "Run the checks", command: "./check.sh" });
  });

  it("lends a finished call only to a sudo of its program that follows it closely", () => {
    // Only sudo's own argv can match: the wrapper's argv is unreadable.
    const hello = {
      argv: ["sudo", "-u", "root", "cat", "/dev/null"],
      chain: [entry(200, null), entry(150, ["claude"]), serverEntry],
    };
    const attributeTo = (
      finishedAt: number,
      text = "sleep 1; sudo -u root cat /dev/null",
      chain = hello.chain,
    ) => {
      const background = run("a", [{ text, explanation: "Run a test request", finishedAt }]);
      return attribute({
        hello: { ...hello, chain },
        server,
        now,
        liveRuns: [background],
        providerProcesses: [{ pid: 150, startTime: 6000, threadId: "thread:a", driver: null }],
        serverSudos: [],
      });
    };
    expect(attributeTo(now - 2000)).toMatchObject({ explanation: "Run a test request" });
    // Too old: the thread still owns it, without the call's text or reason.
    expect(attributeTo(now - 2001)).toMatchObject({ type: "mine", explanation: null });
    expect(attributeTo(now - 2001)).not.toHaveProperty("command");
    // A script's argv holding the call's text lends it only to a sudo of a program it names.
    const script = [entry(210, ["/bin/sh", "./check.sh"]), ...hello.chain];
    expect(attributeTo(now - 100, "./check.sh", script)).toMatchObject({ explanation: null });
  });

  it("credits a finished call of any age whose text a parent shell still runs", () => {
    // Measured: Claude's background `just darwin-macbook` returned 34 ms after it started, and
    // its deploy script's sudo arrived 15 s later. The same text ran once before, 3 minutes ago.
    const hello = {
      argv: ["sudo", "python3", "/Users/k/nix-hosts/deploy.py", "_submit-system", "macbook"],
      chain: [
        entry(230, ["python3", "/Users/k/nix-hosts/deploy.py", "_submit-system", "macbook"]),
        entry(210, ["just", "darwin-macbook"]),
        entry(200, claudeBash("just darwin-macbook")),
        entry(150, ["claude"]),
        serverEntry,
      ],
    };
    const attributeAt = (finishedAt: number) => {
      const a: LiveRun = {
        ...run("a", [
          {
            text: "just darwin-macbook",
            explanation: "Resubmit the nix-darwin deployment and wait",
            finishedAt,
          },
          {
            text: "just darwin-macbook",
            explanation: "Submit the nix-darwin deployment and wait",
            finishedAt: now - 180_000,
          },
          // Matches sudo's own argv within the window, but the shell names the deploy.
          {
            text: "sudo python3 /Users/k/nix-hosts/deploy.py _submit-system macbook",
            explanation: "Submit by hand",
            finishedAt: now - 500,
          },
        ]),
        backgroundWork: true,
      };
      return {
        a,
        result: attribute({
          hello,
          server,
          now,
          liveRuns: [a],
          providerProcesses: [{ pid: 150, startTime: 6000, threadId: "thread:a", driver: null }],
          serverSudos: [],
        }),
      };
    };
    for (const finishedAt of [now - 15_000, now - 256]) {
      const { a, result } = attributeAt(finishedAt);
      expect(result).toEqual({
        type: "mine",
        run: a,
        explanation: "Resubmit the nix-darwin deployment and wait",
        command: "just darwin-macbook",
      });
    }
  });

  it("credits an old finished call only when a parent shell runs exactly its text", () => {
    // A background script from an earlier run: its call isn't in this run, but the
    // run's old `pwd` and `make` calls appear inside the chain's argv.
    const a = run("a", [
      { text: "pwd", explanation: "Show the directory", finishedAt: now - 60_000 },
      { text: "make", explanation: "Build", finishedAt: now - 60_000 },
    ]);
    expect(
      attribute({
        hello: {
          argv: ["sudo", "make", "install"],
          chain: [
            entry(220, ["make", "install"]),
            entry(210, ["/bin/sh", "-c", "make install"]),
            entry(200, claudeBash("./build.sh")),
            entry(150, ["claude"]),
            serverEntry,
          ],
        },
        server,
        now,
        liveRuns: [a],
        providerProcesses: [{ pid: 150, startTime: 6000, threadId: "thread:a", driver: null }],
        serverSudos: [],
      }),
    ).toEqual({ type: "mine", run: a, explanation: null });
  });

  it("finds the program sudo runs past its options", () => {
    expect(sudoProgram(["sudo", "-u", "root", "-E", "/usr/bin/cat", "x"])).toBe("cat");
    expect(sudoProgram(["sudo", "LANG=C", "apt-get", "update"])).toBe("apt-get");
    expect(sudoProgram(["sudo", "--", "-weird"])).toBe("-weird");
    expect(sudoProgram(["sudo", "-s"])).toBeNull();
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
        now,
        liveRuns: [a, b],
        providerProcesses: [{ pid: 300, startTime: 6000, threadId: null, driver: null }],
        serverSudos: [],
      }),
    ).toEqual({
      type: "mine",
      run: b,
      explanation: "Refresh packages",
      command: "sudo apt-get update",
      commandItemId: TurnItemId.make("item:b:0"),
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
        now,
        liveRuns: [a, run("b", [{ text: "ls" }])],
        providerProcesses: [{ pid: 300, startTime: 6000, threadId: null, driver: null }],
        serverSudos: [],
      }),
    ).toEqual({
      type: "mine",
      run: a,
      explanation: null,
      command: "sudo systemctl restart nginx && curl localhost",
      commandItemId: TurnItemId.make("item:a:0"),
    });
  });

  it("links no call when two calls of the thread could be the one running the sudo", () => {
    const a = run("a", [
      { text: "sudo apt-get update", explanation: "Refresh packages" },
      { text: "sleep 5; sudo apt-get update" },
    ]);
    expect(
      attribute({
        hello: {
          argv: ["sudo", "apt-get", "update"],
          chain: [entry(300, ["codex", "app-server"]), serverEntry],
        },
        server,
        now,
        liveRuns: [a],
        providerProcesses: [{ pid: 300, startTime: 6000, threadId: null, driver: null }],
        serverSudos: [],
      }),
    ).toEqual({
      type: "mine",
      run: a,
      explanation: "Refresh packages",
      command: "sudo apt-get update",
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
        now,
        liveRuns: [a, run("b", [{ text: "ls" }])],
        providerProcesses: [{ pid: 300, startTime: 6000, threadId: null, driver: null }],
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
        now,
        liveRuns: [
          run("a", [{ text: "sudo apt-get update" }]),
          run("b", [{ text: "sudo apt-get update" }]),
        ],
        providerProcesses: [{ pid: 300, startTime: 6000, threadId: null, driver: null }],
        serverSudos: [],
      }),
    ).toEqual({ type: "mine", run: null, explanation: null });
  });

  it("names the agent's driver when no thread can be told apart", () => {
    // The deploy script's second sudo: `just` → `python3 deploy.py`, under Codex's shared
    // app-server, while two threads run calls whose text appears nowhere in the chain.
    expect(
      attribute({
        hello: {
          argv: ["sudo", "python3", "deploy.py", "_status-system", "darwin-7ede7e6d", "--wait"],
          chain: [
            entry(320, ["python3", "deploy.py", "_status-system", "darwin-7ede7e6d", "--wait"]),
            entry(310, ["just", "darwin-macbook"]),
            entry(300, ["codex", "app-server"]),
            serverEntry,
          ],
        },
        server,
        now,
        liveRuns: [run("a", [{ text: "pnpm dev" }]), run("b", [{ text: "cargo test" }])],
        providerProcesses: [{ pid: 300, startTime: 6000, threadId: null, driver: "codex" }],
        serverSudos: [],
      }),
    ).toEqual({ type: "mine", run: null, explanation: null, driver: "codex" });
  });

  it("names the driver of a matched thread's process too", () => {
    const a = run("a", [{ text: "sudo ls /var/db", explanation: "List the databases" }]);
    expect(
      attribute({
        hello: {
          argv: ["sudo", "ls", "/var/db"],
          chain: [entry(200, claudeBash("sudo ls /var/db")), entry(150, ["claude"]), serverEntry],
        },
        server,
        now,
        liveRuns: [a],
        providerProcesses: [
          { pid: 150, startTime: 6000, threadId: "thread:a", driver: "claudeAgent" },
        ],
        serverSudos: [],
      }),
    ).toEqual({
      type: "mine",
      run: a,
      explanation: "List the databases",
      command: "sudo ls /var/db",
      commandItemId: TurnItemId.make("item:a:0"),
      driver: "claudeAgent",
    });
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
        now,
        liveRuns: [run("b", [{ text: "ls" }]), a],
        providerProcesses: [{ pid: 150, startTime: 6000, threadId: "thread:a", driver: null }],
        serverSudos: [],
      }),
    ).toEqual({ type: "mine", run: a, explanation: null });
  });

  it("gives a sudo deep in a script the reason of the thread's one running call", () => {
    // `just` ran `python3 deploy.py`, which ran sudo. No level below the
    // wrapper holds the call's text, and here the wrapper's argv is unreadable.
    const hello = {
      argv: ["sudo", "darwin-rebuild", "switch", "--flake", ".#macbook"],
      chain: [
        entry(230, ["python3", "deploy.py", "--host", "macbook"]),
        entry(220, ["sh", "-cu", "python3 deploy.py --host macbook"]),
        entry(210, ["just", "darwin-macbook"]),
        entry(200, null),
        entry(150, ["claude"]),
        serverEntry,
      ],
    };
    const call = {
      text: "just darwin-macbook 2>&1 | tail -30",
      explanation: "Apply the macbook configuration",
    };
    const attributeWith = (commands: Parameters<typeof run>[1]) => {
      const a = run("a", commands);
      return {
        a,
        result: attribute({
          hello,
          server,
          now,
          liveRuns: [run("b", [{ text: "pnpm dev", explanation: "Start the dev server" }]), a],
          providerProcesses: [{ pid: 150, startTime: 6000, threadId: "thread:a", driver: null }],
          serverSudos: [],
        }),
      };
    };
    const one = attributeWith([
      call,
      { text: "git status", explanation: "Check the tree", finishedAt: now - 60_000 },
    ]);
    expect(one.result).toEqual({
      type: "mine",
      run: one.a,
      explanation: "Apply the macbook configuration",
      command: call.text,
    });
    // Two running calls: either could have reached sudo.
    const two = attributeWith([call, { text: "pnpm dev", explanation: "Start the dev server" }]);
    expect(two.result).toEqual({ type: "mine", run: two.a, explanation: null });
  });

  it("gives no reason while a background command could be the one that ran sudo", () => {
    // Measured: Claude's `run_in_background` deploy returned at once, then its script's
    // second sudo arrived while a call waiting on the deploy's log was the only running one.
    const deploy = "just darwin-macbook > deploy.log 2>&1; echo rc=$? >> deploy.log";
    const a: LiveRun = {
      ...run("a", [
        {
          text: "until grep -q ^rc= deploy.log; do sleep 5; done",
          explanation: "Wait until the deploy command exits",
        },
        { text: deploy, explanation: "Deploy nix-darwin", finishedAt: now - 15_000 },
      ]),
      backgroundWork: true,
    };
    const attributeUnder = (wrapperArgv: ReadonlyArray<string> | null) =>
      attribute({
        hello: {
          argv: ["sudo", "python3", "deploy.py", "_status-system", "darwin-7ede7e6d", "--wait"],
          chain: [
            entry(230, ["python3", "deploy.py", "_submit-system"]),
            entry(210, ["just", "darwin-macbook"]),
            entry(200, wrapperArgv),
            entry(150, ["claude"]),
            serverEntry,
          ],
        },
        server,
        now,
        liveRuns: [a],
        providerProcesses: [{ pid: 150, startTime: 6000, threadId: "thread:a", driver: null }],
        serverSudos: [],
      });
    expect(attributeUnder(null)).toEqual({ type: "mine", run: a, explanation: null });
    // With the wrapper readable, the deploy's own shell names its call.
    expect(attributeUnder(claudeBash(deploy))).toEqual({
      type: "mine",
      run: a,
      explanation: "Deploy nix-darwin",
      command: deploy,
    });
  });

  it("ignores a registered pid whose start time no longer matches", () => {
    expect(
      attribute({
        hello: {
          argv: ["sudo", "make", "install"],
          chain: [entry(200, ["make"]), entry(150, ["vim"], 9999), serverEntry],
        },
        server,
        now,
        liveRuns: [run("a", [])],
        providerProcesses: [{ pid: 150, startTime: 6000, threadId: "thread:a", driver: null }],
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
        now,
        liveRuns: [run("a", [{ text: "pnpm dev" }])],
        providerProcesses: [{ pid: 300, startTime: 6000, threadId: null, driver: null }],
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
        now,
        liveRuns: [],
        providerProcesses: [],
        serverSudos: [own],
      }),
    ).toEqual({ type: "mine", run: null, explanation: "Test device approval", serverSudo: own });
    expect(
      attribute({
        hello: { argv: ["sudo", "-S", "-k", "-p", "", "true"], chain: [serverEntry] },
        server,
        now,
        liveRuns: [run("a", [{ text: "sudo -S -k -p true" }])],
        providerProcesses: [],
        serverSudos: [own],
      }),
    ).toEqual({ type: "not_mine" });
  });
});
