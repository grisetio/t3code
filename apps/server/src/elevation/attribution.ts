/**
 * Picks the thread a `sudo` belongs to from the process chain the PAM module
 * reports. This only decides where a prompt is shown: the chain comes from
 * the same uid as every agent, and the phone's signature is what authorizes.
 */
import type { ProviderProcess } from "@t3tools/shared/ProviderProcesses";
import type { NodeId, RunId, ThreadId } from "@t3tools/contracts";

import type { Hello } from "./protocol.ts";

export interface LiveRun {
  readonly threadId: ThreadId;
  readonly runId: RunId;
  readonly rootNodeId: NodeId;
  /** This run's command items, newest first. */
  readonly commands: ReadonlyArray<{
    readonly text: string;
    readonly explanation: string | null;
    /**
     * False once the tool call returned. A background command (Claude's
     * `run_in_background`) returns before its shell reaches sudo.
     */
    readonly running: boolean;
  }>;
}

/** A sudo the server spawned itself, such as the setup test or a helper call. */
export interface ServerSudo {
  readonly argv: ReadonlyArray<string>;
  readonly explanation: string;
}

export type Attribution =
  | { readonly type: "not_mine" }
  | {
      readonly type: "mine";
      readonly run: LiveRun | null;
      readonly explanation: string | null;
      /** The matched tool call's command line. */
      readonly command?: string;
      /** Set when the sudo is one this server spawned. */
      readonly serverSudo?: ServerSudo;
    };

const NOT_MINE: Attribution = { type: "not_mine" };

/**
 * Quoting differs between the text an agent's tool reports and the argv the
 * kernel holds (`zsh -lc 'sudo x'`, `bash -c '… eval '\''sudo x'\'' …'`), so
 * both sides compare as whitespace-separated tokens with quotes removed.
 */
function tokens(text: string): ReadonlyArray<string> {
  return text
    .replace(/['"\\]/g, "")
    .split(/\s+/)
    .filter(Boolean);
}

function containsSequence(haystack: ReadonlyArray<string>, needle: ReadonlyArray<string>) {
  if (needle.length === 0 || needle.length > haystack.length) return false;
  for (let start = 0; start + needle.length <= haystack.length; start++) {
    if (needle.every((token, index) => haystack[start + index] === token)) return true;
  }
  return false;
}

const basename = (path: string | undefined) => path?.split("/").at(-1);

/** argv[0] is whatever the spawner passed, a bare name or a resolved path. */
const sameArgv = (left: ReadonlyArray<string>, right: ReadonlyArray<string>) =>
  left.length === right.length &&
  basename(left[0]) === basename(right[0]) &&
  left.every((value, index) => index === 0 || value === right[index]);

export function attribute(input: {
  readonly hello: Pick<Hello, "argv" | "chain">;
  readonly server: { readonly pid: number; readonly startTime: number | null };
  readonly liveRuns: ReadonlyArray<LiveRun>;
  readonly providerProcesses: ReadonlyArray<ProviderProcess>;
  readonly serverSudos: ReadonlyArray<ServerSudo>;
}): Attribution {
  const { hello, server } = input;
  const serverIndex = hello.chain.findIndex(
    (entry) =>
      entry.pid === server.pid &&
      (server.startTime === null || entry.startTime === server.startTime),
  );
  // Everything an agent runs descends from this server.
  if (serverIndex === -1) return NOT_MINE;
  if (serverIndex === 0) {
    const own = input.serverSudos.find((sudo) => sameArgv(sudo.argv, hello.argv));
    return own === undefined
      ? NOT_MINE
      : { type: "mine", run: null, explanation: own.explanation, serverSudo: own };
  }
  if (input.liveRuns.length === 0) return NOT_MINE;

  // A shell execs its last command, so a lone `sudo …` has no shell above it:
  // sudo's own argv is matched inside the command text, and an ancestor's argv
  // (the shell) must contain the command text.
  const belowServer = hello.chain.slice(0, serverIndex);
  const levels = [hello.argv, ...belowServer.map((entry) => entry.argv)];
  // Finished calls only after every level missed, so an old `sudo x` item
  // can't take the place of the running script that runs it.
  for (const running of [true, false]) {
    for (const [level, argv] of levels.entries()) {
      if (argv === null) continue;
      const processTokens = tokens(argv.join(" "));
      const matches = input.liveRuns.flatMap((run) =>
        run.commands
          .filter((command) => {
            if (command.running !== running) return false;
            const commandTokens = tokens(command.text);
            return level === 0
              ? containsSequence(commandTokens, processTokens)
              : containsSequence(processTokens, commandTokens);
          })
          .map((command) => ({ run, command })),
      );
      const threads = new Set(matches.map((match) => match.run.threadId));
      const first = matches[0];
      if (threads.size === 1 && first !== undefined) {
        const explained = matches.find((match) => match.command.explanation !== null) ?? first;
        return {
          type: "mine",
          run: first.run,
          explanation: explained.command.explanation,
          command: explained.command.text,
        };
      }
    }
  }

  const providerProcessAt = (entry: (typeof belowServer)[number]) =>
    input.providerProcesses.find(
      (process) =>
        process.pid === entry.pid &&
        (process.startTime === null || process.startTime === entry.startTime),
    );
  for (const entry of belowServer) {
    const process = providerProcessAt(entry);
    if (process === undefined) continue;
    if (process.threadId === null) break;
    const run = input.liveRuns.find((candidate) => candidate.threadId === process.threadId);
    return { type: "mine", run: run ?? null, explanation: null };
  }

  // The server's integrated terminal and its other children are not agents.
  const child = belowServer.at(-1);
  return child !== undefined && providerProcessAt(child) !== undefined
    ? { type: "mine", run: null, explanation: null }
    : NOT_MINE;
}
