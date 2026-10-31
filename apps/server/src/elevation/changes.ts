// @effect-diagnostics nodeBuiltinImport:off -- Counts lines in untracked files, which Effect's FileSystem would read whole.
/**
 * The "Uncommitted changes" pointer on a sudo request: what the checkout at
 * the request's cwd holds that isn't committed. Clients open the diff itself
 * through `review.getDiffPreview` with the same cwd.
 */
import * as NodeFSP from "node:fs/promises";
import * as NodePath from "node:path";

import type { OrchestrationV2ElevationChanges } from "@t3tools/contracts";
import * as Effect from "effect/Effect";

import * as ProcessRunner from "../processRunner.ts";

const GIT_TIMEOUT = "2 seconds";
// A generated tree left untracked shouldn't turn the pointer into a disk scan.
const MAX_UNTRACKED_FILES_READ = 200;
const MAX_UNTRACKED_FILE_BYTES = 1024 * 1024;

/** `git diff-index --numstat -z`: `added\tdeleted\tpath\0`, with `-` for binary files. */
export function parseNumstat(stdout: string): OrchestrationV2ElevationChanges {
  let files = 0;
  let additions = 0;
  let deletions = 0;
  for (const record of stdout.split("\0")) {
    const match = /^(\d+|-)\t(\d+|-)\t./.exec(record);
    if (match === null) continue;
    files++;
    if (match[1] !== "-") additions += Number(match[1]);
    if (match[2] !== "-") deletions += Number(match[2]);
  }
  return { files, additions, deletions };
}

/** Lines the way git counts an added file: a last line without a newline still counts. */
export function countLines(bytes: Uint8Array): number {
  if (bytes.includes(0)) return 0;
  let lines = 0;
  for (const byte of bytes) if (byte === 0x0a) lines++;
  return bytes.length > 0 && bytes[bytes.length - 1] !== 0x0a ? lines + 1 : lines;
}

const readLines = (path: string) =>
  Effect.promise(async () => {
    const stat = await NodeFSP.lstat(path).catch(() => null);
    if (stat === null || !stat.isFile() || stat.size > MAX_UNTRACKED_FILE_BYTES) return 0;
    const bytes = await NodeFSP.readFile(path).catch(() => null);
    return bytes === null ? 0 : countLines(bytes);
  });

/**
 * Null when the cwd isn't in a git repository, the checkout is clean, or git
 * fails. Untracked files count as additions.
 */
export const uncommittedChanges = Effect.fn("ElevationChanges.read")(
  function* (cwd: string) {
    const runner = yield* ProcessRunner.ProcessRunner;
    const git = (args: ReadonlyArray<string>) =>
      runner.run({
        command: "git",
        args: ["-C", cwd, ...args],
        // Plumbing plus no optional locks: reading must never rewrite the index.
        env: { GIT_OPTIONAL_LOCKS: "0" },
        timeout: GIT_TIMEOUT,
        maxOutputBytes: 4 * 1024 * 1024,
      });
    const [tracked, untracked] = yield* Effect.all(
      [
        git(["diff-index", "--numstat", "-z", "HEAD", "--"]),
        // `:/` lists the whole repository, relative to the cwd.
        git(["ls-files", "--others", "--exclude-standard", "-z", "--", ":/"]),
      ],
      { concurrency: 2 },
    );
    if (tracked.code !== 0 || untracked.code !== 0) return null;
    const changes = parseNumstat(tracked.stdout);
    const paths = untracked.stdout.split("\0").filter((path) => path.length > 0);
    const lines = yield* Effect.forEach(
      paths.slice(0, MAX_UNTRACKED_FILES_READ),
      (path) => readLines(NodePath.resolve(cwd, path)),
      { concurrency: 8 },
    );
    const total = {
      files: changes.files + paths.length,
      additions: changes.additions + lines.reduce((sum, count) => sum + count, 0),
      deletions: changes.deletions,
    };
    return total.files === 0 ? null : total;
  },
  Effect.orElseSucceed((): OrchestrationV2ElevationChanges | null => null),
);
