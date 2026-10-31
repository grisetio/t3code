// @effect-diagnostics nodeBuiltinImport:off -- Stats worktree files and lays out a scratch index and object directory.
/**
 * The "Uncommitted changes" pointer on a sudo request: what the checkout at
 * the request's cwd holds that isn't committed. Clients open the diff itself
 * through `review.getDiffPreview` with the same cwd.
 *
 * The cwd comes from whatever ran sudo and this server runs unsandboxed, so
 * git here must never start a program the checkout configures. Comparing
 * worktree content runs the `filter.<x>.clean` driver `.gitattributes` names
 * (`diff-index HEAD`, `diff-files --numstat`, `status`, even the stat check of
 * a racily clean entry), filter names can't be disabled by wildcard, and
 * `$GIT_DIR/info/attributes` outranks any attributes file we could pass. So
 * git only ever compares objects: a copy of the index, stamped with mtime 0 so
 * no entry counts as racy, lists stat-changed paths without reading them; the
 * worktree content of those paths is hashed with `--no-filters` into a scratch
 * object directory and staged into the copy; `diff-index --cached` then reads
 * HEAD and that copy from the object database alone. A filter that rewrites
 * line endings makes those files differ wholesale, which is fine for a count.
 */
import * as NodeFSP from "node:fs/promises";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";

import type { OrchestrationV2ElevationChanges } from "@t3tools/contracts";
import * as HostProcess from "@t3tools/shared/HostProcess";
import * as Effect from "effect/Effect";

import * as ProcessRunner from "../processRunner.ts";
import { explicitBareRepositoryEnv } from "../vcs/VcsProcess.ts";

const GIT_TIMEOUT = "2 seconds";
// A generated tree left untracked shouldn't turn the pointer into a disk scan.
const MAX_FILES_HASHED = 200;
const MAX_FILE_BYTES = 1024 * 1024;

const HARDENED_CONFIG = [
  // fsmonitor and the untracked cache's hook run commands from config.
  "core.fsmonitor=false",
  "core.untrackedCache=false",
  // Writing the scratch index must not touch the shared index files beside the real one.
  "core.splitIndex=false",
  "splitIndex.sharedIndexExpire=never",
].flatMap((entry) => ["-c", entry]);

interface NumstatRecord {
  readonly path: string;
  readonly additions: number;
  readonly deletions: number;
}

/** `git diff-index --numstat -z`: `added\tdeleted\tpath\0`, with `-` for binary files. */
function numstatRecords(stdout: string): ReadonlyArray<NumstatRecord> {
  return stdout.split("\0").flatMap((record) => {
    const match = /^(\d+|-)\t(\d+|-)\t(.+)$/s.exec(record);
    if (match === null) return [];
    const count = (value: string | undefined) => (value === "-" ? 0 : Number(value));
    return [{ path: match[3]!, additions: count(match[1]), deletions: count(match[2]) }];
  });
}

export function parseNumstat(stdout: string): OrchestrationV2ElevationChanges {
  const records = numstatRecords(stdout);
  return {
    files: records.length,
    additions: records.reduce((sum, record) => sum + record.additions, 0),
    deletions: records.reduce((sum, record) => sum + record.deletions, 0),
  };
}

const nulSeparated = (stdout: string) => stdout.split("\0").filter((path) => path.length > 0);

/** Whether `child` is `parent` or below it; both already resolved. */
function isWithin(parent: string, child: string): boolean {
  const relative = NodePath.relative(parent, child);
  return relative === "" || (!relative.startsWith("..") && !NodePath.isAbsolute(relative));
}

const realPath = (path: string) => Effect.promise(() => NodeFSP.realpath(path).catch(() => null));

/**
 * Null when the cwd is outside every root (the checkouts this server already
 * runs git in for the request's thread), isn't in a git repository, the
 * checkout is clean, or git fails. Untracked files count as additions.
 */
export const uncommittedChanges = Effect.fn("ElevationChanges.read")(
  function* (cwd: string, roots: ReadonlyArray<string>) {
    const resolvedCwd = yield* realPath(cwd);
    if (resolvedCwd === null) return null;
    const resolvedRoots = yield* Effect.forEach(roots, realPath);
    if (!resolvedRoots.some((root) => root !== null && isWithin(root, resolvedCwd))) return null;

    const runner = yield* ProcessRunner.ProcessRunner;
    const scratch = yield* Effect.acquireRelease(
      Effect.promise(() => NodeFSP.mkdtemp(NodePath.join(NodeOS.tmpdir(), "t3-elevation-git-"))),
      (dir) => Effect.promise(() => NodeFSP.rm(dir, { recursive: true, force: true })),
    );
    const baseEnv = {
      ...explicitBareRepositoryEnv(process.env, yield* HostProcess.Platform),
      GIT_OPTIONAL_LOCKS: "0",
      // A partial clone would otherwise fetch missing blobs with the repo's transport config.
      GIT_NO_LAZY_FETCH: "1",
    };
    const git = (
      dir: string,
      args: ReadonlyArray<string>,
      options: { readonly env?: NodeJS.ProcessEnv; readonly stdin?: string } = {},
    ) =>
      runner.run({
        command: "git",
        args: ["-C", dir, ...HARDENED_CONFIG, ...args],
        env: { ...baseEnv, ...options.env },
        ...(options.stdin === undefined ? {} : { stdin: options.stdin }),
        timeout: GIT_TIMEOUT,
        maxOutputBytes: 4 * 1024 * 1024,
      });

    const located = yield* git(resolvedCwd, [
      "rev-parse",
      "--path-format=absolute",
      "--show-toplevel",
      "--git-path",
      "index",
      "--git-path",
      "objects",
      "--show-object-format",
    ]);
    if (located.code !== 0) return null;
    const [top, index, objects, format] = located.stdout.split("\n");
    if (top === undefined || index === undefined || objects === undefined) return null;
    const nullOid = "0".repeat(format === "sha256" ? 64 : 40);

    const scratchIndex = NodePath.join(scratch, "index");
    const scratchObjects = NodePath.join(scratch, "objects");
    yield* Effect.promise(async () => {
      await NodeFSP.mkdir(scratchObjects);
      const copied = await NodeFSP.copyFile(index, scratchIndex).then(
        () => true,
        () => false,
      );
      // Git rechecks content (through filters) for entries no older than the index file.
      if (copied) await NodeFSP.utimes(scratchIndex, 0, 0);
    });
    const env = {
      GIT_INDEX_FILE: scratchIndex,
      GIT_OBJECT_DIRECTORY: scratchObjects,
      GIT_ALTERNATE_OBJECT_DIRECTORIES: objects,
    };

    const [modified, untracked] = yield* Effect.all(
      [
        // Submodules are skipped: checking one runs `git status` inside it.
        git(top, ["diff-files", "--name-only", "-z", "--ignore-submodules=all"], { env }),
        git(top, ["ls-files", "--others", "--exclude-standard", "-z"], { env }),
      ],
      { concurrency: 2 },
    );
    if (modified.code !== 0 || untracked.code !== 0) return null;
    const changedPaths = [
      ...new Set([...nulSeparated(modified.stdout), ...nulSeparated(untracked.stdout)]),
    ];

    const stats = yield* Effect.forEach(
      changedPaths,
      (path) => Effect.promise(() => NodeFSP.lstat(NodePath.join(top, path)).catch(() => null)),
      { concurrency: 8 },
    );
    const removed: Array<string> = [];
    const hashed: Array<{ readonly path: string; readonly mode: string }> = [];
    // Counted as files without lines: too many, too large, or not a plain file.
    const opaque: Array<string> = [];
    for (const [position, path] of changedPaths.entries()) {
      const stat = stats[position];
      if (stat === null || stat === undefined) removed.push(path);
      else if (
        stat.isFile() &&
        stat.size <= MAX_FILE_BYTES &&
        hashed.length < MAX_FILES_HASHED &&
        // `--stdin-paths` and `--index-info` are newline-separated.
        !path.includes("\n")
      )
        hashed.push({ path, mode: stat.mode & 0o100 ? "100755" : "100644" });
      else opaque.push(path);
    }

    const hashes =
      hashed.length === 0
        ? null
        : yield* git(top, ["hash-object", "-w", "--no-filters", "--stdin-paths"], {
            env,
            stdin: hashed.map((entry) => `${entry.path}\n`).join(""),
          });
    if (hashes !== null && hashes.code !== 0) return null;
    const oids = hashes?.stdout.split("\n") ?? [];
    const indexInfo = [
      ...hashed.map((entry, position) => `${entry.mode} ${oids[position]}\t${entry.path}\n`),
      // Mode 0 drops the entry.
      ...removed.filter((path) => !path.includes("\n")).map((path) => `0 ${nullOid}\t${path}\n`),
    ].join("");
    if (indexInfo.length > 0) {
      const staged = yield* git(top, ["update-index", "--index-info"], { env, stdin: indexInfo });
      if (staged.code !== 0) return null;
    }

    const diff = yield* git(
      top,
      ["diff-index", "--cached", "--numstat", "-z", "--no-ext-diff", "--no-textconv", "HEAD", "--"],
      { env },
    );
    if (diff.code !== 0) return null;
    const records = numstatRecords(diff.stdout);
    const counted = new Set(records.map((record) => record.path));
    const total = {
      files: records.length + opaque.filter((path) => !counted.has(path)).length,
      additions: records.reduce((sum, record) => sum + record.additions, 0),
      deletions: records.reduce((sum, record) => sum + record.deletions, 0),
    };
    return total.files === 0 ? null : total;
  },
  Effect.scoped,
  Effect.orElseSucceed((): OrchestrationV2ElevationChanges | null => null),
);
