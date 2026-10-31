// @effect-diagnostics nodeBuiltinImport:off -- Lays out a throwaway git checkout.
import * as NodeChildProcess from "node:child_process";
import * as NodeFSP from "node:fs/promises";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";

import * as NodeServices from "@effect/platform-node/NodeServices";
import { describe, expect, it } from "@effect/vitest";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";

import * as ProcessRunner from "../processRunner.ts";
import { parseNumstat, uncommittedChanges } from "./changes.ts";

describe("parseNumstat", () => {
  it("sums text files and counts binary files without lines", () => {
    expect(parseNumstat("3\t1\tsrc/a.ts\0" + "0\t7\told name.md\0" + "-\t-\tlogo.png\0")).toEqual({
      files: 3,
      additions: 3,
      deletions: 8,
    });
    expect(parseNumstat("")).toEqual({ files: 0, additions: 0, deletions: 0 });
  });

  it("keeps paths with tabs and newlines in one record", () => {
    expect(parseNumstat("2\t0\ta\tb\nc\0")).toEqual({ files: 1, additions: 2, deletions: 0 });
  });
});

describe("uncommittedChanges", () => {
  const read = (cwd: string, roots: ReadonlyArray<string>) =>
    uncommittedChanges(cwd, roots).pipe(
      Effect.provide(ProcessRunner.layer.pipe(Layer.provide(NodeServices.layer))),
    );

  const makeRepo = Effect.gen(function* () {
    const root = yield* Effect.acquireRelease(
      Effect.promise(() =>
        NodeFSP.mkdtemp(NodePath.join(NodeOS.tmpdir(), "t3-elevation-changes-")),
      ),
      (dir) => Effect.promise(() => NodeFSP.rm(dir, { recursive: true, force: true })),
    );
    const git = (...args: ReadonlyArray<string>) =>
      NodeChildProcess.execFileSync("git", ["-C", root, ...args], {
        env: {
          ...process.env,
          GIT_AUTHOR_NAME: "t",
          GIT_AUTHOR_EMAIL: "t@example.com",
          GIT_COMMITTER_NAME: "t",
          GIT_COMMITTER_EMAIL: "t@example.com",
        },
      });
    const write = (path: string, content: string) =>
      NodeFSP.writeFile(NodePath.join(root, path), content);
    return { root, git, write };
  });

  it.live(
    "reads the whole repository from a subfolder, counting untracked files as additions",
    () =>
      Effect.gen(function* () {
        const { root, git, write } = yield* makeRepo;
        yield* Effect.promise(async () => {
          git("init", "-q");
          await NodeFSP.mkdir(NodePath.join(root, "sub"));
          await write("tracked.txt", "one\ntwo\nthree\n");
          await write("gone.txt", "x\ny\n");
          await write(".gitignore", "ignored.txt\n");
          git("add", ".");
          git("commit", "-q", "-m", "init");
        });

        expect(yield* read(NodePath.join(root, "sub"), [root])).toBeNull();

        yield* Effect.promise(async () => {
          await write("tracked.txt", "one\n2\nthree\nfour\n");
          await write("new.txt", "a\nb");
          await write("ignored.txt", "x\n");
          await NodeFSP.rm(NodePath.join(root, "gone.txt"));
        });
        expect(yield* read(NodePath.join(root, "sub"), [root])).toEqual({
          files: 3,
          additions: 4,
          deletions: 3,
        });
        expect(yield* read(NodeOS.tmpdir(), [NodeOS.tmpdir()])).toBeNull();
        // Outside the thread's checkouts nothing runs at all.
        expect(yield* read(root, [NodePath.join(root, "sub")])).toBeNull();
      }).pipe(Effect.scoped),
  );

  it.live("never runs a clean filter the checkout configures", () =>
    Effect.gen(function* () {
      const { root, git, write } = yield* makeRepo;
      const marker = NodePath.join(root, "..", `${NodePath.basename(root)}-filter-ran`);
      yield* Effect.addFinalizer(() => Effect.promise(() => NodeFSP.rm(marker, { force: true })));
      yield* Effect.promise(async () => {
        git("init", "-q");
        await write("tracked.txt", "one\n");
        // Written in the index's second, so git would recheck its content.
        await write("racy.txt", "same\n");
        git("add", ".");
        git("commit", "-q", "-m", "init");
        // Configured after the commit so setting up never runs it.
        await write(".gitattributes", "* filter=evil\n");
        await NodeFSP.writeFile(
          NodePath.join(root, ".git", "info", "attributes"),
          "* filter=evil\n",
        );
        git("config", "filter.evil.clean", `touch '${marker}'; cat`);
        git("config", "filter.evil.process", `touch '${marker}'`);
        await write("tracked.txt", "one\ntwo\n");
        await write("untracked.txt", "a\n");
      });

      expect(yield* read(root, [root])).toEqual({ files: 3, additions: 3, deletions: 0 });
      expect(
        yield* Effect.promise(() =>
          NodeFSP.stat(marker).then(
            () => true,
            () => false,
          ),
        ),
      ).toBe(false);
    }).pipe(Effect.scoped),
  );
});
