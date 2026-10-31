// @effect-diagnostics nodeBuiltinImport:off -- Lays out a throwaway git checkout.
import * as NodeChildProcess from "node:child_process";
import * as NodeFSP from "node:fs/promises";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";

import * as NodeServices from "@effect/platform-node/NodeServices";
import { describe, expect, it } from "@effect/vitest";
import * as Effect from "effect/Effect";

import * as ProcessRunner from "../processRunner.ts";
import { countLines, parseNumstat, uncommittedChanges } from "./changes.ts";

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

describe("countLines", () => {
  it("counts a last line without a newline and nothing for binary", () => {
    const bytes = (text: string) => new TextEncoder().encode(text);
    expect(countLines(bytes("a\nb\n"))).toBe(2);
    expect(countLines(bytes("a\nb"))).toBe(2);
    expect(countLines(bytes(""))).toBe(0);
    expect(countLines(bytes("a\0b\n"))).toBe(0);
  });
});

describe("uncommittedChanges", () => {
  const read = (cwd: string) =>
    uncommittedChanges(cwd).pipe(
      Effect.provide(ProcessRunner.layer),
      Effect.provide(NodeServices.layer),
    );

  it.live(
    "reads the whole repository from a subfolder, counting untracked files as additions",
    () =>
      Effect.gen(function* () {
        const root = yield* Effect.promise(() =>
          NodeFSP.mkdtemp(NodePath.join(NodeOS.tmpdir(), "t3-elevation-changes-")),
        );
        yield* Effect.addFinalizer(() =>
          Effect.promise(() => NodeFSP.rm(root, { recursive: true, force: true })),
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
        yield* Effect.promise(async () => {
          git("init", "-q");
          await NodeFSP.mkdir(NodePath.join(root, "sub"));
          await NodeFSP.writeFile(NodePath.join(root, "tracked.txt"), "one\ntwo\nthree\n");
          await NodeFSP.writeFile(NodePath.join(root, ".gitignore"), "ignored.txt\n");
          git("add", ".");
          git("commit", "-q", "-m", "init");
        });

        expect(yield* read(NodePath.join(root, "sub"))).toBeNull();

        yield* Effect.promise(async () => {
          await NodeFSP.writeFile(NodePath.join(root, "tracked.txt"), "one\n2\nthree\nfour\n");
          await NodeFSP.writeFile(NodePath.join(root, "new.txt"), "a\nb");
          await NodeFSP.writeFile(NodePath.join(root, "ignored.txt"), "x\n");
        });
        expect(yield* read(NodePath.join(root, "sub"))).toEqual({
          files: 2,
          additions: 4,
          deletions: 1,
        });
        expect(yield* read(NodeOS.tmpdir())).toBeNull();
      }).pipe(Effect.scoped),
  );
});
