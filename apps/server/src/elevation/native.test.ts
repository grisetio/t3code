// @effect-diagnostics nodeBuiltinImport:off -- Lays out a fake /proc for the check used without node:ffi.
import * as NodeFS from "node:fs";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";

import { describe, expect, it } from "@effect/vitest";

import { linuxSudoChildExists } from "./native.ts";

const sudoArgv = ["sudo", "-n", "true"];

/** A parent pid 100 whose threads forked the given children. */
function fakeProc(
  children: Record<string, ReadonlyArray<{ pid: number; argv: ReadonlyArray<string> }>>,
) {
  const dir = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "t3-proc-"));
  for (const [tid, forked] of Object.entries(children)) {
    NodeFS.mkdirSync(NodePath.join(dir, "100", "task", tid), { recursive: true });
    NodeFS.writeFileSync(
      NodePath.join(dir, "100", "task", tid, "children"),
      forked.map((child) => `${child.pid} `).join(""),
    );
    for (const child of forked) {
      NodeFS.mkdirSync(NodePath.join(dir, String(child.pid)), { recursive: true });
      NodeFS.writeFileSync(
        NodePath.join(dir, String(child.pid), "cmdline"),
        `${child.argv.join("\0")}\0`,
      );
    }
  }
  return {
    dir,
    [Symbol.dispose]: () => NodeFS.rmSync(dir, { recursive: true, force: true }),
  };
}

describe("linuxSudoChildExists", () => {
  // The fake tree belongs to the test's uid, which stands in for root.
  const rootUid = NodeOS.userInfo().uid;

  it("accepts a parent with a root-owned child running sudo's argv, on any thread", () => {
    using proc = fakeProc({
      "100": [{ pid: 201, argv: ["node"] }],
      "101": [{ pid: 202, argv: sudoArgv }],
    });
    expect(linuxSudoChildExists({ dir: proc.dir, rootUid }, 100, sudoArgv)).toBe(true);
  });

  it("rejects a parent whose children don't run that argv, or aren't root's", () => {
    using proc = fakeProc({ "100": [{ pid: 201, argv: ["sudo", "-n", "false"] }] });
    expect(linuxSudoChildExists({ dir: proc.dir, rootUid }, 100, sudoArgv)).toBe(false);
    using owned = fakeProc({ "100": [{ pid: 202, argv: sudoArgv }] });
    expect(linuxSudoChildExists({ dir: owned.dir, rootUid: rootUid + 1 }, 100, sudoArgv)).toBe(
      false,
    );
  });

  it("passes when the kernel doesn't list children", () => {
    using proc = fakeProc({});
    expect(linuxSudoChildExists({ dir: proc.dir, rootUid }, 100, sudoArgv)).toBe(true);
  });
});
