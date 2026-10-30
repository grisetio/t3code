// @effect-diagnostics nodeBuiltinImport:off -- Reads kernel process facts that Effect does not wrap.
/**
 * Node has no API for a Unix socket's peer credentials or another process's
 * start time. `node:ffi` (Node 26, experimental) reaches the libc calls
 * without a native addon. Electron's embedded Node (24 in Electron 44) has
 * none, so the desktop server runs without both: the module verifies every
 * signature itself, which leaves the peer check stopping only fake prompts and
 * start times serving only attribution, a UX concern.
 */
import * as NodeFS from "node:fs";
import type * as NodeNet from "node:net";

interface FfiLibrary {
  readonly functions: Record<string, (...args: ReadonlyArray<unknown>) => unknown>;
}
interface FfiModule {
  readonly dlopen: (
    path: string | null,
    definitions: Record<
      string,
      { readonly arguments: ReadonlyArray<string>; readonly return: string }
    >,
  ) => FfiLibrary;
}

// SO_PEERCRED differs on mips, powerpc and sparc; those stay unsupported.
const LINUX_SO_PEERCRED_ARCHES = new Set(["x64", "arm64", "arm", "ia32", "riscv64"]);
const SOL_SOCKET = 1;
const SO_PEERCRED = 17;
const CTL_KERN = 1;
const KERN_PROC = 14;
const KERN_PROC_PID = 1;
const KINFO_PROC_BYTES = 648;

/** Callers pass `HostProcess.Platform` and `HostProcess.Architecture`. */
export interface NativeHost {
  readonly platform: NodeJS.Platform;
  readonly arch: NodeJS.Architecture;
}

interface NativeCalls {
  readonly peerUid: (fd: number) => number | null;
  readonly startTime: (pid: number) => number | null;
}

let native: NativeCalls | null | undefined;

function openLibc(ffi: FfiModule, definitions: Parameters<FfiModule["dlopen"]>[1]) {
  try {
    return ffi.dlopen(null, definitions);
  } catch {
    return ffi.dlopen("libc.so.6", definitions);
  }
}

function load(host: NativeHost): NativeCalls | null {
  if (host.platform !== "darwin" && host.platform !== "linux") return null;
  if (host.platform === "linux" && !LINUX_SO_PEERCRED_ARCHES.has(host.arch)) return null;
  try {
    const ffi = process.getBuiltinModule("node:ffi") as FfiModule | undefined;
    if (ffi === undefined) return null;
    if (host.platform === "darwin") {
      const libc = openLibc(ffi, {
        getpeereid: { arguments: ["int32", "buffer", "buffer"], return: "int32" },
        sysctl: {
          arguments: ["buffer", "uint32", "buffer", "buffer", "pointer", "uint64"],
          return: "int32",
        },
      });
      const { getpeereid, sysctl } = libc.functions;
      if (getpeereid === undefined || sysctl === undefined) return null;
      return {
        peerUid: (fd) => {
          const uid = Buffer.alloc(4);
          const gid = Buffer.alloc(4);
          return getpeereid(fd, uid, gid) === 0 ? uid.readUInt32LE(0) : null;
        },
        // kinfo_proc begins with extern_proc, whose first member is p_starttime.
        startTime: (pid) => {
          const mib = Buffer.alloc(16);
          [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid].forEach((value, index) =>
            mib.writeInt32LE(value, index * 4),
          );
          const info = Buffer.alloc(KINFO_PROC_BYTES);
          const length = Buffer.alloc(8);
          length.writeBigUInt64LE(BigInt(info.length));
          if (sysctl(mib, 4, info, length, 0n, 0n) !== 0) return null;
          if (length.readBigUInt64LE(0) !== BigInt(KINFO_PROC_BYTES)) return null;
          return Number(info.readBigInt64LE(0));
        },
      };
    }
    const libc = openLibc(ffi, {
      getsockopt: {
        arguments: ["int32", "int32", "int32", "buffer", "buffer"],
        return: "int32",
      },
    });
    const { getsockopt } = libc.functions;
    if (getsockopt === undefined) return null;
    return {
      peerUid: (fd) => {
        // struct ucred { pid_t pid; uid_t uid; gid_t gid; }
        const credentials = Buffer.alloc(12);
        const length = Buffer.alloc(4);
        length.writeUInt32LE(credentials.length);
        return getsockopt(fd, SOL_SOCKET, SO_PEERCRED, credentials, length) === 0
          ? credentials.readUInt32LE(4)
          : null;
      },
      startTime: linuxStartTime,
    };
  } catch {
    return null;
  }
}

/** Field 22 of /proc/<pid>/stat, clock ticks since boot; the PAM module sends the same value. */
function linuxStartTime(pid: number): number | null {
  try {
    const stat = NodeFS.readFileSync(`/proc/${pid}/stat`, "utf8");
    // The command name in field 2 may contain spaces and parentheses.
    const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
    const value = Number(fields[19]);
    return Number.isSafeInteger(value) ? value : null;
  } catch {
    return null;
  }
}

function calls(host: NativeHost): NativeCalls | null {
  if (native === undefined) native = load(host);
  return native;
}

/**
 * Without peer credentials, a Linux hello must still name a parent that has a
 * root-owned child running exactly sudo's argv. False only when every child
 * could be read and none matched; anything unreadable passes.
 */
export function linuxSudoChildExists(
  proc: { readonly dir: string; readonly rootUid: number },
  parentPid: number,
  argv: ReadonlyArray<string>,
): boolean {
  if (!Number.isSafeInteger(parentPid) || parentPid <= 0) return false;
  let children: Array<string>;
  try {
    // Each thread lists the children it forked; multi-threaded parents fork from any.
    const taskDir = `${proc.dir}/${parentPid}/task`;
    children = NodeFS.readdirSync(taskDir).flatMap((tid) =>
      NodeFS.readFileSync(`${taskDir}/${tid}/children`, "utf8").split(" ").filter(Boolean),
    );
  } catch {
    return true;
  }
  const expected = `${argv.join("\0")}\0`;
  return children.some((pid) => {
    try {
      if (NodeFS.statSync(`${proc.dir}/${pid}`).uid !== proc.rootUid) return false;
      return NodeFS.readFileSync(`${proc.dir}/${pid}/cmdline`, "utf8") === expected;
    } catch {
      return true;
    }
  });
}

/** Whether this runtime can verify who connected to the approval socket. */
export const peerCredentialsSupported = (host: NativeHost): boolean => calls(host) !== null;

/** The connected peer's effective uid, or null when it can't be read. */
export function socketPeerUid(host: NativeHost, socket: NodeNet.Socket): number | null {
  // `_handle.fd` is internal but stable for Unix sockets; there is no public accessor.
  const fd = (socket as unknown as { readonly _handle?: { readonly fd?: unknown } })._handle?.fd;
  if (typeof fd !== "number" || fd < 0) return null;
  try {
    return calls(host)?.peerUid(fd) ?? null;
  } catch {
    return null;
  }
}

/**
 * The start time the PAM module reports for this pid, or null. With
 * `onlyIfLoaded`, macOS answers only once device approval has loaded FFI, so
 * spawning a provider never loads it (Node warns when it does).
 */
export function processStartTime(
  host: NativeHost,
  pid: number,
  options?: { readonly onlyIfLoaded?: boolean },
) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return null;
  if (host.platform === "linux") return linuxStartTime(pid);
  if (options?.onlyIfLoaded && native === undefined) return null;
  try {
    return calls(host)?.startTime(pid) ?? null;
  } catch {
    return null;
  }
}
