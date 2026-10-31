import * as Context from "effect/Context";

/**
 * Provider processes the server started, so a `sudo` the device-approval
 * module reports can be traced back to the thread that ran it. Attribution
 * only picks where a prompt is shown; it never grants anything.
 */
export interface ProviderProcess {
  readonly pid: number;
  /** In the PAM module's units (docs/internals/device-approval.md); null when unreadable. */
  readonly startTime: number | null;
  /** Null for a process shared by several threads (Codex app-server, OpenCode 2.x). */
  readonly threadId: string | null;
}

export interface ProviderProcessesShape {
  /** Records a spawned process. Call the returned function once it exits. */
  readonly register: (input: {
    readonly pid: number;
    readonly threadId: string | null;
  }) => () => void;
  readonly list: () => ReadonlyArray<ProviderProcess>;
}

export const ProviderProcesses = Context.Reference<ProviderProcessesShape>(
  "@t3tools/shared/ProviderProcesses",
  { defaultValue: () => ({ register: () => () => {}, list: () => [] }) },
);
