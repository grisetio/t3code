import { scopeProjectRef } from "@t3tools/client-runtime/environment";
import {
  DEVICE_APPROVAL_DIAGNOSIS_FILE_NAME,
  deviceApprovalCheckPaths,
  deviceApprovalHandoff,
  pickDeviceApprovalFixProject,
} from "@t3tools/client-runtime/elevation-fix";
import { clampFileAttachmentUploadBytes } from "@t3tools/client-runtime/state/attachments";
import type { ElevationCheck, ElevationStatus, EnvironmentId } from "@t3tools/contracts";

import { useComposerDraftStore } from "../../composerDraftStore";
import { useNewThreadHandler } from "../../hooks/useHandleNewThread";
import { useScratchProject } from "../../hooks/useScratchProject";
import { randomUUID } from "../../lib/utils";
import { appAtomRegistry } from "../../rpc/atomRegistry";
import { readProjects } from "../../state/entities";
import { serverEnvironment } from "../../state/server";

/**
 * Opens a new thread with a short unsent message and the diagnosis attached, in the project that
 * holds a failing part (a Nix repo, say), else in the machine's project-less threads. The user
 * reads it and presses send. A server without file attachments gets the diagnosis inline.
 */
export function useDeviceApprovalAgentHandoff() {
  const handleNewThread = useNewThreadHandler();
  const { openScratchProject } = useScratchProject();

  return async (input: {
    readonly purpose: "fix" | "turn_off";
    readonly environmentId: EnvironmentId;
    readonly machine: string;
    readonly status: ElevationStatus;
    readonly failing: readonly ElevationCheck[];
  }) => {
    const owner = pickDeviceApprovalFixProject(
      readProjects(),
      input.environmentId,
      deviceApprovalCheckPaths(input.failing),
    );
    const project =
      owner ?? (await openScratchProject(input.environmentId, "Couldn't open a thread"));
    if (project === null) return;
    const opened = await handleNewThread(scopeProjectRef(project.environmentId, project.id));
    if (opened === null) return;
    const { draft, diagnosis } = deviceApprovalHandoff({
      purpose: input.purpose,
      machine: input.machine,
      status: input.status,
      failing: input.failing,
      repair: null,
      projectOwnsConfig: owner !== null,
    });
    const capabilities = appAtomRegistry.get(
      serverEnvironment.configValueAtom(project.environmentId),
    )?.environment.capabilities;
    const maxBytes = capabilities?.attachmentUploads
      ? capabilities.fileAttachments?.maxUploadBytes
      : undefined;
    const file = new File([diagnosis], DEVICE_APPROVAL_DIAGNOSIS_FILE_NAME, {
      type: "text/plain;charset=utf-8",
    });
    const attach = maxBytes !== undefined && file.size <= clampFileAttachmentUploadBytes(maxBytes);
    const message = attach ? draft : `${draft}\n\n${diagnosis}`;
    const store = useComposerDraftStore.getState();
    const existing = store.getComposerDraft(opened.draftId)?.prompt.trim() ?? "";
    // A draft reused for the project may already hold the user's words.
    store.setPrompt(opened.draftId, existing === "" ? message : `${existing}\n\n${message}`);
    if (attach) {
      store.addFiles(
        opened.draftId,
        [
          {
            type: "file",
            id: randomUUID(),
            name: file.name,
            mimeType: "text/plain;charset=utf-8",
            sizeBytes: file.size,
            file,
          },
        ],
        { appendReference: true },
      );
    }
  };
}
