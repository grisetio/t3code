import { scopeProjectRef } from "@t3tools/client-runtime/environment";
import {
  deviceApprovalAgentPrompt,
  deviceApprovalCheckPaths,
  pickDeviceApprovalFixProject,
} from "@t3tools/client-runtime/elevation-fix";
import type { ElevationCheck, ElevationStatus, EnvironmentId } from "@t3tools/contracts";

import { useComposerDraftStore } from "../../composerDraftStore";
import { useNewThreadHandler } from "../../hooks/useHandleNewThread";
import { useScratchProject } from "../../hooks/useScratchProject";
import { readProjects } from "../../state/entities";

/**
 * Opens a new thread with the diagnosis as an unsent draft, in the project
 * that holds a failing part (a Nix repo, say), else in the machine's
 * project-less threads. The user reads it and presses send.
 */
export function useDeviceApprovalAgentHandoff() {
  const handleNewThread = useNewThreadHandler();
  const { openScratchProject } = useScratchProject();

  return async (input: {
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
    const prompt = deviceApprovalAgentPrompt({
      machine: input.machine,
      status: input.status,
      failing: input.failing,
      repair: null,
      projectOwnsConfig: owner !== null,
    });
    const store = useComposerDraftStore.getState();
    const existing = store.getComposerDraft(opened.draftId)?.prompt.trim() ?? "";
    // A draft reused for the project may already hold the user's words.
    store.setPrompt(opened.draftId, existing === "" ? prompt : `${existing}\n\n${prompt}`);
  };
}
