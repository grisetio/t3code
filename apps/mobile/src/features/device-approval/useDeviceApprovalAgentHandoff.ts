import { StackActions, useNavigation } from "@react-navigation/native";
import {
  deviceApprovalAgentPrompt,
  deviceApprovalCheckPaths,
  pickDeviceApprovalFixProject,
  type DeviceApprovalRepairAttempt,
} from "@t3tools/client-runtime/elevation-fix";
import {
  isAtomCommandInterrupted,
  squashAtomCommandFailure,
} from "@t3tools/client-runtime/state/runtime";
import type { ElevationCheck, ElevationStatus, EnvironmentId } from "@t3tools/contracts";

import * as Dialog from "../../components/ui/Dialog";
import { useProjects } from "../../state/entities";
import { projectEnvironment } from "../../state/projects";
import { useAtomCommand } from "../../state/use-atom-command";
import {
  createNewTaskDraft,
  setComposerDraftText,
  waitForComposerDraftsLoaded,
} from "../../state/use-composer-drafts";

/**
 * Opens a new thread with the diagnosis as an unsent draft, in the project
 * that holds a failing part (a Nix repo, say), else in the machine's
 * project-less threads. The user reads it and presses send.
 */
export function useDeviceApprovalAgentHandoff() {
  const navigation = useNavigation();
  const projects = useProjects();
  const openScratch = useAtomCommand(projectEnvironment.openScratch, { reportFailure: false });

  return async (input: {
    readonly environmentId: EnvironmentId;
    readonly machine: string;
    readonly status: ElevationStatus;
    readonly failing: readonly ElevationCheck[];
    readonly repair: DeviceApprovalRepairAttempt | null;
  }) => {
    const owner = pickDeviceApprovalFixProject(
      projects,
      input.environmentId,
      deviceApprovalCheckPaths(input.failing),
    );
    let project = owner;
    if (project === null) {
      const scratch = await openScratch({ environmentId: input.environmentId, input: {} });
      if (scratch._tag === "Failure") {
        if (!isAtomCommandInterrupted(scratch)) {
          const error = squashAtomCommandFailure(scratch);
          Dialog.alert(
            "Couldn't open a thread",
            error instanceof Error
              ? error.message
              : "Start a thread on this machine and ask an agent to fix device approval.",
          );
        }
        return;
      }
      project = scratch.value;
    }
    try {
      await waitForComposerDraftsLoaded();
    } catch {
      Dialog.alert("Couldn't open a thread", "Drafts could not be loaded.");
      return;
    }
    const draftKey = createNewTaskDraft({
      environmentId: project.environmentId,
      projectId: project.id,
    });
    setComposerDraftText(
      draftKey,
      deviceApprovalAgentPrompt({
        machine: input.machine,
        status: input.status,
        failing: input.failing,
        repair: input.repair,
        projectOwnsConfig: owner !== null,
      }),
    );
    navigation.dispatch(
      StackActions.push("Thread", { draft: { draftId: draftKey, title: project.title } }),
    );
  };
}
