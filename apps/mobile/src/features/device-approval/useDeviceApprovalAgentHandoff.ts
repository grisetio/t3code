import { StackActions, useNavigation } from "@react-navigation/native";
import {
  DEVICE_APPROVAL_DIAGNOSIS_FILE_NAME,
  deviceApprovalCheckPaths,
  deviceApprovalHandoff,
  pickDeviceApprovalFixProject,
  type DeviceApprovalRepairAttempt,
} from "@t3tools/client-runtime/elevation-fix";
import { clampFileAttachmentUploadBytes } from "@t3tools/client-runtime/state/attachments";
import {
  isAtomCommandInterrupted,
  squashAtomCommandFailure,
} from "@t3tools/client-runtime/state/runtime";
import type { ElevationCheck, ElevationStatus, EnvironmentId } from "@t3tools/contracts";

import * as Dialog from "../../components/ui/Dialog";
import { createPastedTextComposerAttachment } from "../../lib/composerImages";
import { appAtomRegistry } from "../../state/atom-registry";
import { useProjects } from "../../state/entities";
import { projectEnvironment } from "../../state/projects";
import { environmentServerConfigsAtom } from "../../state/server";
import { useAtomCommand } from "../../state/use-atom-command";
import {
  appendComposerDraftAttachments,
  createNewTaskDraft,
  setComposerDraftText,
  waitForComposerDraftsLoaded,
} from "../../state/use-composer-drafts";

/**
 * Opens a new thread with a short unsent message and the diagnosis attached, in the project that
 * holds a failing part (a Nix repo, say), else in the machine's project-less threads. The user
 * reads it and presses send. A server without file attachments gets the diagnosis inline.
 */
export function useDeviceApprovalAgentHandoff() {
  const navigation = useNavigation();
  const projects = useProjects();
  const openScratch = useAtomCommand(projectEnvironment.openScratch, { reportFailure: false });

  return async (input: {
    readonly purpose: "fix" | "turn_off";
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
    const { draft, diagnosis } = deviceApprovalHandoff({
      purpose: input.purpose,
      machine: input.machine,
      status: input.status,
      failing: input.failing,
      repair: input.repair,
      projectOwnsConfig: owner !== null,
    });
    setComposerDraftText(draftKey, draft);
    if (!(await attachDiagnosis(draftKey, project.environmentId, diagnosis))) {
      setComposerDraftText(draftKey, `${draft}\n\n${diagnosis}`);
    }
    navigation.dispatch(
      StackActions.push("Thread", { draft: { draftId: draftKey, title: project.title } }),
    );
  };
}

async function attachDiagnosis(
  draftKey: string,
  environmentId: EnvironmentId,
  diagnosis: string,
): Promise<boolean> {
  const capabilities = appAtomRegistry.get(environmentServerConfigsAtom).get(environmentId)
    ?.environment.capabilities;
  const maxBytes = capabilities?.attachmentUploads
    ? capabilities.fileAttachments?.maxUploadBytes
    : undefined;
  if (maxBytes === undefined) return false;
  try {
    const attachment = await createPastedTextComposerAttachment({
      text: diagnosis,
      name: DEVICE_APPROVAL_DIAGNOSIS_FILE_NAME,
      maxBytes: clampFileAttachmentUploadBytes(maxBytes),
    });
    return appendComposerDraftAttachments(draftKey, [attachment], { appendReference: true }) === 0;
  } catch {
    return false;
  }
}
