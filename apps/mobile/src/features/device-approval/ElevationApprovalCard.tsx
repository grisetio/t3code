import { useAtomValue } from "@effect/atom-react";
import {
  elevationDecodeFailureMessage,
  elevationFailureMessage,
  type DecodedElevationPayload,
} from "@t3tools/client-runtime/elevation";
import {
  elevationCommandDisplay,
  elevationCommandMoreLabel,
} from "@t3tools/client-runtime/elevation-command";
import { resolveProviderInstanceDisplayName } from "@t3tools/client-runtime/state/provider-instance-display";
import {
  isAtomCommandInterrupted,
  squashAtomCommandFailure,
} from "@t3tools/client-runtime/state/runtime";
import {
  escapeElevationDisplayText,
  type ElevationPayloadDecodeFailure,
  type ElevationRequestId,
  type ElevationRespondInput,
  type EnvironmentId,
  type OrchestrationV2ElevationChanges,
  type ThreadId,
} from "@t3tools/contracts";
import { useNavigation } from "@react-navigation/native";
import * as Result from "effect/Result";
import { useRef, useState } from "react";
import { Pressable, View } from "react-native";

import { ProviderIcon } from "../../components/ProviderIcon";
import { SymbolView } from "../../components/ui/AppSymbol";
import { AppText as Text } from "../../components/ui/AppText";
import { Button } from "../../components/ui/Button";
import { scopedThreadKey } from "../../lib/scopedEntities";
import { useThreadShell } from "../../state/entities";
import { environmentPresentations } from "../../state/presentation";
import { elevation } from "../../state/elevation";
import { environmentServerConfigsAtom } from "../../state/server";
import { useAtomCommand } from "../../state/use-atom-command";
import { REVIEW_WORKING_TREE_SECTION_ID } from "../review/reviewModel";
import { setReviewSelectedSectionId } from "../review/reviewState";
import { approvalHaptic } from "./approvalHaptics";
import { deviceApprovalKeys } from "./deviceApprovalKeys";
import {
  deviceApprovalSigner,
  deviceApprovalSignerErrorCode,
  deviceApprovalSignerErrorMessage,
} from "./deviceApprovalSigner";
import { elevationApprovalBlockerMessage, prepareElevationSigning } from "./elevationApproval";
import { ElevationRequestDetails } from "./ElevationRequestDetails";

/** A request this phone can't sign; the message says why. */
class BlockedApproval extends Error {}

/** Sends one answer at a time and keeps its failure for display. */
function useElevationRespond(environmentId: EnvironmentId) {
  const respond = useAtomCommand(elevation.respond, "answer sudo request");
  const canRespond = useAtomValue(elevation.respond.permissionAtom(environmentId));
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);
  /** Resolves true once the server took the answer. */
  const run = async (
    input: ElevationRespondInput | (() => Promise<ElevationRespondInput>),
  ): Promise<boolean> => {
    if (inFlight.current) return false;
    inFlight.current = true;
    setPending(true);
    setError(null);
    try {
      const resolved = typeof input === "function" ? await input() : input;
      const result = await respond({ environmentId, input: resolved });
      if (result._tag === "Failure") {
        if (!isAtomCommandInterrupted(result)) {
          setError(elevationFailureMessage(squashAtomCommandFailure(result), "Couldn't send."));
        }
        return false;
      }
      return true;
    } catch (cause) {
      if (cause instanceof BlockedApproval) {
        setError(cause.message);
      } else {
        const code = deviceApprovalSignerErrorCode(cause);
        if (code !== "cancelled" && code !== "declined") {
          setError(deviceApprovalSignerErrorMessage(code));
        }
      }
      return false;
    } finally {
      inFlight.current = false;
      setPending(false);
    }
  };
  return { canRespond, pending, error, run };
}

/** Who asks and where: the agent from the thread's provider, the machine as named on this phone. */
export function useElevationRequestContext(
  environmentId: EnvironmentId,
  threadId: ThreadId | null,
  fallbackHost: string | null,
) {
  const thread = useThreadShell(threadId === null ? null : { environmentId, threadId });
  const presentations = useAtomValue(environmentPresentations.presentationsAtom);
  const configs = useAtomValue(environmentServerConfigsAtom);
  const provider = configs
    .get(environmentId)
    ?.providers.find((candidate) => candidate.instanceId === thread?.modelSelection.instanceId);
  return {
    agent:
      provider === undefined
        ? null
        : {
            driver: provider.driver,
            iconUrl: provider.iconUrl,
            name: resolveProviderInstanceDisplayName(provider),
          },
    machine: presentations.get(environmentId)?.entry.target.label ?? fallbackHost ?? "this machine",
    threadTitle: thread ? escapeElevationDisplayText(thread.title) : null,
  };
}

type ElevationRequestContext = ReturnType<typeof useElevationRequestContext>;

/** The agent's mark, then the machine; the thread title under it outside the open thread. */
function ElevationRequestMeta(props: {
  readonly context: ElevationRequestContext;
  readonly showThread: boolean;
}) {
  const { agent, machine, threadTitle } = props.context;
  return (
    <View className="gap-0.5">
      <View className="flex-row items-center gap-1.5">
        {agent ? (
          <>
            <ProviderIcon provider={agent.driver} iconUrl={agent.iconUrl} size={14} />
            <Text className="text-sm text-foreground-muted">{agent.name}</Text>
            <Text className="text-sm text-foreground-muted">·</Text>
          </>
        ) : null}
        <Text numberOfLines={1} className="min-w-0 shrink text-sm text-foreground-muted">
          {machine}
        </Text>
      </View>
      {props.showThread && threadTitle ? (
        <Text numberOfLines={1} className="text-sm text-foreground-muted">
          {threadTitle}
        </Text>
      ) : null}
    </View>
  );
}

/** One quiet line; a long command collapses to its first line and the programs run as admin. */
function ElevationCommandLine(props: {
  readonly commandArgv: readonly string[];
  readonly agentCommand: string | undefined;
  readonly lead: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const display = elevationCommandDisplay(props);
  const more = elevationCommandMoreLabel(display);
  const textClass = props.lead
    ? "font-mono text-base text-foreground"
    : "font-mono text-sm text-foreground-muted";
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel="Command"
      accessibilityState={{ expanded }}
      accessibilityHint={expanded ? "Collapses the command" : "Shows the whole command"}
      className="gap-1"
      onPress={() => setExpanded((current) => !current)}
    >
      {expanded ? (
        display.lines.map((line, index) => (
          <Text key={index} selectable className={textClass}>
            {line}
          </Text>
        ))
      ) : (
        <>
          <Text numberOfLines={2} className={textClass}>
            {display.lines[0]}
          </Text>
          {more ? <Text className="text-xs text-foreground-muted">{more}</Text> : null}
        </>
      )}
    </Pressable>
  );
}

/** "Uncommitted changes · 3 files +42 −8"; absent when the checkout is clean. */
function ElevationChangesPointer(props: {
  readonly environmentId: EnvironmentId;
  readonly threadId: ThreadId | null;
  readonly changes: OrchestrationV2ElevationChanges | undefined;
  /** Runs before the diff opens, e.g. to close a sheet or unlock; calls `open` to proceed. */
  readonly openChanges?: ((open: () => void) => void) | undefined;
}) {
  const navigation = useNavigation();
  const { changes, threadId } = props;
  if (changes === undefined || changes.files === 0 || threadId === null) return null;
  const open = () => {
    setReviewSelectedSectionId(
      scopedThreadKey(props.environmentId, threadId),
      REVIEW_WORKING_TREE_SECTION_ID,
    );
    navigation.navigate("ThreadReview", { environmentId: props.environmentId, threadId });
  };
  const files = `${changes.files} file${changes.files === 1 ? "" : "s"}`;
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={`Uncommitted changes, ${files}, ${changes.additions} added, ${changes.deletions} removed`}
      className="min-h-9 flex-row items-center gap-1.5"
      onPress={() => (props.openChanges ? props.openChanges(open) : open())}
    >
      <Text className="text-sm text-foreground-muted">Uncommitted changes · {files}</Text>
      <Text className="text-sm tabular-nums text-adaptive-emerald-700-300">
        +{changes.additions}
      </Text>
      <Text className="text-sm tabular-nums text-adaptive-rose-700-300">−{changes.deletions}</Text>
      <SymbolView name="chevron.right" size={12} tintColorClassName="accent-icon" />
    </Pressable>
  );
}

interface ElevationApprovalRequest {
  readonly environmentId: EnvironmentId;
  readonly requestId: ElevationRequestId;
  readonly threadId: ThreadId | null;
  readonly decoded: Result.Result<DecodedElevationPayload, ElevationPayloadDecodeFailure>;
  readonly explanation: string | null;
  readonly agentCommand?: string | undefined;
  readonly changes?: OrchestrationV2ElevationChanges | undefined;
}

/**
 * The request card: the agent's reason as the headline, who and where under it, the command, and
 * Deny / Approve. Approve opens the fingerprint prompt; backing out of it denies, because the
 * user has already read the request. `hidden` is the lock screen with notification content
 * hidden: only who and where, and no Approve until the phone is unlocked.
 */
export function ElevationApprovalCard(props: {
  readonly request: ElevationApprovalRequest;
  /** Inside the open thread, whose title is already on screen. */
  readonly inline: boolean;
  readonly hidden?: { readonly onUnlock: () => void };
  /** Called once the answer reached the server. */
  readonly onAnswered?: (decision: "approve" | "deny") => void;
  readonly openChanges?: (open: () => void) => void;
}) {
  const { request } = props;
  const answer = useElevationRespond(request.environmentId);
  const [approved, setApproved] = useState(false);
  const decoded = Result.isSuccess(request.decoded) ? request.decoded.success : null;
  const context = useElevationRequestContext(
    request.environmentId,
    request.threadId,
    decoded?.view.host ?? null,
  );
  const signerPresent = deviceApprovalSigner.isPresent();
  const enroll = decoded?.view.enroll ?? null;

  const deny = async () => {
    if (await answer.run({ requestId: request.requestId, decision: "deny" })) {
      approvalHaptic("denied");
      props.onAnswered?.("deny");
    }
  };

  const approve = async () => {
    if (decoded === null) return;
    let declined = false;
    const sent = await answer.run(async () => {
      const prepared = prepareElevationSigning({
        requestId: request.requestId,
        decoded,
        key: await deviceApprovalKeys.read(request.environmentId),
        machine: context.machine,
      });
      if (!prepared.ok) {
        throw new BlockedApproval(
          elevationApprovalBlockerMessage(prepared.blocker, context.machine),
        );
      }
      const { signing } = prepared;
      try {
        const { signature } = await deviceApprovalSigner.sign(
          signing.alias,
          signing.payloadB64url,
          signing.prompt,
        );
        approvalHaptic("approved");
        setApproved(true);
        return signing.respond(signature);
      } catch (cause) {
        declined = deviceApprovalSignerErrorCode(cause) === "declined";
        throw cause;
      }
    });
    if (sent) {
      props.onAnswered?.("approve");
    } else if (declined && !enroll) {
      // Adding a device keeps Cancel as a plain cancel, like setup.
      await deny();
    } else {
      setApproved(false);
    }
  };

  const actions = (
    <View className="flex-row gap-2">
      <View className="flex-1">
        <Button
          label="Deny"
          tone="secondary"
          fullWidth
          disabled={!answer.canRespond || answer.pending || approved}
          onPress={() => void deny()}
        />
      </View>
      <View className="flex-1">
        {props.hidden ? (
          <Button
            label="Unlock to review"
            tone="primary"
            fullWidth
            onPress={props.hidden.onUnlock}
          />
        ) : (
          <Button
            label={approved ? "Approved" : "Approve"}
            icon={approved ? "checkmark" : { ios: "touchid", android: "fingerprint" }}
            tone="primary"
            fullWidth
            disabled={
              !answer.canRespond || !signerPresent || decoded === null || answer.pending || approved
            }
            loading={answer.pending && !approved}
            onPress={() => void approve()}
          />
        )}
      </View>
    </View>
  );

  const errorLine =
    answer.error !== null ? (
      <Text accessibilityRole="alert" className="text-sm text-danger-foreground">
        {answer.error}
      </Text>
    ) : null;

  if (props.hidden) {
    return (
      <View className="gap-4">
        <ElevationRequestMeta context={context} showThread={false} />
        {errorLine}
        {actions}
      </View>
    );
  }

  const reason =
    request.explanation && request.explanation.trim() !== ""
      ? escapeElevationDisplayText(request.explanation.trim())
      : null;

  return (
    <View className="gap-3">
      {decoded === null ? (
        <Text className="text-sm text-danger-foreground">
          {Result.isFailure(request.decoded)
            ? elevationDecodeFailureMessage(request.decoded.failure)
            : null}{" "}
          Deny it, or approve it on another device.
        </Text>
      ) : enroll ? (
        <ElevationRequestDetails view={decoded.view} explanation={request.explanation} />
      ) : (
        <>
          {reason ? (
            <Text selectable className="font-t3-bold text-lg text-foreground">
              “{reason}”
            </Text>
          ) : (
            <ElevationCommandLine
              commandArgv={decoded.payload.command.argv}
              agentCommand={request.agentCommand}
              lead
            />
          )}
          <ElevationRequestMeta context={context} showThread={!props.inline} />
          {reason ? (
            <ElevationCommandLine
              commandArgv={decoded.payload.command.argv}
              agentCommand={request.agentCommand}
              lead={false}
            />
          ) : null}
          {decoded.view.runAs === "root" ? null : (
            <Text className="text-sm text-foreground-muted">Runs as {decoded.view.runAs}</Text>
          )}
          {decoded.view.warnings.map((warning, index) => (
            <View key={`${warning.code}:${index}`} className="flex-row items-start gap-2">
              <SymbolView
                name="exclamationmark.triangle"
                size={14}
                tintColorClassName="accent-icon"
                type="monochrome"
              />
              <Text className="min-w-0 flex-1 text-sm text-foreground-muted">
                {warning.message}
              </Text>
            </View>
          ))}
          <ElevationChangesPointer
            environmentId={request.environmentId}
            threadId={request.threadId}
            changes={request.changes}
            openChanges={props.openChanges}
          />
        </>
      )}
      {errorLine}
      {signerPresent ? null : (
        <Text className="text-sm text-foreground-muted">
          Approving needs the T3 app on an Android phone with a fingerprint. You can still deny.
        </Text>
      )}
      {actions}
    </View>
  );
}
