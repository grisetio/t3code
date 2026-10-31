import { useAtomValue } from "@effect/atom-react";
import {
  ELEVATION_CANT_APPROVE_HERE,
  elevationAgent,
  elevationFailureMessage,
  elevationHeadline,
  type DecodedElevationPayload,
  type ElevationAgent,
} from "@t3tools/client-runtime/elevation";
import {
  elevationCommandDisplay,
  elevationCommandMoreLabel,
  type ElevationCommandDisplay,
} from "@t3tools/client-runtime/elevation-command";
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
import { rememberDeniedHere } from "./elevationApprovalTarget";
import { useComparisonCode } from "./ElevationRequestDetails";

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
  return {
    agent: elevationAgent(thread, configs.get(environmentId)?.providers ?? []),
    machine: presentations.get(environmentId)?.entry.target.label ?? fallbackHost ?? "this machine",
    threadTitle: thread ? escapeElevationDisplayText(thread.title) : null,
  };
}

type ElevationRequestContext = ReturnType<typeof useElevationRequestContext>;

function ElevationAgentMark(props: { readonly agent: ElevationAgent; readonly size: number }) {
  return (
    <View className="flex-row items-center gap-1.5">
      <ProviderIcon provider={props.agent.driver} iconUrl={props.agent.iconUrl} size={props.size} />
      <Text className="text-sm text-foreground-muted">{props.agent.name}</Text>
    </View>
  );
}

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
            <ElevationAgentMark agent={agent} size={14} />
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

/** The command in a quiet box; a long one collapses to its first line and the programs run as admin. */
function ElevationCommandLine(props: {
  readonly display: ElevationCommandDisplay;
  /** No reason given, so the command is the headline. */
  readonly lead: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const { display } = props;
  const more = elevationCommandMoreLabel(display);
  const textClass = props.lead
    ? "font-mono text-sm text-foreground"
    : "font-mono text-xs text-foreground-secondary";
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel="Command"
      accessibilityState={{ expanded }}
      accessibilityHint={expanded ? "Collapses the command" : "Shows the whole command"}
      className="gap-1 rounded-xl border border-border bg-subtle px-3 py-2"
      onPress={() => setExpanded((current) => !current)}
    >
      {expanded ? (
        <Text selectable className={textClass}>
          {display.lines.join("\n")}
        </Text>
      ) : (
        <>
          <Text numberOfLines={2} className={textClass}>
            {display.collapsed}
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
      <SymbolView name="file.diff" size={14} tintColorClassName="accent-icon" />
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
  readonly changes?: OrchestrationV2ElevationChanges | undefined;
}

/**
 * The request card: the headline, who and where under it, the command, and Deny / Approve.
 * Approve opens the fingerprint prompt; backing out of it denies, because the user has already
 * read the request. `hidden` is the lock screen with notification content hidden: the agent and
 * machine only, and no Approve until the phone is unlocked.
 */
export function ElevationApprovalCard(props: {
  readonly request: ElevationApprovalRequest;
  /** Inside the open thread, whose title is already on screen. */
  readonly inline: boolean;
  readonly hidden?: { readonly onUnlock: () => void };
  /** Called once the answer reached the server. */
  readonly onAnswered?: (decision: "approve" | "deny") => void;
  /**
   * True once the fingerprint signed, false if the approval then failed to send. The request
   * can leave the pending list before the answer returns, so the parent keeps the card up
   * from here to show "✓ Approved".
   */
  readonly onApproving?: (active: boolean) => void;
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
    rememberDeniedHere(request.requestId);
    if (await answer.run({ requestId: request.requestId, decision: "deny" })) {
      approvalHaptic("denied");
      props.onAnswered?.("deny");
    }
  };

  const approve = async () => {
    if (decoded === null) return;
    let declined = false;
    let signed = false;
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
        signed = true;
        props.onApproving?.(true);
        return signing.respond(signature);
      } catch (cause) {
        declined = deviceApprovalSignerErrorCode(cause) === "declined";
        throw cause;
      }
    });
    if (sent) {
      props.onAnswered?.("approve");
      return;
    }
    if (signed) props.onApproving?.(false);
    if (declined && !enroll) {
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
        <View className="gap-1">
          {context.agent ? <ElevationAgentMark agent={context.agent} size={14} /> : null}
          <Text numberOfLines={2} className="font-t3-bold text-lg text-foreground">
            {context.machine}
          </Text>
        </View>
        {errorLine}
        {actions}
      </View>
    );
  }

  const headline = elevationHeadline({
    explanation: request.explanation,
    decoded: request.decoded,
  });
  const command = decoded === null ? null : elevationCommandDisplay(decoded.payload);

  return (
    <View className="gap-3">
      {headline.command && command ? (
        <ElevationCommandLine display={command} lead />
      ) : (
        <Text selectable className="font-t3-bold text-lg text-foreground">
          {headline.text}
        </Text>
      )}
      <ElevationRequestMeta context={context} showThread={!props.inline} />
      {decoded === null ? (
        <Text className="text-sm text-foreground-muted">
          Deny it, or approve it on another device.
        </Text>
      ) : enroll ? (
        <EnrollComparison publicKey={enroll.publicKey} />
      ) : (
        <>
          {headline.command || command === null ? null : (
            <ElevationCommandLine display={command} lead={false} />
          )}
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
          {ELEVATION_CANT_APPROVE_HERE} You can still deny.
        </Text>
      )}
      {actions}
    </View>
  );
}

/** Both phones show a code derived from the new key; matching codes mean it is the same key. */
function EnrollComparison(props: { readonly publicKey: Uint8Array }) {
  const code = useComparisonCode(props.publicKey);
  return (
    <View className="gap-1 rounded-xl bg-subtle px-3 py-3">
      <Text
        selectable
        accessibilityLabel={code === null ? "Comparison code loading" : `Comparison code ${code}`}
        className="font-mono text-2xl tracking-widest text-foreground"
      >
        {code ?? "…"}
      </Text>
      <Text className="text-sm text-foreground-muted">
        Approve only if the new phone shows this same code.
      </Text>
    </View>
  );
}
