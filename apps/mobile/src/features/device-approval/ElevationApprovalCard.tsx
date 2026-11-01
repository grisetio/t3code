import { useAtomValue } from "@effect/atom-react";
import {
  ELEVATION_CANT_APPROVE_HERE,
  elevationAgent,
  elevationAgoRefreshMs,
  elevationDecodeFailureMessage,
  elevationEndedLine,
  elevationFailureMessage,
  elevationHeadline,
  elevationRequestFacts,
  elevationRequestSource,
  elevationSeriesLine,
  type DecodedElevationPayload,
  type ElevationAgent,
  type ElevationRequestFact,
  type ElevationWarningView,
} from "@t3tools/client-runtime/elevation";
import {
  elevationCommandDisplay,
  type ElevationCommandDisplay,
} from "@t3tools/client-runtime/elevation-command";
import {
  isAtomCommandInterrupted,
  squashAtomCommandFailure,
} from "@t3tools/client-runtime/state/runtime";
import {
  type ElevationEndedRequest,
  type ElevationPayloadDecodeFailure,
  type ElevationRequestId,
  type ElevationRequestSeries,
  type ElevationRespondInput,
  type EnvironmentId,
  type OrchestrationV2ElevationChanges,
  type ProviderDriverKind,
  type ThreadId,
} from "@t3tools/contracts";
import { useNavigation } from "@react-navigation/native";
import * as Result from "effect/Result";
import { useEffect, useRef, useState } from "react";
import { Pressable, View } from "react-native";
import Animated, { FadeIn, FadeOut, LinearTransition } from "react-native-reanimated";

import { ProviderIcon } from "../../components/ProviderIcon";
import { SymbolView, type AppSymbolName } from "../../components/ui/AppSymbol";
import { AppText as Text } from "../../components/ui/AppText";
import { Button } from "../../components/ui/Button";
import { scopedThreadKey } from "../../lib/scopedEntities";
import { useProject, useThreadShell } from "../../state/entities";
import { environmentPresentations } from "../../state/presentation";
import { elevation } from "../../state/elevation";
import { environmentServerConfigsAtom } from "../../state/server";
import { useAtomCommand } from "../../state/use-atom-command";
import { REVIEW_WORKING_TREE_SECTION_ID } from "../review/reviewModel";
import { setReviewSelectedSectionId } from "../review/reviewState";
import { THREAD_DISCLOSURE_TRANSITION_MS } from "../threads/thread-work-log";
import { approvalHaptic } from "./approvalHaptics";
import { deviceApprovalKeys, useThisPhoneKeyId } from "./deviceApprovalKeys";
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

/**
 * Who asks and where: the agent from the thread's provider, or from the driver the server found
 * on its process, the machine as named on this phone, and the checkout a command normally runs in.
 */
export function useElevationRequestContext(
  environmentId: EnvironmentId,
  threadId: ThreadId | null,
  fallbackHost: string | null,
  driver?: ProviderDriverKind,
) {
  const thread = useThreadShell(threadId === null ? null : { environmentId, threadId });
  const project = useProject(
    thread === null ? null : { environmentId, projectId: thread.projectId },
  );
  const presentations = useAtomValue(environmentPresentations.presentationsAtom);
  const configs = useAtomValue(environmentServerConfigsAtom);
  return {
    agent: elevationAgent(thread, configs.get(environmentId)?.providers ?? [], driver),
    machine: presentations.get(environmentId)?.entry.target.label ?? fallbackHost ?? "this machine",
    threadTitle: thread?.title ?? null,
    checkout: thread?.worktreePath ?? project?.workspaceRoot ?? null,
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

/**
 * "{mark} Claude · Killian's MacBook Pro", or "Killian's MacBook Pro · thread not found": the
 * same second line on every surface.
 */
function ElevationRequestMeta(props: {
  readonly context: ElevationRequestContext;
  readonly source: ReturnType<typeof elevationRequestSource>;
}) {
  const { agent } = props.context;
  const mark = props.source.agentMark ? agent : null;
  if (mark === null && props.source.parts.length === 0) return null;
  return (
    <View className="flex-row items-center gap-1.5">
      {mark ? <ElevationAgentMark agent={mark} size={14} /> : null}
      {mark && props.source.parts.length > 0 ? (
        <Text className="text-sm text-foreground-muted">·</Text>
      ) : null}
      {props.source.parts.length > 0 ? (
        <Text numberOfLines={1} className="min-w-0 shrink text-sm text-foreground-muted">
          {props.source.parts.join(" · ")}
        </Text>
      ) : null}
    </View>
  );
}

/** The current time, kept fresh enough for an "ago" measured from `since`. */
function useElevationNow(since: number | null): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (since === null) return;
    const timer = setTimeout(() => setNow(Date.now()), elevationAgoRefreshMs(since, now));
    return () => clearTimeout(timer);
  }, [since, now]);
  return now;
}

/** "2nd request this turn · first approved 4 s ago", from the second request of a turn on. */
function ElevationSeriesLine(props: {
  readonly series: ElevationRequestSeries;
  readonly threadId: ThreadId | null;
}) {
  const now = useElevationNow(props.series.first.resolvedAt?.epochMilliseconds ?? null);
  const line = elevationSeriesLine(props.series, props.threadId, now);
  return (
    // Wraps rather than cuts: the end of the line is the part that says how the first one went.
    <View className="flex-row items-start gap-1.5">
      <View className="h-5 justify-center">
        <SymbolView
          name="arrow.clockwise"
          size={12}
          tintColorClassName="accent-icon"
          type="monochrome"
        />
      </View>
      <Text className="min-w-0 shrink text-sm text-foreground-muted">
        <Text className="font-t3-semibold text-sm text-foreground">{line.ordinal}</Text>
        {line.rest}
      </Text>
    </View>
  );
}

const DISCLOSURE_LAYOUT = LinearTransition.duration(THREAD_DISCLOSURE_TRANSITION_MS);

/** Runs as and Directory where they aren't the default, then the module's warnings. */
export function ElevationRequestFacts(props: {
  readonly facts: readonly ElevationRequestFact[];
  readonly warnings: readonly ElevationWarningView[];
}) {
  if (props.facts.length === 0 && props.warnings.length === 0) return null;
  return (
    <View className="gap-1">
      {props.facts.map((fact) => (
        <View key={fact.label} className="flex-row gap-3">
          <Text className="w-20 text-sm text-foreground-muted">{fact.label}</Text>
          <Text
            selectable
            className={`min-w-0 flex-1 text-sm text-foreground-muted ${fact.mono ? "font-mono" : ""}`}
          >
            {fact.value}
          </Text>
        </View>
      ))}
      {props.warnings.map((warning) => (
        <View key={`${warning.code}:${warning.message}`} className="flex-row items-start gap-2">
          <SymbolView
            name="exclamationmark.triangle"
            size={13}
            tintColorClassName="accent-icon"
            type="monochrome"
          />
          <Text className="min-w-0 flex-1 text-sm text-foreground-muted">{warning.message}</Text>
        </View>
      ))}
    </View>
  );
}

/** The short command in up to two quiet rows; tap for the whole command and where it runs. */
function ElevationCommandLine(props: {
  readonly display: ElevationCommandDisplay;
  readonly facts: readonly ElevationRequestFact[];
  readonly warnings: readonly ElevationWarningView[];
}) {
  const [expanded, setExpanded] = useState(false);
  const { display } = props;
  return (
    <Animated.View layout={DISCLOSURE_LAYOUT}>
      <Pressable
        accessibilityRole="button"
        accessibilityLabel={`Command, ${display.short}`}
        accessibilityState={{ expanded }}
        accessibilityHint={expanded ? "Hides the full command" : "Shows the full command"}
        className="min-h-9 flex-row items-center gap-1.5 self-start"
        onPress={() => setExpanded((current) => !current)}
      >
        <Text numberOfLines={2} className="min-w-0 shrink font-mono text-sm text-foreground-muted">
          {display.short}
        </Text>
        <SymbolView
          name={expanded ? "chevron.up" : "chevron.down"}
          size={11}
          tintColorClassName="accent-icon-subtle"
          type="monochrome"
        />
      </Pressable>
      {expanded ? (
        <Animated.View
          entering={FadeIn.duration(140)}
          exiting={FadeOut.duration(120)}
          className="gap-2 pb-1"
        >
          <Text selectable className="font-mono text-sm text-foreground-muted">
            {display.lines.join("\n")}
          </Text>
          <ElevationRequestFacts facts={props.facts} warnings={props.warnings} />
        </Animated.View>
      ) : null}
    </Animated.View>
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
  readonly driver?: ProviderDriverKind | undefined;
  readonly raisedByT3?: boolean | undefined;
  readonly series?: ElevationRequestSeries | undefined;
}

const ENDED_SYMBOL: Record<ElevationEndedRequest["elevationStatus"], AppSymbolName> = {
  approved: "checkmark",
  denied: "xmark",
  expired: "clock",
  cancelled: "minus",
};

/**
 * The request card: the headline, who and where under it, the command, and Deny / Approve.
 * Approve opens the fingerprint prompt; backing out of it denies, because the user has already
 * read the request. `hidden` is the lock screen with notification content hidden: the agent and
 * machine only, and no Approve until the phone is unlocked.
 */
export function ElevationApprovalCard(props: {
  readonly request: ElevationApprovalRequest;
  readonly hidden?: { readonly onUnlock: () => void };
  /** Under a header that names the machine, which the card then leaves out. */
  readonly inMachineSection?: boolean;
  /** Called once the answer reached the server. */
  readonly onAnswered?: (decision: "approve" | "deny") => void;
  /**
   * True once the fingerprint signed, false if the approval then failed to send. The request
   * can leave the pending list before the answer returns, so the parent keeps the card up
   * from here while it shows "✓ Approved".
   */
  readonly onApproving?: (active: boolean) => void;
  /** How the request ended elsewhere, said in place of the buttons while the card settles. */
  readonly ended?: Pick<ElevationEndedRequest, "elevationStatus" | "resolvedBy"> | null;
  readonly openChanges?: (open: () => void) => void;
}) {
  const { request } = props;
  const answer = useElevationRespond(request.environmentId);
  const thisKeyId = useThisPhoneKeyId(request.environmentId);
  const [approved, setApproved] = useState(false);
  const decoded = Result.isSuccess(request.decoded) ? request.decoded.success : null;
  const context = useElevationRequestContext(
    request.environmentId,
    request.threadId,
    decoded?.view.host ?? null,
    request.driver,
  );
  const signerPresent = deviceApprovalSigner.isPresent();
  const enroll = decoded?.view.enroll ?? null;
  const headline = elevationHeadline({
    explanation: request.explanation,
    decoded: request.decoded,
    agentName: context.agent?.name ?? null,
  });

  const deny = async () => {
    rememberDeniedHere(request.requestId);
    const input = { requestId: request.requestId, decision: "deny" as const };
    if (await answer.run(thisKeyId === null ? input : { ...input, keyId: thisKeyId })) {
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
        headline,
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

  const ended = approved
    ? ({ kind: "approved", text: "Approved" } as const)
    : props.ended
      ? elevationEndedLine(props.ended, thisKeyId)
      : null;
  const buttons = (
    <View className="flex-row gap-2">
      <View className="flex-1">
        <Button
          label="Deny"
          tone="secondary"
          fullWidth
          disabled={!answer.canRespond || answer.pending}
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
            label="Approve"
            icon={{ ios: "touchid", android: "fingerprint" }}
            tone="primary"
            fullWidth
            disabled={!answer.canRespond || !signerPresent || decoded === null || answer.pending}
            loading={answer.pending}
            onPress={() => void approve()}
          />
        )}
      </View>
    </View>
  );
  const actions = ended ? (
    // Over the buttons, kept at their size but unseen, so nothing moves until the card settles.
    <View>
      <View
        className="opacity-0"
        pointerEvents="none"
        accessibilityElementsHidden
        importantForAccessibility="no-hide-descendants"
      >
        {buttons}
      </View>
      <View
        accessibilityRole="text"
        accessibilityLiveRegion="polite"
        className="absolute inset-0 flex-row items-center justify-center gap-2"
      >
        <SymbolView
          name={ENDED_SYMBOL[ended.kind]}
          size={16}
          tintColorClassName="accent-foreground"
        />
        <Text numberOfLines={1} className="min-w-0 shrink font-t3-medium text-base text-foreground">
          {ended.text}
        </Text>
      </View>
    </View>
  ) : (
    buttons
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
          <Text numberOfLines={2} className="font-t3-semibold text-lg text-foreground">
            Admin request on {context.machine}
          </Text>
        </View>
        {errorLine}
        {actions}
      </View>
    );
  }

  return (
    <View className="gap-3">
      <View className="gap-1">
        <ElevationHeadlineText text={headline} />
        {request.series ? (
          <ElevationSeriesLine series={request.series} threadId={request.threadId} />
        ) : null}
      </View>
      <ElevationRequestMeta
        context={context}
        source={elevationRequestSource({
          explanation: request.explanation,
          threadId: request.threadId,
          raisedByT3: request.raisedByT3,
          machine: props.inMachineSection ? null : context.machine,
        })}
      />
      {decoded === null ? (
        <Text className="text-sm text-foreground-muted">
          {Result.isFailure(request.decoded)
            ? `${elevationDecodeFailureMessage(request.decoded.failure)} `
            : ""}
          Deny it, or approve it on another device.
        </Text>
      ) : enroll ? (
        <EnrollComparison publicKey={enroll.publicKey} />
      ) : (
        <View>
          <ElevationCommandLine
            display={elevationCommandDisplay(decoded.payload)}
            facts={elevationRequestFacts(decoded.view, { cwd: context.checkout })}
            warnings={decoded.view.warnings}
          />
          <ElevationChangesPointer
            environmentId={request.environmentId}
            threadId={request.threadId}
            changes={request.changes}
            openChanges={props.openChanges}
          />
        </View>
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

/** At most three lines, at the weight of a thread's headings; tap to read the rest. */
function ElevationHeadlineText(props: { readonly text: string }) {
  const [open, setOpen] = useState(false);
  return (
    <Text
      selectable={open}
      numberOfLines={open ? undefined : 3}
      onPress={() => setOpen((current) => !current)}
      className="font-t3-semibold text-lg text-foreground"
    >
      {props.text}
    </Text>
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
