import { useAtomValue } from "@effect/atom-react";
import {
  elevationDecodeFailureMessage,
  elevationFailureMessage,
} from "@t3tools/client-runtime/elevation";
import type { PendingElevationRequest } from "@t3tools/client-runtime/state/elevation";
import {
  isAtomCommandInterrupted,
  squashAtomCommandFailure,
} from "@t3tools/client-runtime/state/runtime";
import type { ElevationRespondInput, EnvironmentId } from "@t3tools/contracts";
import * as Result from "effect/Result";
import { useEffect, useRef, useState } from "react";
import { Platform, ScrollView, View } from "react-native";

import { AppText as Text } from "../../components/ui/AppText";
import { Button } from "../../components/ui/Button";
import { Sheet } from "../../components/ui/Sheet";
import { appAtomRegistry } from "../../state/atom-registry";
import { elevation } from "../../state/elevation";
import { useAtomCommand } from "../../state/use-atom-command";
import { deviceApprovalKeys } from "./deviceApprovalKeys";
import {
  deviceApprovalSigner,
  deviceApprovalSignerErrorCode,
  deviceApprovalSignerErrorMessage,
} from "./deviceApprovalSigner";
import { elevationApprovalBlockerMessage, prepareElevationSigning } from "./elevationApproval";
import {
  closeElevationApproval,
  elevationApprovalTargetAtom,
  elevationNotificationIntentAtom,
  openElevationApproval,
  pendingRequestForNotificationIntent,
} from "./elevationApprovalTarget";
import { ElevationRequestDetails } from "./ElevationRequestDetails";

/** A request this phone can't sign; the message says why. */
class BlockedApproval extends Error {}

/** Sends one answer at a time and keeps its failure for display. */
export function useElevationRespond(environmentId: EnvironmentId) {
  const respond = useAtomCommand(elevation.respond, "answer sudo request");
  const canRespond = useAtomValue(elevation.respond.permissionAtom(environmentId));
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);
  const run = async (input: ElevationRespondInput | (() => Promise<ElevationRespondInput>)) => {
    if (inFlight.current) return;
    inFlight.current = true;
    setPending(true);
    setError(null);
    try {
      const resolved = typeof input === "function" ? await input() : input;
      const result = await respond({ environmentId, input: resolved });
      if (result._tag === "Failure" && !isAtomCommandInterrupted(result)) {
        setError(elevationFailureMessage(squashAtomCommandFailure(result), "Couldn't send."));
      }
    } catch (cause) {
      if (cause instanceof BlockedApproval) {
        setError(cause.message);
      } else {
        const code = deviceApprovalSignerErrorCode(cause);
        if (code !== "cancelled") setError(deviceApprovalSignerErrorMessage(code));
      }
    } finally {
      inFlight.current = false;
      setPending(false);
    }
  };
  return { canRespond, pending, error, run };
}

/**
 * Shows the approval sheet for whichever request was opened, and opens the
 * request a tapped push was about once it reaches this phone.
 */
export function ElevationApprovalHost() {
  const pending = useAtomValue(elevation.pendingAcrossEnvironmentsAtom);
  const target = useAtomValue(elevationApprovalTargetAtom);
  const intent = useAtomValue(elevationNotificationIntentAtom);

  useEffect(() => {
    if (intent === null) return;
    const match = pendingRequestForNotificationIntent(intent, pending, Date.now());
    if (match === null) return;
    appAtomRegistry.set(elevationNotificationIntentAtom, null);
    if (match !== "expired") {
      openElevationApproval({
        environmentId: match.environmentId,
        requestId: match.request.requestId,
      });
    }
  }, [intent, pending]);

  const entry =
    target === null
      ? undefined
      : pending.find(
          (candidate) =>
            candidate.environmentId === target.environmentId &&
            candidate.request.requestId === target.requestId,
        );
  // Answered here, elsewhere, or expired: the request left the pending list.
  useEffect(() => {
    if (target !== null && entry === undefined) closeElevationApproval();
  }, [target, entry]);

  if (entry === undefined) return null;
  return (
    <Sheet title="Approve sudo" onClose={closeElevationApproval}>
      <ElevationApprovalContent key={entry.request.requestId} entry={entry} />
    </Sheet>
  );
}

function ElevationApprovalContent({ entry }: { readonly entry: PendingElevationRequest }) {
  const { environmentId, request, decoded } = entry;
  const answer = useElevationRespond(environmentId);
  const signerPresent = deviceApprovalSigner.isPresent();

  const approve = () =>
    answer.run(async () => {
      if (!Result.isSuccess(decoded)) throw new Error("undecodable payload");
      const prepared = prepareElevationSigning({
        requestId: request.requestId,
        decoded: decoded.success,
        key: await deviceApprovalKeys.read(environmentId),
      });
      if (!prepared.ok) {
        throw new BlockedApproval(
          elevationApprovalBlockerMessage(prepared.blocker, decoded.success.view.host),
        );
      }
      const { signing } = prepared;
      const { signature } = await deviceApprovalSigner.sign(
        signing.alias,
        signing.payloadB64url,
        signing.prompt,
      );
      return signing.respond(signature);
    });

  return (
    <ScrollView
      nestedScrollEnabled
      className="flex-1"
      contentInsetAdjustmentBehavior={Platform.OS === "ios" ? "automatic" : "never"}
      contentContainerClassName="gap-4 px-5 pt-3 pb-8"
    >
      {Result.isSuccess(decoded) ? (
        <ElevationRequestDetails view={decoded.success.view} explanation={request.explanation} />
      ) : (
        <Text className="text-sm text-danger-foreground">
          {elevationDecodeFailureMessage(decoded.failure)} Deny it, or approve it on another device.
        </Text>
      )}
      {answer.error !== null ? (
        <Text accessibilityRole="alert" className="text-sm text-danger-foreground">
          {answer.error}
        </Text>
      ) : null}
      {signerPresent ? null : (
        <Text className="text-sm text-foreground-muted">
          Approving needs the T3 app on an Android phone with a fingerprint. You can still deny.
        </Text>
      )}
      <View className="gap-2">
        <Button
          label="Approve with fingerprint"
          icon={{ ios: "lock", android: "lock" }}
          tone="primary"
          fullWidth
          disabled={
            !answer.canRespond || !signerPresent || !Result.isSuccess(decoded) || answer.pending
          }
          loading={answer.pending}
          onPress={() => void approve()}
        />
        <Button
          label="Deny"
          tone="secondary"
          fullWidth
          disabled={!answer.canRespond || answer.pending}
          onPress={() => void answer.run({ requestId: request.requestId, decision: "deny" })}
        />
      </View>
    </ScrollView>
  );
}
