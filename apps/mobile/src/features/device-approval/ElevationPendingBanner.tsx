import { useAtomValue } from "@effect/atom-react";
import * as Result from "effect/Result";
import { useState } from "react";
import { View } from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";

import { Toast } from "../../components/ui/Toast";
import { APP_BAR_HEIGHT } from "../../lib/layoutMetrics";
import { elevation } from "../../state/elevation";
import {
  encodeThreadDeepLink,
  threadDeepLinkOnScreen,
} from "../agent-awareness/notificationPayload";
import { elevationApprovalTargetAtom, openElevationApproval } from "./elevationApprovalTarget";

/**
 * Pending sudo requests from every connected environment, so a request is
 * seen even when another environment or screen is in front. Hidden while its
 * own thread, which shows the request inline, is on screen.
 */
export function ElevationPendingBanner(props: { readonly pathname: string }) {
  const pending = useAtomValue(elevation.pendingAcrossEnvironmentsAtom);
  const target = useAtomValue(elevationApprovalTargetAtom);
  const insets = useSafeAreaInsets();
  const [dismissed, setDismissed] = useState<ReadonlySet<string>>(() => new Set());
  const threadOnScreen = threadDeepLinkOnScreen(props.pathname);
  const visible = pending.filter(
    (entry) =>
      !dismissed.has(entry.request.requestId) &&
      (entry.request.threadId === null ||
        encodeThreadDeepLink({
          environmentId: entry.environmentId,
          threadId: entry.request.threadId,
        }) !== threadOnScreen),
  );
  const first = visible[0];
  if (target !== null || first === undefined) return null;
  const view = Result.isSuccess(first.decoded) ? first.decoded.success.view : null;
  const command = view?.enroll
    ? `Add device ${view.enroll.label}`
    : (view?.commandArgv.join(" ") ?? "A sudo command");
  return (
    <View
      className="absolute inset-x-3 z-[100]"
      style={{ top: insets.top + APP_BAR_HEIGHT + 8 }}
      pointerEvents="box-none"
    >
      <Toast
        tone="danger"
        message={`sudo on ${view?.host ?? "a machine"} is waiting for approval`}
        description={visible.length > 1 ? `${command} · ${visible.length - 1} more` : command}
        action={{
          label: "Review",
          onPress: () =>
            openElevationApproval({
              environmentId: first.environmentId,
              requestId: first.request.requestId,
            }),
        }}
        onDismiss={() => setDismissed((current) => new Set(current).add(first.request.requestId))}
      />
    </View>
  );
}
