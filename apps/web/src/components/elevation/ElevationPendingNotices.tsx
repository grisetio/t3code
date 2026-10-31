import { useAtomValue } from "@effect/atom-react";
import {
  ELEVATION_APPROVE_ON_PHONE,
  elevationDecodeFailureMessage,
} from "@t3tools/client-runtime/elevation";
import { elevationCommandDisplay } from "@t3tools/client-runtime/elevation-command";
import { scopeThreadRef } from "@t3tools/client-runtime/environment";
import type { PendingElevationRequest } from "@t3tools/client-runtime/state/elevation";
import { escapeElevationDisplayText } from "@t3tools/contracts";
import { useNavigate } from "@tanstack/react-router";
import * as Result from "effect/Result";
import { useEffect, useRef } from "react";

import { readThreadShell } from "../../state/entities";
import { useEnvironments } from "../../state/environments";
import { elevation } from "../../state/elevation";
import { useAtomCommand } from "../../state/use-atom-command";
import { toastManager } from "../ui/toast";

type ToastId = ReturnType<typeof toastManager.add>;

function requestKey(entry: PendingElevationRequest) {
  return `${entry.environmentId}\u0000${entry.request.requestId}`;
}

/** The reason leads, as on the card; without one, the command does. */
function headline(entry: PendingElevationRequest): string {
  if (Result.isFailure(entry.decoded)) return elevationDecodeFailureMessage(entry.decoded.failure);
  const { view, payload } = entry.decoded.success;
  if (view.enroll) return `Add device ${view.enroll.label}`;
  if (entry.request.explanation)
    return `“${escapeElevationDisplayText(entry.request.explanation)}”`;
  return elevationCommandDisplay(payload).collapsed;
}

/**
 * One persistent notice per pending sudo request on any connected
 * environment, so a request is seen whichever thread or machine is open. It
 * closes when the request resolves anywhere.
 */
export function ElevationPendingNotices() {
  const pending = useAtomValue(elevation.pendingAcrossEnvironmentsAtom);
  const { environments } = useEnvironments();
  const navigate = useNavigate();
  const respond = useAtomCommand(elevation.respond, "deny device approval");
  // A key maps to null once the user dismissed its notice, so it isn't reopened.
  const shown = useRef(new Map<string, ToastId | null>());

  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- opens and closes imperative toasts to match the pending requests
  useEffect(() => {
    const live = new Set(pending.map(requestKey));
    for (const [key, id] of shown.current) {
      if (live.has(key)) continue;
      if (id !== null) toastManager.close(id);
      shown.current.delete(key);
    }
    for (const entry of pending) {
      const key = requestKey(entry);
      if (shown.current.has(key)) continue;
      const { threadId } = entry.request;
      // The machine is this client's name for the environment, like the phone's.
      const machine =
        environments.find((environment) => environment.environmentId === entry.environmentId)
          ?.label ?? (Result.isSuccess(entry.decoded) ? entry.decoded.success.view.host : "");
      const threadTitle =
        threadId === null
          ? null
          : (readThreadShell(scopeThreadRef(entry.environmentId, threadId))?.title ?? null);
      const id: ToastId = toastManager.add({
        type: "info",
        title: headline(entry),
        description: [threadTitle, machine, ELEVATION_APPROVE_ON_PHONE]
          .filter((part) => part !== null && part !== "")
          .join(" · "),
        timeout: 0,
        onClose: () => {
          if (shown.current.get(key) === id) shown.current.set(key, null);
        },
        ...(threadId === null
          ? {}
          : {
              actionProps: {
                children: "Open thread",
                onClick: () =>
                  void navigate({
                    to: "/$environmentId/$threadId",
                    params: { environmentId: entry.environmentId, threadId },
                  }),
              },
            }),
        data: {
          actionLayout: "stacked-end",
          secondaryActionVariant: "ghost",
          secondaryActionProps: {
            children: "Deny",
            onClick: () =>
              void respond({
                environmentId: entry.environmentId,
                input: { requestId: entry.request.requestId, decision: "deny" },
              }),
          },
        },
      });
      shown.current.set(key, id);
    }
  }, [environments, navigate, pending, respond]);

  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- closes the toasts this component opened when it unmounts
  useEffect(() => {
    const notices = shown.current;
    return () => {
      for (const id of notices.values()) if (id !== null) toastManager.close(id);
      notices.clear();
    };
  }, []);

  return null;
}
