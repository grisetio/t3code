import { useAtomValue } from "@effect/atom-react";
import {
  ELEVATION_APPROVE_ON_PHONE,
  elevationDecodeFailureMessage,
} from "@t3tools/client-runtime/elevation";
import type { PendingElevationRequest } from "@t3tools/client-runtime/state/elevation";
import { useNavigate } from "@tanstack/react-router";
import * as Result from "effect/Result";
import { useEffect, useRef } from "react";

import { useEnvironments } from "../../state/environments";
import { elevation } from "../../state/elevation";
import { useAtomCommand } from "../../state/use-atom-command";
import { toastManager } from "../ui/toast";

type ToastId = ReturnType<typeof toastManager.add>;

function requestKey(entry: PendingElevationRequest) {
  return `${entry.environmentId}\u0000${entry.request.requestId}`;
}

function describe(entry: PendingElevationRequest): string {
  if (Result.isFailure(entry.decoded)) return elevationDecodeFailureMessage(entry.decoded.failure);
  const { view } = entry.decoded.success;
  const what = view.enroll ? `Add device ${view.enroll.label}` : view.commandArgv.join(" ");
  return `${what} · ${ELEVATION_APPROVE_ON_PHONE}`;
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
      const host = Result.isSuccess(entry.decoded)
        ? entry.decoded.success.view.host
        : (environments.find((environment) => environment.environmentId === entry.environmentId)
            ?.label ?? "");
      const { threadId } = entry.request;
      const id: ToastId = toastManager.add({
        type: "warning",
        title: host ? `sudo on ${host} is waiting for approval` : "sudo is waiting for approval",
        description: describe(entry),
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

  useEffect(() => {
    const notices = shown.current;
    return () => {
      for (const id of notices.values()) if (id !== null) toastManager.close(id);
      notices.clear();
    };
  }, []);

  return null;
}
