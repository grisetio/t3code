import { useAtomValue } from "@effect/atom-react";
import { elevationHeadline } from "@t3tools/client-runtime/elevation";
import type { PendingElevationRequest } from "@t3tools/client-runtime/state/elevation";
import { useNavigate, useParams } from "@tanstack/react-router";
import { useEffect, useRef } from "react";

import { useEnvironment } from "../../state/environments";
import { elevation } from "../../state/elevation";
import { useAtomCommand } from "../../state/use-atom-command";
import { toastManager } from "../ui/toast";
import { ElevationAgentIcon, useElevationAgent } from "./ElevationAgentMark";

type ToastId = ReturnType<typeof toastManager.add>;

function requestKey(entry: PendingElevationRequest) {
  return `${entry.environmentId}\u0000${entry.request.requestId}`;
}

/**
 * One persistent notice per pending sudo request on any connected
 * environment, so a request is seen whichever thread or machine is open. It
 * closes when the request resolves anywhere, and stays away while the
 * request's own thread is open, where the card already shows it.
 */
export function ElevationPendingNotices() {
  const pending = useAtomValue(elevation.pendingAcrossEnvironmentsAtom);
  const navigate = useNavigate();
  const openEnvironmentId = useParams({ strict: false, select: (params) => params.environmentId });
  const openThreadId = useParams({ strict: false, select: (params) => params.threadId });
  const respond = useAtomCommand(elevation.respond, "deny device approval");
  // A key maps to null once the user dismissed its notice, so it isn't reopened.
  const shown = useRef(new Map<string, ToastId | null>());

  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- opens and closes imperative toasts to match the pending requests
  useEffect(() => {
    const inOpenThread = (entry: PendingElevationRequest) =>
      entry.request.threadId !== null &&
      entry.environmentId === openEnvironmentId &&
      entry.request.threadId === openThreadId;
    const live = new Set(pending.filter((entry) => !inOpenThread(entry)).map(requestKey));
    const stillPending = new Set(pending.map(requestKey));
    for (const [key, id] of shown.current) {
      if (live.has(key)) continue;
      // A dismissed notice stays dismissed when its thread is opened and closed again.
      if (id === null && stillPending.has(key)) continue;
      shown.current.delete(key);
      if (id !== null) toastManager.close(id);
    }
    for (const entry of pending) {
      const key = requestKey(entry);
      if (shown.current.has(key) || !live.has(key)) continue;
      const { threadId } = entry.request;
      const id: ToastId = toastManager.add({
        type: "info",
        title: <NoticeHeadline entry={entry} />,
        description: <NoticeSource entry={entry} />,
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
          leadingIcon: (
            <ElevationAgentIcon environmentId={entry.environmentId} threadId={threadId} />
          ),
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
  }, [navigate, openEnvironmentId, openThreadId, pending, respond]);

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

// Toasts are added outside render, so the agent's name resolves inside them.
function NoticeHeadline(props: { readonly entry: PendingElevationRequest }) {
  const { entry } = props;
  const agent = useElevationAgent(entry.environmentId, entry.request.threadId);
  return (
    <span className="line-clamp-2">
      {elevationHeadline({
        explanation: entry.request.explanation,
        decoded: entry.decoded,
        agentName: agent?.name ?? null,
      })}
    </span>
  );
}

/** "Claude · Killian's MacBook Pro": this client's name for the machine, not its hostname. */
function NoticeSource(props: { readonly entry: PendingElevationRequest }) {
  const { entry } = props;
  const agent = useElevationAgent(entry.environmentId, entry.request.threadId);
  const machine = useEnvironment(entry.environmentId)?.label ?? null;
  return [agent?.name, machine].filter(Boolean).join(" · ");
}
