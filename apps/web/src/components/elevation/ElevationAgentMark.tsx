import { useAtomValue } from "@effect/atom-react";
import { elevationAgent } from "@t3tools/client-runtime/elevation";
import { scopeThreadRef } from "@t3tools/client-runtime/environment";
import type { EnvironmentId, ThreadId } from "@t3tools/contracts";

import {
  applyProviderInstanceSettings,
  deriveProviderInstanceEntries,
} from "../../providerInstances";
import { useQuietThreadShell } from "../../state/entities";
import { EMPTY_SERVER_PROVIDERS, serverEnvironment } from "../../state/server";
import { ProviderInstanceIcon } from "../chat/ProviderInstanceIcon";

/**
 * The agent that asked, named as the phone names it. The icon uses this client's provider entries
 * for its accent; the name comes from the shared helper so both clients say the same thing.
 */
export function useElevationAgent(environmentId: EnvironmentId, threadId: ThreadId | null) {
  const shell = useQuietThreadShell(
    threadId === null ? null : scopeThreadRef(environmentId, threadId),
  );
  const providers =
    useAtomValue(serverEnvironment.providersValueAtom(environmentId)) ?? EMPTY_SERVER_PROVIDERS;
  const settings = useAtomValue(serverEnvironment.settingsValueAtom(environmentId));
  const agent = elevationAgent(shell, providers);
  if (agent === null) return null;
  const derived = deriveProviderInstanceEntries(providers);
  const entries = settings ? applyProviderInstanceSettings(derived, settings, null) : derived;
  const entry = entries.find((candidate) => candidate.instanceId === agent.instanceId);
  return { name: agent.name, entry };
}

export function ElevationAgentIcon(props: {
  readonly environmentId: EnvironmentId;
  readonly threadId: ThreadId | null;
}) {
  const entry = useElevationAgent(props.environmentId, props.threadId)?.entry;
  return entry ? (
    <ProviderInstanceIcon
      driverKind={entry.driverKind}
      displayName={entry.displayName}
      accentColor={entry.accentColor}
      acpRegistryAgentId={entry.acpRegistryAgentId}
      acpRegistryIconUrl={entry.acpRegistryIconUrl}
      size="compact"
    />
  ) : null;
}

/** Icon and name; nothing when the thread or its provider isn't known here. */
export function ElevationAgentMark(props: {
  readonly environmentId: EnvironmentId;
  readonly threadId: ThreadId | null;
}) {
  const agent = useElevationAgent(props.environmentId, props.threadId);
  if (agent === null) return null;
  return (
    <span className="inline-flex min-w-0 items-center gap-1">
      {agent.entry ? (
        <ProviderInstanceIcon
          driverKind={agent.entry.driverKind}
          displayName={agent.entry.displayName}
          accentColor={agent.entry.accentColor}
          acpRegistryAgentId={agent.entry.acpRegistryAgentId}
          acpRegistryIconUrl={agent.entry.acpRegistryIconUrl}
          size="compact"
        />
      ) : null}
      <span className="truncate">{agent.name}</span>
    </span>
  );
}
