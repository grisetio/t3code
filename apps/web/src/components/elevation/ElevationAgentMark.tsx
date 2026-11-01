import { useAtomValue } from "@effect/atom-react";
import { elevationAgent } from "@t3tools/client-runtime/elevation";
import { scopeThreadRef } from "@t3tools/client-runtime/environment";
import type { EnvironmentId, ProviderDriverKind, ThreadId } from "@t3tools/contracts";

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
 * `driver` names the agent when no thread is found.
 */
export function useElevationAgent(
  environmentId: EnvironmentId,
  threadId: ThreadId | null,
  driver?: ProviderDriverKind,
) {
  const shell = useQuietThreadShell(
    threadId === null ? null : scopeThreadRef(environmentId, threadId),
  );
  const providers =
    useAtomValue(serverEnvironment.providersValueAtom(environmentId)) ?? EMPTY_SERVER_PROVIDERS;
  const settings = useAtomValue(serverEnvironment.settingsValueAtom(environmentId));
  const agent = elevationAgent(shell, providers, driver);
  if (agent === null) return null;
  const derived = deriveProviderInstanceEntries(providers);
  const entries = settings ? applyProviderInstanceSettings(derived, settings, null) : derived;
  const entry = entries.find((candidate) =>
    agent.instanceId === null
      ? candidate.driverKind === agent.driver
      : candidate.instanceId === agent.instanceId,
  );
  return { name: agent.name, entry };
}

export type ElevationAgentView = NonNullable<ReturnType<typeof useElevationAgent>>;

function AgentIcon(props: { readonly entry: ElevationAgentView["entry"] }) {
  const { entry } = props;
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

export function ElevationAgentIcon(props: {
  readonly environmentId: EnvironmentId;
  readonly threadId: ThreadId | null;
  readonly driver?: ProviderDriverKind | undefined;
}) {
  return (
    <AgentIcon
      entry={useElevationAgent(props.environmentId, props.threadId, props.driver)?.entry}
    />
  );
}

export function ElevationAgentMark(props: { readonly agent: ElevationAgentView }) {
  return (
    <span className="inline-flex min-w-0 items-center gap-1">
      <AgentIcon entry={props.agent.entry} />
      <span className="truncate">{props.agent.name}</span>
    </span>
  );
}
