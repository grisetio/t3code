import { createFileRoute } from "@tanstack/react-router";
import { EnvironmentId } from "@t3tools/contracts";

import { DeviceApprovalSettings } from "../components/settings/DeviceApprovalSettings";

function SettingsDeviceApprovalRoute() {
  const { setup } = Route.useSearch();
  return <DeviceApprovalSettings setup={setup ?? null} />;
}

export const Route = createFileRoute("/settings/device-approval")({
  // `setup` names the machine to set this device up on, from a card's "Set up this browser".
  validateSearch: (raw: Record<string, unknown>) =>
    typeof raw.setup === "string" && raw.setup.trim()
      ? { setup: EnvironmentId.make(raw.setup) }
      : {},
  component: SettingsDeviceApprovalRoute,
});
