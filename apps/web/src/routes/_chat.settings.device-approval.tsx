import { createFileRoute } from "@tanstack/react-router";

import { DeviceApprovalSettings } from "../components/settings/DeviceApprovalSettings";

function SettingsDeviceApprovalRoute() {
  return <DeviceApprovalSettings />;
}

export const Route = createFileRoute("/_chat/settings/device-approval")({
  component: SettingsDeviceApprovalRoute,
});
