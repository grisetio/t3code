import { AsyncResult } from "effect/reactivity";
import { describe, expect, it, vi } from "vite-plus/test";
import { userEvent } from "vite-plus/test/browser";

import { render } from "../../../test/render";
import { SudoConfirmForm } from "./DeviceApprovalSettings";

describe("SudoConfirmForm", () => {
  it("asks the phone when one is enrolled, and takes the password only on request", async () => {
    const run = vi.fn(async (_password: string | undefined) => AsyncResult.success(undefined));
    await using screen = await render(
      <SudoConfirmForm actionLabel="Turn off" phoneFirst onCancel={() => {}} run={run} />,
    );
    await expect.element(screen.getByText("Approve on your phone.")).toBeVisible();
    expect(screen.container.querySelector("input")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Turn off" }));
    expect(run).toHaveBeenLastCalledWith(undefined);

    await userEvent.click(screen.getByRole("button", { name: "Use the Mac password instead" }));
    await expect.element(screen.getByText(/goes through the T3 server/)).toBeVisible();
    await userEvent.type(screen.getByPlaceholder("Mac password (optional)"), "hunter2");
    await userEvent.click(screen.getByRole("button", { name: "Turn off" }));
    expect(run).toHaveBeenLastCalledWith("hunter2");
  });

  it("requires the password when no phone can approve", async () => {
    const run = vi.fn(async (_password: string | undefined) => AsyncResult.success(undefined));
    await using screen = await render(
      <SudoConfirmForm
        actionLabel="Turn off"
        phoneFirst={false}
        passwordRequired
        onCancel={() => {}}
        run={run}
      />,
    );
    const submit = screen.getByRole("button", { name: "Turn off" });
    await expect.element(submit).toBeDisabled();
    await userEvent.type(screen.getByPlaceholder("Mac password"), "hunter2");
    await userEvent.click(submit);
    expect(run).toHaveBeenLastCalledWith("hunter2");
  });
});
