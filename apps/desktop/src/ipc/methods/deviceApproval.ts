import {
  DesktopDeviceApprovalCreateKeyResultSchema,
  DesktopDeviceApprovalOperationSchema,
  DesktopDeviceApprovalSignInputSchema,
  DesktopDeviceApprovalSignResultSchema,
  DesktopDeviceApprovalStateSchema,
  EnvironmentId,
} from "@t3tools/contracts";
import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";

import * as DesktopDeviceApproval from "../../app/DesktopDeviceApproval.ts";
import * as IpcChannels from "../channels.ts";
import { makeIpcMethod } from "../DesktopIpc.ts";

export const getDeviceApprovalState = makeIpcMethod({
  channel: IpcChannels.DEVICE_APPROVAL_GET_STATE_CHANNEL,
  payload: EnvironmentId,
  result: DesktopDeviceApprovalStateSchema,
  handler: Effect.fn("desktop.ipc.deviceApproval.getState")(function* (environmentId) {
    return yield* (yield* DesktopDeviceApproval.DesktopDeviceApproval).state(environmentId);
  }),
});

export const createDeviceApprovalKey = makeIpcMethod({
  channel: IpcChannels.DEVICE_APPROVAL_CREATE_KEY_CHANNEL,
  payload: DesktopDeviceApprovalOperationSchema,
  result: DesktopDeviceApprovalCreateKeyResultSchema,
  handler: Effect.fn("desktop.ipc.deviceApproval.createKey")(function* (input) {
    return yield* (yield* DesktopDeviceApproval.DesktopDeviceApproval).createKey(input);
  }),
});

export const signDeviceApproval = makeIpcMethod({
  channel: IpcChannels.DEVICE_APPROVAL_SIGN_CHANNEL,
  payload: DesktopDeviceApprovalSignInputSchema,
  result: DesktopDeviceApprovalSignResultSchema,
  handler: Effect.fn("desktop.ipc.deviceApproval.sign")(function* (input) {
    return yield* (yield* DesktopDeviceApproval.DesktopDeviceApproval).sign(input);
  }),
});

export const abortDeviceApproval = makeIpcMethod({
  channel: IpcChannels.DEVICE_APPROVAL_ABORT_CHANNEL,
  payload: Schema.String,
  result: Schema.Void,
  handler: Effect.fn("desktop.ipc.deviceApproval.abort")(function* (operationId) {
    yield* (yield* DesktopDeviceApproval.DesktopDeviceApproval).abort(operationId);
  }),
});

export const forgetDeviceApprovalKey = makeIpcMethod({
  channel: IpcChannels.DEVICE_APPROVAL_FORGET_CHANNEL,
  payload: EnvironmentId,
  result: Schema.Void,
  handler: Effect.fn("desktop.ipc.deviceApproval.forget")(function* (environmentId) {
    yield* (yield* DesktopDeviceApproval.DesktopDeviceApproval).forget(environmentId);
  }),
});
