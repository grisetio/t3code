import type { DecodedElevationPayload } from "@t3tools/client-runtime/elevation";
import type { ElevationRequestId, ElevationRespondInput } from "@t3tools/contracts";
import * as Base64Url from "effect/encoding/Base64Url";

import type { DeviceApprovalKeyRecord } from "./deviceApprovalKeys";

export type ElevationApprovalBlocker = "not_set_up" | "other_user" | "not_enrolled";

export interface ElevationSigningRequest {
  readonly alias: string;
  /** The decoded bytes, re-encoded: the signer signs exactly what was rendered. */
  readonly payloadB64url: string;
  readonly prompt: {
    readonly title: string;
    readonly subtitle?: string;
    readonly description: string;
  };
  readonly respond: (signature: string) => ElevationRespondInput;
}

/** Everything the signer and the response need, taken only from the decoded payload. */
export function prepareElevationSigning(input: {
  readonly requestId: ElevationRequestId;
  readonly decoded: DecodedElevationPayload;
  readonly key: DeviceApprovalKeyRecord | null;
  /** This phone's name for the machine. */
  readonly machine: string;
}):
  | { readonly ok: true; readonly signing: ElevationSigningRequest }
  | {
      readonly ok: false;
      readonly blocker: ElevationApprovalBlocker;
    } {
  const { decoded, key } = input;
  if (key === null) return { ok: false, blocker: "not_set_up" };
  if (key.user !== decoded.payload.user) return { ok: false, blocker: "other_user" };
  // The module only accepts keys it lists; a revoked or replaced key would fail there.
  if (!decoded.payload.keyIds.includes(key.keyId)) return { ok: false, blocker: "not_enrolled" };
  const { view } = decoded;
  return {
    ok: true,
    signing: {
      alias: key.alias,
      payloadB64url: Base64Url.encode(decoded.bytes),
      prompt: {
        title: view.enroll ? `Add device ${view.enroll.label}` : `Approve on ${input.machine}`,
        ...(view.enroll || view.runAs === "root" ? {} : { subtitle: `Runs as ${view.runAs}` }),
        description: view.commandArgv.join(" "),
      },
      respond: (signature) => ({
        requestId: input.requestId,
        decision: "approve",
        keyId: key.keyId,
        alg: "es256-der",
        signature,
      }),
    },
  };
}

export function elevationApprovalBlockerMessage(
  blocker: ElevationApprovalBlocker,
  host: string,
): string {
  switch (blocker) {
    case "not_set_up":
      return `This phone isn't set up to approve sudo on ${host}. Set it up in Settings → Device approval.`;
    case "other_user":
      return `This phone approves a different user on ${host}.`;
    case "not_enrolled":
      return `This phone's key isn't enrolled on ${host} anymore. Set it up again in Settings → Device approval.`;
  }
}
