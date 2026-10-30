/**
 * The NDJSON protocol between the PAM module and the server
 * (docs/internals/device-approval.md, "Socket protocol").
 */
import { ElevationBase64Url, type ElevationSignedResponse } from "@t3tools/contracts";
import * as Schema from "effect/Schema";

export const MAX_LINE_BYTES = 262144;

const ChainEntry = Schema.Struct({
  pid: Schema.Int,
  ppid: Schema.Int,
  startTime: Schema.Number,
  exe: Schema.NullOr(Schema.String),
  argv: Schema.NullOr(Schema.Array(Schema.String)),
  argvTruncated: Schema.Boolean,
});
export type ChainEntry = typeof ChainEntry.Type;

export const Hello = Schema.Struct({
  type: Schema.Literal("hello"),
  v: Schema.Literal(1),
  user: Schema.String,
  uid: Schema.Int,
  service: Schema.String,
  host: Schema.Struct({ name: Schema.String, machineId: Schema.String }),
  argv: Schema.Array(Schema.String),
  cwd: Schema.String,
  chain: Schema.Array(ChainEntry),
});
export type Hello = typeof Hello.Type;

export const ModuleOutcome = Schema.Literals([
  "approved",
  "denied",
  "expired",
  "bad_signature",
  "too_large",
  "invalid_encoding",
]);
export type ModuleOutcome = typeof ModuleOutcome.Type;

/** Unknown fields are ignored; an unknown `type` ends the connection. */
const ModuleMessage = Schema.Union([
  Schema.Struct({ type: Schema.Literal("hello"), v: Schema.Unknown }),
  Schema.Struct({ type: Schema.Literal("request"), payload: ElevationBase64Url }),
  Schema.Struct({ type: Schema.Literal("result"), outcome: ModuleOutcome }),
]);
export type ModuleMessage = typeof ModuleMessage.Type;

const decodeModuleMessage = Schema.decodeUnknownOption(Schema.fromJsonString(ModuleMessage));
export const decodeHello = Schema.decodeUnknownOption(Hello);

/** Null ends the connection. A hello keeps its raw JSON so its version can be checked first. */
export function parseModuleLine(
  line: string,
): { readonly message: ModuleMessage; readonly json: unknown } | null {
  const message = decodeModuleMessage(line);
  if (message._tag === "None") return null;
  return { message: message.value, json: JSON.parse(line) };
}

export type ServerMessage =
  | { readonly type: "hello_reply"; readonly v: 1; readonly decision: "mine" | "not_mine" }
  | ({ readonly type: "response"; readonly decision: "approve" } & ElevationSignedResponse)
  | { readonly type: "response"; readonly decision: "deny" }
  | { readonly type: "cancel"; readonly reason: "shutdown" | "interrupted" };

export const encodeServerMessage = (message: ServerMessage): string =>
  `${JSON.stringify(message)}\n`;

/** Splits a byte stream into lines; null once a line is over the limit. */
export function makeLineSplitter() {
  let pending: Buffer = Buffer.alloc(0);
  return (chunk: Buffer): ReadonlyArray<string> | null => {
    pending = pending.length === 0 ? chunk : Buffer.concat([pending, chunk]);
    const lines: Array<string> = [];
    let newline = pending.indexOf(0x0a);
    while (newline !== -1) {
      if (newline > MAX_LINE_BYTES) return null;
      lines.push(pending.subarray(0, newline).toString("utf8"));
      pending = pending.subarray(newline + 1);
      newline = pending.indexOf(0x0a);
    }
    return pending.length > MAX_LINE_BYTES ? null : lines;
  };
}
