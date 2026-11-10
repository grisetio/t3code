import { OrchestrationV2TurnItemJson, hasUnknownUnionTag } from "@t3tools/contracts";
import * as Effect from "effect/Effect";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";

const decodeKnownTurnItemPayload = Schema.decodeUnknownEffect(
  Schema.fromJsonString(OrchestrationV2TurnItemJson),
);
const parseJson = Schema.decodeUnknownOption(Schema.fromJsonString(Schema.Unknown));
const decodeTurnItemJson = Schema.decodeUnknownEffect(OrchestrationV2TurnItemJson);
const isUnknownTurnItemJson = hasUnknownUnionTag(OrchestrationV2TurnItemJson.members, "type");
const warnedUnknownTurnItemTypes = new Set<string>();

/**
 * Rows written by a newer server can carry item types this one lacks; one such row must not make
 * the whole thread unreadable. It reads as a notice that keeps the row's place, and the stored row
 * is left as is. Malformed rows of known types still fail.
 */
export const decodeTurnItemPayload = Effect.fnUntraced(function* (payload: string) {
  const parsed = parseJson(payload);
  if (Option.isNone(parsed) || !isUnknownTurnItemJson(parsed.value)) {
    return yield* decodeKnownTurnItemPayload(payload);
  }
  const raw = parsed.value as Record<string, unknown>;
  const unknownType = String(raw.type);
  if (!warnedUnknownTurnItemTypes.has(unknownType)) {
    warnedUnknownTurnItemTypes.add(unknownType);
    yield* Effect.logWarning("Showing turn items of an unknown type as notices", {
      type: unknownType,
      firstItemId: raw.id,
    });
  }
  const inProgress =
    raw.status === "idle" ||
    raw.status === "pending" ||
    raw.status === "running" ||
    raw.status === "waiting";
  return yield* decodeTurnItemJson({
    ...raw,
    type: "system_notice",
    status: inProgress ? "cancelled" : raw.status,
    message: `This item (${unknownType}) was recorded by a newer version of T3 Code and can't be shown here.`,
  });
});
