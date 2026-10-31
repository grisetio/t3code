import { decodeElevationRequestPayload } from "@t3tools/client-runtime/elevation";
import { ElevationRequestId } from "@t3tools/contracts";
import * as Base64Url from "effect/encoding/Base64Url";
import * as Result from "effect/Result";
import { describe, expect, it } from "vite-plus/test";

import { prepareElevationSigning } from "./elevationApproval";

const KEY_ID = "doBaY6aYDBgHVCShPzJ3LQ";
const requestId = ElevationRequestId.make("request-1");

// Spacing and key order the server would not reproduce if it re-serialized.
const PAYLOAD_TEXT = `{"v":1,"kind":"sudo","nonce":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","issuedAt":1793318400,"expiresAt":1793318500,"host":{"name":"mac‮book","machineId":"PrG9Q5lH63YpmOVmzMLgmceREYsvQFecxPfaK1Bht_k"},"user":"kgriset","uid":501,"runAs":"root","runAsGroup":null,"argv":["sudo","rm","-rf","/tmp/x"],"command":{"argv":["rm","-rf","/tmp/x"],"resolvedPath":"/bin/rm","warnings":[]},"cwd":"/","service":"sudo","keyIds":["${KEY_ID}"]}`;
const payloadBytes = new TextEncoder().encode(PAYLOAD_TEXT);
const decoded = Result.getOrThrow(decodeElevationRequestPayload(Base64Url.encode(payloadBytes)));
const key = { alias: "t3-elevation:env:kgriset", keyId: KEY_ID, user: "kgriset", label: "Fold" };

describe("prepareElevationSigning", () => {
  it("signs the exact payload bytes and answers with the enrolled key", () => {
    const prepared = prepareElevationSigning({ requestId, decoded, key });
    if (!prepared.ok) throw new Error(prepared.blocker);
    expect(Base64Url.decode(prepared.signing.payloadB64url)).toEqual(Result.succeed(payloadBytes));
    expect(prepared.signing.prompt).toEqual({
      title: "Run as root",
      subtitle: "mac\\u{202E}book",
      description: "rm -rf /tmp/x",
    });
    expect(prepared.signing.respond("c2ln")).toEqual({
      requestId,
      decision: "approve",
      keyId: KEY_ID,
      alg: "es256-der",
      signature: "c2ln",
    });
  });

  it("refuses to sign when the module would not accept this phone's key", () => {
    expect(prepareElevationSigning({ requestId, decoded, key: null })).toEqual({
      ok: false,
      blocker: "not_set_up",
    });
    expect(
      prepareElevationSigning({
        requestId,
        decoded,
        key: { ...key, keyId: "v8uit0KoB7u3K1IvpGlMRg" },
      }),
    ).toEqual({ ok: false, blocker: "not_enrolled" });
    expect(prepareElevationSigning({ requestId, decoded, key: { ...key, user: "root" } })).toEqual({
      ok: false,
      blocker: "other_user",
    });
  });
});
