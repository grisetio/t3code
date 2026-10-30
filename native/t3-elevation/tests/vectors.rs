//! The shared vectors in packages/contracts/test-vectors, also consumed by the
//! TypeScript contracts and the Android signer.

use serde_json::Value;
use t3_elevation::keys::{self, EnrolledKey};
use t3_elevation::verify::{self, Response};
use t3_elevation::{b64, enroll, escape, payload};

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../packages/contracts/test-vectors/device-approval.json");
    serde_json::from_slice(&std::fs::read(path).expect("vectors")).expect("vectors json")
}

fn str_of<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or_else(|| panic!("{key} missing"))
}

fn bytes(value: &Value, key: &str) -> Vec<u8> {
    b64::decode(str_of(value, key)).unwrap_or_else(|| panic!("{key} isn't base64url"))
}

fn enrolled(vectors: &Value, ids: &[String]) -> Vec<EnrolledKey> {
    vectors["keys"]
        .as_object()
        .unwrap()
        .values()
        .filter(|key| key.is_object())
        .filter(|key| ids.iter().any(|id| id == str_of(key, "keyId")))
        .map(|key| {
            let file = serde_json::json!({
                "version": 1, "keyId": key["keyId"], "alg": "es256", "publicKey": key["spkiDer"],
                "label": "test", "securityLevel": "tee", "enrolledAt": "2026-10-30T12:00:00Z",
                "attestationSummary": { "packageName": "p", "signingCertDigest": "d", "devAttestation": true }
            });
            let name = format!("{}.json", str_of(key, "keyId"));
            keys::parse_key_file(&name, file.to_string().as_bytes()).expect("key file")
        })
        .collect()
}

#[test]
fn context_matches() {
    let vectors = vectors();
    assert_eq!(bytes(&vectors, "contextBase64Url"), t3_elevation::SIGNATURE_CONTEXT);
    assert_eq!(vectors["maxPayloadBytes"].as_u64(), Some(t3_elevation::MAX_PAYLOAD_BYTES as u64));
}

#[test]
fn payloads_decode_reencode_and_verify() {
    let vectors = vectors();
    let keys = enrolled(&vectors, &[str_of(&vectors["keys"]["enrolled"], "keyId").to_string()]);
    for vector in vectors["payloads"].as_array().unwrap() {
        let name = str_of(vector, "name");
        let raw = bytes(vector, "payload");
        let decoded = payload::decode(&raw).unwrap_or_else(|error| panic!("{name}: {}", error.as_str()));
        // The module's encoder reproduces the exact signed bytes.
        assert_eq!(decoded.to_bytes(), raw, "{name}");
        let parsed: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(parsed, vector["decoded"], "{name}");
        let signature = &vector["signature"];
        let response = Response {
            key_id: str_of(signature, "keyId"),
            alg: str_of(signature, "alg"),
            signature: str_of(signature, "signature"),
        };
        let issued_at = vector["decoded"]["issuedAt"].as_i64().unwrap();
        let expires_at = vector["decoded"]["expiresAt"].as_i64().unwrap();
        assert!(verify::verify(&raw, expires_at, &response, &keys, issued_at).is_ok(), "{name}");
    }
}

#[test]
fn parse() {
    let vectors = vectors();
    for vector in vectors["parse"].as_array().unwrap() {
        let name = str_of(vector, "name");
        let raw = bytes(vector, "payload");
        let result = match payload::decode(&raw) {
            Ok(_) => "ok",
            Err(error) => error.as_str(),
        };
        assert_eq!(result, str_of(vector, "expected"), "{name}");
    }
}

#[test]
fn verify_vectors() {
    let vectors = vectors();
    for vector in vectors["verify"].as_array().unwrap() {
        let name = str_of(vector, "name");
        let ids: Vec<String> = serde_json::from_value(vector["enrolledKeyIds"].clone()).unwrap();
        let keys = enrolled(&vectors, &ids);
        assert_eq!(keys.len(), ids.len(), "{name}");
        let raw = bytes(vector, "payload");
        let expires_at = payload::decode(&raw).map(|payload| payload.expires_at).unwrap_or(0);
        let response = &vector["response"];
        let response = Response {
            key_id: response["keyId"].as_str().unwrap_or_default(),
            alg: response["alg"].as_str().unwrap_or_default(),
            signature: response["signature"].as_str().unwrap_or_default(),
        };
        let now = vector["now"].as_i64().unwrap();
        let result = match verify::verify(&raw, expires_at, &response, &keys, now) {
            Ok(_) => "ok",
            Err(error) => error.as_str(),
        };
        assert_eq!(result, str_of(vector, "expected"), "{name}");
    }
}

#[test]
fn enroll_parse() {
    let vectors = vectors();
    let payloads = vectors["payloads"].as_array().unwrap();
    for vector in vectors["enrollParse"].as_array().unwrap() {
        let name = str_of(vector, "name");
        let source = payloads.iter().find(|payload| payload["name"] == name).expect("payload for enrollParse");
        let argv: Vec<String> = serde_json::from_value(source["decoded"]["command"]["argv"].clone()).unwrap();
        let parsed = enroll::parse_command(&argv);
        let expected = &vector["expected"];
        if expected.is_null() {
            assert_eq!(parsed, None, "{name}");
            continue;
        }
        let parsed = parsed.unwrap_or_else(|| panic!("{name} should parse"));
        assert_eq!(parsed.user, str_of(expected, "user"));
        assert_eq!(parsed.label, str_of(expected, "label"));
        assert_eq!(parsed.public_key, str_of(expected, "publicKey"));
        assert_eq!(parsed.challenge, str_of(expected, "challenge"));
        assert_eq!(parsed.allow_dev_attestation, expected["allowDevAttestation"].as_bool().unwrap());
        let spki = b64::decode(&parsed.public_key).unwrap();
        assert_eq!(keys::comparison_code(&spki), str_of(expected, "comparisonCode"));
    }
}

#[test]
fn enroll_grammar_is_strict() {
    let key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUadYCDOJjqGxg8vXNQpAmQeMbvHB4Y6XDNdoMDXyXn0BEFInErC1p8_wgWhUhphKlOaDHtrEbnNg-p2DSnqBoQ";
    let challenge = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";
    let argv = |extra: &[&str]| -> Vec<String> {
        let mut argv = vec!["/usr/local/lib/t3-elevation/t3-elevation", "enroll", "--challenge", challenge, "--user", "u", "--label", "x", "--public-key", key];
        argv.extend_from_slice(extra);
        argv.into_iter().map(str::to_string).collect()
    };
    assert!(enroll::parse_command(&argv(&[])).is_some());
    assert!(enroll::parse_command(&argv(&["--allow-dev-attestation"])).unwrap().allow_dev_attestation);
    assert!(enroll::parse_command(&argv(&["--allow-dev-attestation", "--allow-dev-attestation"])).is_none());
    assert!(enroll::parse_command(&argv(&["--user", "v"])).is_none());
    assert!(enroll::parse_command(&argv(&["extra"])).is_none());
    assert!(enroll::parse_command(&argv(&["--label"])).is_none());
    let mut renamed = argv(&[]);
    renamed[0] = "/tmp/t3-elevation-evil".into();
    assert!(enroll::parse_command(&renamed).is_none());
    let mut short = argv(&[]);
    short[3] = "BwcH".into();
    assert!(enroll::parse_command(&short).is_none());
}

#[test]
fn comparison_codes() {
    let vectors = vectors();
    for vector in vectors["comparisonCodes"].as_array().unwrap() {
        let spki = bytes(vector, "spkiDer");
        assert_eq!(keys::key_id(&spki), str_of(vector, "keyId"));
        assert_eq!(keys::comparison_code(&spki), str_of(vector, "code"));
    }
}

#[test]
fn display_escaping() {
    let vectors = vectors();
    for vector in vectors["displayEscaping"].as_array().unwrap() {
        let name = str_of(vector, "name");
        assert_eq!(escape::display(str_of(vector, "input")), str_of(vector, "expected"), "{name}");
    }
}

#[test]
fn vector_keys_derive_their_ids() {
    let vectors = vectors();
    for (name, key) in vectors["keys"].as_object().unwrap().iter().filter(|(_, key)| key.is_object()) {
        let spki = bytes(key, "spkiDer");
        assert_eq!(keys::key_id(&spki), str_of(key, "keyId"), "{name}");
        assert!(keys::parse_p256_spki(&spki).is_some(), "{name}");
    }
}
