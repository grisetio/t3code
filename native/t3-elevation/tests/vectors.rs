//! The shared vectors in packages/contracts/test-vectors, also consumed by the
//! TypeScript contracts and the Android signer.

use serde_json::Value;
use t3_elevation::attestation::Trust;
use t3_elevation::enroll::Proof;
use t3_elevation::keys::{self, EnrolledKey};
use t3_elevation::verify::{self, Assertion, Response};
use t3_elevation::{b64, enroll, escape, payload, shell_words};

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../packages/contracts/test-vectors/device-approval.json"
    );
    serde_json::from_slice(&std::fs::read(path).expect("vectors")).expect("vectors json")
}

fn str_of<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} missing"))
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
            let file = if key["webauthn"].is_object() {
                serde_json::json!({
                    "version": 1, "keyId": key["keyId"], "alg": "webauthn-es256", "publicKey": key["spkiDer"],
                    "label": "test", "securityLevel": "webauthn", "enrolledAt": "2026-10-30T12:00:00Z",
                    "webauthn": key["webauthn"]
                })
            } else {
                serde_json::json!({
                    "version": 1, "keyId": key["keyId"], "alg": "es256", "publicKey": key["spkiDer"],
                    "label": "test", "securityLevel": "tee", "enrolledAt": "2026-10-30T12:00:00Z",
                    "attestationSummary": { "packageName": "p", "signingCertDigest": "d", "devAttestation": true }
                })
            };
            let name = format!("{}.json", str_of(key, "keyId"));
            keys::parse_key_file(&name, file.to_string().as_bytes()).expect("key file")
        })
        .collect()
}

#[test]
fn context_matches() {
    let vectors = vectors();
    assert_eq!(
        bytes(&vectors, "contextBase64Url"),
        t3_elevation::SIGNATURE_CONTEXT
    );
    assert_eq!(
        vectors["maxPayloadBytes"].as_u64(),
        Some(t3_elevation::MAX_PAYLOAD_BYTES as u64)
    );
}

#[test]
fn payloads_decode_reencode_and_verify() {
    let vectors = vectors();
    let keys = enrolled(
        &vectors,
        &[str_of(&vectors["keys"]["enrolled"], "keyId").to_string()],
    );
    for vector in vectors["payloads"].as_array().unwrap() {
        let name = str_of(vector, "name");
        let raw = bytes(vector, "payload");
        let decoded =
            payload::decode(&raw).unwrap_or_else(|error| panic!("{name}: {}", error.as_str()));
        // The module's encoder reproduces the exact signed bytes.
        assert_eq!(decoded.to_bytes(), raw, "{name}");
        let parsed: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(parsed, vector["decoded"], "{name}");
        let signature = &vector["signature"];
        let response = Response {
            key_id: str_of(signature, "keyId"),
            alg: str_of(signature, "alg"),
            signature: str_of(signature, "signature"),
            webauthn: None,
        };
        let issued_at = vector["decoded"]["issuedAt"].as_i64().unwrap();
        let expires_at = vector["decoded"]["expiresAt"].as_i64().unwrap();
        assert!(
            verify::verify(&raw, expires_at, &response, &keys, issued_at, false).is_ok(),
            "{name}"
        );
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

fn response_of(response: &Value) -> Response<'_> {
    let webauthn = &response["webauthn"];
    Response {
        key_id: response["keyId"].as_str().unwrap_or_default(),
        alg: response["alg"].as_str().unwrap_or_default(),
        signature: response["signature"].as_str().unwrap_or_default(),
        webauthn: webauthn.is_object().then(|| Assertion {
            authenticator_data: str_of(webauthn, "authenticatorData"),
            client_data_json: str_of(webauthn, "clientDataJSON"),
        }),
    }
}

#[test]
fn verify_vectors() {
    let vectors = vectors();
    let sections = ["verify", "webauthnVerify"];
    for vector in sections
        .iter()
        .flat_map(|name| vectors[*name].as_array().unwrap())
    {
        let name = str_of(vector, "name");
        let ids: Vec<String> = serde_json::from_value(vector["enrolledKeyIds"].clone()).unwrap();
        let keys = enrolled(&vectors, &ids);
        assert_eq!(keys.len(), ids.len(), "{name}");
        let raw = bytes(vector, "payload");
        let expires_at = payload::decode(&raw)
            .map(|payload| payload.expires_at)
            .unwrap_or(0);
        let response = response_of(&vector["response"]);
        let now = vector["now"].as_i64().unwrap();
        let result = match verify::verify(&raw, expires_at, &response, &keys, now, false) {
            Ok(_) => "ok",
            Err(error) => error.as_str(),
        };
        assert_eq!(result, str_of(vector, "expected"), "{name}");
    }
}

/// Each failing assertion fails at the step it was built to fail, not at a
/// later one by accident.
#[test]
fn webauthn_steps() {
    let vectors = vectors();
    for vector in vectors["webauthnVerify"].as_array().unwrap() {
        let name = str_of(vector, "name");
        let ids: Vec<String> = serde_json::from_value(vector["enrolledKeyIds"].clone()).unwrap();
        let [key] = enrolled(&vectors, &ids).try_into().unwrap();
        let response = response_of(&vector["response"]);
        let (Some(binding), Some(assertion)) = (&key.file.webauthn, &response.webauthn) else {
            assert!(vector["failure"].is_null(), "{name}");
            continue;
        };
        let signature = b64::decode(response.signature).unwrap();
        let step = verify::check_webauthn(
            &key.verifying_key,
            binding,
            &bytes(vector, "payload"),
            assertion,
            &signature,
            false,
        )
        .err()
        .map(|failure| failure.as_str());
        assert_eq!(step, vector["failure"].as_str(), "{name}");
    }
}

#[test]
fn enroll_parse() {
    let vectors = vectors();
    let payloads = vectors["payloads"].as_array().unwrap();
    for vector in vectors["enrollParse"].as_array().unwrap() {
        let name = str_of(vector, "name");
        let source = payloads
            .iter()
            .find(|payload| payload["name"] == name)
            .expect("payload for enrollParse");
        let argv: Vec<String> =
            serde_json::from_value(source["decoded"]["command"]["argv"].clone()).unwrap();
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
        let (challenge, trust, unattested, site) = match &parsed.proof {
            Proof::Attested { challenge, trust } => (Some(challenge.as_str()), *trust, false, None),
            Proof::Unattested { site } => (None, Trust::Release, true, site.as_ref()),
        };
        assert_eq!(challenge, expected["challenge"].as_str(), "{name}");
        assert_eq!(
            trust == Trust::Dev,
            expected["allowDevAttestation"].as_bool().unwrap()
        );
        assert_eq!(
            trust == Trust::Test,
            expected["allowTestAttestation"].as_bool().unwrap()
        );
        assert_eq!(
            unattested,
            expected["unattested"].as_bool().unwrap(),
            "{name}"
        );
        assert_eq!(
            site.map(|site| serde_json::json!({ "rpId": site.rp_id, "origin": site.origin })),
            expected["site"]
                .is_object()
                .then(|| expected["site"].clone()),
            "{name}"
        );
        let spki = b64::decode(&parsed.public_key).unwrap();
        assert_eq!(
            keys::comparison_code(&spki),
            str_of(expected, "comparisonCode")
        );
    }
}

#[test]
fn enroll_grammar_is_strict() {
    let key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUadYCDOJjqGxg8vXNQpAmQeMbvHB4Y6XDNdoMDXyXn0BEFInErC1p8_wgWhUhphKlOaDHtrEbnNg-p2DSnqBoQ";
    let challenge = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";
    let argv = |extra: &[&str]| -> Vec<String> {
        let mut argv = vec![
            "/usr/local/lib/t3-elevation/t3-elevation",
            "enroll",
            "--challenge",
            challenge,
            "--user",
            "u",
            "--label",
            "x",
            "--public-key",
            key,
        ];
        argv.extend_from_slice(extra);
        argv.into_iter().map(str::to_string).collect()
    };
    assert!(enroll::parse_command(&argv(&[])).is_some());
    let trust = |extra: &[&str]| match enroll::parse_command(&argv(extra))?.proof {
        Proof::Attested { trust, .. } => Some(trust),
        Proof::Unattested { .. } => None,
    };
    assert_eq!(trust(&["--allow-dev-attestation"]), Some(Trust::Dev));
    assert_eq!(trust(&["--allow-test-attestation"]), Some(Trust::Test));
    // Unattested keys never ride the attested grammar, nor it theirs.
    assert!(enroll::parse_command(&argv(&["--unattested"])).is_none());
    assert!(
        enroll::parse_command(&argv(&[
            "--rp-id",
            "localhost",
            "--origin",
            "http://localhost:3773"
        ]))
        .is_none()
    );
    let unattested = |extra: &[&str]| {
        let mut argv = argv(&[]);
        argv.drain(2..4);
        argv.push("--unattested".into());
        argv.extend(extra.iter().map(|arg| arg.to_string()));
        enroll::parse_command(&argv)
    };
    assert!(unattested(&[]).is_some());
    assert!(unattested(&["--unattested"]).is_none());
    assert!(unattested(&["--allow-test-attestation"]).is_none());
    assert!(unattested(&["--challenge", challenge]).is_none());
    assert!(unattested(&["--rp-id", "localhost", "--origin", "http://localhost:3773"]).is_some());
    assert!(unattested(&["--rp-id", "localhost"]).is_none());
    assert!(unattested(&["--origin", "http://localhost:3773"]).is_none());
    assert!(
        unattested(&[
            "--rp-id",
            "localhost",
            "--origin",
            "http://192.168.1.20:3773"
        ])
        .is_none()
    );
    assert!(
        enroll::parse_command(&argv(&[
            "--allow-dev-attestation",
            "--allow-test-attestation"
        ]))
        .is_none()
    );
    assert!(
        enroll::parse_command(&argv(&[
            "--allow-dev-attestation",
            "--allow-dev-attestation"
        ]))
        .is_none()
    );
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
        assert_eq!(
            escape::display(str_of(vector, "input")),
            str_of(vector, "expected"),
            "{name}"
        );
    }
}

#[test]
fn vector_keys_derive_their_ids() {
    let vectors = vectors();
    for (name, key) in vectors["keys"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, key)| key.is_object())
    {
        let spki = bytes(key, "spkiDer");
        assert_eq!(keys::key_id(&spki), str_of(key, "keyId"), "{name}");
        assert!(keys::parse_p256_spki(&spki).is_some(), "{name}");
    }
}

#[test]
fn webauthn_registrations() {
    let vectors = vectors();
    for vector in vectors["webauthnRegistrations"].as_array().unwrap() {
        let name = str_of(vector, "name");
        let refusal = enroll::check_registration(
            &bytes(vector, "authenticatorData"),
            str_of(vector, "rpId"),
            &bytes(vector, "credentialId"),
            false,
        )
        .err()
        .map(|refusal| match refusal {
            enroll::RegistrationRefusal::Synced => "synced",
            enroll::RegistrationRefusal::Invalid => "invalid",
        });
        assert_eq!(refusal, vector["refusal"].as_str(), "{name}");
    }
}

#[test]
fn unattested_passkeys_carry_their_registration() {
    let vectors = vectors();
    let device = &vectors["keys"]["webauthnDevice"];
    let registration = |name: &str| {
        vectors["webauthnRegistrations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["name"] == name)
            .map(|vector| str_of(vector, "authenticatorData").to_string())
            .unwrap()
    };
    let enrollment = |authenticator_data: Option<String>| {
        let mut webauthn = device["webauthn"].clone();
        if let Some(data) = authenticator_data {
            webauthn["authenticatorData"] = data.into();
        }
        serde_json::from_value::<enroll::UnattestedEnrollment>(serde_json::json!({
            "label": "Chrome on Mac",
            "publicKey": device["spkiDer"],
            "webauthn": webauthn,
        }))
    };
    // The site alone no longer decodes: the registration is required.
    assert!(enrollment(None).is_err());
    let check = |name: &str, allow_synced: bool| {
        enroll::check_unattested(&enrollment(Some(registration(name))).unwrap(), allow_synced)
            .map(|(_, registration)| registration.unwrap().synced)
            .map_err(|rejected| rejected.code)
    };
    assert_eq!(check("device_bound", false), Ok(false));
    assert_eq!(check("synced", false), Err("synced_passkey"));
    assert_eq!(check("other_credential", false), Err("invalid_passkey"));
    // Allowing synced passkeys admits them, marked synced, and nothing invalid.
    assert_eq!(check("device_bound", true), Ok(false));
    assert_eq!(check("synced", true), Ok(true));
    assert_eq!(check("other_credential", true), Err("invalid_passkey"));
}

#[test]
fn helper_input() {
    let vectors = vectors();
    let section = &vectors["helperInput"];
    assert_eq!(
        enroll::INPUT_MARKER,
        format!("{}\n", str_of(section, "marker")).as_bytes()
    );
    for vector in section["cases"].as_array().unwrap() {
        let name = str_of(vector, "name");
        let mut input = str_of(vector, "input").as_bytes().to_vec();
        let body = enroll::unframe_input(&mut input).map(String::from_utf8_lossy);
        let expected = vector["body"].as_str().map(std::borrow::Cow::Borrowed);
        assert_eq!(body, expected, "{name}");
    }
}

#[test]
fn session_commands() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../packages/contracts/test-vectors/elevation-commands.json"
    );
    let vectors: Value = serde_json::from_slice(&std::fs::read(path).expect("vectors")).unwrap();
    for vector in vectors["commands"].as_array().unwrap() {
        let name = str_of(vector, "name");
        let command = str_of(vector, "command");
        assert_eq!(
            shell_words::agent_command(command),
            str_of(vector, "agentCommand"),
            "{name}"
        );
        let calls = shell_words::sudo_calls(command).map(|calls| {
            calls
                .into_iter()
                .map(|call| serde_json::json!({ "args": call.args, "execTail": call.exec_tail }))
                .collect::<Vec<_>>()
        });
        assert_eq!(serde_json::json!(calls), vector["sudos"], "{name}");
    }
}
