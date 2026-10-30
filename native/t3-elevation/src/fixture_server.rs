//! A stand-in for the T3 server's side of the socket, for tests and the VM
//! test server only. It signs with the public test-vector keys, so nothing it
//! produces may ever be trusted outside a test.

use crate::attestation::{Enrollment, fixture};
use crate::{b64, payload, verify};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey as _;
use serde_json::{Value, json};
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::time::Duration;

pub const VECTORS: &str = include_str!("../../../packages/contracts/test-vectors/device-approval.json");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Approve,
    Deny,
    /// Never answers, so the module's window runs out.
    Expire,
    /// Signs with another key but claims the enrolled keyId.
    BadSignature,
    /// Signs different bytes than the module sent.
    WrongPayload,
    Cancel,
    /// Closes the connection after the request.
    Close,
    NotMine,
    /// Replies to hello with something that isn't JSON.
    Garbage,
}

impl Mode {
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text.trim() {
            "approve" => Self::Approve,
            "deny" => Self::Deny,
            "expire" => Self::Expire,
            "bad_signature" => Self::BadSignature,
            "wrong_payload" => Self::WrongPayload,
            "cancel" => Self::Cancel,
            "close" => Self::Close,
            "not_mine" => Self::NotMine,
            "garbage" => Self::Garbage,
            _ => return None,
        })
    }
}

pub struct VectorKey {
    pub key_id: String,
    pub spki: Vec<u8>,
    pub signing: SigningKey,
}

pub fn vector_key(name: &str) -> VectorKey {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors");
    let key = &vectors["keys"][name];
    let decode = |field: &str| b64::decode(key[field].as_str().expect("vector key field")).expect("base64url");
    VectorKey {
        key_id: key["keyId"].as_str().expect("keyId").to_string(),
        spki: decode("spkiDer"),
        signing: SigningKey::from_pkcs8_der(&decode("pkcs8Der")).expect("pkcs8"),
    }
}

/// An enrollment object for a vector key, with a fixture chain that verifies
/// only under `--allow-dev-attestation`.
pub fn enrollment(name: &str, label: &str, challenge: &[u8; 32], now: i64) -> Enrollment {
    let key = vector_key(name);
    let chain = fixture::chain(&key.spki, &fixture::Options::new(challenge, now));
    Enrollment {
        label: label.into(),
        public_key: b64::encode(&key.spki),
        challenge: b64::encode(challenge),
        attestation_chain: chain.iter().map(|cert| b64::encode(cert)).collect(),
    }
}

#[derive(Debug, Default)]
pub struct Exchange {
    pub hello: Option<Value>,
    pub payload: Option<Value>,
    pub result: Option<String>,
}

impl Exchange {
    pub fn to_json(&self) -> Value {
        json!({ "hello": self.hello, "payload": self.payload, "result": self.result })
    }
}

fn read_json(reader: &mut BufReader<UnixStream>) -> Option<Value> {
    let mut line = String::new();
    (reader.read_line(&mut line).ok()? > 0).then_some(())?;
    serde_json::from_str(&line).ok()
}

/// Serves one module connection.
pub fn handle(stream: UnixStream, mode: Mode) -> Exchange {
    let mut exchange = Exchange::default();
    let _ = stream.set_read_timeout(Some(Duration::from_secs(400)));
    let Ok(mut writer) = stream.try_clone() else { return exchange };
    let mut reader = BufReader::new(stream);
    exchange.hello = read_json(&mut reader);
    let mut send = |value: String| writer.write_all(format!("{value}\n").as_bytes()).is_ok();
    match mode {
        Mode::NotMine => {
            send(json!({ "type": "hello_reply", "v": 1, "decision": "not_mine" }).to_string());
            return exchange;
        }
        Mode::Garbage => {
            send("not json".into());
            return exchange;
        }
        _ => send(json!({ "type": "hello_reply", "v": 1, "decision": "mine" }).to_string()),
    };
    let Some(request) = read_json(&mut reader) else { return exchange };
    if request["type"] == "result" {
        exchange.result = request["outcome"].as_str().map(str::to_string);
        return exchange;
    }
    let Some(bytes) = request["payload"].as_str().and_then(b64::decode) else { return exchange };
    exchange.payload = serde_json::from_slice(&bytes).ok();
    if payload::decode(&bytes).is_err() {
        exchange.result = Some("fixture_rejected_payload".into());
        return exchange;
    }
    let enrolled = vector_key("enrolled");
    let sign = |key: &SigningKey, message: &[u8]| {
        let signature: Signature = key.sign(&verify::signed_message(message));
        json!({
            "type": "response", "decision": "approve", "keyId": enrolled.key_id,
            "alg": "es256-der", "signature": b64::encode(signature.to_der().as_bytes()),
        })
        .to_string()
    };
    match mode {
        Mode::Approve => send(sign(&enrolled.signing, &bytes)),
        Mode::BadSignature => send(sign(&vector_key("other").signing, &bytes)),
        Mode::WrongPayload => {
            let mut other = bytes.clone();
            other[0] ^= 1;
            send(sign(&enrolled.signing, &other))
        }
        Mode::Deny => send(json!({ "type": "response", "decision": "deny" }).to_string()),
        Mode::Cancel => send(json!({ "type": "cancel" }).to_string()),
        Mode::Close => return exchange,
        Mode::Expire | Mode::NotMine | Mode::Garbage => true,
    };
    exchange.result = read_json(&mut reader).and_then(|value| value["outcome"].as_str().map(str::to_string));
    exchange
}
