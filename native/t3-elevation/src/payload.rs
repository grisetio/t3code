//! The signed payload (v1). The module produces these bytes and verifies the
//! signature over exactly them; nothing re-serializes them.

use crate::{MAX_PAYLOAD_BYTES, b64, json};
use serde_json::{Map, Value};

pub const MAX_WINDOW_SECONDS: i64 = 300;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning {
    pub code: String,
    pub arg: Option<usize>,
}

impl Warning {
    pub fn new(code: &str) -> Self {
        Self {
            code: code.to_string(),
            arg: None,
        }
    }
    pub fn at(code: &str, arg: usize) -> Self {
        Self {
            code: code.to_string(),
            arg: Some(arg),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    pub argv: Vec<String>,
    pub resolved_path: Option<String>,
    pub warnings: Vec<Warning>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payload {
    pub nonce: [u8; 32],
    pub issued_at: i64,
    pub expires_at: i64,
    pub host_name: String,
    pub machine_id: String,
    pub user: String,
    pub uid: u32,
    pub run_as: String,
    pub run_as_group: Option<String>,
    pub argv: Vec<String>,
    pub command: Command,
    pub cwd: String,
    pub service: String,
    pub key_ids: Vec<String>,
}

impl Payload {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = String::with_capacity(1024);
        out.push_str("{\"v\":1,\"kind\":\"sudo\",\"nonce\":");
        json::push_str(&mut out, &b64::encode(&self.nonce));
        out.push_str(&format!(
            ",\"issuedAt\":{},\"expiresAt\":{},\"host\":{{\"name\":",
            self.issued_at, self.expires_at
        ));
        json::push_str(&mut out, &self.host_name);
        out.push_str(",\"machineId\":");
        json::push_str(&mut out, &self.machine_id);
        out.push_str("},\"user\":");
        json::push_str(&mut out, &self.user);
        out.push_str(&format!(",\"uid\":{},\"runAs\":", self.uid));
        json::push_str(&mut out, &self.run_as);
        out.push_str(",\"runAsGroup\":");
        json::push_opt_str(&mut out, self.run_as_group.as_deref());
        out.push_str(",\"argv\":");
        json::push_str_array(&mut out, &self.argv);
        out.push_str(",\"command\":{\"argv\":");
        json::push_str_array(&mut out, &self.command.argv);
        out.push_str(",\"resolvedPath\":");
        json::push_opt_str(&mut out, self.command.resolved_path.as_deref());
        out.push_str(",\"warnings\":[");
        for (index, warning) in self.command.warnings.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str("{\"code\":");
            json::push_str(&mut out, &warning.code);
            if let Some(arg) = warning.arg {
                out.push_str(&format!(",\"arg\":{arg}"));
            }
            out.push('}');
        }
        out.push_str("]},\"cwd\":");
        json::push_str(&mut out, &self.cwd);
        out.push_str(",\"service\":");
        json::push_str(&mut out, &self.service);
        out.push_str(",\"keyIds\":");
        json::push_str_array(&mut out, &self.key_ids);
        out.push('}');
        out.into_bytes()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    TooLarge,
    InvalidJson,
    UnsupportedVersion,
    UnknownKind,
    Invalid,
}

impl DecodeError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TooLarge => "too_large",
            Self::InvalidJson => "invalid_json",
            Self::UnsupportedVersion => "unsupported_version",
            Self::UnknownKind => "unknown_kind",
            Self::Invalid => "invalid",
        }
    }
}

/// Decodes payload bytes with the same rules, in the same order, as the
/// contract's `decodeElevationPayload`.
pub fn decode(bytes: &[u8]) -> Result<Payload, DecodeError> {
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(DecodeError::TooLarge);
    }
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(DecodeError::InvalidJson);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| DecodeError::InvalidJson)?;
    let value: Value = serde_json::from_str(text).map_err(|_| DecodeError::InvalidJson)?;
    let Value::Object(object) = value else {
        return Err(DecodeError::InvalidJson);
    };
    if object.get("v") != Some(&Value::from(1)) {
        return Err(DecodeError::UnsupportedVersion);
    }
    if object.get("kind").and_then(Value::as_str) != Some("sudo") {
        return Err(DecodeError::UnknownKind);
    }
    fields(&object).ok_or(DecodeError::Invalid)
}

const PAYLOAD_KEYS: [&str; 15] = [
    "v",
    "kind",
    "nonce",
    "issuedAt",
    "expiresAt",
    "host",
    "user",
    "uid",
    "runAs",
    "runAsGroup",
    "argv",
    "command",
    "cwd",
    "service",
    "keyIds",
];

fn exact_keys(object: &Map<String, Value>, keys: &[&str], optional: &[&str]) -> bool {
    keys.iter().all(|key| object.contains_key(*key))
        && object
            .keys()
            .all(|key| keys.contains(&key.as_str()) || optional.contains(&key.as_str()))
}

fn non_negative(value: &Value) -> Option<u64> {
    // `as_u64` is None for negatives and for any number written with a
    // fraction or exponent, which the contract's integer rule rejects.
    value.as_u64()
}

fn strings(value: &Value) -> Option<Vec<String>> {
    value
        .as_array()?
        .iter()
        .map(|item| item.as_str().map(str::to_string))
        .collect()
}

fn b64_of_len(value: &Value, chars: usize) -> Option<String> {
    let text = value.as_str()?;
    (text.len() == chars && b64::decode(text).is_some()).then(|| text.to_string())
}

fn fields(object: &Map<String, Value>) -> Option<Payload> {
    if !exact_keys(object, &PAYLOAD_KEYS, &[]) {
        return None;
    }
    let nonce_text = b64_of_len(&object["nonce"], 43)?;
    let nonce: [u8; 32] = b64::decode(&nonce_text)?.try_into().ok()?;
    let issued_at = i64::try_from(non_negative(&object["issuedAt"])?).ok()?;
    let expires_at = i64::try_from(non_negative(&object["expiresAt"])?).ok()?;
    if expires_at <= issued_at || expires_at - issued_at > MAX_WINDOW_SECONDS {
        return None;
    }
    let host = object["host"].as_object()?;
    if !exact_keys(host, &["name", "machineId"], &[]) {
        return None;
    }
    let command = object["command"].as_object()?;
    if !exact_keys(command, &["argv", "resolvedPath", "warnings"], &[]) {
        return None;
    }
    let warnings = command["warnings"]
        .as_array()?
        .iter()
        .map(|item| {
            let warning = item.as_object()?;
            if !exact_keys(warning, &["code"], &["arg"]) {
                return None;
            }
            let code = warning["code"].as_str()?;
            if code.is_empty()
                || code.len() > 64
                || !code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
            {
                return None;
            }
            let arg = match warning.get("arg") {
                Some(arg) => Some(usize::try_from(non_negative(arg)?).ok()?),
                None => None,
            };
            Some(Warning {
                code: code.to_string(),
                arg,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    let key_ids = strings(&object["keyIds"])?;
    if !key_ids.iter().all(|id| crate::keys::is_key_id(id)) {
        return None;
    }
    Some(Payload {
        nonce,
        issued_at,
        expires_at,
        host_name: host["name"].as_str()?.to_string(),
        machine_id: b64_of_len(&host["machineId"], 43)?,
        user: object["user"].as_str()?.to_string(),
        uid: u32::try_from(non_negative(&object["uid"])?).ok()?,
        run_as: object["runAs"].as_str()?.to_string(),
        run_as_group: match &object["runAsGroup"] {
            Value::Null => None,
            value => Some(value.as_str()?.to_string()),
        },
        argv: strings(&object["argv"])?,
        command: Command {
            argv: strings(&command["argv"])?,
            resolved_path: match &command["resolvedPath"] {
                Value::Null => None,
                value => Some(value.as_str()?.to_string()),
            },
            warnings,
        },
        cwd: object["cwd"].as_str()?.to_string(),
        service: object["service"].as_str()?.to_string(),
        key_ids,
    })
}

/// Argv or cwd that isn't UTF-8 can't be shown faithfully (contract:
/// `invalid_encoding`).
pub fn utf8_strings(raw: &[Vec<u8>]) -> Option<Vec<String>> {
    raw.iter()
        .map(|bytes| String::from_utf8(bytes.clone()).ok())
        .collect()
}
