//! Signature verification over `context || payload`, in the contract's order:
//! unsupported_alg → unknown_key → expired → bad_signature.

use crate::keys::{EnrolledKey, WebauthnBinding, is_key_id};
use crate::{SIGNATURE_CONTEXT, b64};
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    UnsupportedAlg,
    UnknownKey,
    Expired,
    BadSignature,
}

impl VerifyError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedAlg => "unsupported_alg",
            Self::UnknownKey => "unknown_key",
            Self::Expired => "expired",
            Self::BadSignature => "bad_signature",
        }
    }
}

pub struct Response<'a> {
    pub key_id: &'a str,
    pub alg: &'a str,
    pub signature: &'a str,
    /// `webauthn-es256` only.
    pub webauthn: Option<Assertion<'a>>,
}

/// The base64url `authenticatorData` and `clientDataJSON` of a WebAuthn assertion.
pub struct Assertion<'a> {
    pub authenticator_data: &'a str,
    pub client_data_json: &'a str,
}

/// Why a WebAuthn assertion failed, in the order it is checked. Each is a
/// `bad_signature` to everyone else; tests and the vectors name the step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebauthnFailure {
    Encoding,
    Type,
    Challenge,
    Origin,
    CrossOrigin,
    RpId,
    UserPresence,
    UserVerification,
    /// A synced passkey while the user's config doesn't allow them: other
    /// devices could approve with it.
    BackupEligible,
    Signature,
}

impl WebauthnFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encoding => "encoding",
            Self::Type => "type",
            Self::Challenge => "challenge",
            Self::Origin => "origin",
            Self::CrossOrigin => "cross_origin",
            Self::RpId => "rp_id",
            Self::UserPresence => "user_presence",
            Self::UserVerification => "user_verification",
            Self::BackupEligible => "backup_eligible",
            Self::Signature => "signature",
        }
    }
}

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;

/// The WebAuthn challenge for a payload: `SHA-256(context || payload)`.
pub fn webauthn_challenge(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(signed_message(payload)).into()
}

/// WebAuthn L3 §7.2 for one enrolled credential. signCount is ignored: synced
/// and some platform authenticators always report 0. BE is checked on every
/// assertion, whatever enrollment saw, so turning `allow_synced` off stops a
/// synced key at once.
pub fn check_webauthn(
    key: &VerifyingKey,
    binding: &WebauthnBinding,
    payload: &[u8],
    assertion: &Assertion,
    signature_der: &[u8],
    allow_synced: bool,
) -> Result<(), WebauthnFailure> {
    use WebauthnFailure as F;
    let authenticator_data = b64::decode(assertion.authenticator_data)
        .filter(|bytes| bytes.len() >= 37)
        .ok_or(F::Encoding)?;
    let client_data_json = b64::decode(assertion.client_data_json).ok_or(F::Encoding)?;
    let client_data: Value = std::str::from_utf8(&client_data_json)
        .ok()
        .and_then(|text| serde_json::from_str(text).ok())
        .filter(Value::is_object)
        .ok_or(F::Encoding)?;
    let field = |name: &str| client_data.get(name).and_then(Value::as_str);
    if field("type") != Some("webauthn.get") {
        return Err(F::Type);
    }
    if field("challenge") != Some(b64::encode(&webauthn_challenge(payload)).as_str()) {
        return Err(F::Challenge);
    }
    if field("origin") != Some(binding.origin.as_str()) {
        return Err(F::Origin);
    }
    if !matches!(
        client_data.get("crossOrigin"),
        None | Some(Value::Bool(false))
    ) {
        return Err(F::CrossOrigin);
    }
    if authenticator_data[..32] != Sha256::digest(binding.rp_id.as_bytes())[..] {
        return Err(F::RpId);
    }
    let flags = authenticator_data[32];
    if flags & FLAG_UP == 0 {
        return Err(F::UserPresence);
    }
    if flags & FLAG_UV == 0 {
        return Err(F::UserVerification);
    }
    if flags & FLAG_BE != 0 && !allow_synced {
        return Err(F::BackupEligible);
    }
    let Ok(signature) = Signature::from_der(signature_der) else {
        return Err(F::Signature);
    };
    let mut signed = authenticator_data;
    signed.extend_from_slice(&Sha256::digest(&client_data_json));
    key.verify(&signed, &signature).map_err(|_| F::Signature)
}

pub fn signed_message(payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNATURE_CONTEXT.len() + payload.len());
    message.extend_from_slice(SIGNATURE_CONTEXT);
    message.extend_from_slice(payload);
    message
}

pub fn verify_es256(key: &VerifyingKey, payload: &[u8], signature_der: &[u8]) -> bool {
    let Ok(signature) = Signature::from_der(signature_der) else {
        return false;
    };
    key.verify(&signed_message(payload), &signature).is_ok()
}

/// `expires_at` and `now` are the module's own clock; the payload is the exact
/// bytes the module produced. `allow_synced` is the user's config.
pub fn verify(
    payload: &[u8],
    expires_at: i64,
    response: &Response,
    keys: &[EnrolledKey],
    now: i64,
    allow_synced: bool,
) -> Result<String, VerifyError> {
    if !matches!(response.alg, "es256-der" | "webauthn-es256") {
        return Err(VerifyError::UnsupportedAlg);
    }
    if !is_key_id(response.key_id) {
        return Err(VerifyError::UnknownKey);
    }
    let Some(key) = keys.iter().find(|key| key.key_id == response.key_id) else {
        return Err(VerifyError::UnknownKey);
    };
    if now >= expires_at {
        return Err(VerifyError::Expired);
    }
    let Some(signature) = b64::decode(response.signature) else {
        return Err(VerifyError::BadSignature);
    };
    // A key signs only in its own format: a WebAuthn key's signatures are
    // good only with the origin and flags checks around them.
    let verified = match (response.alg, &key.file.webauthn, &response.webauthn) {
        ("es256-der", None, None) => verify_es256(&key.verifying_key, payload, &signature),
        ("webauthn-es256", Some(binding), Some(assertion)) => check_webauthn(
            &key.verifying_key,
            binding,
            payload,
            assertion,
            &signature,
            allow_synced,
        )
        .is_ok(),
        _ => false,
    };
    if !verified {
        return Err(VerifyError::BadSignature);
    }
    Ok(key.key_id.clone())
}
