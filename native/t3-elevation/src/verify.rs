//! Signature verification over `context || payload`, in the contract's order:
//! unsupported_alg → unknown_key → expired → bad_signature.

use crate::keys::{EnrolledKey, is_key_id};
use crate::{SIGNATURE_CONTEXT, b64};
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};

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
/// bytes the module produced.
pub fn verify(
    payload: &[u8],
    expires_at: i64,
    response: &Response,
    keys: &[EnrolledKey],
    now: i64,
) -> Result<String, VerifyError> {
    if response.alg != "es256-der" {
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
    if !verify_es256(&key.verifying_key, payload, &signature) {
        return Err(VerifyError::BadSignature);
    }
    Ok(key.key_id.clone())
}
