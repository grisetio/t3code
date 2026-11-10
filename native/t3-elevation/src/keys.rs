//! Enrolled keys: keyId, comparison code, and the root-owned key files.

use crate::b64;
use crate::rootsafe::{self, Unsafe};
use p256::ecdsa::VerifyingKey;
use p256::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub fn is_key_id(text: &str) -> bool {
    text.len() == 22
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub fn key_id(spki_der: &[u8]) -> String {
    b64::encode(&Sha256::digest(spki_der)[..16])
}

/// Crockford base32 of the first 50 bits of SHA-256(SPKI DER), `XXXXX-XXXXX`.
pub fn comparison_code(spki_der: &[u8]) -> String {
    let digest = Sha256::digest(spki_der);
    let mut bits: u64 = 0;
    for byte in &digest[..7] {
        bits = (bits << 8) | u64::from(*byte);
    }
    bits >>= 6;
    let mut code = String::with_capacity(11);
    for index in (0..10).rev() {
        code.push(CROCKFORD[((bits >> (index * 5)) & 31) as usize] as char);
        if index == 5 {
            code.push('-');
        }
    }
    code
}

/// A P-256 SPKI DER public key, or None.
pub fn parse_p256_spki(spki_der: &[u8]) -> Option<VerifyingKey> {
    VerifyingKey::from_public_key_der(spki_der).ok()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AttestationSummary {
    pub package_name: String,
    pub signing_cert_digest: String,
    /// Enrolled with `--allow-dev-attestation` or `--allow-test-attestation`.
    pub dev_attestation: bool,
    /// Enrolled with `--allow-test-attestation`: the device is unproven.
    #[serde(default)]
    pub test_attestation: bool,
}

/// Where a `webauthn-es256` key signs: assertions must come from exactly this
/// origin, for this rpId.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebauthnBinding {
    pub rp_id: String,
    /// `scheme://host[:port]`, as browsers write it in clientDataJSON.
    pub origin: String,
    /// base64url; clients pass it in `allowCredentials`. The module never uses it.
    pub credential_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KeyFile {
    pub version: u32,
    pub key_id: String,
    /// `es256` (responses sign with `es256-der`) or `webauthn-es256`.
    pub alg: String,
    pub public_key: String,
    pub label: String,
    pub security_level: String,
    pub enrolled_at: String,
    /// Absent for keys enrolled with `--unattested`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_summary: Option<AttestationSummary>,
    /// Present exactly when `alg` is `webauthn-es256`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webauthn: Option<WebauthnBinding>,
    /// A passkey whose registration was backup eligible: a password manager
    /// syncs it. It approves only while the user's config allows synced passkeys.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub synced: bool,
    /// The passkey's authenticator model, as a lowercase UUID; it names the
    /// password manager. Absent when the browser reported none (all zeros).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aaguid: Option<String>,
}

#[derive(Clone, Debug)]
pub struct EnrolledKey {
    pub key_id: String,
    pub verifying_key: VerifyingKey,
    pub file: KeyFile,
}

/// A key file is used only when its name, its `keyId`, and the keyId derived
/// from its public key agree, and the key is P-256. A WebAuthn key also needs a
/// valid binding and no attestation, which WebAuthn keys never have.
pub fn parse_key_file(file_name: &str, bytes: &[u8]) -> Option<EnrolledKey> {
    let name_id = file_name.strip_suffix(".json")?;
    let file: KeyFile = serde_json::from_slice(bytes).ok()?;
    if file.version != 1 || !is_key_id(name_id) || file.key_id != name_id {
        return None;
    }
    let kind_ok = match (file.alg.as_str(), &file.webauthn) {
        ("es256", None) => !file.synced && file.aaguid.is_none(),
        ("webauthn-es256", Some(binding)) => {
            file.attestation_summary.is_none()
                && crate::enroll::webauthn_site(&binding.rp_id, &binding.origin).is_some()
        }
        _ => false,
    };
    if !kind_ok {
        return None;
    }
    let spki = b64::decode(&file.public_key)?;
    if key_id(&spki) != file.key_id {
        return None;
    }
    let verifying_key = parse_p256_spki(&spki)?;
    Some(EnrolledKey {
        key_id: file.key_id.clone(),
        verifying_key,
        file,
    })
}

/// Loads `keys/<user>/`. Unsafe files or directories fail the whole load;
/// files that don't parse or disagree with their name are skipped.
pub fn load_dir(dir: &Path, policy: &rootsafe::Policy) -> Result<Vec<EnrolledKey>, Unsafe> {
    rootsafe::check_path(dir, policy, rootsafe::Kind::Dir)?;
    let entries = std::fs::read_dir(dir).map_err(|_| Unsafe::Missing)?;
    let mut keys = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| Unsafe::Unreadable)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.ends_with(".json") || name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        rootsafe::check_leaf(&path, policy, rootsafe::Kind::File)?;
        let Ok(bytes) = rootsafe::read_limited(&path, 64 * 1024) else {
            return Err(Unsafe::Unreadable);
        };
        if let Some(key) = parse_key_file(name, &bytes) {
            keys.push(key);
        }
    }
    keys.sort_by(|a, b| a.key_id.cmp(&b.key_id));
    Ok(keys)
}
