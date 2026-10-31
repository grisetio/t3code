//! Android key attestation for enrollment (spec §8). A key is enrolled only if
//! its certificate chain ends at a pinned Google root and the attested key is
//! a fresh, hardware-backed, biometric-per-use P-256 signing key made by a
//! pinned T3 app. `--allow-dev-attestation` admits debug builds of the app on
//! real phones: only the app pins widen, to the dev ones this helper was built
//! with. `--allow-test-attestation` admits emulators and fixture chains, which
//! prove nothing about the device. The key file records either.

use crate::b64;
use crate::der::{self, Class, Reader, Tlv};
use serde::Deserialize;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// SHA-256 of the SPKI of Google's hardware attestation roots, from
/// https://android.googleapis.com/attestation/root (RSA-4096 root, which has
/// several certificates for one key, and the 2025 ECDSA P-384 root).
const GOOGLE_ROOT_SPKI_SHA256: [&str; 2] = [
    "feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae",
    "3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec",
];

/// Release builds of the T3 app. Builders of other apps set these at compile time.
const RELEASE_PACKAGES: &str = match option_env!("T3_ELEVATION_ANDROID_PACKAGES") {
    Some(value) => value,
    None => "com.t3tools.t3code",
};
/// SHA-256 digests of the release signing certificates, hex or base64url,
/// comma-separated. Unknown for now: without one, only dev enrollment works.
const RELEASE_SIGNING_DIGESTS: &str = match option_env!("T3_ELEVATION_ANDROID_SIGNING_DIGESTS") {
    Some(value) => value,
    None => "",
};
/// Debug signing certificates `--allow-dev-attestation` accepts, as above.
const DEV_SIGNING_DIGESTS: &str = match option_env!("T3_ELEVATION_ANDROID_DEV_SIGNING_DIGESTS") {
    Some(value) => value,
    None => "",
};
const DEV_PACKAGES: [&str; 2] = ["com.t3tools.t3code.preview", "com.t3tools.t3code.dev"];

/// How much an enrollment's attestation must prove.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trust {
    Release,
    /// `--allow-dev-attestation`.
    Dev,
    /// `--allow-test-attestation`.
    Test,
}

const KEY_ATTESTATION_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x11];
const MAX_CREATION_SKEW_MS: i64 = 10 * 60 * 1000;
const MAX_CHAIN: usize = 10;

#[derive(Clone, Debug)]
pub struct Pins {
    pub root_spki_sha256: Vec<[u8; 32]>,
    pub packages: Vec<String>,
    pub signing_digests: Vec<[u8; 32]>,
    pub dev_signing_digests: Vec<[u8; 32]>,
}

fn digests(list: &str) -> Vec<[u8; 32]> {
    list.split(',')
        .filter(|text| !text.trim().is_empty())
        .filter_map(parse_digest)
        .collect()
}

fn parse_digest(text: &str) -> Option<[u8; 32]> {
    let text = text.trim();
    let bytes = if text.len() == 64 {
        (0..32)
            .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok())
            .collect::<Option<Vec<u8>>>()?
    } else {
        b64::decode(text)?
    };
    bytes.try_into().ok()
}

impl Pins {
    pub fn release() -> Self {
        Self {
            root_spki_sha256: GOOGLE_ROOT_SPKI_SHA256
                .iter()
                .filter_map(|hex| parse_digest(hex))
                .collect(),
            packages: RELEASE_PACKAGES
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_string)
                .collect(),
            signing_digests: digests(RELEASE_SIGNING_DIGESTS),
            dev_signing_digests: digests(DEV_SIGNING_DIGESTS),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Enrollment {
    pub label: String,
    pub public_key: String,
    pub challenge: String,
    pub attestation_chain: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    pub security_level: &'static str,
    pub package_name: String,
    pub signing_cert_digest: String,
    pub trust: Trust,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejected {
    pub code: &'static str,
    pub message: String,
}

fn reject(code: &'static str, message: impl Into<String>) -> Rejected {
    Rejected {
        code,
        message: message.into(),
    }
}

struct Certificate<'a> {
    tbs: &'a [u8],
    signature_algorithm: &'a [u8],
    signature: &'a [u8],
    issuer: &'a [u8],
    subject: &'a [u8],
    not_before: i64,
    not_after: i64,
    spki: &'a [u8],
    extensions: Vec<(&'a [u8], &'a [u8])>,
}

fn parse_time(tlv: &Tlv) -> Option<i64> {
    let text = std::str::from_utf8(tlv.value).ok()?;
    let text = text.strip_suffix('Z')?;
    let (year, rest) = match tlv.number {
        23 if text.len() == 12 => {
            let year: i64 = text[..2].parse().ok()?;
            (
                if year >= 50 { 1900 + year } else { 2000 + year },
                &text[2..],
            )
        }
        24 if text.len() == 14 => (text[..4].parse().ok()?, &text[4..]),
        _ => return None,
    };
    let field = |range: std::ops::Range<usize>| rest.get(range)?.parse::<i64>().ok();
    let (month, day, hour, minute, second) = (
        field(0..2)?,
        field(2..4)?,
        field(4..6)?,
        field(6..8)?,
        field(8..10)?,
    );
    // Days from civil (Howard Hinnant).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hour * 3600 + minute * 60 + second)
}

fn parse_certificate(bytes: &[u8]) -> Option<Certificate<'_>> {
    let mut outer = Reader::new(bytes);
    let certificate = outer.universal(der::SEQUENCE)?;
    if !outer.is_empty() {
        return None;
    }
    let mut parts = certificate.reader();
    let tbs = parts.universal(der::SEQUENCE)?;
    let algorithm = parts.universal(der::SEQUENCE)?;
    let signature = parts.universal(der::BIT_STRING)?;
    let signature_bits = signature.value.strip_prefix(&[0])?;
    let signature_algorithm = algorithm.reader().universal(der::OID)?.value;

    let mut fields = tbs.reader();
    let mut first = fields.next()?;
    if first.class == Class::Context && first.number == 0 {
        first = fields.next()?;
    }
    if first.number != der::INTEGER {
        return None;
    }
    fields.universal(der::SEQUENCE)?;
    let issuer = fields.universal(der::SEQUENCE)?.raw;
    let validity = fields.universal(der::SEQUENCE)?;
    let mut times = validity.reader();
    let not_before = parse_time(&times.next()?)?;
    let not_after = parse_time(&times.next()?)?;
    let subject = fields.universal(der::SEQUENCE)?.raw;
    let spki = fields.universal(der::SEQUENCE)?.raw;
    let mut extensions = Vec::new();
    for field in fields {
        if field.class == Class::Context && field.number == 3 {
            let list = field.reader().universal(der::SEQUENCE)?.reader();
            for extension in list {
                let mut parts = extension.reader();
                let oid = parts.universal(der::OID)?.value;
                let mut value = parts.next()?;
                if value.number == der::BOOLEAN {
                    value = parts.next()?;
                }
                if value.number != der::OCTET_STRING {
                    return None;
                }
                extensions.push((oid, value.value));
            }
        }
    }
    Some(Certificate {
        tbs: tbs.raw,
        signature_algorithm,
        signature: signature_bits,
        issuer,
        subject,
        not_before,
        not_after,
        spki,
        extensions,
    })
}

const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

fn signature_hash(algorithm: &[u8]) -> Option<(bool, Hash)> {
    match algorithm {
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02] => Some((true, Hash::Sha256)),
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03] => Some((true, Hash::Sha384)),
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04] => Some((true, Hash::Sha512)),
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b] => Some((false, Hash::Sha256)),
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c] => Some((false, Hash::Sha384)),
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d] => Some((false, Hash::Sha512)),
        _ => None,
    }
}

fn spki_algorithm(spki: &[u8]) -> Option<(&[u8], Option<&[u8]>)> {
    let mut outer = Reader::new(spki).universal(der::SEQUENCE)?.reader();
    let mut algorithm = outer.universal(der::SEQUENCE)?.reader();
    let oid = algorithm.universal(der::OID)?.value;
    let parameter = algorithm
        .next()
        .filter(|tlv| tlv.number == der::OID)
        .map(|tlv| tlv.value);
    Some((oid, parameter))
}

/// Whether `signed` carries a valid signature by the key in `issuer_spki`.
fn signed_by(signed: &Certificate, issuer_spki: &[u8]) -> bool {
    use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
    use p256::pkcs8::DecodePublicKey as _;
    let Some((is_ecdsa, hash)) = signature_hash(signed.signature_algorithm) else {
        return false;
    };
    let digest = match hash {
        Hash::Sha256 => Sha256::digest(signed.tbs).to_vec(),
        Hash::Sha384 => Sha384::digest(signed.tbs).to_vec(),
        Hash::Sha512 => Sha512::digest(signed.tbs).to_vec(),
    };
    let Some((key_algorithm, curve)) = spki_algorithm(issuer_spki) else {
        return false;
    };
    match (is_ecdsa, key_algorithm, curve) {
        (true, OID_EC_PUBLIC_KEY, Some(OID_P256)) => {
            let (Ok(key), Ok(signature)) = (
                p256::ecdsa::VerifyingKey::from_public_key_der(issuer_spki),
                p256::ecdsa::Signature::from_der(signed.signature),
            ) else {
                return false;
            };
            key.verify_prehash(&digest, &signature).is_ok()
        }
        (true, OID_EC_PUBLIC_KEY, Some(OID_P384)) => {
            let (Ok(key), Ok(signature)) = (
                p384::ecdsa::VerifyingKey::from_public_key_der(issuer_spki),
                p384::ecdsa::Signature::from_der(signed.signature),
            ) else {
                return false;
            };
            key.verify_prehash(&digest, &signature).is_ok()
        }
        (false, OID_RSA, _) => {
            let Ok(key) = rsa::RsaPublicKey::from_public_key_der(issuer_spki) else {
                return false;
            };
            let scheme = match hash {
                Hash::Sha256 => rsa::Pkcs1v15Sign::new::<Sha256>(),
                Hash::Sha384 => rsa::Pkcs1v15Sign::new::<Sha384>(),
                Hash::Sha512 => rsa::Pkcs1v15Sign::new::<Sha512>(),
            };
            key.verify(scheme, &digest, signed.signature).is_ok()
        }
        _ => false,
    }
}

/// Context-tagged entries of an AuthorizationList, by tag number.
struct Authorizations<'a>(Vec<(u32, Tlv<'a>)>);

impl<'a> Authorizations<'a> {
    fn parse(list: Tlv<'a>) -> Option<Self> {
        let mut entries = Vec::new();
        let reader = list.reader();
        for tagged in reader {
            if tagged.class != Class::Context {
                return None;
            }
            let inner = tagged.reader().next()?;
            entries.push((tagged.number, inner));
        }
        Some(Self(entries))
    }
    fn get(&self, tag: u32) -> Option<&Tlv<'a>> {
        self.0
            .iter()
            .find(|(number, _)| *number == tag)
            .map(|(_, tlv)| tlv)
    }
    fn has(&self, tag: u32) -> bool {
        self.get(tag).is_some()
    }
    fn int(&self, tag: u32) -> Option<u64> {
        self.get(tag)?.as_u64()
    }
}

const TAG_PURPOSE: u32 = 1;
const TAG_ALGORITHM: u32 = 2;
const TAG_EC_CURVE: u32 = 10;
const TAG_NO_AUTH_REQUIRED: u32 = 503;
const TAG_USER_AUTH_TYPE: u32 = 504;
const TAG_AUTH_TIMEOUT: u32 = 505;
const TAG_CREATION_DATETIME: u32 = 701;
const TAG_ORIGIN: u32 = 702;
const TAG_ROOT_OF_TRUST: u32 = 704;
const TAG_APPLICATION_ID: u32 = 709;

const PURPOSE_SIGN: u64 = 2;
const ALGORITHM_EC: u64 = 3;
const CURVE_P256: u64 = 1;
const AUTH_TYPE_PASSWORD: u64 = 1;
const AUTH_TYPE_BIOMETRIC: u64 = 2;
const ORIGIN_GENERATED: u64 = 0;
const BOOT_STATE_VERIFIED: u64 = 0;

fn level_name(level: u64) -> Option<&'static str> {
    match level {
        0 => Some("software"),
        1 => Some("tee"),
        2 => Some("strongbox"),
        _ => None,
    }
}

pub fn verify(
    enrollment: &Enrollment,
    now: i64,
    pins: &Pins,
    trust: Trust,
) -> Result<Verified, Rejected> {
    // Only test attestation lets the device itself go unproven.
    let any_device = trust == Trust::Test;
    let label_ok = !enrollment.label.trim().is_empty()
        && enrollment.label.chars().count() <= 100
        && !enrollment.label.chars().any(char::is_control);
    if !label_ok {
        return Err(reject(
            "invalid_label",
            "label must be 1-100 characters without control characters",
        ));
    }
    let public_key = b64::decode(&enrollment.public_key)
        .ok_or_else(|| reject("invalid_public_key", "publicKey is not base64url"))?;
    crate::keys::parse_p256_spki(&public_key)
        .ok_or_else(|| reject("invalid_public_key", "publicKey is not a P-256 SPKI"))?;
    let challenge = b64::decode(&enrollment.challenge)
        .filter(|bytes| bytes.len() == 32)
        .ok_or_else(|| {
            reject(
                "invalid_challenge",
                "challenge must be 32 bytes of base64url",
            )
        })?;
    if enrollment.attestation_chain.len() < 2 || enrollment.attestation_chain.len() > MAX_CHAIN {
        return Err(reject(
            "invalid_chain",
            "attestation chain must have 2 to 10 certificates",
        ));
    }
    let raw: Vec<Vec<u8>> = enrollment
        .attestation_chain
        .iter()
        .map(|text| b64::decode(text))
        .collect::<Option<_>>()
        .ok_or_else(|| reject("invalid_chain", "certificate is not base64url"))?;
    let chain: Vec<Certificate> = raw
        .iter()
        .map(|bytes| parse_certificate(bytes))
        .collect::<Option<_>>()
        .ok_or_else(|| reject("invalid_chain", "certificate is not valid DER"))?;

    let leaf = &chain[0];
    if leaf.spki != public_key.as_slice() {
        return Err(reject(
            "key_mismatch",
            "attested key differs from publicKey",
        ));
    }
    for (index, pair) in chain.windows(2).enumerate() {
        if pair[0].issuer != pair[1].subject || !signed_by(&pair[0], pair[1].spki) {
            return Err(reject(
                "invalid_chain",
                format!(
                    "certificate {index} is not signed by certificate {}",
                    index + 1
                ),
            ));
        }
    }
    let root = chain.last().expect("chain has at least two certificates");
    if root.issuer != root.subject || !signed_by(root, root.spki) {
        return Err(reject(
            "invalid_chain",
            "chain does not end in a self-signed root",
        ));
    }
    let root_pinned = pins
        .root_spki_sha256
        .iter()
        .any(|pin| Sha256::digest(root.spki).as_slice() == pin);
    if !root_pinned && !any_device {
        return Err(reject(
            "untrusted_root",
            "chain does not end at a Google attestation root",
        ));
    }
    // The leaf's validity is the key's, which Android sets loosely; freshness
    // comes from the attested creation time instead.
    if let Some(index) = chain
        .iter()
        .skip(1)
        .position(|cert| now < cert.not_before || now > cert.not_after)
    {
        return Err(reject(
            "invalid_chain",
            format!("certificate {} is outside its validity period", index + 1),
        ));
    }

    let mut descriptions = leaf
        .extensions
        .iter()
        .filter(|(oid, _)| *oid == KEY_ATTESTATION_OID);
    let (Some((_, description)), None) = (descriptions.next(), descriptions.next()) else {
        return Err(reject(
            "no_attestation",
            "leaf has no single Android key attestation extension",
        ));
    };
    let parsed = parse_description(description)
        .ok_or_else(|| reject("invalid_attestation", "key description does not parse"))?;

    if parsed.challenge != challenge.as_slice() {
        return Err(reject("challenge_mismatch", "attested challenge differs"));
    }
    let attestation_level = level_name(parsed.attestation_level)
        .ok_or_else(|| reject("invalid_attestation", "unknown security level"))?;
    let keymint_level = level_name(parsed.keymint_level)
        .ok_or_else(|| reject("invalid_attestation", "unknown security level"))?;
    let hardware = parsed.attestation_level >= 1 && parsed.keymint_level >= 1;
    if !hardware && !any_device {
        return Err(reject(
            "insecure_key",
            format!("key is {keymint_level}/{attestation_level}, not hardware-backed"),
        ));
    }
    let software = &parsed.software;
    let enforced = if parsed.keymint_level >= 1 {
        &parsed.hardware
    } else {
        &parsed.software
    };

    let purposes_sign = enforced.get(TAG_PURPOSE).is_some_and(|set| {
        let mut reader = set.reader();
        std::iter::from_fn(|| reader.next()).any(|purpose| purpose.as_u64() == Some(PURPOSE_SIGN))
    });
    if !purposes_sign
        || enforced.int(TAG_ALGORITHM) != Some(ALGORITHM_EC)
        || enforced.int(TAG_EC_CURVE) != Some(CURVE_P256)
    {
        return Err(reject("wrong_key_type", "key is not a P-256 signing key"));
    }
    if enforced.int(TAG_ORIGIN) != Some(ORIGIN_GENERATED) {
        return Err(reject(
            "imported_key",
            "key was not generated on the device",
        ));
    }
    if enforced.has(TAG_NO_AUTH_REQUIRED) || software.has(TAG_NO_AUTH_REQUIRED) {
        return Err(reject(
            "no_user_auth",
            "key does not require user authentication",
        ));
    }
    let auth_type = enforced.int(TAG_USER_AUTH_TYPE).unwrap_or(0);
    if auth_type & AUTH_TYPE_BIOMETRIC == 0 || auth_type & AUTH_TYPE_PASSWORD != 0 {
        return Err(reject(
            "not_biometric_only",
            "key must require strong biometric authentication only",
        ));
    }
    let timeout = |list: &Authorizations| list.get(TAG_AUTH_TIMEOUT).map(|tlv| tlv.as_u64());
    if [timeout(enforced), timeout(software)]
        .iter()
        .any(|value| matches!(value, Some(value) if *value != Some(0)))
    {
        return Err(reject(
            "not_per_use",
            "key allows use without authentication for each signature",
        ));
    }
    if !any_device {
        let root_of_trust = enforced
            .get(TAG_ROOT_OF_TRUST)
            .and_then(parse_root_of_trust);
        if root_of_trust != Some((true, BOOT_STATE_VERIFIED)) {
            return Err(reject(
                "unverified_boot",
                "device bootloader is unlocked or boot is not verified",
            ));
        }
    }
    let created_ms = enforced
        .int(TAG_CREATION_DATETIME)
        .or_else(|| software.int(TAG_CREATION_DATETIME))
        .ok_or_else(|| reject("stale_attestation", "attestation has no key creation time"))?;
    let skew = (now * 1000).abs_diff(i64::try_from(created_ms).unwrap_or(i64::MAX));
    if skew > MAX_CREATION_SKEW_MS as u64 {
        return Err(reject(
            "stale_attestation",
            "key was not created within 10 minutes of this machine's clock",
        ));
    }

    let application = software
        .get(TAG_APPLICATION_ID)
        .or_else(|| enforced.get(TAG_APPLICATION_ID))
        .and_then(|tlv| parse_application_id(tlv.value))
        .ok_or_else(|| reject("unknown_app", "attestation has no application id"))?;
    let [package] = application.packages.as_slice() else {
        return Err(reject("unknown_app", "key must belong to exactly one app"));
    };
    let package_pinned = pins.packages.iter().any(|name| name == package);
    let package_dev = DEV_PACKAGES.contains(&package.as_str());
    if !(package_pinned || trust != Trust::Release && package_dev) {
        return Err(reject(
            "unknown_app",
            format!("app {package} is not a pinned T3 app"),
        ));
    }
    if application.digests.is_empty() {
        return Err(reject(
            "unknown_app",
            "attestation has no signing certificate digest",
        ));
    }
    if trust != Trust::Test {
        let mut accepted = pins.signing_digests.clone();
        if trust == Trust::Dev {
            accepted.extend(&pins.dev_signing_digests);
        }
        if accepted.is_empty() {
            return Err(reject(
                "signing_digest_not_pinned",
                match trust {
                    Trust::Dev => {
                        "this helper was built without a pinned T3 app signing digest, release or dev"
                    }
                    _ => {
                        "this helper was built without a pinned T3 app signing digest; use --allow-dev-attestation with a dev build"
                    }
                },
            ));
        }
        if !application.digests.iter().all(|digest| {
            accepted
                .iter()
                .any(|pin| pin.as_slice() == digest.as_slice())
        }) {
            return Err(reject(
                "unknown_app",
                "app is not signed with a pinned T3 certificate",
            ));
        }
    }
    Ok(Verified {
        security_level: keymint_level,
        package_name: package.clone(),
        signing_cert_digest: b64::encode(&application.digests[0]),
        trust,
    })
}

struct Description<'a> {
    attestation_level: u64,
    keymint_level: u64,
    challenge: &'a [u8],
    software: Authorizations<'a>,
    hardware: Authorizations<'a>,
}

fn parse_description(bytes: &[u8]) -> Option<Description<'_>> {
    let mut outer = Reader::new(bytes);
    let mut fields = outer.universal(der::SEQUENCE)?.reader();
    fields.universal(der::INTEGER)?;
    let attestation_level = fields.universal(der::ENUMERATED)?.as_u64()?;
    fields.universal(der::INTEGER)?;
    let keymint_level = fields.universal(der::ENUMERATED)?.as_u64()?;
    let challenge = fields.universal(der::OCTET_STRING)?.value;
    fields.universal(der::OCTET_STRING)?;
    let software = Authorizations::parse(fields.universal(der::SEQUENCE)?)?;
    let hardware = Authorizations::parse(fields.universal(der::SEQUENCE)?)?;
    Some(Description {
        attestation_level,
        keymint_level,
        challenge,
        software,
        hardware,
    })
}

/// (deviceLocked, verifiedBootState).
fn parse_root_of_trust(tlv: &Tlv) -> Option<(bool, u64)> {
    let mut fields = tlv.reader();
    fields.universal(der::OCTET_STRING)?;
    let locked = fields.universal(der::BOOLEAN)?.value == [0xff];
    let state = fields.universal(der::ENUMERATED)?.as_u64()?;
    Some((locked, state))
}

struct Application {
    packages: Vec<String>,
    digests: Vec<Vec<u8>>,
}

fn parse_application_id(bytes: &[u8]) -> Option<Application> {
    let mut outer = Reader::new(bytes);
    let mut fields = outer.universal(der::SEQUENCE)?.reader();
    let infos = fields.universal(der::SET)?.reader();
    let mut packages = Vec::new();
    for info in infos {
        let mut parts = info.reader();
        packages.push(String::from_utf8(parts.universal(der::OCTET_STRING)?.value.to_vec()).ok()?);
    }
    let set = fields.universal(der::SET)?.reader();
    let mut digests = Vec::new();
    for digest in set {
        if digest.number != der::OCTET_STRING {
            return None;
        }
        digests.push(digest.value.to_vec());
    }
    Some(Application { packages, digests })
}

/// Fake attestation chains for tests and the VM test server. A chain from here
/// never verifies without `--allow-test-attestation`: its root isn't Google's.
#[cfg(any(test, feature = "fixtures"))]
pub mod fixture {
    use crate::der::write::*;
    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::pkcs8::EncodePublicKey as _;

    #[derive(Clone)]
    pub struct Options {
        pub attestation_level: u64,
        pub keymint_level: u64,
        pub challenge: Vec<u8>,
        pub created_ms: u64,
        pub user_auth_type: Option<u64>,
        pub auth_timeout: Option<u64>,
        pub no_auth_required: bool,
        pub origin: u64,
        pub purpose: u64,
        pub package: String,
        pub digest: Vec<u8>,
        pub device_locked: bool,
    }

    impl Options {
        pub fn new(challenge: &[u8], now: i64) -> Self {
            Self {
                attestation_level: 1,
                keymint_level: 1,
                challenge: challenge.to_vec(),
                created_ms: (now as u64) * 1000,
                user_auth_type: Some(2),
                auth_timeout: None,
                no_auth_required: false,
                origin: 0,
                purpose: 2,
                package: "com.t3tools.t3code.dev".into(),
                digest: vec![0xab; 32],
                device_locked: true,
            }
        }
    }

    fn name(common_name: &str) -> Vec<u8> {
        seq(&[set(&[seq(&[
            oid(&[0x55, 0x04, 0x03]),
            tlv(0, false, 12, common_name.as_bytes()),
        ])])])
    }

    const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

    fn certificate(
        issuer: &str,
        subject: &str,
        spki: &[u8],
        extensions: Option<Vec<u8>>,
        signer: &SigningKey,
    ) -> Vec<u8> {
        let mut tbs_parts = vec![
            explicit(0, &int(2)),
            int(1),
            seq(&[oid(ECDSA_SHA256)]),
            name(issuer),
            seq(&[
                tlv(0, false, 23, b"250101000000Z"),
                tlv(0, false, 23, b"491231235959Z"),
            ]),
            name(subject),
            spki.to_vec(),
        ];
        if let Some(extensions) = extensions {
            tbs_parts.push(explicit(3, &seq(&[extensions])));
        }
        let tbs = seq(&tbs_parts);
        let signature: Signature = signer.sign(&tbs);
        seq(&[
            tbs,
            seq(&[oid(ECDSA_SHA256)]),
            bits(signature.to_der().as_bytes()),
        ])
    }

    fn description(options: &Options) -> Vec<u8> {
        let mut enforced = vec![
            explicit(1, &set(&[int(options.purpose)])),
            explicit(2, &int(3)),
            explicit(10, &int(1)),
        ];
        if options.no_auth_required {
            enforced.push(explicit(503, &null()));
        }
        if let Some(auth_type) = options.user_auth_type {
            enforced.push(explicit(504, &int(auth_type)));
        }
        if let Some(timeout) = options.auth_timeout {
            enforced.push(explicit(505, &int(timeout)));
        }
        enforced.push(explicit(702, &int(options.origin)));
        enforced.push(explicit(
            704,
            &seq(&[
                octets(&[0; 32]),
                boolean(options.device_locked),
                enumerated(0),
                octets(&[0; 32]),
            ]),
        ));
        let application = seq(&[
            set(&[seq(&[octets(options.package.as_bytes()), int(1)])]),
            set(&[octets(&options.digest)]),
        ]);
        let software = vec![
            explicit(701, &int(options.created_ms)),
            explicit(709, &octets(&application)),
        ];
        let (software, hardware) = if options.keymint_level == 0 {
            ([software, enforced].concat(), vec![])
        } else {
            (software, enforced)
        };
        seq(&[
            int(300),
            enumerated(options.attestation_level),
            int(300),
            enumerated(options.keymint_level),
            octets(&options.challenge),
            octets(&[]),
            seq(&software),
            seq(&hardware),
        ])
    }

    /// `[leaf, root]` for `leaf_spki`, signed by a fixed fixture CA.
    pub fn chain(leaf_spki: &[u8], options: &Options) -> Vec<Vec<u8>> {
        let ca = SigningKey::from_slice(&[0x5a; 32]).expect("valid scalar");
        let ca_spki = ca
            .verifying_key()
            .to_public_key_der()
            .expect("spki")
            .into_vec();
        let extension = seq(&[
            oid(super::KEY_ATTESTATION_OID),
            octets(&description(options)),
        ]);
        let leaf = certificate(
            "t3 fixture root",
            "Android Keystore Key",
            leaf_spki,
            Some(extension),
            &ca,
        );
        let root = certificate("t3 fixture root", "t3 fixture root", &ca_spki, None, &ca);
        vec![leaf, root]
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{Options, chain};
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePublicKey as _;

    const NOW: i64 = 1_793_318_400;

    fn enrollment(options: &Options, key: &SigningKey) -> Enrollment {
        let spki = key.verifying_key().to_public_key_der().unwrap().into_vec();
        Enrollment {
            label: "Pixel".into(),
            public_key: b64::encode(&spki),
            challenge: b64::encode(&[7; 32]),
            attestation_chain: chain(&spki, options)
                .iter()
                .map(|cert| b64::encode(cert))
                .collect(),
        }
    }

    fn key() -> SigningKey {
        SigningKey::from_slice(&[0x33; 32]).unwrap()
    }

    fn dev_pins() -> Pins {
        Pins {
            root_spki_sha256: vec![],
            packages: vec!["com.t3tools.t3code".into()],
            signing_digests: vec![],
            dev_signing_digests: vec![],
        }
    }

    fn check(options: &Options, trust: Trust) -> Result<Verified, &'static str> {
        verify(&enrollment(options, &key()), NOW, &dev_pins(), trust)
            .map_err(|rejected| rejected.code)
    }

    #[test]
    fn accepts_a_fixture_chain_only_with_the_test_flag() {
        let options = Options::new(&[7; 32], NOW);
        let verified = check(&options, Trust::Test).unwrap();
        assert_eq!(verified.security_level, "tee");
        assert_eq!(verified.package_name, "com.t3tools.t3code.dev");
        assert_eq!(verified.trust, Trust::Test);
        assert_eq!(check(&options, Trust::Dev), Err("untrusted_root"));
        assert_eq!(check(&options, Trust::Release), Err("untrusted_root"));
    }

    /// Pins whose root is the fixture's, standing in for Google's.
    fn pinned_root(options: &Options) -> Pins {
        let spki = key()
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .into_vec();
        let root = chain(&spki, options)[1].clone();
        let root = parse_certificate(&root).unwrap();
        let mut pins = dev_pins();
        pins.root_spki_sha256 = vec![Sha256::digest(root.spki).into()];
        pins
    }

    fn check_pinned(options: &Options, pins: &Pins, trust: Trust) -> Result<Trust, &'static str> {
        verify(&enrollment(options, &key()), NOW, pins, trust)
            .map(|verified| verified.trust)
            .map_err(|rejected| rejected.code)
    }

    #[test]
    fn pinned_root_still_needs_package_and_digest_pins() {
        let mut options = Options::new(&[7; 32], NOW);
        options.package = "com.t3tools.t3code".into();
        let mut pins = pinned_root(&options);
        assert_eq!(
            check_pinned(&options, &pins, Trust::Release),
            Err("signing_digest_not_pinned")
        );
        pins.signing_digests = vec![[0xab; 32]];
        assert_eq!(
            check_pinned(&options, &pins, Trust::Release),
            Ok(Trust::Release)
        );
        pins.signing_digests = vec![[0xcd; 32]];
        assert_eq!(
            check_pinned(&options, &pins, Trust::Release),
            Err("unknown_app")
        );
        options.package = "com.t3tools.t3code.dev".into();
        pins.signing_digests = vec![[0xab; 32]];
        assert_eq!(
            check_pinned(&options, &pins, Trust::Release),
            Err("unknown_app")
        );
    }

    /// Review finding 6: dev attestation is for debug builds on real phones,
    /// so it keeps every device check and widens only the app pins.
    #[test]
    fn dev_flag_widens_only_the_app_pins() {
        let options = Options::new(&[7; 32], NOW);
        let mut pins = pinned_root(&options);
        assert_eq!(
            check_pinned(&options, &pins, Trust::Dev),
            Err("signing_digest_not_pinned")
        );
        pins.signing_digests = vec![[0xcd; 32]];
        assert_eq!(
            check_pinned(&options, &pins, Trust::Dev),
            Err("unknown_app"),
            "a debug build's digest must be one this helper was built with"
        );
        pins.dev_signing_digests = vec![[0xab; 32]];
        assert_eq!(check_pinned(&options, &pins, Trust::Dev), Ok(Trust::Dev));
        assert_eq!(
            check_pinned(&options, &pins, Trust::Release),
            Err("unknown_app"),
            "dev digests and packages are not release pins"
        );
        let mut other_app = options.clone();
        other_app.package = "com.example.evil".into();
        assert_eq!(
            check_pinned(&other_app, &pins, Trust::Dev),
            Err("unknown_app")
        );
        let mut software = options.clone();
        software.attestation_level = 0;
        software.keymint_level = 0;
        assert_eq!(
            check_pinned(&software, &pins, Trust::Dev),
            Err("insecure_key")
        );
        let mut unlocked = options.clone();
        unlocked.device_locked = false;
        assert_eq!(
            check_pinned(&unlocked, &pins, Trust::Dev),
            Err("unverified_boot")
        );
        assert_eq!(check_pinned(&unlocked, &pins, Trust::Test), Ok(Trust::Test));
    }

    #[test]
    fn rejects_each_weak_property_even_with_the_test_flag() {
        let base = Options::new(&[7; 32], NOW);
        type Case = (&'static str, Box<dyn Fn(&mut Options)>);
        let cases: Vec<Case> = vec![
            (
                "challenge_mismatch",
                Box::new(|o| o.challenge = vec![8; 32]),
            ),
            (
                "stale_attestation",
                Box::new(|o| o.created_ms -= 11 * 60 * 1000),
            ),
            (
                "stale_attestation",
                Box::new(|o| o.created_ms += 11 * 60 * 1000),
            ),
            (
                "not_biometric_only",
                Box::new(|o| o.user_auth_type = Some(3)),
            ),
            ("not_biometric_only", Box::new(|o| o.user_auth_type = None)),
            ("not_per_use", Box::new(|o| o.auth_timeout = Some(30))),
            ("no_user_auth", Box::new(|o| o.no_auth_required = true)),
            ("imported_key", Box::new(|o| o.origin = 2)),
            ("wrong_key_type", Box::new(|o| o.purpose = 3)),
            (
                "unknown_app",
                Box::new(|o| o.package = "com.example.evil".into()),
            ),
        ];
        for (expected, mutate) in cases {
            let mut options = base.clone();
            mutate(&mut options);
            assert_eq!(check(&options, Trust::Test).map(|_| ()), Err(expected));
        }
        let mut per_use_zero = base.clone();
        per_use_zero.auth_timeout = Some(0);
        assert!(check(&per_use_zero, Trust::Test).is_ok());
    }

    #[test]
    fn software_keys_and_unlocked_boot_need_the_test_flag() {
        let mut software = Options::new(&[7; 32], NOW);
        software.attestation_level = 0;
        software.keymint_level = 0;
        assert_eq!(
            check(&software, Trust::Test).unwrap().security_level,
            "software"
        );
        let mut unlocked = Options::new(&[7; 32], NOW);
        unlocked.device_locked = false;
        assert!(check(&unlocked, Trust::Test).is_ok());
    }

    #[test]
    fn rejects_key_substitution_and_broken_chains() {
        let options = Options::new(&[7; 32], NOW);
        let mut substituted = enrollment(&options, &key());
        let other = SigningKey::from_slice(&[0x44; 32]).unwrap();
        substituted.public_key = b64::encode(
            &other
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .into_vec(),
        );
        assert_eq!(
            verify(&substituted, NOW, &dev_pins(), Trust::Test).map_err(|r| r.code),
            Err("key_mismatch")
        );
        let mut tampered = enrollment(&options, &key());
        let mut leaf = b64::decode(&tampered.attestation_chain[0]).unwrap();
        let last = leaf.len() - 40;
        leaf[last] ^= 1;
        tampered.attestation_chain[0] = b64::encode(&leaf);
        assert!(verify(&tampered, NOW, &dev_pins(), Trust::Test).is_err());
        let mut short = enrollment(&options, &key());
        short.attestation_chain.truncate(1);
        assert_eq!(
            verify(&short, NOW, &dev_pins(), Trust::Test).map_err(|r| r.code),
            Err("invalid_chain")
        );
    }

    #[test]
    fn google_root_pins_match_the_published_roots() {
        assert_eq!(Pins::release().root_spki_sha256.len(), 2);
    }

    #[test]
    fn parses_time_formats() {
        let utc = Tlv {
            class: Class::Universal,
            constructed: false,
            number: 23,
            value: b"700101000000Z",
            raw: &[],
        };
        assert_eq!(parse_time(&utc), Some(0));
        let generalized = Tlv {
            class: Class::Universal,
            constructed: false,
            number: 24,
            value: b"20261030120000Z",
            raw: &[],
        };
        assert_eq!(parse_time(&generalized), Some(1_793_361_600));
    }
}
