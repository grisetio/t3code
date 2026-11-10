//! The `enroll` argv grammar. Clients show "Add device" exactly when a
//! request's `command.argv` matches it (`parseElevationEnrollCommand`), so
//! the helper must accept nothing looser.

use crate::attestation::Trust;
use crate::b64;
use crate::keys::WebauthnBinding;
use serde::Deserialize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollCommand {
    pub user: String,
    pub label: String,
    pub public_key: String,
    pub proof: Proof,
}

/// What admits the key besides the approval itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Proof {
    /// Android key attestation over the phone's challenge.
    Attested { challenge: String, trust: Trust },
    /// `--unattested`: nothing proves where the key lives, so only the approval
    /// of this argv (an enrolled device showing its comparison code, or the
    /// password) admits it. With a site, the key is a WebAuthn credential.
    Unattested { site: Option<Site> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Site {
    pub rp_id: String,
    pub origin: String,
}

/// `<path>/t3-elevation enroll <options>`.
pub fn parse_command(argv: &[String]) -> Option<EnrollCommand> {
    let [program, subcommand, rest @ ..] = argv else {
        return None;
    };
    (program.rsplit('/').next() == Some("t3-elevation") && subcommand == "enroll").then_some(())?;
    parse_options(rest)
}

const VALUE_OPTIONS: [&str; 6] = [
    "--user",
    "--label",
    "--public-key",
    "--challenge",
    "--rp-id",
    "--origin",
];

/// The options after `enroll`: each at most once, any order, nothing else.
/// Attested: `--challenge` and at most one of `--allow-dev-attestation` and
/// `--allow-test-attestation`. Unattested: `--unattested`, and `--rp-id` with
/// `--origin` for a WebAuthn key; no challenge and no attestation option.
pub fn parse_options(rest: &[String]) -> Option<EnrollCommand> {
    let mut values: [Option<&String>; 6] = [None; 6];
    let mut trust = Trust::Release;
    let mut unattested = false;
    let mut args = rest.iter();
    while let Some(option) = args.next() {
        if let Some(flag) = trust_flag(option) {
            if trust != Trust::Release {
                return None;
            }
            trust = flag;
            continue;
        }
        if option == "--unattested" {
            if unattested {
                return None;
            }
            unattested = true;
            continue;
        }
        let slot = VALUE_OPTIONS.iter().position(|name| name == option)?;
        if values[slot].is_some() {
            return None;
        }
        values[slot] = Some(args.next()?);
    }
    let [
        Some(user),
        Some(label),
        Some(public_key),
        challenge,
        rp_id,
        origin,
    ] = values
    else {
        return None;
    };
    b64::decode(public_key)?;
    let proof = if unattested {
        if trust != Trust::Release || challenge.is_some() {
            return None;
        }
        let site = match (rp_id, origin) {
            (None, None) => None,
            (Some(rp_id), Some(origin)) => Some(webauthn_site(rp_id, origin)?),
            _ => return None,
        };
        Proof::Unattested { site }
    } else {
        let challenge = challenge?;
        if rp_id.is_some() || origin.is_some() {
            return None;
        }
        (b64::decode(challenge)?.len() == 32).then_some(())?;
        Proof::Attested {
            challenge: challenge.clone(),
            trust,
        }
    };
    Some(EnrollCommand {
        user: user.clone(),
        label: label.clone(),
        public_key: public_key.clone(),
        proof,
    })
}

pub fn trust_flag(option: &str) -> Option<Trust> {
    match option {
        "--allow-dev-attestation" => Some(Trust::Dev),
        "--allow-test-attestation" => Some(Trust::Test),
        _ => None,
    }
}

/// A host as a WebAuthn rpId can name it: lowercase DNS labels, not an IP.
fn is_host(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 253
        && text.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && !text
            .rsplit('.')
            .next()
            .is_some_and(|last| last.bytes().all(|b| b.is_ascii_digit()))
}

/// The origin exactly as a browser serializes it into clientDataJSON:
/// `https://host[:port]`, or `http://localhost[:port]`, with no default port,
/// path or trailing slash; and an rpId that is that host or a parent of it.
/// Anything else could never match an assertion, or would match too much.
pub fn webauthn_site(rp_id: &str, origin: &str) -> Option<Site> {
    let (scheme, authority) = origin.split_once("://")?;
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    let default_port = match (scheme, host) {
        ("https", _) => "443",
        ("http", "localhost") => "80",
        _ => return None,
    };
    if let Some(port) = port {
        let valid = !port.is_empty()
            && !port.starts_with('0')
            && port.bytes().all(|b| b.is_ascii_digit())
            && port.parse::<u16>().is_ok()
            && port != default_port;
        if !valid {
            return None;
        }
    }
    if !is_host(host) || !is_host(rp_id) {
        return None;
    }
    let covers = host == rp_id
        || host
            .strip_suffix(rp_id)
            .is_some_and(|prefix| prefix.ends_with('.'));
    covers.then(|| Site {
        rp_id: rp_id.to_string(),
        origin: origin.to_string(),
    })
}

/// The enrollment object for `--unattested`: no challenge and no chain, since
/// nothing could check them.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnattestedEnrollment {
    pub label: String,
    pub public_key: String,
    #[serde(default)]
    pub webauthn: Option<WebauthnEnrollment>,
}

/// A passkey's site, plus its registration's authenticator data, which only
/// enrollment reads: the key file keeps the site.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebauthnEnrollment {
    pub rp_id: String,
    pub origin: String,
    pub credential_id: String,
    pub authenticator_data: String,
}

impl WebauthnEnrollment {
    pub fn binding(&self) -> WebauthnBinding {
        WebauthnBinding {
            rp_id: self.rp_id.clone(),
            origin: self.origin.clone(),
            credential_id: self.credential_id.clone(),
        }
    }
}

const FLAG_BE: u8 = 0x08;
const FLAG_AT: u8 = 0x40;

/// Why a registration can't be enrolled (`elevationWebauthnRegistrationRefusal`
/// in packages/contracts). With `attestation: "none"` nothing signs this data,
/// so it only stops an honest mistake early; refusing BE in every assertion
/// (`check_webauthn`) is the guarantee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistrationRefusal {
    /// Backup eligible: the passkey can sync to devices nobody enrolled.
    Synced,
    /// Not this site's rpIdHash, no attested credential, or another credential.
    Invalid,
}

pub fn check_registration(
    authenticator_data: &[u8],
    rp_id: &str,
    credential_id: &[u8],
) -> Result<(), RegistrationRefusal> {
    use sha2::{Digest as _, Sha256};
    // rpIdHash, flags, signCount, then the attested credential: AAGUID and the ID's length.
    const ID_START: usize = 37 + 16 + 2;
    let data = authenticator_data;
    if data.len() < ID_START || data[..32] != Sha256::digest(rp_id.as_bytes())[..] {
        return Err(RegistrationRefusal::Invalid);
    }
    let flags = data[32];
    if flags & FLAG_AT == 0 {
        return Err(RegistrationRefusal::Invalid);
    }
    let id_len = usize::from(u16::from_be_bytes([data[53], data[54]]));
    if data.get(ID_START..ID_START + id_len) != Some(credential_id) {
        return Err(RegistrationRefusal::Invalid);
    }
    if flags & FLAG_BE != 0 {
        return Err(RegistrationRefusal::Synced);
    }
    Ok(())
}

/// WebAuthn allows credential IDs up to 1023 bytes.
const MAX_CREDENTIAL_ID_BYTES: usize = 1023;

/// The checks attestation would otherwise make on the label and key, plus a
/// valid site for a WebAuthn key. Returns the SPKI DER.
pub fn check_unattested(
    enrollment: &UnattestedEnrollment,
) -> Result<Vec<u8>, crate::attestation::Rejected> {
    use crate::attestation::{Rejected, label_ok};
    let reject = |code: &'static str, message: &str| Rejected {
        code,
        message: message.into(),
    };
    if !label_ok(&enrollment.label) {
        return Err(reject(
            "invalid_label",
            "label must be 1-100 characters without control characters",
        ));
    }
    let spki = b64::decode(&enrollment.public_key)
        .filter(|spki| crate::keys::parse_p256_spki(spki).is_some())
        .ok_or_else(|| reject("invalid_public_key", "publicKey is not a P-256 SPKI"))?;
    if let Some(binding) = &enrollment.webauthn {
        webauthn_site(&binding.rp_id, &binding.origin).ok_or_else(|| {
            reject(
                "invalid_site",
                "origin must be https://host[:port] or http://localhost[:port], and rpId that host or a parent of it",
            )
        })?;
        let credential_id = b64::decode(&binding.credential_id)
            .filter(|id| !id.is_empty() && id.len() <= MAX_CREDENTIAL_ID_BYTES)
            .ok_or_else(|| {
                reject(
                    "invalid_credential_id",
                    "credentialId must be 1-1023 bytes of base64url",
                )
            })?;
        let authenticator_data = b64::decode(&binding.authenticator_data).unwrap_or_default();
        match check_registration(&authenticator_data, &binding.rp_id, &credential_id) {
            Ok(()) => {}
            Err(RegistrationRefusal::Synced) => {
                return Err(reject(
                    "synced_passkey",
                    "this passkey syncs to other devices; only a passkey kept on one device can approve",
                ));
            }
            Err(RegistrationRefusal::Invalid) => {
                return Err(reject(
                    "invalid_passkey",
                    "authenticatorData isn't this credential's registration for this rpId",
                ));
            }
        }
    }
    Ok(spki)
}

/// The first line of `enroll`'s stdin. With `sudo -S`, sudo reads the
/// password line only when PAM asks for it (Touch ID or an enrolled phone
/// may approve instead), so the password may still come before the marker.
pub const INPUT_MARKER: &[u8] = b"t3-elevation-input-v1\n";

/// The bytes after the marker line, skipping at most one line before it.
/// That line may be the sudo password: it is zeroed, and so is the whole
/// input when there is no marker.
pub fn unframe_input(input: &mut [u8]) -> Option<&[u8]> {
    let start = if input.starts_with(INPUT_MARKER) {
        Some(0)
    } else {
        input
            .iter()
            .position(|&byte| byte == b'\n')
            .map(|newline| newline + 1)
            .filter(|&start| input[start..].starts_with(INPUT_MARKER))
    };
    let Some(start) = start else {
        wipe(input);
        return None;
    };
    wipe(&mut input[..start]);
    Some(&input[start + INPUT_MARKER.len()..])
}

fn wipe(bytes: &mut [u8]) {
    bytes.fill(0);
    std::hint::black_box(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sites_are_exact_origins_their_rp_id_covers() {
        let ok = |rp_id: &str, origin: &str| webauthn_site(rp_id, origin).is_some();
        assert!(ok("app.t3.codes", "https://app.t3.codes"));
        assert!(ok("t3.codes", "https://app.t3.codes"));
        assert!(ok(
            "mac.tail1234.ts.net",
            "https://mac.tail1234.ts.net:8443"
        ));
        assert!(ok("localhost", "http://localhost:3773"));
        assert!(ok("localhost", "https://localhost"));
        assert!(!ok("app.t3.codes", "https://t3.codes"));
        assert!(!ok("pp.t3.codes", "https://app.t3.codes"));
        assert!(!ok("app.t3.codes", "http://app.t3.codes"));
        assert!(!ok("app.t3.codes", "https://app.t3.codes/"));
        assert!(!ok("app.t3.codes", "https://app.t3.codes:443"));
        assert!(!ok("localhost", "http://localhost:80"));
        assert!(!ok("app.t3.codes", "https://app.t3.codes:0443"));
        assert!(!ok("app.t3.codes", "https://app.t3.codes:70000"));
        assert!(!ok("App.t3.codes", "https://App.t3.codes"));
        assert!(!ok("192.168.1.20", "https://192.168.1.20"));
        assert!(!ok("", "https://app.t3.codes"));
        assert!(!ok("app.t3.codes", "https://user@app.t3.codes"));
        assert!(!ok("app.t3.codes", "t3code://app.t3.codes"));
    }

    #[test]
    fn zeroes_a_password_line_left_by_sudo() {
        let mut input = b"hunter2\nt3-elevation-input-v1\n{}".to_vec();
        assert_eq!(unframe_input(&mut input), Some(&b"{}"[..]));
        assert_eq!(&input[..8], &[0; 8]);

        let mut unframed = b"hunter2\n{}".to_vec();
        assert_eq!(unframe_input(&mut unframed), None);
        assert!(unframed.iter().all(|&byte| byte == 0));
    }
}
