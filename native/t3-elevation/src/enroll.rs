//! The `enroll` argv grammar. Clients show "Add device" exactly when a
//! request's `command.argv` matches it (`parseElevationEnrollCommand`), so
//! the helper must accept nothing looser.

use crate::attestation::Trust;
use crate::b64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollCommand {
    pub user: String,
    pub label: String,
    pub public_key: String,
    pub challenge: String,
    pub trust: Trust,
}

/// `<path>/t3-elevation enroll <options>`.
pub fn parse_command(argv: &[String]) -> Option<EnrollCommand> {
    let [program, subcommand, rest @ ..] = argv else {
        return None;
    };
    (program.rsplit('/').next() == Some("t3-elevation") && subcommand == "enroll").then_some(())?;
    parse_options(rest)
}

/// The options after `enroll`: each at most once, any order, nothing else.
/// At most one of `--allow-dev-attestation` and `--allow-test-attestation`.
pub fn parse_options(rest: &[String]) -> Option<EnrollCommand> {
    let mut values: [Option<&String>; 4] = [None; 4];
    let mut trust = Trust::Release;
    let mut args = rest.iter();
    while let Some(option) = args.next() {
        if let Some(flag) = trust_flag(option) {
            if trust != Trust::Release {
                return None;
            }
            trust = flag;
            continue;
        }
        let slot = ["--user", "--label", "--public-key", "--challenge"]
            .iter()
            .position(|name| name == option)?;
        if values[slot].is_some() {
            return None;
        }
        values[slot] = Some(args.next()?);
    }
    let [Some(user), Some(label), Some(public_key), Some(challenge)] = values else {
        return None;
    };
    b64::decode(public_key)?;
    (b64::decode(challenge)?.len() == 32).then_some(())?;
    Some(EnrollCommand {
        user: user.clone(),
        label: label.clone(),
        public_key: public_key.clone(),
        challenge: challenge.clone(),
        trust,
    })
}

pub fn trust_flag(option: &str) -> Option<Trust> {
    match option {
        "--allow-dev-attestation" => Some(Trust::Dev),
        "--allow-test-attestation" => Some(Trust::Test),
        _ => None,
    }
}
