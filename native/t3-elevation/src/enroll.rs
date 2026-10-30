//! The `enroll` argv grammar. Clients show "Add device" exactly when a
//! request's `command.argv` matches it (`parseElevationEnrollCommand`), so
//! the helper must accept nothing looser.

use crate::b64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollCommand {
    pub user: String,
    pub label: String,
    pub public_key: String,
    pub challenge: String,
    pub allow_dev_attestation: bool,
}

/// `<path>/t3-elevation enroll <options>`.
pub fn parse_command(argv: &[String]) -> Option<EnrollCommand> {
    let [program, subcommand, rest @ ..] = argv else { return None };
    (program.rsplit('/').next() == Some("t3-elevation") && subcommand == "enroll").then_some(())?;
    parse_options(rest)
}

/// The options after `enroll`: each at most once, any order, nothing else.
pub fn parse_options(rest: &[String]) -> Option<EnrollCommand> {
    let mut values: [Option<&String>; 4] = [None; 4];
    let mut allow_dev_attestation = false;
    let mut args = rest.iter();
    while let Some(option) = args.next() {
        if option == "--allow-dev-attestation" {
            if allow_dev_attestation {
                return None;
            }
            allow_dev_attestation = true;
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
    let [Some(user), Some(label), Some(public_key), Some(challenge)] = values else { return None };
    b64::decode(public_key)?;
    (b64::decode(challenge)?.len() == 32).then_some(())?;
    Some(EnrollCommand {
        user: user.clone(),
        label: label.clone(),
        public_key: public_key.clone(),
        challenge: challenge.clone(),
        allow_dev_attestation,
    })
}
