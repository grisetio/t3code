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
    fn zeroes_a_password_line_left_by_sudo() {
        let mut input = b"hunter2\nt3-elevation-input-v1\n{}".to_vec();
        assert_eq!(unframe_input(&mut input), Some(&b"{}"[..]));
        assert_eq!(&input[..8], &[0; 8]);

        let mut unframed = b"hunter2\n{}".to_vec();
        assert_eq!(unframe_input(&mut unframed), None);
        assert!(unframed.iter().all(|&byte| byte == 0));
    }
}
