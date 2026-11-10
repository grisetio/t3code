//! `/etc/t3-elevation/users/<user>.toml`.

use crate::MAX_SOCKET_PATH_BYTES;

pub const DEFAULT_WINDOW_SECONDS: i64 = 100;
pub const MIN_WINDOW_SECONDS: i64 = 10;
pub const MAX_WINDOW_SECONDS: i64 = 300;
/// Later sudos in an approved agent command that pass without the phone.
/// Remote commands hold up to 11 sudos; 0 asks the phone for every sudo.
pub const DEFAULT_SESSION_MAX_USES: u32 = 16;
pub const MAX_SESSION_MAX_USES: u32 = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserConfig {
    pub enabled: bool,
    pub socket: String,
    pub approval_window_seconds: i64,
    pub session_max_uses: u32,
    /// Passkeys a password manager syncs (backup eligible) may enroll and
    /// approve. Off by default: anyone with that account could approve.
    pub allow_synced_passkeys: bool,
}

/// None for anything the module must not act on: a version other than 1, a
/// missing or over-long socket path, or text that isn't TOML.
pub fn parse(text: &str) -> Option<UserConfig> {
    let table: toml::Table = text.parse().ok()?;
    if table.get("version")?.as_integer()? != 1 {
        return None;
    }
    let enabled = table.get("enabled")?.as_bool()?;
    let socket = table.get("socket")?.as_str()?.to_string();
    if !socket.starts_with('/') || socket.len() > MAX_SOCKET_PATH_BYTES || socket.contains('\0') {
        return None;
    }
    let approval_window_seconds = match table.get("approval_window_seconds") {
        None => DEFAULT_WINDOW_SECONDS,
        Some(value) => value
            .as_integer()?
            .clamp(MIN_WINDOW_SECONDS, MAX_WINDOW_SECONDS),
    };
    let session_max_uses = match table.get("session_max_uses") {
        None => DEFAULT_SESSION_MAX_USES,
        Some(value) => value
            .as_integer()?
            .clamp(0, i64::from(MAX_SESSION_MAX_USES)) as u32,
    };
    let allow_synced_passkeys = match table.get("allow_synced_passkeys") {
        None => false,
        Some(value) => value.as_bool()?,
    };
    Some(UserConfig {
        enabled,
        socket,
        approval_window_seconds,
        session_max_uses,
        allow_synced_passkeys,
    })
}

/// Optional keys appear only when they differ from their defaults, so a
/// rewrite keeps every setting `parse` read.
pub fn render(config: &UserConfig) -> String {
    let mut text = format!(
        "version = 1\nenabled = {}\nsocket = {}\napproval_window_seconds = {}\n",
        config.enabled,
        toml::Value::String(config.socket.clone()),
        config.approval_window_seconds
    );
    if config.session_max_uses != DEFAULT_SESSION_MAX_USES {
        text.push_str(&format!("session_max_uses = {}\n", config.session_max_uses));
    }
    if config.allow_synced_passkeys {
        text.push_str("allow_synced_passkeys = true\n");
    }
    text
}

/// User names that are safe in a file name and a sudoers `Defaults:` binding.
pub fn is_safe_user_name(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 64
        && !user.starts_with('-')
        && !user.starts_with('.')
        && user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_contract_example_and_clamps_window() {
        let config = parse(
            "version = 1\nenabled = true\nsocket = \"/Users/kgriset/.t3/userdata/elevation.sock\"\napproval_window_seconds = 100 # optional\nunknown = 3\n",
        )
        .unwrap();
        assert_eq!(config.approval_window_seconds, 100);
        assert!(config.enabled);
        let long =
            parse("version = 1\nenabled = true\nsocket = \"/s\"\napproval_window_seconds = 900\n")
                .unwrap();
        assert_eq!(long.approval_window_seconds, 300);
        let short =
            parse("version = 1\nenabled = true\nsocket = \"/s\"\napproval_window_seconds = 1\n")
                .unwrap();
        assert_eq!(short.approval_window_seconds, 10);
        let defaults = parse("version = 1\nenabled = true\nsocket = \"/s\"\n").unwrap();
        assert_eq!(
            (defaults.approval_window_seconds, defaults.session_max_uses),
            (100, 16)
        );
        let uses = |value: &str| {
            parse(&format!(
                "version = 1\nenabled = true\nsocket = \"/s\"\nsession_max_uses = {value}\n"
            ))
            .map(|config| config.session_max_uses)
        };
        assert_eq!(
            [uses("0"), uses("-3"), uses("500"), uses("\"x\"")],
            [Some(0), Some(0), Some(64), None]
        );
    }

    #[test]
    fn synced_passkeys_are_off_unless_the_config_allows_them() {
        let synced = |line: &str| {
            parse(&format!(
                "version = 1\nenabled = true\nsocket = \"/s\"\n{line}\n"
            ))
            .map(|config| config.allow_synced_passkeys)
        };
        assert_eq!(
            [
                synced(""),
                synced("allow_synced_passkeys = true"),
                synced("allow_synced_passkeys = false"),
                synced("allow_synced_passkeys = \"yes\""),
            ],
            [Some(false), Some(true), Some(false), None]
        );
    }

    #[test]
    fn rejects_other_versions_and_bad_sockets() {
        assert!(parse("version = 2\nenabled = true\nsocket = \"/s\"\n").is_none());
        assert!(parse("version = 1\nenabled = true\nsocket = \"relative\"\n").is_none());
        let long = format!(
            "version = 1\nenabled = true\nsocket = \"/{}\"\n",
            "a".repeat(100)
        );
        assert!(parse(&long).is_none());
    }

    #[test]
    fn render_round_trips() {
        let config = UserConfig {
            enabled: true,
            socket: "/home/a \"q\"/elevation.sock".into(),
            approval_window_seconds: 100,
            session_max_uses: DEFAULT_SESSION_MAX_USES,
            allow_synced_passkeys: false,
        };
        assert_eq!(parse(&render(&config)), Some(config.clone()));
        let changed = UserConfig {
            session_max_uses: 0,
            allow_synced_passkeys: true,
            ..config
        };
        assert_eq!(parse(&render(&changed)), Some(changed));
    }
}
