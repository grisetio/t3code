//! Just enough of sudoers to know sudo's `secure_path`, which decides where a
//! program without a slash is found. Bindings we can't evaluate make the
//! result uncertain rather than guessed.

use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Applies {
    Yes,
    No,
    Maybe,
}

pub struct Subject<'a> {
    pub user: &'a str,
    pub uid: u32,
    pub groups: &'a [String],
    pub host: &'a str,
    pub run_as: &'a str,
}

/// A scalar or boolean Defaults setting as sudoers leaves it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Setting {
    /// Never mentioned: sudo's compiled-in default.
    Default,
    /// `!name`.
    Negated,
    /// `name=value`, or `name` alone for a flag (empty value).
    Value(String),
}

/// Every value `name` may end up with for `subject`.
pub fn setting(root: &Path, subject: &Subject, name: &str) -> Vec<Setting> {
    let lines = defaults_lines(root);
    // sudo applies Defaults by binding type, in file order within a type.
    let mut ordered: Vec<(u8, Applies, Setting)> = Vec::new();
    for line in &lines {
        if let Some(entry) = defaults_setting(line, subject, name) {
            ordered.push(entry);
        }
    }
    ordered.sort_by_key(|(rank, _, _)| *rank);
    let mut possible = vec![Setting::Default];
    for (_, applies, value) in ordered {
        match applies {
            Applies::Yes => possible = vec![value],
            Applies::Maybe => {
                if !possible.contains(&value) {
                    possible.push(value);
                }
            }
            Applies::No => {}
        }
    }
    possible
}

/// Every value `secure_path` may end up with; `None` means unset.
pub fn secure_path(root: &Path, subject: &Subject) -> Vec<Option<String>> {
    let mut possible = Vec::new();
    for value in setting(root, subject, "secure_path") {
        let value = match value {
            Setting::Value(path) => Some(path),
            Setting::Default | Setting::Negated => None,
        };
        if !possible.contains(&value) {
            possible.push(value);
        }
    }
    possible
}

enum ListOp {
    Set(Vec<String>),
    Add(Vec<String>),
    Remove(Vec<String>),
    Clear,
}

/// Every entry list setting `name` (`env_keep`, `env_check`) may hold for
/// `subject` running `command`, starting from sudo's compiled-in `initial`.
/// An uncertain binding may add entries but never removes any.
fn list_setting(
    lines: &[String],
    subject: &Subject,
    command: Option<&Path>,
    name: &str,
    initial: &[&str],
) -> Vec<String> {
    let mut ordered: Vec<(u8, Applies, ListOp)> = Vec::new();
    for line in lines {
        let Some((rank, applies, params)) = binding(line, subject, command) else {
            continue;
        };
        for param in split_params(params) {
            let param = param.trim();
            if param.strip_prefix('!').map(str::trim) == Some(name) {
                ordered.push((rank, applies.clone(), ListOp::Clear));
                continue;
            }
            let Some(rest) = param.strip_prefix(name).map(str::trim_start) else {
                continue;
            };
            let words = |value: &str| -> Vec<String> {
                value
                    .trim()
                    .trim_matches('"')
                    .split_whitespace()
                    .map(str::to_string)
                    .collect()
            };
            let op = if let Some(value) = rest.strip_prefix("+=") {
                ListOp::Add(words(value))
            } else if let Some(value) = rest.strip_prefix("-=") {
                ListOp::Remove(words(value))
            } else if let Some(value) = rest.strip_prefix('=') {
                ListOp::Set(words(value))
            } else {
                continue;
            };
            ordered.push((rank, applies.clone(), op));
        }
    }
    ordered.sort_by_key(|(rank, _, _)| *rank);
    let mut entries: Vec<String> = initial.iter().map(|entry| entry.to_string()).collect();
    for (_, applies, op) in ordered {
        match (applies, op) {
            (Applies::No, _) => {}
            (Applies::Yes, ListOp::Set(values)) => entries = values,
            (Applies::Yes, ListOp::Clear) => entries.clear(),
            (Applies::Yes, ListOp::Remove(values)) => {
                entries.retain(|entry| !values.contains(entry))
            }
            (_, ListOp::Add(values) | ListOp::Set(values)) => entries.extend(values),
            (Applies::Maybe, ListOp::Remove(_) | ListOp::Clear) => {}
        }
    }
    entries
}

/// sudo's compiled-in lists, the same in sudo.ws and sudo-rs.
const INITIAL_ENV_KEEP: &[&str] = &[
    "COLORS",
    "DISPLAY",
    "HOSTNAME",
    "KRB5CCNAME",
    "LS_COLORS",
    "PATH",
    "PS1",
    "PS2",
    "XAUTHORITY",
    "XAUTHORIZATION",
    "XDG_CURRENT_DESKTOP",
];
const INITIAL_ENV_CHECK: &[&str] = &[
    "COLORTERM",
    "LANG",
    "LANGUAGE",
    "LC_*",
    "LINGUAS",
    "TERM",
    "TZ",
];

/// Variables the platforms keep by default whose values don't point root's
/// code at the caller's files: display, locale, terminal and agent sockets.
/// Terminfo is only parsed, never run.
const HARMLESS_ENV: &[&str] = &[
    "BLOCKSIZE",
    "CHARSET",
    "COLORFGBG",
    "COLORS",
    "COLORTERM",
    "COLUMNS",
    "DISPLAY",
    "HISTSIZE",
    "HOSTNAME",
    "KRB5CCNAME",
    "LANG",
    "LANGUAGE",
    "LC_*",
    "LINES",
    "LINGUAS",
    "LSCOLORS",
    "LS_COLORS",
    "MAIL",
    "PS1",
    "PS2",
    "SSH_AUTH_SOCK",
    "TERM",
    "TERMINFO",
    "TERMINFO_DIRS",
    "TZ",
    "USERNAME",
    "XAUTHORITY",
    "XAUTHORIZATION",
    "XDG_CURRENT_DESKTOP",
    "_XKB_CHARSET",
    "__CF_USER_TEXT_ENCODING",
];

/// sudo's env list patterns: `*` matches any run of characters, and a
/// `NAME=value` entry is treated as matching the name alone.
fn env_pattern_matches(pattern: &str, name: &str) -> bool {
    let pattern = pattern.split_once('=').map_or(pattern, |(name, _)| name);
    fn glob(pattern: &[u8], name: &[u8]) -> bool {
        match pattern.split_first() {
            None => name.is_empty(),
            Some((b'*', rest)) => (0..=name.len()).any(|skip| glob(rest, &name[skip..])),
            Some((byte, rest)) => name.first() == Some(byte) && glob(rest, &name[1..]),
        }
    }
    glob(pattern.as_bytes(), name.as_bytes())
}

/// The caller's variables, from `env`, that sudo may pass to `command`
/// outside the harmless set. The payload can't show them, so they are the
/// caller's input to root's code. `secure_path` set means PATH is replaced.
pub fn kept_variables(
    root: &Path,
    subject: &Subject,
    command: Option<&Path>,
    env: &[(String, String)],
    secure_path: bool,
) -> Vec<String> {
    let lines = defaults_lines(root);
    // sudo-rs always resets; sudo.ws without env_reset passes everything
    // except its delete list.
    let reset_off = setting(root, subject, "env_reset").contains(&Setting::Negated);
    let keep = list_setting(&lines, subject, command, "env_keep", INITIAL_ENV_KEEP);
    let check = list_setting(&lines, subject, command, "env_check", INITIAL_ENV_CHECK);
    let mut kept = Vec::new();
    for (name, value) in env {
        let listed = |list: &[String]| {
            list.iter()
                .any(|pattern| env_pattern_matches(pattern, name))
        };
        // Both sudos drop exported shell functions.
        let passes = !value.starts_with("()")
            && (reset_off || listed(&keep) || (listed(&check) && !value.contains(['/', '%'])));
        if passes
            && !(secure_path && name == "PATH")
            && !HARMLESS_ENV
                .iter()
                .any(|pattern| env_pattern_matches(pattern, name))
            && !kept.contains(name)
        {
            kept.push(name.clone());
        }
    }
    kept
}

/// Every `Defaults` line reachable from `root`, includes followed.
pub fn defaults_lines(root: &Path) -> Vec<String> {
    let mut lines = Vec::new();
    collect(root, 0, &mut lines);
    lines
}

fn collect(path: &Path, depth: usize, out: &mut Vec<String>) {
    if depth > 8 {
        return;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let mut joined = String::new();
    for raw in text.lines() {
        if let Some(stripped) = raw.strip_suffix('\\') {
            joined.push_str(stripped);
            joined.push(' ');
            continue;
        }
        joined.push_str(raw);
        let line = std::mem::take(&mut joined);
        let trimmed = line.trim();
        if let Some(target) = include_target(trimmed, "include") {
            collect(&relative_to(path, &target), depth + 1, out);
        } else if let Some(target) = include_target(trimmed, "includedir") {
            let dir = relative_to(path, &target);
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            let mut names: Vec<String> = entries
                .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
                .filter(|name| !name.ends_with('~') && !name.contains('.'))
                .collect();
            names.sort();
            for name in names {
                collect(&dir.join(name), depth + 1, out);
            }
        } else if trimmed.starts_with("Defaults") {
            out.push(strip_comment(trimmed).to_string());
        }
    }
}

fn include_target(line: &str, directive: &str) -> Option<String> {
    let rest = line
        .strip_prefix('#')
        .or_else(|| line.strip_prefix('@'))?
        .strip_prefix(directive)?;
    if !rest.starts_with([' ', '\t']) {
        return None;
    }
    let target = rest.trim().trim_matches('"');
    (!target.is_empty()).then(|| target.to_string())
}

fn relative_to(file: &Path, target: &str) -> PathBuf {
    if target.starts_with('/') {
        PathBuf::from(target)
    } else {
        file.parent().unwrap_or(Path::new("/")).join(target)
    }
}

fn strip_comment(line: &str) -> &str {
    let mut quoted = false;
    for (index, ch) in line.char_indices() {
        match ch {
            '"' => quoted = !quoted,
            '#' if !quoted => return line[..index].trim_end(),
            _ => {}
        }
    }
    line
}

/// A `Defaults` line's binding: the pass sudo applies it in (global, host,
/// user, runas, command), whether it binds `subject` running `command`, and
/// its parameters. Without a command, a command binding is uncertain.
fn binding<'a>(
    line: &'a str,
    subject: &Subject,
    command: Option<&Path>,
) -> Option<(u8, Applies, &'a str)> {
    let rest = line.strip_prefix("Defaults")?;
    Some(match rest.chars().next()? {
        c if c.is_whitespace() => (0, Applies::Yes, rest),
        binding @ (':' | '@' | '>' | '!') => {
            let body = &rest[1..];
            let end = body.find(char::is_whitespace).unwrap_or(body.len());
            let list = &body[..end];
            let (rank, applies) = match binding {
                '@' => (1, list_applies(list, |item| item == subject.host)),
                ':' => (2, user_list_applies(list, subject)),
                '>' => (3, list_applies(list, |item| item == subject.run_as)),
                _ => (4, command_list_applies(list, command)),
            };
            (rank, applies, &body[end..])
        }
        _ => return None,
    })
}

/// `Defaults!` lists name commands by path; sudo also matches the same file
/// under another name (`/usr/sbin` → `/usr/bin`). Aliases, globs, arguments
/// and negations are left uncertain.
fn command_list_applies(list: &str, command: Option<&Path>) -> Applies {
    let mut result = Applies::No;
    for item in list.split(',').map(str::trim) {
        if item == "ALL" {
            return Applies::Yes;
        }
        let Some(command) = command else {
            return Applies::Maybe;
        };
        if !item.starts_with('/') || item.contains(['*', '?', '[', '\\']) {
            return Applies::Maybe;
        }
        let same_file = |a: &Path, b: &Path| match (std::fs::metadata(a), std::fs::metadata(b)) {
            (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
            _ => false,
        };
        let in_dir =
            item.ends_with('/') && command.parent() == Some(Path::new(item.trim_end_matches('/')));
        if Path::new(item) == command || in_dir || same_file(Path::new(item), command) {
            result = Applies::Yes;
        }
    }
    result
}

fn defaults_setting(line: &str, subject: &Subject, name: &str) -> Option<(u8, Applies, Setting)> {
    let (rank, applies, params) = binding(line, subject, None)?;
    let mut found = None;
    for param in split_params(params) {
        let param = param.trim();
        if let Some(rest) = param.strip_prefix(name) {
            let rest = rest.trim_start();
            if rest.is_empty() {
                found = Some(Setting::Value(String::new()));
            } else if let Some(value) = rest.strip_prefix('=') {
                found = Some(Setting::Value(value.trim().trim_matches('"').to_string()));
            }
        } else if param.strip_prefix('!').map(str::trim) == Some(name) {
            found = Some(Setting::Negated);
        }
    }
    found.map(|value| (rank, applies, value))
}

fn split_params(params: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut quoted = false;
    let mut start = 0;
    for (index, ch) in params.char_indices() {
        match ch {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                parts.push(&params[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&params[start..]);
    parts
}

fn list_applies(list: &str, matches: impl Fn(&str) -> bool) -> Applies {
    let mut result = Applies::No;
    for item in list.split(',').map(str::trim) {
        if item == "ALL" || matches(item) {
            result = Applies::Yes;
        } else if item.starts_with('!')
            || item.starts_with('+')
            || item
                .chars()
                .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
        {
            // Negations, netgroups and aliases.
            return Applies::Maybe;
        }
    }
    result
}

fn user_list_applies(list: &str, subject: &Subject) -> Applies {
    list_applies(list, |item| {
        if let Some(group) = item.strip_prefix('%') {
            subject.groups.iter().any(|name| name == group)
        } else if let Some(uid) = item.strip_prefix('#') {
            uid.parse::<u32>().ok() == Some(subject.uid)
        } else {
            item == subject.user
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject<'a>(groups: &'a [String]) -> Subject<'a> {
        Subject {
            user: "alice",
            uid: 1000,
            groups,
            host: "box",
            run_as: "root",
        }
    }

    fn with_files(name: &str, files: &[(&str, &str)]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("t3e-sudoers-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sudoers.d")).unwrap();
        for (name, text) in files {
            std::fs::write(dir.join(name), text).unwrap();
        }
        dir
    }

    #[test]
    fn global_user_and_includes() {
        let dir = with_files(
            "includes",
            &[
                (
                    "sudoers",
                    "Defaults env_reset\nDefaults\tsecure_path=\"/usr/sbin:/usr/bin\" # comment\n@includedir sudoers.d\n",
                ),
                (
                    "sudoers.d/a",
                    "Defaults:alice secure_path=/opt/bin:\\\n/usr/bin\n",
                ),
                ("sudoers.d/b.disabled", "Defaults secure_path=/ignored\n"),
            ],
        );
        let groups = vec![];
        assert_eq!(
            secure_path(&dir.join("sudoers"), &subject(&groups)),
            vec![Some("/opt/bin: /usr/bin".to_string())]
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn user_binding_wins_regardless_of_order() {
        let dir = with_files(
            "order",
            &[(
                "sudoers",
                "Defaults:%wheel !secure_path\nDefaults secure_path=\"/sbin\"\nDefaults:bob secure_path=/x\n",
            )],
        );
        let groups = vec!["wheel".to_string()];
        assert_eq!(
            secure_path(&dir.join("sudoers"), &subject(&groups)),
            vec![None]
        );
        let none = vec![];
        assert_eq!(
            secure_path(&dir.join("sudoers"), &subject(&none)),
            vec![Some("/sbin".to_string())]
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn aliases_make_it_uncertain() {
        let dir = with_files(
            "aliases",
            &[(
                "sudoers",
                "Defaults secure_path=/a\nDefaults:ADMINS secure_path=/b\n",
            )],
        );
        let groups = vec![];
        assert_eq!(
            secure_path(&dir.join("sudoers"), &subject(&groups)),
            vec![Some("/a".to_string()), Some("/b".to_string())]
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn flags_and_negation() {
        let dir = with_files(
            "flags",
            &[(
                "sudoers",
                "Defaults ignore_dot_x\nDefaults:alice !ignore_dot\nDefaults runchroot=*\n",
            )],
        );
        let groups = vec![];
        let sudoers = dir.join("sudoers");
        assert_eq!(
            setting(&sudoers, &subject(&groups), "ignore_dot"),
            vec![Setting::Negated]
        );
        assert_eq!(
            setting(&sudoers, &subject(&groups), "runchroot"),
            vec![Setting::Value("*".into())]
        );
        assert_eq!(
            setting(&sudoers, &subject(&groups), "env_editor"),
            vec![Setting::Default]
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Review 2, G4: with `Defaults env_keep += "PYTHONPATH"`,
    /// `PYTHONPATH=~/lib sudo python3 -c pass` ran the user's sitecustomize
    /// as root while the payload showed nothing in red.
    #[test]
    fn kept_variables_follow_env_keep_and_env_check() {
        let tmp = with_files("kept", &[]);
        let visudo = tmp.join("visudo");
        std::fs::write(&visudo, "").unwrap();
        let drop_in = crate::install::sudoers_drop_in("alice");
        let env = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
            pairs
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect()
        };
        let kept = |extra: &str, command: Option<&Path>, vars: &[(&str, &str)]| {
            std::fs::write(tmp.join("sudoers"), format!("{extra}\n{drop_in}")).unwrap();
            let groups = vec![];
            kept_variables(
                &tmp.join("sudoers"),
                &subject(&groups),
                command,
                &env(vars),
                false,
            )
        };
        let usual = [
            ("HOME", "/home/alice"),
            ("EDITOR", "vim"),
            ("PATH", "/home/alice/bin:/usr/bin"),
            ("LANG", "C.UTF-8"),
            ("LC_ALL", "C"),
            ("SSH_AUTH_SOCK", "/tmp/agent"),
            ("PYTHONPATH", "/home/alice/lib"),
        ];
        let true_path = Some(Path::new("/usr/bin/true"));
        let fedora = "Defaults env_keep = \"COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS\"\n\
                      Defaults env_keep += \"MAIL QTDIR USERNAME LANG LC_ADDRESS XAUTHORITY\"";
        let arch = format!(
            "Defaults!{} env_keep += \"SUDO_EDITOR EDITOR VISUAL\"",
            visudo.display()
        );
        let results = [
            kept("Defaults env_reset", true_path, &usual),
            kept("Defaults env_keep += \"PYTHONPATH\"", true_path, &usual),
            kept("Defaults env_keep += \"PYTHON*\"", true_path, &usual),
            kept(
                fedora,
                true_path,
                &[("KDEDIR", "/x"), ("QTDIR", "/x"), ("MAIL", "/x")],
            ),
            kept(&arch, true_path, &usual),
            kept(&arch, Some(&visudo), &usual),
            kept(&arch, None, &usual),
            // env_check keeps a value only without `/` or `%`.
            kept("Defaults env_check += \"PYTHONPATH\"", true_path, &usual),
            kept(
                "Defaults env_check += \"PYTHONPATH\"",
                true_path,
                &[("PYTHONPATH", "lib")],
            ),
            // An alias may name alice; a later removal for alice still wins.
            kept(
                "Defaults:ADMINS env_keep += \"PERL5LIB\"",
                true_path,
                &[("PERL5LIB", "/x")],
            ),
            kept(
                "Defaults:ADMINS env_keep += \"PERL5LIB\"\nDefaults:alice env_keep -= PERL5LIB",
                true_path,
                &[("PERL5LIB", "/x")],
            ),
            kept(
                "Defaults:alice !env_reset",
                true_path,
                &[("FOO", "1"), ("LANG", "C")],
            ),
        ];
        std::fs::remove_dir_all(&tmp).unwrap();
        let names = |names: &[&str]| {
            names
                .iter()
                .map(|name| name.to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            results,
            [
                names(&[]),
                names(&["PYTHONPATH"]),
                names(&["PYTHONPATH"]),
                names(&[]),
                names(&[]),
                names(&["EDITOR"]),
                names(&["EDITOR"]),
                names(&[]),
                names(&["PYTHONPATH"]),
                names(&["PERL5LIB"]),
                names(&[]),
                names(&["FOO"]),
            ]
        );
    }

    #[test]
    fn a_kept_path_is_replaced_by_secure_path() {
        let tmp = with_files("securepath", &[("sudoers", "Defaults env_keep += PATH\n")]);
        let groups = vec![];
        let path = [("PATH".to_string(), "/home/alice/bin".to_string())];
        let sudoers = tmp.join("sudoers");
        let results = [
            kept_variables(&sudoers, &subject(&groups), None, &path, false),
            kept_variables(&sudoers, &subject(&groups), None, &path, true),
        ];
        std::fs::remove_dir_all(&tmp).unwrap();
        assert_eq!(results, [vec!["PATH".to_string()], vec![]]);
    }

    #[test]
    fn missing_file_means_unset() {
        let groups = vec![];
        assert_eq!(
            secure_path(Path::new("/nonexistent/sudoers"), &subject(&groups)),
            vec![None]
        );
    }
}
