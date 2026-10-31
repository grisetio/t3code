//! Just enough of sudoers to know sudo's `secure_path`, which decides where a
//! program without a slash is found. Bindings we can't evaluate make the
//! result uncertain rather than guessed.

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

fn defaults_setting(line: &str, subject: &Subject, name: &str) -> Option<(u8, Applies, Setting)> {
    let rest = line.strip_prefix("Defaults")?;
    let (rank, applies, params) = match rest.chars().next()? {
        c if c.is_whitespace() => (0, Applies::Yes, rest),
        binding @ (':' | '@' | '>' | '!') => {
            let body = &rest[1..];
            let end = body.find(char::is_whitespace).unwrap_or(body.len());
            let list = &body[..end];
            let (rank, applies) = match binding {
                '@' => (1, list_applies(list, |item| item == subject.host)),
                ':' => (2, user_list_applies(list, subject)),
                '>' => (3, list_applies(list, |item| item == subject.run_as)),
                _ => (4, Applies::Maybe),
            };
            (rank, applies, &body[end..])
        }
        _ => return None,
    };
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

    #[test]
    fn missing_file_means_unset() {
        let groups = vec![];
        assert_eq!(
            secure_path(Path::new("/nonexistent/sudoers"), &subject(&groups)),
            vec![None]
        );
    }
}
