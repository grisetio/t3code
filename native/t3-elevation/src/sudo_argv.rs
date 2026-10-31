//! What sudo will run, from sudo's own argv. Only options that are fully
//! understood are parsed; anything else shows the raw argv with
//! `unparsed_options`, so the phone never displays a guess as fact.

use crate::payload::{Command, Warning};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    Run(Vec<String>),
    Shell(Vec<String>),
    Login(Vec<String>),
    Edit(Vec<String>),
    Unparsed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parsed {
    pub mode: Mode,
    pub user: Option<String>,
    pub group: Option<String>,
    pub non_interactive: bool,
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Short options that take no argument and don't change what runs or as whom.
const SHORT_FLAGS: &[char] = &['A', 'B', 'b', 'H', 'k', 'n', 'S', 's', 'i', 'e'];
const SHORT_WITH_ARG: &[char] = &['u', 'g', 'p'];
const LONG_FLAGS: &[&str] = &[
    "askpass",
    "bell",
    "background",
    "set-home",
    "non-interactive",
    "stdin",
    "shell",
    "login",
    "edit",
];
const LONG_WITH_ARG: &[&str] = &["user", "group", "prompt"];

#[derive(Default)]
struct Flags {
    shell: bool,
    login: bool,
    edit: bool,
    non_interactive: bool,
    user: Option<String>,
    group: Option<String>,
}

impl Flags {
    fn set(&mut self, name: &str) {
        match name {
            "s" | "shell" => self.shell = true,
            "i" | "login" => self.login = true,
            "e" | "edit" => self.edit = true,
            "n" | "non-interactive" => self.non_interactive = true,
            _ => {}
        }
    }
    fn set_value(&mut self, name: &str, value: String) {
        match name {
            "u" | "user" => self.user = Some(value),
            "g" | "group" => self.group = Some(value),
            _ => {}
        }
    }
}

/// sudo stops at the first non-option (getopt with `+`). Leading `VAR=value`
/// arguments set environment variables, which can change what a program does,
/// so they are treated as not understood.
pub fn parse(argv: &[String]) -> Parsed {
    let mut flags = Flags::default();
    if argv
        .first()
        .is_some_and(|arg0| basename(arg0) == "sudoedit")
    {
        flags.edit = true;
    }
    let unparsed = |flags: Flags, rest: &[String]| Parsed {
        mode: Mode::Unparsed,
        non_interactive: flags.non_interactive || looks_non_interactive(rest),
        user: flags.user,
        group: flags.group,
    };
    let mut index = 1;
    let mut command_start = None;
    while index < argv.len() {
        let arg = &argv[index];
        if arg == "--" {
            command_start = Some(index + 1);
            break;
        }
        if let Some(long) = arg.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value.to_string())),
                None => (long, None),
            };
            if LONG_FLAGS.contains(&name) && value.is_none() {
                flags.set(name);
            } else if LONG_WITH_ARG.contains(&name) {
                let value = match value {
                    Some(value) => value,
                    None => {
                        index += 1;
                        match argv.get(index) {
                            Some(value) => value.clone(),
                            None => return unparsed(flags, &argv[index.min(argv.len())..]),
                        }
                    }
                };
                flags.set_value(name, value);
            } else {
                return unparsed(flags, &argv[index..]);
            }
            index += 1;
            continue;
        }
        if arg.len() > 1 && arg.starts_with('-') {
            let chars: Vec<char> = arg[1..].chars().collect();
            let mut position = 0;
            while position < chars.len() {
                let option = chars[position];
                if SHORT_FLAGS.contains(&option) {
                    flags.set(&option.to_string());
                    position += 1;
                } else if SHORT_WITH_ARG.contains(&option) {
                    let attached: String = chars[position + 1..].iter().collect();
                    let value = if attached.is_empty() {
                        index += 1;
                        match argv.get(index) {
                            Some(value) => value.clone(),
                            None => return unparsed(flags, &[]),
                        }
                    } else {
                        attached
                    };
                    flags.set_value(&option.to_string(), value);
                    break;
                } else {
                    return unparsed(flags, &argv[index..]);
                }
            }
            index += 1;
            continue;
        }
        command_start = Some(index);
        break;
    }
    let command: Vec<String> = command_start
        .map(|start| argv[start.min(argv.len())..].to_vec())
        .unwrap_or_default();
    if command.first().is_some_and(|first| first.contains('=')) && command_start.is_some() {
        // `sudo -- A=b cmd` still sets A for sudo.
        return unparsed(flags, &[]);
    }
    let exclusive = [flags.shell, flags.login, flags.edit]
        .iter()
        .filter(|set| **set)
        .count();
    if exclusive > 1 {
        return unparsed(flags, &[]);
    }
    let mode = if flags.edit {
        if command.is_empty() {
            return unparsed(flags, &[]);
        }
        Mode::Edit(command)
    } else if flags.shell {
        Mode::Shell(command)
    } else if flags.login {
        Mode::Login(command)
    } else if command.is_empty() {
        return unparsed(flags, &[]);
    } else {
        Mode::Run(command)
    };
    Parsed {
        mode,
        user: flags.user,
        group: flags.group,
        non_interactive: flags.non_interactive,
    }
}

/// After an option we don't understand, `-n` may still follow among the
/// options. Scanning stops at the first non-option so a command's own `-n`
/// (for example `vi -n`) never counts.
fn looks_non_interactive(rest: &[String]) -> bool {
    for arg in rest {
        if arg == "--" || !arg.starts_with('-') || arg.len() < 2 {
            return false;
        }
        if arg == "--non-interactive" {
            return true;
        }
        if !arg.starts_with("--") && arg[1..].contains('n') {
            return true;
        }
    }
    false
}

/// sudo's own `-s`/`-i` command string: every byte that isn't alphanumeric,
/// `_`, `-` or `$` gets a backslash. Escaping per character instead of per
/// byte keeps the text valid UTF-8 and means the same to the shell.
pub fn shell_command_string(command: &[String]) -> String {
    let mut out = String::new();
    for (index, arg) in command.iter().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        for ch in arg.chars() {
            if !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '$') {
                out.push('\\');
            }
            out.push(ch);
        }
    }
    out
}

/// Which sudo the module may be running inside. They resolve programs
/// differently, so a result is certain only when every candidate agrees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flavor {
    /// sudo.ws: searches relative PATH entries against the cwd, `.` last
    /// unless `ignore_dot`; reads the last non-empty `PATH=` in its environment.
    Classic,
    /// sudo-rs: skips relative entries; reads `getenv("PATH")`, the first one.
    Rs,
}

impl Flavor {
    /// macOS only ships sudo.ws; Linux may run either.
    pub fn platform() -> &'static [Flavor] {
        if cfg!(target_os = "macos") {
            &[Flavor::Classic]
        } else {
            &[Flavor::Classic, Flavor::Rs]
        }
    }
}

/// Everything that decides where sudo finds a program without a slash.
#[derive(Clone, Debug)]
pub struct Search {
    /// Every value sudoers' `secure_path` may have; `None` means unset.
    pub secure_path: Vec<Option<String>>,
    /// Every value `ignore_dot` may have.
    pub ignore_dot: Vec<bool>,
    /// sudoers may set `runchroot`, which resolves inside another root.
    pub chroot: bool,
    /// Each `PATH=` value in sudo's environment, in order; `None` when one
    /// isn't valid UTF-8.
    pub env_paths: Option<Vec<String>>,
    pub flavors: &'static [Flavor],
}

impl Search {
    /// The caller's PATH with no sudoers settings in the way.
    pub fn caller(path: &str) -> Self {
        Self {
            secure_path: vec![None],
            ignore_dot: vec![true],
            chroot: false,
            env_paths: Some(vec![path.to_string()]),
            flavors: Flavor::platform(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolved {
    Found(String),
    /// sudo won't find it either, so nothing runs.
    NotFound,
    /// The candidates disagree; showing any one of them could be wrong.
    Uncertain,
}

pub struct Context<'a> {
    pub user: &'a str,
    pub uid: u32,
    pub gids: &'a [u32],
    pub cwd: &'a str,
    /// `$SHELL` in sudo's environment, else the caller's passwd shell (`-s`).
    pub caller_shell: Option<&'a str>,
    /// The target user's passwd shell (`-i`).
    pub target_shell: Option<&'a str>,
    pub search: Search,
    pub shells: &'a [String],
}

pub struct Described {
    pub run_as: String,
    pub run_as_group: Option<String>,
    pub command: Command,
}

pub fn describe(sudo_argv: &[String], parsed: &Parsed, context: &Context) -> Described {
    let run_as = match (&parsed.user, &parsed.group) {
        (Some(user), _) => user.clone(),
        // `-g` alone runs the command as the invoking user.
        (None, Some(_)) => context.user.to_string(),
        (None, None) => "root".to_string(),
    };
    let run_as_group = parsed.group.clone();
    let mut warnings = Vec::new();
    let (argv, resolved_path, shell, arg_checks) = match &parsed.mode {
        Mode::Unparsed => {
            warnings.push(Warning::new("unparsed_options"));
            let raw = sudo_argv.get(1..).unwrap_or_default().to_vec();
            return Described {
                run_as,
                run_as_group,
                command: Command {
                    argv: raw,
                    resolved_path: None,
                    warnings,
                },
            };
        }
        Mode::Edit(files) => {
            let mut argv = vec!["sudoedit".to_string()];
            argv.extend(files.iter().cloned());
            warnings.push(Warning::new("edit"));
            return Described {
                run_as,
                run_as_group,
                command: Command {
                    argv,
                    resolved_path: None,
                    warnings,
                },
            };
        }
        Mode::Shell(command) | Mode::Login(command) => {
            let shell = if matches!(parsed.mode, Mode::Shell(_)) {
                context.caller_shell
            } else {
                context.target_shell
            }
            .unwrap_or("/bin/sh")
            .to_string();
            let mut argv = vec![shell.clone()];
            if !command.is_empty() {
                argv.push("-c".to_string());
                argv.push(shell_command_string(command));
            }
            let resolved = shell.starts_with('/').then(|| shell.clone());
            (argv, resolved, true, false)
        }
        Mode::Run(command) => {
            let resolved = match resolve_program(&command[0], context) {
                Resolved::Found(path) => Some(path),
                Resolved::NotFound => None,
                Resolved::Uncertain => {
                    warnings.push(Warning::new("unresolved_program"));
                    None
                }
            };
            let is_shell = is_shell_program(&command[0], resolved.as_deref(), context.shells);
            (command.clone(), resolved, is_shell, true)
        }
    };
    if let Some(path) = &resolved_path
        && program_writable(Path::new(path), context)
    {
        warnings.push(Warning::new("user_writable_program"));
    }
    if arg_checks {
        for (index, arg) in argv.iter().enumerate().skip(1) {
            if argument_writable(arg, context) {
                warnings.push(Warning::at("user_writable_argument", index));
            }
        }
    }
    if shell {
        warnings.push(Warning::new("shell"));
    }
    Described {
        run_as,
        run_as_group,
        command: Command {
            argv,
            resolved_path,
            warnings,
        },
    }
}

const KNOWN_SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "fish", "dash", "ksh", "mksh", "csh", "tcsh", "ash", "nu", "elvish",
    "xonsh", "pwsh", "yash", "oksh", "rbash", "busybox",
];

fn is_shell_program(program: &str, resolved: Option<&str>, shells: &[String]) -> bool {
    KNOWN_SHELLS.contains(&basename(program))
        || resolved.is_some_and(|path| shells.iter().any(|shell| shell == path))
}

fn executable_file(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.mode() & 0o111 != 0)
}

/// sudo's `sudo_goodpath`: a regular file with any execute bit, symlinks followed.
fn good_path(candidate: &str, cwd: &str) -> Option<String> {
    let path: PathBuf = Path::new(cwd).join(candidate).components().collect();
    executable_file(&path).then(|| path.to_string_lossy().into_owned())
}

/// sudo.ws `find_path`: empty entries are skipped, other relative entries
/// are searched in order against the cwd, and `.` is tried last; a match
/// there counts only without `ignore_dot`.
fn classic_search(
    program: &str,
    path: Option<&str>,
    cwd: &str,
    ignore_dot: bool,
) -> Option<String> {
    let mut check_dot = false;
    for dir in path?.split(':').filter(|dir| !dir.is_empty()) {
        if dir == "." {
            check_dot = true;
            continue;
        }
        if let Some(found) = good_path(&format!("{dir}/{program}"), cwd) {
            return Some(found);
        }
    }
    if check_dot && !ignore_dot {
        return good_path(&format!("./{program}"), cwd);
    }
    None
}

/// sudo-rs `resolve_path`: absolute entries only.
fn rs_search(program: &str, path: &str) -> Option<String> {
    path.split(':')
        .filter(|dir| dir.starts_with('/'))
        .find_map(|dir| good_path(&format!("{dir}/{program}"), "/"))
}

/// Mirrors sudo's own lookup: `secure_path` when set, else the caller's PATH.
pub fn resolve_program(program: &str, context: &Context) -> Resolved {
    let search = &context.search;
    if search.chroot {
        return Resolved::Uncertain;
    }
    let mut outcomes = Vec::new();
    if program.contains('/') {
        // `components()` drops `.` and repeated slashes but keeps `..`,
        // which a symlinked directory makes non-lexical.
        outcomes.push(good_path(program, context.cwd));
    } else {
        let Some(env_paths) = &search.env_paths else {
            return Resolved::Uncertain;
        };
        for flavor in search.flavors {
            for secure in &search.secure_path {
                match flavor {
                    Flavor::Classic => {
                        let path = secure.as_deref().or_else(|| {
                            env_paths
                                .iter()
                                .rev()
                                .find(|path| !path.is_empty())
                                .map(String::as_str)
                        });
                        for ignore_dot in &search.ignore_dot {
                            outcomes.push(classic_search(program, path, context.cwd, *ignore_dot));
                        }
                    }
                    Flavor::Rs => {
                        let path = secure
                            .as_deref()
                            .or_else(|| env_paths.first().map(String::as_str))
                            .unwrap_or_default();
                        outcomes.push(rs_search(program, path));
                    }
                }
            }
        }
    }
    let Some(first) = outcomes.first().cloned() else {
        return Resolved::Uncertain;
    };
    if outcomes.iter().any(|outcome| *outcome != first) {
        return Resolved::Uncertain;
    }
    first.map_or(Resolved::NotFound, Resolved::Found)
}

fn writable_by(meta: &std::fs::Metadata, context: &Context) -> bool {
    if context.uid == 0 || meta.uid() == context.uid {
        return true;
    }
    if context.gids.contains(&meta.gid()) {
        return meta.mode() & 0o020 != 0;
    }
    meta.mode() & 0o002 != 0
}

/// Whether the user could change what runs at `path`: the file itself, or
/// any directory on the way that lets them replace an entry.
fn path_replaceable(path: &Path, context: &Context) -> bool {
    let mut prefix = PathBuf::new();
    let components: Vec<_> = path.components().collect();
    for (index, component) in components.iter().enumerate() {
        let parent = prefix.clone();
        prefix.push(component);
        let Ok(meta) = std::fs::symlink_metadata(&prefix) else {
            return false;
        };
        if index > 0
            && let Ok(dir) = std::fs::metadata(&parent)
            && writable_by(&dir, context)
        {
            let sticky = dir.mode() & 0o1000 != 0;
            if !sticky || meta.uid() == context.uid {
                return true;
            }
        }
        if index + 1 == components.len()
            && !meta.file_type().is_symlink()
            && writable_by(&meta, context)
        {
            return true;
        }
    }
    false
}

fn program_writable(path: &Path, context: &Context) -> bool {
    path_replaceable(path, context)
        || std::fs::canonicalize(path).is_ok_and(|canonical| path_replaceable(&canonical, context))
}

fn argument_writable(arg: &str, context: &Context) -> bool {
    if arg.is_empty() || arg.starts_with('-') {
        return false;
    }
    let path = if arg.starts_with('/') {
        PathBuf::from(arg)
    } else {
        Path::new(context.cwd).join(arg)
    };
    std::fs::metadata(&path).is_ok_and(|meta| writable_by(&meta, context))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| arg.to_string()).collect()
    }

    fn run(args: &[&str]) -> Mode {
        Mode::Run(argv(args))
    }

    #[test]
    fn parses_user_group_and_separator() {
        let parsed = parse(&argv(&[
            "sudo",
            "-u",
            "root",
            "--",
            "nix-collect-garbage",
            "-d",
        ]));
        assert_eq!(parsed.mode, run(&["nix-collect-garbage", "-d"]));
        assert_eq!(parsed.user.as_deref(), Some("root"));
        let parsed = parse(&argv(&["sudo", "-g", "wheel", "python3", "x.py"]));
        assert_eq!(parsed.group.as_deref(), Some("wheel"));
        assert_eq!(parsed.mode, run(&["python3", "x.py"]));
        let parsed = parse(&argv(&["sudo", "-nuroot", "-gwheel", "id"]));
        assert!(parsed.non_interactive);
        assert_eq!(parsed.user.as_deref(), Some("root"));
        assert_eq!(parsed.group.as_deref(), Some("wheel"));
        let parsed = parse(&argv(&[
            "sudo",
            "--user=bob",
            "--group",
            "staff",
            "--non-interactive",
            "id",
        ]));
        assert_eq!(
            (
                parsed.user.as_deref(),
                parsed.group.as_deref(),
                parsed.non_interactive
            ),
            (Some("bob"), Some("staff"), true)
        );
    }

    #[test]
    fn stops_at_first_non_option() {
        let parsed = parse(&argv(&["sudo", "vi", "-n", "-u", "x"]));
        assert_eq!(parsed.mode, run(&["vi", "-n", "-u", "x"]));
        assert!(!parsed.non_interactive);
        assert_eq!(parsed.user, None);
        assert_eq!(
            parse(&argv(&["sudo", "--", "-weird"])).mode,
            run(&["-weird"])
        );
    }

    #[test]
    fn shell_login_and_edit() {
        assert_eq!(parse(&argv(&["sudo", "-s"])).mode, Mode::Shell(vec![]));
        assert_eq!(
            parse(&argv(&["sudo", "-i", "id", "-u"])).mode,
            Mode::Login(argv(&["id", "-u"]))
        );
        assert_eq!(
            parse(&argv(&["sudo", "-e", "/etc/hosts"])).mode,
            Mode::Edit(argv(&["/etc/hosts"]))
        );
        assert_eq!(
            parse(&argv(&["/usr/bin/sudoedit", "/etc/hosts"])).mode,
            Mode::Edit(argv(&["/etc/hosts"]))
        );
        assert_eq!(
            parse(&argv(&["sudo", "-s", "-i", "id"])).mode,
            Mode::Unparsed
        );
        assert_eq!(parse(&argv(&["sudo", "-e"])).mode, Mode::Unparsed);
    }

    #[test]
    fn unknown_options_are_unparsed_but_keep_n() {
        let parsed = parse(&argv(&["sudo", "-n", "--chroot=/x", "id"]));
        assert_eq!(parsed.mode, Mode::Unparsed);
        assert!(parsed.non_interactive);
        let parsed = parse(&argv(&["sudo", "-E", "-n", "id"]));
        assert_eq!(parsed.mode, Mode::Unparsed);
        assert!(parsed.non_interactive);
        let parsed = parse(&argv(&["sudo", "--chroot", "/x", "vi", "-n"]));
        assert!(!parsed.non_interactive, "a command's own -n never counts");
        for unknown in [
            &["sudo", "-E", "id"][..],
            &["sudo", "-v"],
            &["sudo", "-l"],
            &["sudo", "-D", "/tmp", "id"],
            &["sudo", "--preserve-env", "id"],
            &["sudo", "--us=root", "id"],
            &["sudo", "FOO=bar", "id"],
            &["sudo", "-u"],
            &["sudo"],
            &["sudo", "-n"],
        ] {
            assert_eq!(parse(&argv(unknown)).mode, Mode::Unparsed, "{unknown:?}");
        }
    }

    #[test]
    fn shell_string_matches_sudo_escaping() {
        assert_eq!(
            shell_command_string(&argv(&["echo", "a b;c", "$HOME", "x_y-z"])),
            "echo a\\ b\\;c $HOME x_y-z"
        );
        assert_eq!(shell_command_string(&argv(&["é"])), "\\é");
    }

    fn context<'a>(dir: &'a str, gids: &'a [u32], shells: &'a [String]) -> Context<'a> {
        Context {
            user: "me",
            uid: unsafe { libc::getuid() },
            gids,
            cwd: dir,
            caller_shell: Some("/bin/zsh"),
            target_shell: Some("/bin/bash"),
            search: Search::caller("/usr/bin:/bin"),
            shells,
        }
    }

    #[test]
    fn describes_with_warnings() {
        let tmp = std::env::temp_dir().join(format!("t3e-argv-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let script = tmp.join("x.py");
        std::fs::write(&script, "print(1)").unwrap();
        let tool = tmp.join("tool");
        std::fs::write(&tool, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&tool, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let cwd = tmp.to_string_lossy().into_owned();
        let shells = vec!["/bin/zsh".to_string()];
        let ctx = context(&cwd, &[], &shells);

        let sudo = argv(&["sudo", "-g", "wheel", "./tool", "x.py", "-v", "missing"]);
        let described = describe(&sudo, &parse(&sudo), &ctx);
        assert_eq!(described.run_as, "me");
        assert_eq!(described.run_as_group.as_deref(), Some("wheel"));
        assert_eq!(
            described.command.resolved_path.as_deref(),
            Some(tool.to_str().unwrap())
        );
        assert_eq!(
            described.command.warnings,
            vec![
                Warning::new("user_writable_program"),
                Warning::at("user_writable_argument", 1)
            ]
        );

        let sudo = argv(&["sudo", "true"]);
        let described = describe(&sudo, &parse(&sudo), &ctx);
        assert_eq!(described.run_as, "root");
        let true_path = described.command.resolved_path.unwrap();
        assert!(true_path.ends_with("/true"), "{true_path}");

        let sudo = argv(&["sudo", "-s", "echo", "a;b"]);
        let described = describe(&sudo, &parse(&sudo), &ctx);
        assert_eq!(
            described.command.argv,
            argv(&["/bin/zsh", "-c", "echo a\\;b"])
        );
        assert_eq!(described.command.warnings, vec![Warning::new("shell")]);

        let sudo = argv(&["sudo", "-i"]);
        assert_eq!(
            describe(&sudo, &parse(&sudo), &ctx).command.argv,
            argv(&["/bin/bash"])
        );

        let sudo = argv(&["sudo", "sh", "-c", "id"]);
        let described = describe(&sudo, &parse(&sudo), &ctx);
        assert_eq!(described.command.warnings, vec![Warning::new("shell")]);

        let sudo = argv(&["sudo", "-e", "/etc/hosts"]);
        let described = describe(&sudo, &parse(&sudo), &ctx);
        assert_eq!(described.command.argv, argv(&["sudoedit", "/etc/hosts"]));
        assert_eq!(
            (described.command.resolved_path, described.command.warnings),
            (None, vec![Warning::new("edit")])
        );

        let sudo = argv(&["sudo", "-n", "--chroot=/x", "id"]);
        let described = describe(&sudo, &parse(&sudo), &ctx);
        assert_eq!(described.command.argv, argv(&["-n", "--chroot=/x", "id"]));
        assert_eq!(
            described.command.warnings,
            vec![Warning::new("unparsed_options")]
        );

        let sudo = argv(&["sudo", "definitely-not-a-program-t3"]);
        assert_eq!(
            describe(&sudo, &parse(&sudo), &ctx).command.resolved_path,
            None
        );
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    fn planted(name: &str) -> (PathBuf, String) {
        let tmp = std::env::temp_dir().join(format!("t3e-argv-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("bin")).unwrap();
        let planted = tmp.join("bin/true");
        std::fs::write(&planted, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(
            &planted,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();
        let cwd = tmp.to_string_lossy().into_owned();
        (tmp, cwd)
    }

    #[test]
    fn classic_and_rs_search_like_sudo() {
        let (tmp, cwd) = planted("search");
        let bin_true = tmp.join("bin/true").to_string_lossy().into_owned();
        let classic = |path: &str, ignore_dot| classic_search("true", Some(path), &cwd, ignore_dot);
        assert_eq!(classic("bin:/nonexistent", true), Some(bin_true.clone()));
        assert_eq!(classic("./bin", true), Some(bin_true.clone()));
        // Empty entries are skipped, not the cwd; `.` comes last.
        assert_eq!(classic("::/nonexistent", false), None);
        std::fs::copy(tmp.join("bin/true"), tmp.join("true")).unwrap();
        let dot_true = tmp.join("true").to_string_lossy().into_owned();
        assert_eq!(classic(".:bin", false), Some(bin_true.clone()));
        assert_eq!(classic(".:/nonexistent", false), Some(dot_true));
        assert_eq!(classic(".:/nonexistent", true), None);
        assert_eq!(classic_search("true", None, &cwd, true), None);
        assert_eq!(rs_search("true", "bin:."), None);
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn disagreement_is_uncertain() {
        let (tmp, cwd) = planted("disagree");
        let shells = vec![];
        let mut ctx = context(&cwd, &[], &shells);
        let sudo = argv(&["sudo", "true"]);
        let describe_true = |ctx: &Context| describe(&sudo, &parse(&sudo), ctx).command;

        ctx.search.env_paths = Some(vec!["bin:/usr/bin:/bin".into()]);
        ctx.search.flavors = &[Flavor::Classic, Flavor::Rs];
        let command = describe_true(&ctx);
        assert_eq!(command.resolved_path, None);
        assert!(
            command
                .warnings
                .contains(&Warning::new("unresolved_program"))
        );

        // Classic reads the last PATH, sudo-rs the first.
        ctx.search.env_paths = Some(vec!["/nonexistent".into(), "/usr/bin:/bin".into()]);
        ctx.search.flavors = &[Flavor::Classic];
        assert!(describe_true(&ctx).resolved_path.is_some());
        ctx.search.flavors = &[Flavor::Classic, Flavor::Rs];
        assert_eq!(describe_true(&ctx).resolved_path, None);

        ctx.search.secure_path = vec![Some("/usr/bin:/bin".into())];
        assert!(
            describe_true(&ctx).resolved_path.is_some(),
            "secure_path wins"
        );
        ctx.search.secure_path = vec![Some("/usr/bin".into()), Some("/nonexistent".into())];
        assert_eq!(describe_true(&ctx).resolved_path, None);
        ctx.search.secure_path = vec![None];
        ctx.search.env_paths = None;
        assert_eq!(describe_true(&ctx).resolved_path, None);
        ctx.search.env_paths = Some(vec!["/usr/bin:/bin".into()]);
        ctx.search.chroot = true;
        assert_eq!(describe_true(&ctx).resolved_path, None);
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    /// Review finding (R2): an option sudo reads an argument for, or an
    /// abbreviated long option, hides a later `-n`. The module then returns
    /// IGNORE, pam_unix fails without a conversation and pam_faillock counts
    /// it, which plain `sudo -n` never did before install.
    #[test]
    #[ignore = "review: -n after -D/-C/--chdir or as --non is missed; remove when fixed"]
    fn non_interactive_after_options_with_arguments() {
        for spelling in [
            &["sudo", "-D", "/", "-n", "true"][..],
            &["sudo", "-C", "3", "-n", "true"],
            &["sudo", "--chdir", "/", "-n", "true"],
            &["sudo", "--non", "true"],
        ] {
            assert!(parse(&argv(spelling)).non_interactive, "{spelling:?}");
        }
    }

    /// Review finding (S3): sudo searches relative PATH entries against the
    /// cwd when sudoers has no `secure_path` (macOS), but `search_one` skips
    /// them, so the phone shows `/usr/bin/true` while sudo runs `./bin/true`.
    #[test]
    fn relative_search_entries_are_not_skipped() {
        let (tmp, cwd) = planted("relpath");
        let planted = tmp.join("bin/true");
        let shells = vec![];
        let mut ctx = context(&cwd, &[], &shells);
        ctx.search = Search::caller("bin:/usr/bin:/bin");
        let sudo = argv(&["sudo", "true"]);
        let command = describe(&sudo, &parse(&sudo), &ctx).command;
        std::fs::remove_dir_all(&tmp).unwrap();
        let honest = match command.resolved_path.as_deref() {
            None => true,
            Some(path) => {
                path == planted.to_str().unwrap()
                    && command
                        .warnings
                        .contains(&Warning::new("user_writable_program"))
            }
        };
        assert!(honest, "{command:?}");
    }

    /// Review finding (S3): an argument that is a symlink in a user-writable
    /// directory, or doesn't exist there yet, gets no warning. Its owner can
    /// point it elsewhere after approval; demonstrated with
    /// `sudo python3 ~/tool.py` on Ubuntu 24.04.
    #[test]
    #[ignore = "review: replaceable arguments get no user_writable_argument warning; remove when fixed"]
    fn replaceable_arguments_are_warned() {
        let tmp = std::env::temp_dir().join(format!("t3e-argv-replace-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::os::unix::fs::symlink("/etc/hosts", tmp.join("tool.py")).unwrap();
        let cwd = tmp.to_string_lossy().into_owned();
        let shells = vec![];
        let ctx = context(&cwd, &[], &shells);
        let warnings = |arg: &str| {
            let sudo = argv(&["sudo", "/bin/cat", arg]);
            describe(&sudo, &parse(&sudo), &ctx).command.warnings
        };
        let symlinked = warnings("tool.py");
        let missing = warnings("later.py");
        std::fs::remove_dir_all(&tmp).unwrap();
        let expected = vec![Warning::at("user_writable_argument", 1)];
        assert_eq!((symlinked, missing), (expected.clone(), expected));
    }
}
