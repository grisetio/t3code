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
    if argv.first().is_some_and(|arg0| basename(arg0) == "sudoedit") {
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
    Parsed { mode, user: flags.user, group: flags.group, non_interactive: flags.non_interactive }
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

/// Where sudo searches for a program without a slash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SearchPath {
    /// One known value: sudoers `secure_path`, or the caller's PATH.
    Known(String),
    /// sudoers has a `secure_path` whose binding we can't evaluate; each
    /// alternative is resolved and the path is shown only if they agree.
    Uncertain(Vec<String>),
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
    pub search: SearchPath,
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
            return Described { run_as, run_as_group, command: Command { argv: raw, resolved_path: None, warnings } };
        }
        Mode::Edit(files) => {
            let mut argv = vec!["sudoedit".to_string()];
            argv.extend(files.iter().cloned());
            warnings.push(Warning::new("edit"));
            return Described { run_as, run_as_group, command: Command { argv, resolved_path: None, warnings } };
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
            let resolved = resolve_program(&command[0], context);
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
    Described { run_as, run_as_group, command: Command { argv, resolved_path, warnings } }
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

fn search_one(program: &str, search: &str) -> Option<String> {
    search
        .split(':')
        .filter(|dir| dir.starts_with('/'))
        .map(|dir| Path::new(dir).join(program))
        .find(|candidate| executable_file(candidate))
        .map(|candidate| candidate.to_string_lossy().into_owned())
}

pub fn resolve_program(program: &str, context: &Context) -> Option<String> {
    if program.contains('/') {
        let path = if program.starts_with('/') {
            PathBuf::from(program)
        } else {
            Path::new(context.cwd).join(program)
        };
        // `components()` drops `.` and repeated slashes but keeps `..`,
        // which a symlinked directory makes non-lexical.
        let path: PathBuf = path.components().collect();
        return executable_file(&path).then(|| path.to_string_lossy().into_owned());
    }
    match &context.search {
        SearchPath::Known(search) => search_one(program, search),
        SearchPath::Uncertain(alternatives) => {
            let mut results = alternatives.iter().map(|search| search_one(program, search));
            let first = results.next()?;
            results.all(|other| other == first).then_some(first).flatten()
        }
    }
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
        if index + 1 == components.len() && !meta.file_type().is_symlink() && writable_by(&meta, context) {
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
        let parsed = parse(&argv(&["sudo", "-u", "root", "--", "nix-collect-garbage", "-d"]));
        assert_eq!(parsed.mode, run(&["nix-collect-garbage", "-d"]));
        assert_eq!(parsed.user.as_deref(), Some("root"));
        let parsed = parse(&argv(&["sudo", "-g", "wheel", "python3", "x.py"]));
        assert_eq!(parsed.group.as_deref(), Some("wheel"));
        assert_eq!(parsed.mode, run(&["python3", "x.py"]));
        let parsed = parse(&argv(&["sudo", "-nuroot", "-gwheel", "id"]));
        assert!(parsed.non_interactive);
        assert_eq!(parsed.user.as_deref(), Some("root"));
        assert_eq!(parsed.group.as_deref(), Some("wheel"));
        let parsed = parse(&argv(&["sudo", "--user=bob", "--group", "staff", "--non-interactive", "id"]));
        assert_eq!((parsed.user.as_deref(), parsed.group.as_deref(), parsed.non_interactive), (Some("bob"), Some("staff"), true));
    }

    #[test]
    fn stops_at_first_non_option() {
        let parsed = parse(&argv(&["sudo", "vi", "-n", "-u", "x"]));
        assert_eq!(parsed.mode, run(&["vi", "-n", "-u", "x"]));
        assert!(!parsed.non_interactive);
        assert_eq!(parsed.user, None);
        assert_eq!(parse(&argv(&["sudo", "--", "-weird"])).mode, run(&["-weird"]));
    }

    #[test]
    fn shell_login_and_edit() {
        assert_eq!(parse(&argv(&["sudo", "-s"])).mode, Mode::Shell(vec![]));
        assert_eq!(parse(&argv(&["sudo", "-i", "id", "-u"])).mode, Mode::Login(argv(&["id", "-u"])));
        assert_eq!(parse(&argv(&["sudo", "-e", "/etc/hosts"])).mode, Mode::Edit(argv(&["/etc/hosts"])));
        assert_eq!(parse(&argv(&["/usr/bin/sudoedit", "/etc/hosts"])).mode, Mode::Edit(argv(&["/etc/hosts"])));
        assert_eq!(parse(&argv(&["sudo", "-s", "-i", "id"])).mode, Mode::Unparsed);
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
        assert_eq!(shell_command_string(&argv(&["echo", "a b;c", "$HOME", "x_y-z"])), "echo a\\ b\\;c $HOME x_y-z");
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
            search: SearchPath::Known("relative:/usr/bin:/bin".into()),
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
        std::fs::set_permissions(&tool, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let cwd = tmp.to_string_lossy().into_owned();
        let shells = vec!["/bin/zsh".to_string()];
        let ctx = context(&cwd, &[], &shells);

        let sudo = argv(&["sudo", "-g", "wheel", "./tool", "x.py", "-v", "missing"]);
        let described = describe(&sudo, &parse(&sudo), &ctx);
        assert_eq!(described.run_as, "me");
        assert_eq!(described.run_as_group.as_deref(), Some("wheel"));
        assert_eq!(described.command.resolved_path.as_deref(), Some(tool.to_str().unwrap()));
        assert_eq!(
            described.command.warnings,
            vec![Warning::new("user_writable_program"), Warning::at("user_writable_argument", 1)]
        );

        let sudo = argv(&["sudo", "true"]);
        let described = describe(&sudo, &parse(&sudo), &ctx);
        assert_eq!(described.run_as, "root");
        let true_path = described.command.resolved_path.unwrap();
        assert!(true_path.ends_with("/true"), "{true_path}");

        let sudo = argv(&["sudo", "-s", "echo", "a;b"]);
        let described = describe(&sudo, &parse(&sudo), &ctx);
        assert_eq!(described.command.argv, argv(&["/bin/zsh", "-c", "echo a\\;b"]));
        assert_eq!(described.command.warnings, vec![Warning::new("shell")]);

        let sudo = argv(&["sudo", "-i"]);
        assert_eq!(describe(&sudo, &parse(&sudo), &ctx).command.argv, argv(&["/bin/bash"]));

        let sudo = argv(&["sudo", "sh", "-c", "id"]);
        let described = describe(&sudo, &parse(&sudo), &ctx);
        assert_eq!(described.command.warnings, vec![Warning::new("shell")]);

        let sudo = argv(&["sudo", "-e", "/etc/hosts"]);
        let described = describe(&sudo, &parse(&sudo), &ctx);
        assert_eq!(described.command.argv, argv(&["sudoedit", "/etc/hosts"]));
        assert_eq!((described.command.resolved_path, described.command.warnings), (None, vec![Warning::new("edit")]));

        let sudo = argv(&["sudo", "-n", "--chroot=/x", "id"]);
        let described = describe(&sudo, &parse(&sudo), &ctx);
        assert_eq!(described.command.argv, argv(&["-n", "--chroot=/x", "id"]));
        assert_eq!(described.command.warnings, vec![Warning::new("unparsed_options")]);

        let sudo = argv(&["sudo", "definitely-not-a-program-t3"]);
        assert_eq!(describe(&sudo, &parse(&sudo), &ctx).command.resolved_path, None);
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn uncertain_search_path_needs_agreement() {
        let shells = vec![];
        let mut ctx = context("/", &[], &shells);
        ctx.search = SearchPath::Uncertain(vec!["/usr/bin:/bin".into(), "/bin:/usr/bin".into()]);
        let both = resolve_program("true", &ctx);
        ctx.search = SearchPath::Uncertain(vec!["/usr/bin".into(), "/nonexistent".into()]);
        assert_eq!(resolve_program("true", &ctx), None);
        // `true` exists in both /usr/bin and /bin on Linux, only /usr/bin on macOS.
        let _ = both;
    }
}
