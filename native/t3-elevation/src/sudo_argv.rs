//! What sudo will run, from sudo's own argv. The argv is scanned with each
//! sudo implementation's own option table; only options that are fully
//! understood are shown parsed, and anything else shows the raw argv with
//! `unparsed_options`, so the phone never displays a guess as fact.

use crate::payload::{Command, Warning};
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
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
    /// `-S`: the password from stdin.
    pub stdin_password: bool,
    /// `-v` or `-l`: authenticates and runs nothing.
    pub runs_nothing: bool,
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// One option as the sudo that parsed it saw it. `--host` and `-h host` are
/// `Value('h', _)`; help is `Flag('h')`.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Opt {
    Flag(char),
    Value(char, String),
}

/// sudo's argv split the way one sudo implementation splits it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Scan {
    options: Vec<Opt>,
    /// `VAR=value` arguments among the options.
    env: bool,
    /// Invoked as sudoedit.
    edit: bool,
    command: Vec<String>,
}

impl Scan {
    fn has(&self, flag: char) -> bool {
        self.options.contains(&Opt::Flag(flag))
    }
    fn value(&self, option: char) -> Option<&str> {
        self.options.iter().rev().find_map(|opt| match opt {
            Opt::Value(name, value) if *name == option => Some(value.as_str()),
            _ => None,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Arity {
    None,
    Required,
    Optional,
}

/// sudo.ws's getopt strings, without the leading `+`. Options a build
/// compiles out (`-a`, `-c`, `-r`, `-t`) still take their argument before
/// sudo rejects them, so keeping them here is right either way.
const CLASSIC_SHORT: &str = "Aa:BbC:c:D:Eeg:Hh::iKklNnPp:R:r:SsT:t:U:u:Vv";
const CLASSIC_EDIT_SHORT: &str = "Aa:BC:c:D:g:h::KkNnp:R:r:ST:t:u:V";
/// sudo.ws's long options in table order; sudoedit uses those from `askpass`.
const CLASSIC_LONG: &[(&str, Arity, char)] = &[
    ("background", Arity::None, 'b'),
    ("preserve-env", Arity::Optional, 'E'),
    ("edit", Arity::None, 'e'),
    ("set-home", Arity::None, 'H'),
    ("login", Arity::None, 'i'),
    ("remove-timestamp", Arity::None, 'K'),
    ("list", Arity::None, 'l'),
    ("preserve-groups", Arity::None, 'P'),
    ("shell", Arity::None, 's'),
    ("other-user", Arity::Required, 'U'),
    ("validate", Arity::None, 'v'),
    ("askpass", Arity::None, 'A'),
    ("auth-type", Arity::Required, 'a'),
    ("bell", Arity::None, 'B'),
    ("close-from", Arity::Required, 'C'),
    ("login-class", Arity::Required, 'c'),
    ("chdir", Arity::Required, 'D'),
    ("group", Arity::Required, 'g'),
    ("help", Arity::None, 'h'),
    ("host", Arity::Required, 'h'),
    ("reset-timestamp", Arity::None, 'k'),
    ("no-update", Arity::None, 'N'),
    ("non-interactive", Arity::None, 'n'),
    ("prompt", Arity::Required, 'p'),
    ("chroot", Arity::Required, 'R'),
    ("role", Arity::Required, 'r'),
    ("stdin", Arity::None, 'S'),
    ("command-timeout", Arity::Required, 'T'),
    ("type", Arity::Required, 't'),
    ("user", Arity::Required, 'u'),
    ("version", Arity::None, 'V'),
];
const CLASSIC_EDIT_LONG_START: usize = 11;

fn short_arity(spec: &str, option: char) -> Option<Arity> {
    if option == ':' {
        return None;
    }
    let rest = &spec[spec.find(option)? + option.len_utf8()..];
    Some(if rest.starts_with("::") {
        Arity::Optional
    } else if rest.starts_with(':') {
        Arity::Required
    } else {
        Arity::None
    })
}

/// getopt_long: an exact name, else a unique prefix; ambiguity is an error.
fn long_option<'a>(
    table: &'a [(&'a str, Arity, char)],
    name: &str,
) -> Option<&'a (&'a str, Arity, char)> {
    if let Some(exact) = table.iter().find(|(long, _, _)| *long == name) {
        return Some(exact);
    }
    let mut matches = table.iter().filter(|(long, _, _)| long.starts_with(name));
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

/// sudo.ws's `parse_args`: getopt_long in order (`+`), with `VAR=value`
/// interspersed unless the previous element was `--`, and `-h` alone taking
/// the next non-option as a host. `None` when getopt rejects the argv.
fn scan_classic(argv: &[String]) -> Option<Scan> {
    let edit = argv
        .first()
        .is_some_and(|arg0| basename(arg0) == "sudoedit");
    let (short, long) = if edit {
        (CLASSIC_EDIT_SHORT, &CLASSIC_LONG[CLASSIC_EDIT_LONG_START..])
    } else {
        (CLASSIC_SHORT, CLASSIC_LONG)
    };
    let is_envar = |arg: &str| !arg.starts_with('/') && !arg.starts_with('=') && arg.contains('=');
    let mut options = Vec::new();
    let mut env = false;
    let mut index = 1;
    while let Some(arg) = argv.get(index) {
        if arg == "--" {
            index += 1;
            break;
        }
        if let Some(body) = arg.strip_prefix("--") {
            let (name, inline) = match body.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (body, None),
            };
            let &(_, arity, option) = long_option(long, name)?;
            index += 1;
            options.push(match (arity, inline) {
                (Arity::None, Some(_)) => return None,
                (Arity::None, None) | (Arity::Optional, None) => Opt::Flag(option),
                (_, Some(value)) => Opt::Value(option, value.to_string()),
                (Arity::Required, None) => {
                    index += 1;
                    Opt::Value(option, argv.get(index - 1)?.clone())
                }
            });
            continue;
        }
        if arg.len() > 1 && arg.starts_with('-') {
            index += 1;
            let cluster = &arg[1..];
            for (offset, option) in cluster.char_indices() {
                let attached = &cluster[offset + option.len_utf8()..];
                match short_arity(short, option)? {
                    Arity::None => options.push(Opt::Flag(option)),
                    Arity::Required => {
                        let value = if attached.is_empty() {
                            index += 1;
                            argv.get(index - 1)?.clone()
                        } else {
                            attached.to_string()
                        };
                        options.push(Opt::Value(option, value));
                        break;
                    }
                    Arity::Optional if !attached.is_empty() => {
                        options.push(Opt::Value(option, attached.to_string()));
                        break;
                    }
                    Arity::Optional => {
                        let host = argv.get(index).filter(|next| {
                            arg == "-h" && !next.starts_with('-') && !is_envar(next)
                        });
                        options.push(match host {
                            Some(host) => {
                                index += 1;
                                Opt::Value(option, host.clone())
                            }
                            None => Opt::Flag(option),
                        });
                    }
                }
            }
            continue;
        }
        if !(index > 1 && argv[index - 1] == "--") && is_envar(arg) {
            env = true;
            index += 1;
            continue;
        }
        break;
    }
    Some(Scan {
        options,
        env,
        edit,
        command: argv.get(index..).unwrap_or_default().to_vec(),
    })
}

/// sudo-rs's long options with the short letter they act as; it matches long
/// names exactly.
const RS_LONG: &[(&str, char)] = &[
    ("askpass", 'A'),
    ("bell", 'B'),
    ("background", 'b'),
    ("preserve-env", 'E'),
    ("edit", 'e'),
    ("set-home", 'H'),
    ("help", 'h'),
    ("login", 'i'),
    ("remove-timestamp", 'K'),
    ("reset-timestamp", 'k'),
    ("list", 'l'),
    ("non-interactive", 'n'),
    ("stdin", 'S'),
    ("shell", 's'),
    ("version", 'V'),
    ("validate", 'v'),
    ("chdir", 'D'),
    ("group", 'g'),
    ("host", 'h'),
    ("chroot", 'R'),
    ("other-user", 'U'),
    ("user", 'u'),
    ("prompt", 'p'),
];
const RS_LONG_WITH_ARG: &[&str] = &[
    "chdir",
    "group",
    "host",
    "chroot",
    "other-user",
    "user",
    "prompt",
];
const RS_SHORT_WITH_ARG: &[char] = &['D', 'g', 'h', 'p', 'R', 'U', 'u'];

/// sudo-rs's `normalize_arguments` and the option match after it. `None`
/// when sudo-rs rejects the argv.
fn scan_rs(argv: &[String]) -> Option<Scan> {
    let edit = argv
        .first()
        .is_some_and(|arg0| basename(arg0).starts_with("sudoedit"));
    let flag = |option: char| {
        "ABbEeHhiKklnSsVv"
            .contains(option)
            .then_some(Opt::Flag(option))
            .filter(|_| !(edit && option == 'e'))
    };
    let value = |option: char, value: &str| {
        "DEgpUu"
            .contains(option)
            .then(|| Opt::Value(option, value.to_string()))
    };
    let long = |name: &str| {
        RS_LONG
            .iter()
            .find(|(long, _)| *long == name)
            .map(|(_, c)| *c)
    };
    let mut options = Vec::new();
    let mut env = false;
    let mut index = 1;
    while let Some(arg) = argv.get(index) {
        index += 1;
        if arg == "--" {
            break;
        }
        if let Some(body) = arg.strip_prefix("--") {
            if let Some((name, inline)) = body.split_once('=') {
                if !RS_LONG_WITH_ARG.contains(&name) && name != "preserve-env" {
                    return None;
                }
                options.push(value(long(name)?, inline)?);
            } else if RS_LONG_WITH_ARG.contains(&body) {
                index += 1;
                options.push(value(long(body)?, argv.get(index - 1)?)?);
            } else {
                options.push(flag(long(body)?)?);
            }
        } else if let Some(cluster) = arg.strip_prefix('-') {
            for (offset, option) in cluster.char_indices() {
                if !RS_SHORT_WITH_ARG.contains(&option) {
                    options.push(flag(option)?);
                    continue;
                }
                let attached = &cluster[offset + option.len_utf8()..];
                if attached.starts_with('=') {
                    return None;
                }
                if !attached.is_empty() {
                    options.push(value(option, attached)?);
                } else if let Some(next) = argv.get(index) {
                    index += 1;
                    options.push(value(option, next)?);
                } else if option == 'h' {
                    options.push(flag(option)?);
                } else {
                    return None;
                }
                break;
            }
        } else if arg
            .split_once('=')
            .is_some_and(|(name, _)| name.chars().all(|c| c.is_alphanumeric() || c == '_'))
        {
            env = true;
        } else {
            index -= 1;
            break;
        }
    }
    Some(Scan {
        options,
        env,
        edit,
        command: argv.get(index..).unwrap_or_default().to_vec(),
    })
}

fn scan(argv: &[String], flavor: Flavor) -> Option<Scan> {
    match flavor {
        Flavor::Classic => scan_classic(argv),
        Flavor::Rs => scan_rs(argv),
    }
}

/// Options that don't change what runs or as whom, plus `-s`, `-i`, `-e`
/// and the user and group, which the mode and `runAs` show.
const UNDERSTOOD_FLAGS: &[char] = &['A', 'B', 'b', 'H', 'k', 'n', 'S', 's', 'i', 'e'];
const UNDERSTOOD_VALUES: &[char] = &['u', 'g', 'p'];

fn mode(scan: &Scan) -> Mode {
    let understood = scan.options.iter().all(|opt| match opt {
        Opt::Flag(option) => UNDERSTOOD_FLAGS.contains(option),
        Opt::Value('u' | 'g', value) if value.starts_with('#') => numeric_id(value).is_some(),
        Opt::Value(option, _) => UNDERSTOOD_VALUES.contains(option),
    });
    // `VAR=value` sets the command's environment, which can change what it
    // does; `sudo -- A=b cmd` still reads `A=b` as one.
    let env = scan.env
        || scan
            .command
            .first()
            .is_some_and(|first| first.contains('='));
    let edit = scan.edit || scan.has('e');
    let exclusive = [scan.has('s'), scan.has('i'), edit]
        .iter()
        .filter(|set| **set)
        .count();
    if !understood || env || exclusive > 1 {
        return Mode::Unparsed;
    }
    let command = scan.command.clone();
    if edit {
        if command.is_empty() {
            Mode::Unparsed
        } else {
            Mode::Edit(command)
        }
    } else if scan.has('s') {
        Mode::Shell(command)
    } else if scan.has('i') {
        Mode::Login(command)
    } else if command.is_empty() {
        Mode::Unparsed
    } else {
        Mode::Run(command)
    }
}

/// `#123`, a user or group named by id. sudo.ws also takes a sign and falls
/// back to a name lookup when the id doesn't parse, and sudo-rs takes `+`, so
/// only plain digits mean the same id to both. `#4294967295` is "no change".
pub fn numeric_id(value: &str) -> Option<u32> {
    let digits = value.strip_prefix('#')?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok().filter(|id| *id != u32::MAX)
}

/// A `#id` value with the name it resolves to, so the phone shows `#0 (root)`.
fn with_name(value: &str, lookup: impl Fn(u32) -> Option<String>) -> String {
    match numeric_id(value).and_then(lookup) {
        Some(name) => format!("{value} ({name})"),
        None => value.to_string(),
    }
}

/// Every sudo that may be running scans the argv its own way; one that would
/// reject it can't be the one asking. `-n` counts only when every remaining
/// scan has it, and the command only when they all agree, so a command's own
/// `-n` or an option's argument never passes for sudo's.
pub fn parse(argv: &[String]) -> Parsed {
    parse_for(argv, Flavor::platform())
}

fn parse_for(argv: &[String], flavors: &[Flavor]) -> Parsed {
    let scans: Vec<Scan> = flavors
        .iter()
        .filter_map(|flavor| scan(argv, *flavor))
        .collect();
    let agreed = |pick: &dyn Fn(&Scan) -> Option<String>| {
        let first = pick(scans.first()?);
        scans
            .iter()
            .all(|scan| pick(scan) == first)
            .then_some(first)?
    };
    let modes: Vec<Mode> = scans.iter().map(mode).collect();
    let mode = match modes.first() {
        Some(first) if modes.iter().all(|mode| mode == first) => first.clone(),
        _ => Mode::Unparsed,
    };
    Parsed {
        mode,
        user: agreed(&|scan| scan.value('u').map(str::to_string)),
        group: agreed(&|scan| scan.value('g').map(str::to_string)),
        non_interactive: !scans.is_empty() && scans.iter().all(|scan| scan.has('n')),
        stdin_password: !scans.is_empty() && scans.iter().all(|scan| scan.has('S')),
        runs_nothing: !scans.is_empty() && scans.iter().all(|scan| scan.has('v') || scan.has('l')),
    }
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

#[derive(Clone)]
pub struct Described {
    pub run_as: String,
    pub run_as_group: Option<String>,
    pub command: Command,
}

pub fn describe(sudo_argv: &[String], parsed: &Parsed, context: &Context) -> Described {
    let mut described = describe_command(sudo_argv, parsed, context);
    // Approving this enrolls a device the helper checks less strictly. Any
    // argv, parsed or not, since approving an unparsed one runs it too.
    let command = &mut described.command;
    for (index, arg) in command.argv.iter().enumerate() {
        match crate::enroll::trust_flag(arg) {
            Some(crate::attestation::Trust::Dev) => {
                command.warnings.push(Warning::at("dev_attestation", index));
            }
            Some(crate::attestation::Trust::Test) => {
                command
                    .warnings
                    .push(Warning::at("test_attestation", index));
            }
            _ => {}
        }
    }
    described
}

fn describe_command(sudo_argv: &[String], parsed: &Parsed, context: &Context) -> Described {
    let run_as = match (&parsed.user, &parsed.group) {
        (Some(user), _) => with_name(user, |uid| {
            crate::sys::user_by_uid(uid).map(|user| user.name)
        }),
        // `-g` alone runs the command as the invoking user.
        (None, Some(_)) => context.user.to_string(),
        (None, None) => "root".to_string(),
    };
    let run_as_group = parsed
        .group
        .as_deref()
        .map(|group| with_name(group, crate::sys::group_name));
    let mut warnings = Vec::new();
    let (argv, resolved_path, shell, arg_checks, reads_cwd) = match &parsed.mode {
        Mode::Unparsed => {
            warnings.push(Warning::new("unparsed_options"));
            if cwd_writable(context) {
                warnings.push(Warning::new("user_writable_cwd"));
            }
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
            // The command string is what runs; a bare shell reads stdin.
            let reads_cwd = command.is_empty() || command_string_reads_cwd(&argv[2]);
            (argv, resolved, command.is_empty(), false, reads_cwd)
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
            let script = is_shell.then(|| shell_command_arg(command)).flatten();
            let reads_cwd = match script {
                Some(script) => command_string_reads_cwd(script),
                None => is_shell || program_reads_cwd(command, resolved.as_deref()),
            };
            (
                command.clone(),
                resolved,
                is_shell && script.is_none(),
                true,
                reads_cwd,
            )
        }
    };
    if let Some(path) = &resolved_path
        && replaceable(Path::new(path), context)
    {
        warnings.push(Warning::new("user_writable_program"));
    }
    if arg_checks {
        // A program that loads code or files by name from the cwd can be
        // handed a file created there after approval.
        // Inline code and module names aren't files; the cwd warning
        // covers what they load from it.
        let names_are_paths = match interpreter_source(&argv) {
            Some((source, _)) => source == Source::Script,
            None => reads_cwd,
        };
        for (index, arg) in argv.iter().enumerate().skip(1) {
            if argument_writable(arg, names_are_paths, context) {
                warnings.push(Warning::at("user_writable_argument", index));
            }
        }
    }
    // `-i` starts in the target user's home instead.
    if reads_cwd && !matches!(parsed.mode, Mode::Login(_)) && cwd_writable(context) {
        warnings.push(Warning::new("user_writable_cwd"));
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
        // Writing a character device (`/dev/null`, a tty) doesn't change
        // what root reads from it later.
        if index + 1 == components.len()
            && !meta.file_type().is_symlink()
            && !meta.file_type().is_char_device()
            && writable_by(&meta, context)
        {
            return true;
        }
    }
    false
}

/// The path, or the file a symlink there points at, can be changed by the
/// user between approval and use.
fn replaceable(path: &Path, context: &Context) -> bool {
    if path_replaceable(path, context) {
        return true;
    }
    match std::fs::canonicalize(path) {
        Ok(canonical) => path_replaceable(&canonical, context),
        // A dangling symlink becomes whatever its target is created as.
        Err(_) => std::fs::read_link(path).is_ok_and(|target| {
            let parent = path.parent().unwrap_or(Path::new("/"));
            creatable(&parent.join(target), context)
        }),
    }
}

/// Whether a user with `uid` and `gids` could change what runs at `path`.
pub fn replaceable_by(path: &Path, uid: u32, gids: &[u32]) -> bool {
    let context = Context {
        user: "",
        uid,
        gids,
        cwd: "/",
        caller_shell: None,
        target_shell: None,
        search: Search::caller(""),
        shells: &[],
    };
    replaceable(path, &context)
}

/// Programs read config, build files, hooks and modules from the cwd (git
/// trusts a repository owned by `SUDO_UID`, make reads the Makefile, Python
/// puts it on `sys.path`), so a cwd the user can change runs the user's code.
fn cwd_writable(context: &Context) -> bool {
    replaceable(Path::new(context.cwd), context)
}

/// A missing path can be created by whoever can write its nearest existing
/// ancestor.
fn creatable(path: &Path, context: &Context) -> bool {
    path.ancestors()
        .skip(1)
        .find(|dir| std::fs::symlink_metadata(dir).is_ok())
        .is_some_and(|dir| replaceable(dir, context))
}

/// Existing arguments are checked as paths whatever they look like. A missing
/// one counts as a path only with a `/` or `.` in it: every word of
/// `systemctl restart nginx` is "missing" in a writable cwd, and warning on
/// all of them would teach people to skip warnings.
fn argument_writable(arg: &str, names_are_paths: bool, context: &Context) -> bool {
    if option_value(arg).is_some_and(|value| path_writable(value, names_are_paths, context)) {
        return true;
    }
    !arg.starts_with('-') && path_writable(arg, names_are_paths, context)
}

/// The part of an argument a program may read as a path: after the first `=`
/// of `--name=value` or `name=value` (dd), or from the first `/` of a short
/// option cluster such as `-tf/x` or `-I./include`. Where a cluster's letters
/// end isn't knowable without the program's own option table, so a relative
/// value without a `/` is left to `user_writable_cwd`.
fn option_value(arg: &str) -> Option<&str> {
    if let Some(long) = arg.strip_prefix("--") {
        return long.split_once('=').map(|(_, value)| value);
    }
    if let Some(cluster) = arg.strip_prefix('-') {
        let slash = cluster.find('/')?;
        let start = cluster[..slash].trim_end_matches('.').len();
        return Some(&cluster[start..]);
    }
    let (name, value) = arg.split_once('=')?;
    (!name.is_empty() && !name.contains('/')).then_some(value)
}

/// A missing argument counts as a path when it's absolute or starts with
/// `./` or `../`, and, for programs that read files by name from the cwd,
/// when it has a `/` or `.`. To other programs missing relative words
/// (`nginx.service`, `mongodb/brew`, globs) are names, and flagging them
/// fired on most requests from a project folder.
fn path_writable(arg: &str, names_are_paths: bool, context: &Context) -> bool {
    if arg.is_empty() {
        return false;
    }
    let path = Path::new(context.cwd).join(arg);
    if std::fs::symlink_metadata(&path).is_ok() {
        return replaceable(&path, context);
    }
    let explicit = arg.starts_with('/') || arg.starts_with("./") || arg.starts_with("../");
    let named = names_are_paths && (arg.contains('/') || arg.contains('.'));
    (explicit || named) && creatable(&path, context)
}

/// The command string of `sh -c <string>`, `zsh -lc <string>`: the first
/// operand after an option cluster containing `c`. Options that take a
/// value (`-o pipefail`) end the search, which only errs towards no string.
pub fn shell_command_arg(argv: &[String]) -> Option<&str> {
    let mut command = false;
    for arg in argv.iter().skip(1) {
        if arg == "--" || arg == "-" || !(arg.starts_with('-') || arg.starts_with('+')) {
            return command.then_some(arg.as_str());
        }
        if !arg.starts_with("--") && arg[1..].contains('c') {
            command = true;
        }
    }
    None
}

/// Programs that load config, build files or code from the cwd (`git`
/// trusts a repository owned by `SUDO_UID`, `make` reads the Makefile).
const CWD_READERS: &[&str] = &[
    "git",
    "make",
    "gmake",
    "just",
    "cmake",
    "ninja",
    "meson",
    "mvn",
    "gradle",
    "rake",
    "bundle",
    "vagrant",
    "npm",
    "npx",
    "pnpm",
    "yarn",
    "bun",
    "cargo",
    "go",
    "uv",
    "poetry",
    "pytest",
    "nix-build",
    "nix-shell",
    "docker-compose",
    "terraform",
    "tofu",
    "ansible",
    "ansible-playbook",
    "mise",
    "asdf",
    "direnv",
];

fn is_python(name: &str) -> bool {
    name.starts_with("python") || name.starts_with("pypy")
}

/// A flake reference that resolves against the cwd.
fn relative_flake(value: &str) -> bool {
    value.starts_with('.')
        || value.starts_with("path:.")
        || !(value.starts_with('/') || value.contains(':'))
}

/// Whether running `command` reads something from the cwd; only then can a
/// cwd the user controls change what root does.
fn program_reads_cwd(command: &[String], resolved: Option<&str>) -> bool {
    let name = basename(resolved.unwrap_or(&command[0]));
    let args = &command[1..];
    let has = |word: &str| args.iter().any(|arg| arg == word);
    if CWD_READERS.contains(&name) {
        return true;
    }
    if is_python(name) || name == "node" || name == "nodejs" {
        // Python puts the cwd on `sys.path` for `-c`, `-m` and stdin; node
        // resolves `node_modules` from it for `-e`, `-p` and stdin.
        return !matches!(interpreter_source(command), Some((Source::Script, _)));
    }
    match name {
        "nix" => {
            let operands: Vec<&String> = args.iter().filter(|arg| !arg.starts_with('-')).collect();
            operands
                .iter()
                .skip(1)
                .any(|arg| arg.starts_with('.') || arg.starts_with("path:."))
                || (operands.first().is_some_and(|sub| {
                    ["build", "develop", "run", "shell", "flake"].contains(&sub.as_str())
                }) && !operands
                    .iter()
                    .skip(1)
                    .any(|arg| arg.contains('#') || arg.contains(':')))
        }
        "darwin-rebuild" | "nixos-rebuild" | "home-manager" => {
            args.iter()
                .enumerate()
                .any(|(index, arg)| match arg.strip_prefix("--flake") {
                    Some("") => args
                        .get(index + 1)
                        .is_some_and(|value| relative_flake(value)),
                    Some(rest) => rest.strip_prefix('=').is_some_and(relative_flake),
                    None => false,
                })
        }
        "docker" | "podman" => has("compose") || has("build"),
        "brew" => has("bundle") && !args.iter().any(|arg| arg.starts_with("--file")),
        _ => false,
    }
}

/// A shell command string runs whatever it names; it reads the cwd when it
/// runs something by a relative path or a program that reads the cwd.
fn command_string_reads_cwd(script: &str) -> bool {
    script
        .split(|c: char| c.is_whitespace() || ";|&()<>`'\"$".contains(c))
        .filter(|word| !word.is_empty())
        .any(|word| {
            let name = basename(word);
            word.starts_with("./")
                || word.starts_with("../")
                || CWD_READERS.contains(&name)
                || is_python(name)
                || [
                    "node",
                    "nix",
                    "darwin-rebuild",
                    "nixos-rebuild",
                    "home-manager",
                    "docker",
                    "podman",
                ]
                .contains(&name)
        })
}

/// Where an interpreter takes its program from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// In the argv (`-c`, `-e`), so the phone shows it.
    Inline,
    /// A module name (`python -m`).
    Module,
    /// A script file operand.
    Script,
    /// Standard input, which the phone can't show.
    Stdin,
}

/// Options that take their value from the next argument, and the letters
/// that mean "the program follows", per interpreter.
struct Grammar {
    inline: &'static str,
    module: &'static str,
    valued: &'static [&'static str],
    /// The option an agent should use instead of stdin.
    hint: &'static str,
}

fn grammar(name: &str) -> Option<Grammar> {
    if KNOWN_SHELLS.contains(&name) {
        return None;
    }
    Some(if is_python(name) {
        Grammar {
            inline: "c",
            module: "m",
            valued: &["-W", "-X", "-Q"],
            hint: "-c",
        }
    } else {
        match name {
            "node" | "nodejs" => Grammar {
                inline: "ep",
                module: "",
                valued: &[
                    "-r",
                    "--require",
                    "--import",
                    "--loader",
                    "-C",
                    "--conditions",
                ],
                hint: "-e",
            },
            "ruby" => Grammar {
                inline: "e",
                module: "",
                valued: &["-I", "-r", "-C"],
                hint: "-e",
            },
            "perl" => Grammar {
                inline: "eE",
                module: "",
                valued: &["-I", "-M", "-m"],
                hint: "-e",
            },
            "php" => Grammar {
                inline: "r",
                module: "",
                valued: &["-d", "-c", "-z"],
                hint: "-r",
            },
            "osascript" => Grammar {
                inline: "e",
                module: "",
                valued: &["-l", "-s"],
                hint: "-e",
            },
            _ => return None,
        }
    })
}

/// Where `command`'s interpreter reads its program from, with the option
/// that passes it inline; None for programs that aren't interpreters.
pub fn interpreter_source(command: &[String]) -> Option<(Source, &'static str)> {
    let name = basename(&command[0]);
    if KNOWN_SHELLS.contains(&name) {
        if shell_command_arg(command).is_some() {
            return Some((Source::Inline, "-c"));
        }
        let mut args = command.iter().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-" => return Some((Source::Stdin, "-c")),
                "--" => return Some((args.next().map_or(Source::Stdin, |_| Source::Script), "-c")),
                "-o" | "+o" | "-O" | "+O" => {
                    args.next();
                }
                _ if arg.starts_with("--") => {}
                _ if arg.starts_with('-') || arg.starts_with('+') => {
                    if arg[1..].contains('s') {
                        return Some((Source::Stdin, "-c"));
                    }
                }
                _ => return Some((Source::Script, "-c")),
            }
        }
        return Some((Source::Stdin, "-c"));
    }
    let grammar = grammar(name)?;
    let mut args = command.iter().skip(1);
    while let Some(arg) = args.next() {
        if arg == "-" {
            return Some((Source::Stdin, grammar.hint));
        }
        if arg == "--" {
            return Some((
                args.next().map_or(Source::Stdin, |_| Source::Script),
                grammar.hint,
            ));
        }
        if let Some(long) = arg.strip_prefix("--") {
            if ["eval", "print"].contains(&long) && grammar.hint == "-e" && name.starts_with("node")
            {
                return Some((Source::Inline, grammar.hint));
            }
            if grammar.valued.contains(&arg.as_str()) {
                args.next();
            }
            continue;
        }
        let Some(cluster) = arg.strip_prefix('-') else {
            return Some((Source::Script, grammar.hint));
        };
        if grammar.valued.contains(&arg.as_str()) {
            args.next();
            continue;
        }
        for (offset, letter) in cluster.char_indices() {
            if grammar.inline.contains(letter) {
                return Some((Source::Inline, grammar.hint));
            }
            if grammar.module.contains(letter) {
                return Some((Source::Module, grammar.hint));
            }
            // A valued option with its value attached ends the cluster.
            if grammar.valued.contains(&format!("-{letter}").as_str()) {
                if cluster[offset + letter.len_utf8()..].is_empty() {
                    args.next();
                }
                break;
            }
        }
    }
    Some((Source::Stdin, grammar.hint))
}

/// A copy of `name` the user can't change, on the PATH sudo searches or in
/// the usual system folders, other than `resolved` itself.
pub fn system_copy(name: &str, resolved: &str, context: &Context) -> Option<String> {
    let search = &context.search;
    let mut dirs: Vec<&str> = search
        .secure_path
        .iter()
        .flatten()
        .chain(search.env_paths.iter().flatten())
        .flat_map(|path| path.split(':'))
        .collect();
    dirs.extend(["/usr/bin", "/bin", "/usr/sbin", "/sbin"]);
    let current = std::fs::canonicalize(resolved).ok();
    dirs.into_iter()
        .filter(|dir| dir.starts_with('/'))
        .map(|dir| format!("{}/{name}", dir.trim_end_matches('/')))
        .find(|candidate| {
            executable_file(Path::new(candidate))
                && !replaceable(Path::new(candidate), context)
                && std::fs::canonicalize(candidate).ok() != current
        })
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
                Warning::at("user_writable_argument", 1),
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
        // The command string is what runs, and it reads nothing from the cwd.
        assert_eq!(described.command.warnings, vec![]);

        let sudo = argv(&["sudo", "-i"]);
        assert_eq!(
            describe(&sudo, &parse(&sudo), &ctx).command.argv,
            argv(&["/bin/bash"])
        );

        let sudo = argv(&["sudo", "sh", "-c", "id"]);
        let described = describe(&sudo, &parse(&sudo), &ctx);
        assert_eq!(described.command.warnings, vec![]);
        let sudo = argv(&["sudo", "sh", "-c", "cd /src && make install"]);
        let described = describe(&sudo, &parse(&sudo), &ctx);
        assert_eq!(
            described.command.warnings,
            vec![Warning::new("user_writable_cwd")]
        );
        let sudo = argv(&["sudo", "sh", "x.py"]);
        let described = describe(&sudo, &parse(&sudo), &ctx);
        assert_eq!(
            described.command.warnings,
            vec![
                Warning::at("user_writable_argument", 1),
                Warning::new("user_writable_cwd"),
                Warning::new("shell")
            ]
        );

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
            vec![
                Warning::new("unparsed_options"),
                Warning::new("user_writable_cwd")
            ]
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

    #[test]
    fn non_interactive_only_when_every_sudo_sees_it() {
        let both = &[Flavor::Classic, Flavor::Rs][..];
        let classic = &[Flavor::Classic][..];
        let rs = &[Flavor::Rs][..];
        for (args, flavors, expected) in [
            // Environment assignments don't end the options.
            (&["sudo", "FOO=1", "-n", "true"][..], both, true),
            // An option's argument isn't an option.
            (&["sudo", "-u", "-n", "true"], both, false),
            (&["sudo", "-p", "-n", "true"], both, false),
            (&["sudo", "--user", "-n", "true"], both, false),
            // A command's own -n never counts.
            (&["sudo", "true", "-n"], both, false),
            (&["sudo", "--", "-n"], both, false),
            // getopt_long takes a unique prefix; `--no` is ambiguous.
            (&["sudo", "--non", "true"], classic, true),
            (&["sudo", "--no", "true"], classic, false),
            // sudo-rs matches long names exactly and rejects the rest, so
            // only sudo.ws can be asking.
            (&["sudo", "--non", "true"], both, true),
            (&["sudo", "--non", "true"], rs, false),
            // sudo-rs takes `-h`'s argument and rejects it; sudo.ws reads a
            // following non-option as the host.
            (&["sudo", "-h", "box", "-n", "true"], classic, true),
            // `-h` followed by an option is help, which never authenticates.
            (&["sudo", "-n", "-hn"], classic, true),
            // After `--`, an assignment is the command.
            (&["sudo", "-u", "--", "A=b", "-n"], classic, false),
            // sudo-rs ignores a lone `-`; sudo.ws runs it.
            (&["sudo", "-", "-n"], rs, true),
            (&["sudo", "-", "-n"], both, false),
            // `-E` takes no argument as a short option.
            (&["sudo", "-E", "-n", "id"], both, true),
            (&["sudo", "--preserve-env", "-n", "id"], both, true),
            (&["sudo", "-u"], both, false),
        ] {
            assert_eq!(
                parse_for(&argv(args), flavors).non_interactive,
                expected,
                "{args:?} {flavors:?}"
            );
        }
    }

    #[test]
    fn scans_mirror_each_sudo() {
        let scanned = scan_classic(&argv(&["sudo", "-nu", "bob", "-hbox", "-D/x", "A=1", "id"]));
        assert_eq!(
            scanned,
            Some(Scan {
                options: vec![
                    Opt::Flag('n'),
                    Opt::Value('u', "bob".into()),
                    Opt::Value('h', "box".into()),
                    Opt::Value('D', "/x".into()),
                ],
                env: true,
                edit: false,
                command: argv(&["id"]),
            })
        );
        assert_eq!(scan_classic(&argv(&["sudo", "--login=x", "id"])), None);
        assert_eq!(scan_classic(&argv(&["sudo", "-X", "id"])), None);
        assert_eq!(scan_classic(&argv(&["sudoedit", "-e", "f"])), None);
        assert_eq!(
            scan_classic(&argv(&["sudo", "-s", "/a=b"]))
                .unwrap()
                .command,
            argv(&["/a=b"])
        );
        assert_eq!(scan_rs(&argv(&["sudo", "-u=bob", "id"])), None);
        assert_eq!(scan_rs(&argv(&["sudo", "-R", "/", "id"])), None);
        assert_eq!(scan_rs(&argv(&["sudo", "--non", "id"])), None);
        assert_eq!(scan_rs(&argv(&["sudo", "--shell=x"])), None);
        assert_eq!(scan_rs(&argv(&["sudoedit", "-e", "f"])), None);
        let scanned = scan_rs(&argv(&["sudo", "--preserve-env=A,B", "a-b=1", "-n"])).unwrap();
        assert_eq!(scanned.options, vec![Opt::Value('E', "A,B".into())]);
        assert_eq!(scanned.command, argv(&["a-b=1", "-n"]));
    }

    #[test]
    fn numeric_ids_show_their_names() {
        let tmp = std::env::temp_dir();
        let shells = vec![];
        let ctx = context(tmp.to_str().unwrap(), &[], &shells);
        let sudo = argv(&["sudo", "-u", "#0", "-g", "#0", "/usr/bin/true"]);
        let described = describe(&sudo, &parse(&sudo), &ctx);
        assert_eq!(described.run_as, "#0 (root)");
        let group = crate::sys::group_name(0).unwrap();
        assert_eq!(described.run_as_group, Some(format!("#0 ({group})")));
        // No such user: sudo.ws runs as the bare id, so that's what shows.
        let sudo = argv(&["sudo", "-u", "#4000000000", "/usr/bin/true"]);
        assert_eq!(describe(&sudo, &parse(&sudo), &ctx).run_as, "#4000000000");
        // Spellings the two sudos read differently aren't shown as parsed.
        for user in ["#+0", "#-1", "# 0", "#", "#4294967295", "#0x0"] {
            let sudo = argv(&["sudo", "-u", user, "/usr/bin/true"]);
            assert_eq!(parse(&sudo).mode, Mode::Unparsed, "{user}");
        }
    }

    /// Review finding 6: the phone says when approving enrolls a device with
    /// relaxed attestation.
    #[test]
    fn relaxed_attestation_flags_are_warned() {
        let tmp = std::env::temp_dir();
        let shells = vec![];
        let ctx = context(tmp.to_str().unwrap(), &[], &shells);
        let helper = "/usr/local/lib/t3-elevation/t3-elevation";
        let codes = |sudo: &[&str]| -> Vec<(String, Option<usize>)> {
            let sudo = argv(sudo);
            describe(&sudo, &parse(&sudo), &ctx)
                .command
                .warnings
                .into_iter()
                .filter(|warning| warning.code.ends_with("_attestation"))
                .map(|warning| (warning.code, warning.arg))
                .collect()
        };
        let enroll = ["sudo", helper, "enroll", "--user", "u"];
        assert_eq!(codes(&enroll), vec![]);
        assert_eq!(
            codes(&[&enroll[..], &["--allow-dev-attestation"]].concat()),
            vec![("dev_attestation".to_string(), Some(4))]
        );
        assert_eq!(
            codes(&[&enroll[..], &["--allow-test-attestation"]].concat()),
            vec![("test_attestation".to_string(), Some(4))]
        );
        // Unparsed sudo options show the raw argv, which still runs.
        assert_eq!(
            codes(&["sudo", "-E", helper, "install", "--allow-test-attestation"]),
            vec![("test_attestation".to_string(), Some(3))]
        );
    }

    #[test]
    fn abbreviations_are_parsed_where_only_sudo_ws_accepts_them() {
        let parsed = parse_for(
            &argv(&["sudo", "--us=root", "--sh", "id"]),
            &[Flavor::Classic, Flavor::Rs],
        );
        assert_eq!(parsed.user.as_deref(), Some("root"));
        assert_eq!(parsed.mode, Mode::Shell(argv(&["id"])));
        // `--log` could be `--login` or `--login-class`.
        assert_eq!(scan_classic(&argv(&["sudo", "--log", "id"])), None);
        // Where both accept but read it differently, nothing is shown parsed.
        let parsed = parse_for(&argv(&["sudo", "-", "id"]), &[Flavor::Classic, Flavor::Rs]);
        assert_eq!(parsed.mode, Mode::Unparsed);
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
    fn replaceable_arguments_are_warned() {
        let tmp = std::env::temp_dir().join(format!("t3e-argv-replace-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::os::unix::fs::symlink("/etc/hosts", tmp.join("tool.py")).unwrap();
        let cwd = tmp.to_string_lossy().into_owned();
        let shells = vec![];
        let ctx = context(&cwd, &[], &shells);
        let warnings = |program: &str, arg: &str| {
            let sudo = argv(&["sudo", program, arg]);
            argument_warnings(describe(&sudo, &parse(&sudo), &ctx).command.warnings)
        };
        let results = [
            warnings("/bin/cat", "tool.py"),
            warnings("/bin/cat", "./later.py"),
            // An interpreter runs whatever appears under that name.
            warnings("python3", "later.py"),
            // To other programs a missing relative word is a name.
            warnings("/bin/cat", "later.py"),
        ];
        std::fs::remove_dir_all(&tmp).unwrap();
        let flagged = vec![Warning::at("user_writable_argument", 1)];
        assert_eq!(results, [flagged.clone(), flagged.clone(), flagged, vec![]]);
    }

    /// Review 2: `/dev/null` is 0666, so it was flagged on every
    /// `of=/dev/null` or `2>/dev/null`-style argument. Writing to a character
    /// device doesn't change what root later reads from it, and a false
    /// positive teaches people to skip warnings.
    #[test]
    fn character_devices_are_not_warned() {
        let shells = vec![];
        let ctx = context("/", &[], &shells);
        let sudo = argv(&["sudo", "/bin/cat", "/dev/null", "/dev/zero", "/dev/tty"]);
        assert_eq!(
            describe(&sudo, &parse(&sudo), &ctx).command.warnings,
            vec![]
        );
    }

    /// Review 2, G3: a path the user can swap was only checked as an argument
    /// of its own, so `dd if=~/x`, `tar --file=~/x` and `tar -tf~/x` showed
    /// nothing in red while `tar -t -f ~/x` did.
    #[test]
    fn paths_inside_option_values_are_warned() {
        let tmp = std::env::temp_dir().join(format!("t3e-argv-values-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("tool.py"), "").unwrap();
        let mine = tmp.to_string_lossy().into_owned();
        let shells = vec![];
        let ctx = context("/", &[], &shells);
        let flagged = |args: &[String]| -> Vec<usize> {
            let sudo = [vec!["sudo".to_string()], args.to_vec()].concat();
            argument_warnings(describe(&sudo, &parse(&sudo), &ctx).command.warnings)
                .into_iter()
                .filter_map(|warning| warning.arg)
                .collect()
        };
        let cases: Vec<(Vec<String>, Vec<usize>)> = vec![
            (
                argv(&[
                    "/bin/dd",
                    &format!("if={mine}/tool.py"),
                    "of=/dev/null",
                    "status=none",
                ]),
                vec![1],
            ),
            (
                argv(&[
                    "/usr/bin/tar",
                    &format!("--file={mine}/tool.tar"),
                    "-tf",
                    "/dev/null",
                ]),
                vec![1],
            ),
            (
                argv(&["/usr/bin/tar", &format!("-tf{mine}/tool.tar")]),
                vec![1],
            ),
            (
                argv(&["/usr/bin/tar", "-t", "-f", &format!("{mine}/tool.tar")]),
                vec![3],
            ),
            (
                argv(&["/usr/bin/cc", &format!("-I{mine}"), "-c", "/dev/null"]),
                vec![1],
            ),
            // Values root controls, and values that aren't paths.
            (
                argv(&[
                    "/usr/bin/tar",
                    "--file=/etc/hosts",
                    "-C/etc",
                    "--level=3",
                    "-j4",
                    "conv=notrunc",
                    "--",
                    "-",
                ]),
                vec![],
            ),
        ];
        let results: Vec<_> = cases.iter().map(|(args, _)| flagged(args)).collect();
        std::fs::remove_dir_all(&tmp).unwrap();
        let expected: Vec<_> = cases.into_iter().map(|(_, expected)| expected).collect();
        assert_eq!(results, expected);
    }

    fn argument_warnings(warnings: Vec<Warning>) -> Vec<Warning> {
        warnings
            .into_iter()
            .filter(|warning| warning.code == "user_writable_argument")
            .collect()
    }

    /// Review 2, G1: git trusts a repository owned by `SUDO_UID`, so
    /// `sudo git clean -fdx` ran `core.fsmonitor` from the project's
    /// `.git/config` as root, and `sudo make install` ran its Makefile, with
    /// nothing in red. Anything a command reads from a cwd the user can write
    /// is the user's code.
    #[test]
    fn writable_working_directories_are_warned() {
        let tmp = std::env::temp_dir().join(format!("t3e-argv-cwd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("proj")).unwrap();
        let shells = vec![];
        let warned = |cwd: &Path, sudo: &[&str]| {
            let cwd = cwd.to_string_lossy().into_owned();
            let ctx = context(&cwd, &[], &shells);
            let sudo = argv(sudo);
            describe(&sudo, &parse(&sudo), &ctx)
                .command
                .warnings
                .contains(&Warning::new("user_writable_cwd"))
        };
        let proj = tmp.join("proj");
        let in_proj = |sudo: &[&str]| warned(&proj, sudo);
        let reads = [
            &["sudo", "git", "clean", "-fdx"][..],
            &["sudo", "make", "install"],
            &["sudo", "-E", "make"],
            &["sudo", "-s"],
            &["sudo", "python3", "-c", "import x"],
            &["sudo", "python3", "-m", "pip", "list"],
            &["sudo", "nix", "build", ".#x"],
            &["sudo", "nix", "build"],
            &["sudo", "darwin-rebuild", "switch", "--flake", ".#mac"],
            &["sudo", "nixos-rebuild", "switch", "--flake=.#box"],
            &["sudo", "docker", "compose", "up"],
            &["sudo", "sh", "-c", "cd sub && ./configure"],
        ];
        // Programs that don't look at the cwd: 58% of real agent sudo.
        let ignores = [
            &["sudo", "/usr/bin/true"][..],
            &["sudo", "systemctl", "restart", "nginx.service"],
            &["sudo", "launchctl", "kickstart", "system/com.apple.mds"],
            &["sudo", "python3", "/etc/t3/x.py"],
            &["sudo", "nix", "build", "nixpkgs#hello"],
            &[
                "sudo",
                "darwin-rebuild",
                "switch",
                "--flake",
                "/etc/nix-darwin#mac",
            ],
            &["sudo", "sh", "-c", "echo x > /etc/f"],
            // A login shell starts in the target's home.
            &["sudo", "-i"],
            // sudoedit runs the editor as the user.
            &["sudo", "-e", "/etc/hosts"],
        ];
        let read: Vec<bool> = reads.iter().map(|sudo| in_proj(sudo)).collect();
        let ignored: Vec<bool> = ignores.iter().map(|sudo| in_proj(sudo)).collect();
        let from_root = warned(Path::new("/"), &["sudo", "make", "install"]);
        std::fs::remove_dir_all(&tmp).unwrap();
        assert_eq!(read, vec![true; reads.len()]);
        assert_eq!(ignored, vec![false; ignores.len()]);
        assert!(!from_root);
    }

    #[test]
    fn arguments_root_controls_are_not_warned() {
        let tmp = std::env::temp_dir().join(format!("t3e-argv-rootargs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::os::unix::fs::symlink(tmp.join("not-yet.py"), tmp.join("dangling")).unwrap();
        let cwd = tmp.to_string_lossy().into_owned();
        let shells = vec![];
        let ctx = context(&cwd, &[], &shells);
        let sudo = argv(&[
            "sudo",
            "/bin/cat",
            "/etc/hosts",
            "/nonexistent-t3/x.py",
            "restart",
            "./later",
            "dangling",
        ]);
        let warnings = argument_warnings(describe(&sudo, &parse(&sudo), &ctx).command.warnings);
        std::fs::remove_dir_all(&tmp).unwrap();
        assert_eq!(
            warnings,
            vec![
                Warning::at("user_writable_argument", 4),
                Warning::at("user_writable_argument", 5)
            ]
        );
    }
}
