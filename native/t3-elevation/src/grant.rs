//! One approval per agent command. Agents run each tool call in a fresh
//! `<shell> -c` that leads its own kernel session. An approved sudo whose
//! argv is one of the sudos written in that command string records a grant
//! for the other sudos written there, bound to the session, its leader's
//! start time and argv. A later sudo passes without the phone only when it is
//! one of those calls, word for word, as the same target, from the same cwd,
//! while the leader lives and runs the same argv, within the window. Each
//! call is covered once.
//!
//! A session only qualifies when nothing long-lived can feed it commands
//! from later tool calls: its leader must be a shell started with a command
//! string, every process between it and sudo must be a shell, and it must
//! have no controlling terminal (agents' persistent shells are PTYs). Any
//! other sudo gets one approval per sudo.

use crate::keys::EnrolledKey;
use crate::payload::Session;
use crate::rootsafe::{self, Policy};
use crate::sys::{ChainEntry, LeaderFacts};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Path, PathBuf};

/// Grants live in tmpfs on Linux, so a reboot (which restarts tick-based
/// start times) clears them. macOS start times are wall-clock microseconds,
/// and its `/var/run` is group-writable, so they live under `/var/db`.
#[cfg(target_os = "linux")]
pub const GRANTS_DIR: &str = "/run/t3-elevation";
#[cfg(not(target_os = "linux"))]
pub const GRANTS_DIR: &str = "/var/db/t3-elevation";

/// A grant holds at most a payload's worth of calls, JSON-escaped.
const MAX_GRANT_BYTES: u64 = 128 * 1024;

/// A session an approval may also cover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub session: i32,
    pub leader_start: u64,
}

/// A qualified session and what its leader was started to run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope {
    pub anchor: Anchor,
    pub leader_argv: Vec<String>,
    /// The leader's `-c` string, which the payload signs.
    pub command: String,
}

impl Scope {
    /// None unless `leader_argv` is a shell with a `-c` string.
    pub fn new(anchor: Anchor, leader_argv: Vec<String>) -> Option<Self> {
        let command = command_string(&leader_argv)?.to_string();
        Some(Self {
            anchor,
            leader_argv,
            command,
        })
    }
}

/// Shells listed in `/etc/shells` whose file, and every directory above it,
/// is root's and can't be changed by the user. A program merely named like a
/// shell (a renamed copy in `~/bin`) isn't one.
pub struct Shells {
    listed: Vec<PathBuf>,
    policy: Policy,
    uid: u32,
    gids: Vec<u32>,
}

impl Shells {
    /// No shells when the list itself isn't root-safe.
    pub fn load(path: &Path, policy: &Policy, uid: u32, gids: &[u32]) -> Self {
        let listed = rootsafe::check_path(path, policy, rootsafe::Kind::File)
            .ok()
            .and_then(|()| rootsafe::read_limited(path, 64 * 1024).ok())
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .map(|text| {
                text.lines()
                    .map(str::trim)
                    .filter(|line| line.starts_with('/'))
                    .filter_map(|line| std::fs::canonicalize(line).ok())
                    .collect()
            })
            .unwrap_or_default();
        Self {
            listed,
            policy: policy.clone(),
            uid,
            gids: gids.to_vec(),
        }
    }

    pub fn contains(&self, exe: Option<&str>) -> bool {
        let Some(canonical) = exe.and_then(|exe| std::fs::canonicalize(exe).ok()) else {
            return false;
        };
        self.listed.contains(&canonical)
            && rootsafe::owned(&canonical, &self.policy)
            && !crate::sudo_argv::replaceable_by(&canonical, self.uid, &self.gids)
    }
}

/// The string of `sh -c …`, `zsh -lc …`, `bash --norc -c …`: the only
/// operand, after an option cluster with `c`. Trailing operands would set
/// `$0` and `$1`, which the command's reading doesn't follow.
fn command_string(argv: &[String]) -> Option<&str> {
    let mut command = false;
    for (index, arg) in argv.iter().enumerate().skip(1) {
        if arg == "--" || !arg.starts_with('-') {
            return (command && index + 1 == argv.len()).then_some(arg.as_str());
        }
        if !arg.starts_with("--") && arg[1..].contains('c') {
            command = true;
        }
    }
    None
}

/// The scope for a sudo in session `session`, from its ancestor chain
/// (`chain[0]` is sudo's parent) and the leader's kernel facts, or None when
/// the session could carry later, unrelated commands.
pub fn qualify(
    session: i32,
    chain: &[ChainEntry],
    leader: Option<LeaderFacts>,
    shells: &Shells,
) -> Option<Scope> {
    let leader = leader?;
    if leader.has_tty {
        return None;
    }
    let position = chain.iter().position(|entry| entry.pid == session)?;
    let entry = &chain[position];
    // zsh and bash exec a command string's last command, so a bare `sudo …`
    // is the leader itself and never reaches here; a leader that isn't a
    // `-c` shell is a provider process or a shell reading stdin.
    let argv = entry.argv.clone()?;
    // The chain reads argv lossily; a replaced byte would hide a change.
    if entry.argv_truncated
        || argv.iter().any(|arg| arg.contains('\u{FFFD}'))
        || !shells.contains(entry.exe.as_deref())
    {
        return None;
    }
    // `xargs sudo`, `timeout 5 sudo` and the like fall back to one approval
    // per sudo rather than trust a program between sudo and the leader.
    if !chain[..position]
        .iter()
        .all(|entry| shells.contains(entry.exe.as_deref()))
    {
        return None;
    }
    Scope::new(
        Anchor {
            session,
            leader_start: leader.start,
        },
        argv,
    )
}

/// A sudo written in the approved command that the grant still covers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Covered {
    /// sudo's argv without argv[0].
    pub args: Vec<String>,
    /// Where sudo found the program when the approval was given.
    pub resolved_path: String,
    pub run_as: String,
    pub run_as_group: Option<String>,
    /// The command string's last command, which its shell may exec.
    pub exec_tail: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Grant {
    pub version: u32,
    pub uid: u32,
    pub user: String,
    pub session: i32,
    pub leader_start: u64,
    /// `argv_digest` of the leader's argv when the approval was given.
    pub leader_argv: String,
    pub cwd: String,
    pub key_id: String,
    pub until: i64,
    pub sudos: Vec<Covered>,
    /// The rest only says why a later sudo missed (`Miss`); none of it
    /// approves anything. Optional so a grant without it still reads.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub non_literal: bool,
    /// `argv_digest`s of written calls past `session_max_uses`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capped: Vec<String>,
    /// `argv_digest`s of the approved call and the calls used since.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub used: Vec<String>,
}

const GRANT_VERSION: u32 = 2;

/// The written sudos an approval doesn't cover, by why.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Uncovered {
    /// A written sudo had an argument an expansion may change.
    pub non_literal: bool,
    /// Calls past `session_max_uses`, as sudo's argv without argv[0].
    pub capped: Vec<Vec<String>>,
    /// The approved call itself.
    pub approved: Vec<String>,
}

/// base64url SHA-256 of each argument followed by a NUL.
fn argv_digest(argv: &[String]) -> String {
    let mut hash = Sha256::new();
    for arg in argv {
        hash.update(arg.as_bytes());
        hash.update([0]);
    }
    crate::b64::encode(&hash.finalize())
}

impl Grant {
    pub fn new(
        (uid, user): (u32, &str),
        session: &Session,
        leader_argv: &[String],
        cwd: &str,
        key_id: &str,
        until: i64,
        (sudos, uncovered): (Vec<Covered>, Uncovered),
    ) -> Self {
        Self {
            version: GRANT_VERSION,
            uid,
            user: user.to_string(),
            session: session.id,
            leader_start: session.leader_start,
            leader_argv: argv_digest(leader_argv),
            cwd: cwd.to_string(),
            key_id: key_id.to_string(),
            until,
            sudos,
            non_literal: uncovered.non_literal,
            capped: uncovered
                .capped
                .iter()
                .map(|args| argv_digest(args))
                .collect(),
            used: vec![argv_digest(&uncovered.approved)],
        }
    }
}

/// What a later sudo asks a grant for.
pub struct Request<'a> {
    pub uid: u32,
    pub user: &'a str,
    pub anchor: Anchor,
    /// The sudo leads the session: its shell exec'd it.
    pub leading: bool,
    /// sudo's argv without argv[0].
    pub args: &'a [String],
    /// The phone would warn about it, it's the helper, or sudo can't find
    /// the program: never covered.
    pub excluded: bool,
    pub resolved_path: Option<&'a str>,
    pub run_as: &'a str,
    pub run_as_group: Option<&'a str>,
    pub cwd: &'a str,
}

/// How `take` reads the session's leader now.
pub struct Leader<S, A> {
    pub start: S,
    pub argv: A,
}

/// The grants directory, locked for the caller's read-check-write: root-owned
/// (or a test owner), 0700, not a symlink, in a root-safe parent.
struct Locked {
    dir: PathBuf,
    _lock: std::fs::File,
}

fn open_dir(dir: &Path, policy: &Policy, create: bool) -> Option<Locked> {
    rootsafe::check_path(dir.parent()?, policy, rootsafe::Kind::Dir).ok()?;
    if create {
        let _ = std::fs::DirBuilder::new()
            .mode(0o700)
            .create(dir)
            .map(|()| std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)));
    }
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)
        .ok()?;
    let meta = handle.metadata().ok()?;
    if !meta.is_dir() || !policy.owners.contains(&meta.uid()) || meta.mode() & 0o077 != 0 {
        return None;
    }
    use std::os::fd::AsRawFd as _;
    if unsafe { libc::flock(handle.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return None;
    }
    Some(Locked {
        dir: dir.to_path_buf(),
        _lock: handle,
    })
}

fn file_name(uid: u32, session: i32) -> String {
    format!("{uid}-{session}.json")
}

/// None for anything that isn't a well-formed grant file only root wrote.
fn read(path: &Path, policy: &Policy) -> Option<Grant> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file()
        || !policy.owners.contains(&meta.uid())
        || meta.mode() & 0o077 != 0
        || meta.len() > MAX_GRANT_BYTES
    {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_GRANT_BYTES).read_to_end(&mut bytes).ok()?;
    let grant: Grant = serde_json::from_slice(&bytes).ok()?;
    (grant.version == GRANT_VERSION).then_some(grant)
}
/// Writes beside the target and renames over it, so a reader sees the old
/// grant or the new one.
fn write(locked: &Locked, name: &str, grant: &Grant) -> bool {
    let target = locked.dir.join(name);
    let temp = locked
        .dir
        .join(format!(".{name}.{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&temp);
    let written = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)
            .ok()?;
        file.write_all(&serde_json::to_vec(grant).ok()?).ok()?;
        file.sync_all().ok()?;
        std::fs::rename(&temp, &target).ok()
    })();
    if written.is_none() {
        let _ = std::fs::remove_file(&temp);
    }
    written.is_some()
}

/// Expired, used-up and unreadable grants; stale temp files too.
fn prune(locked: &Locked, policy: &Policy, now: i64) {
    let Ok(entries) = std::fs::read_dir(&locked.dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let keep =
            read(&path, policy).is_some_and(|grant| grant.until > now && !grant.sudos.is_empty());
        if !keep {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Records a grant for an approved sudo. Failing only costs later phone
/// prompts, so errors are swallowed.
pub fn record(dir: &Path, policy: &Policy, grant: &Grant, now: i64) {
    if grant.sudos.is_empty() {
        return;
    }
    let Some(locked) = open_dir(dir, policy, true) else {
        return;
    };
    prune(&locked, policy, now);
    write(&locked, &file_name(grant.uid, grant.session), grant);
}

/// Whether a grant file exists for the session, so callers can skip
/// describing the request when there's nothing to take.
pub fn present(dir: &Path, uid: u32, session: i32) -> bool {
    std::fs::symlink_metadata(dir.join(file_name(uid, session))).is_ok()
}

/// Why a sudo in a session with a grant asks the phone anyway. Counted in
/// syslog to learn which sudos agents write that a grant can't cover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Miss {
    /// No readable grant: the normal first prompt, never logged.
    NoGrant,
    Expired,
    /// The leader died, was reused, or now runs something else.
    LeaderChanged,
    Cwd,
    /// Another invoking user, or another `-u`/`-g` than the written call.
    User,
    /// The approving key is no longer enrolled.
    Key,
    /// The written call's program resolves elsewhere now.
    Program,
    Excluded,
    /// The approved call again, or a call already used.
    Used,
    Cap,
    /// Not a covered call, and the approved command had a sudo whose
    /// arguments expand, which this one may be.
    NonLiteral,
    NotInCommand,
    /// Covered, but the use couldn't be counted.
    Unrecorded,
}

impl Miss {
    /// The syslog category; None when there's nothing to count.
    pub fn category(self) -> Option<&'static str> {
        Some(match self {
            Self::NoGrant => return None,
            Self::Expired => "expired",
            Self::LeaderChanged => "leader-changed",
            Self::Cwd => "cwd",
            Self::User => "user",
            Self::Key => "key",
            Self::Program => "program",
            Self::Excluded => "excluded",
            Self::Used => "used",
            Self::Cap => "cap",
            Self::NonLiteral => "non-literal",
            Self::NotInCommand => "not-in-command",
            Self::Unrecorded => "unrecorded",
        })
    }
}

/// Consumes the call of the grant that `request` is, if there is one. The
/// leader is re-read from the kernel, so a dead leader, a reused pid, or a
/// leader that now runs something else never matches.
pub fn take<S, A>(
    dir: &Path,
    policy: &Policy,
    request: &Request,
    keys: &[EnrolledKey],
    now: i64,
    leader: Leader<S, A>,
) -> Result<(), Miss>
where
    S: Fn(i32) -> Option<u64>,
    A: Fn(i32) -> Option<Vec<String>>,
{
    let locked = open_dir(dir, policy, false).ok_or(Miss::NoGrant)?;
    let name = file_name(request.uid, request.anchor.session);
    let path = locked.dir.join(&name);
    let mut grant = read(&path, policy).ok_or(Miss::NoGrant)?;
    let stale = if grant.sudos.is_empty() {
        Some(Miss::NoGrant)
    } else if now >= grant.until {
        Some(Miss::Expired)
    } else if (leader.start)(grant.session) != Some(grant.leader_start) {
        Some(Miss::LeaderChanged)
    } else {
        None
    };
    if let Some(miss) = stale {
        let _ = std::fs::remove_file(&path);
        return Err(miss);
    }
    // A leading sudo replaced the shell, so its argv is sudo's own; only the
    // string's last command can have done that.
    let same_leader = request.leading
        || (leader.argv)(grant.session).is_some_and(|argv| argv_digest(&argv) == grant.leader_argv);
    if grant.uid != request.uid || grant.user != request.user {
        return Err(Miss::User);
    }
    if grant.session != request.anchor.session
        || grant.leader_start != request.anchor.leader_start
        || !same_leader
    {
        return Err(Miss::LeaderChanged);
    }
    if grant.cwd != request.cwd {
        return Err(Miss::Cwd);
    }
    if !keys.iter().any(|key| key.key_id == grant.key_id) {
        return Err(Miss::Key);
    }
    if request.excluded {
        return Err(Miss::Excluded);
    }
    let Some(resolved_path) = request.resolved_path else {
        return Err(Miss::Excluded);
    };
    let Some(position) = grant.sudos.iter().position(|covered| {
        covered.args == request.args
            && covered.resolved_path == resolved_path
            && covered.run_as == request.run_as
            && covered.run_as_group.as_deref() == request.run_as_group
            && (covered.exec_tail || !request.leading)
    }) else {
        return Err(not_covered(&grant, request, resolved_path));
    };
    let taken = grant.sudos.remove(position);
    // A use that can't be counted isn't granted.
    let counted = if grant.sudos.is_empty() {
        std::fs::remove_file(&path).is_ok()
    } else {
        grant.used.push(argv_digest(&taken.args));
        write(&locked, &name, &grant)
    };
    counted.then_some(()).ok_or(Miss::Unrecorded)
}

/// Why no covered call is `request`, which passed every session check.
fn not_covered(grant: &Grant, request: &Request, resolved_path: &str) -> Miss {
    if let Some(written) = grant
        .sudos
        .iter()
        .find(|covered| covered.args == request.args)
    {
        return if written.resolved_path != resolved_path {
            Miss::Program
        } else if written.run_as != request.run_as
            || written.run_as_group.as_deref() != request.run_as_group
        {
            Miss::User
        } else {
            // It leads the session but isn't the string's last command.
            Miss::LeaderChanged
        };
    }
    let digest = argv_digest(request.args);
    if grant.used.contains(&digest) {
        Miss::Used
    } else if grant.capped.contains(&digest) {
        Miss::Cap
    } else if grant.non_literal {
        Miss::NonLiteral
    } else {
        Miss::NotInCommand
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fs;

    fn entry(pid: i32, exe: &str, argv: &[&str]) -> ChainEntry {
        ChainEntry {
            pid,
            ppid: pid - 1,
            start_time: 1,
            exe: Some(exe.to_string()),
            argv: Some(argv.iter().map(|arg| arg.to_string()).collect()),
            argv_truncated: false,
        }
    }

    const NO_TTY: Option<LeaderFacts> = Some(LeaderFacts {
        start: 42,
        has_tty: false,
    });

    /// `/bin/sh` as the only shell, judged as the current user.
    fn shells(listed: &[&Path]) -> Shells {
        Shells {
            listed: listed
                .iter()
                .map(|path| std::fs::canonicalize(path).unwrap())
                .collect(),
            policy: Policy::root(),
            uid: unsafe { libc::getuid() },
            gids: vec![],
        }
    }

    fn strings(argv: &[&str]) -> Vec<String> {
        argv.iter().map(|arg| arg.to_string()).collect()
    }

    #[test]
    fn only_fresh_command_shells_without_a_terminal_qualify() {
        let shells = shells(&[Path::new("/bin/sh")]);
        let claude = entry(10, "/bin/sh", &["bash", "-c", "sudo a; sudo b"]);
        let codex = entry(10, "/bin/sh", &["/bin/zsh", "-lc", "sudo a && sudo b"]);
        let subshell = entry(11, "/bin/sh", &["bash", "-c", "sudo a; sudo b"]);
        let app_server = entry(10, "/bin/sh", &["codex", "app-server"]);
        let stdin_shell = entry(10, "/bin/sh", &["bash", "-s"]);
        let interactive = entry(10, "/bin/sh", &["-zsh"]);
        let positional = entry(10, "/bin/sh", &["sh", "-c", "sudo rm \"$1\"", "sh", "/"]);
        let xargs = entry(11, "/usr/bin/xargs", &["xargs", "sudo", "rm"]);
        let anchor = Anchor {
            session: 10,
            leader_start: 42,
        };
        let scope = |argv: &[&str]| Scope::new(anchor, strings(argv));
        let cases = [
            (
                vec![claude.clone()],
                NO_TTY,
                scope(&["bash", "-c", "sudo a; sudo b"]),
            ),
            (
                vec![codex],
                NO_TTY,
                scope(&["/bin/zsh", "-lc", "sudo a && sudo b"]),
            ),
            (
                vec![subshell, claude.clone()],
                NO_TTY,
                scope(&["bash", "-c", "sudo a; sudo b"]),
            ),
            (vec![app_server], NO_TTY, None),
            (vec![stdin_shell], NO_TTY, None),
            (vec![interactive], NO_TTY, None),
            (vec![positional], NO_TTY, None),
            (vec![xargs, claude.clone()], NO_TTY, None),
            // Persistent agent shells are PTYs.
            (
                vec![claude.clone()],
                Some(LeaderFacts {
                    start: 42,
                    has_tty: true,
                }),
                None,
            ),
            // The leader exited, or isn't an ancestor.
            (vec![claude.clone()], None, None),
            (
                vec![entry(12, "/bin/sh", &["bash", "-c", "x"])],
                NO_TTY,
                None,
            ),
        ];
        for (index, (chain, leader, expected)) in cases.into_iter().enumerate() {
            assert_eq!(
                qualify(10, &chain, leader, &shells),
                expected,
                "case {index}"
            );
        }
        let mut truncated = claude;
        truncated.argv_truncated = true;
        assert_eq!(qualify(10, &[truncated], NO_TTY, &shells), None);
        assert_eq!(
            command_string(&strings(&["bash", "--norc", "-ec", "x"])),
            Some("x")
        );
        assert_eq!(command_string(&strings(&["bash", "script.sh", "-c"])), None);
    }

    /// Review H1: any binary named like a shell passed, so a user's own
    /// `~/bin/bash` between sudo and the leader counted as a shell.
    #[test]
    fn a_renamed_binary_is_not_a_shell() {
        let root = test_fs::private_dir();
        let copy = root.join("bash");
        std::fs::copy("/bin/sh", &copy).unwrap();
        let copy_name = copy.to_str().unwrap().to_string();
        let leader = entry(10, "/bin/sh", &["bash", "-c", "sudo a; sudo b"]);
        let renamed = entry(11, &copy_name, &["bash", "-c", "sudo a"]);
        let chain = [renamed, leader];
        assert_eq!(
            qualify(10, &chain, NO_TTY, &shells(&[Path::new("/bin/sh")])),
            None
        );
        // Listed, but the user can change it.
        let listed = shells(&[Path::new("/bin/sh"), &copy]);
        assert!(!listed.contains(Some(&copy_name)));
        assert_eq!(qualify(10, &chain, NO_TTY, &listed), None);
        // The list itself must be root's.
        let list = root.join("shells");
        std::fs::write(&list, "/bin/sh\n").unwrap();
        let uid = unsafe { libc::getuid() };
        assert!(!Shells::load(&list, &Policy::root(), uid, &[]).contains(Some("/bin/sh")));
        assert!(Shells::load(&list, &test_fs::policy(), uid, &[]).contains(Some("/bin/sh")));
        std::fs::remove_dir_all(&root).unwrap();
    }

    struct Fixture {
        root: PathBuf,
        dir: PathBuf,
        keys: Vec<EnrolledKey>,
        leader: std::process::Child,
        anchor: Anchor,
        leader_argv: std::cell::RefCell<Vec<String>>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.leader.kill();
            let _ = self.leader.wait();
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    const COMMAND: &str = "sudo apt update && sudo systemctl restart nginx";

    fn fixture() -> Fixture {
        let root = test_fs::private_dir();
        let key = crate::fixture_server::vector_key("enrolled");
        let file = serde_json::json!({
            "version": 1, "keyId": key.key_id, "alg": "es256", "publicKey": crate::b64::encode(&key.spki),
            "label": "test", "securityLevel": "tee", "enrolledAt": "2026-10-30T12:00:00Z",
            "attestationSummary": { "packageName": "p", "signingCertDigest": "d", "devAttestation": true }
        });
        let keys = vec![
            crate::keys::parse_key_file(
                &format!("{}.json", key.key_id),
                file.to_string().as_bytes(),
            )
            .unwrap(),
        ];
        let leader = std::process::Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let pid = leader.id() as i32;
        let anchor = Anchor {
            session: pid,
            leader_start: crate::sys::leader_facts(pid).unwrap().start,
        };
        Fixture {
            dir: root.join("grants"),
            root,
            keys,
            leader,
            anchor,
            leader_argv: std::cell::RefCell::new(strings(&["/bin/zsh", "-lc", COMMAND])),
        }
    }

    fn covered(args: &[&str], run_as: &str, exec_tail: bool) -> Covered {
        Covered {
            args: strings(args),
            resolved_path: format!("/usr/bin/{}", args[0]),
            run_as: run_as.to_string(),
            run_as_group: None,
            exec_tail,
        }
    }

    impl Fixture {
        fn record(&self, sudos: Vec<Covered>, until: i64) {
            self.record_with(sudos, until, Uncovered::default());
        }

        fn record_with(&self, sudos: Vec<Covered>, until: i64, uncovered: Uncovered) {
            let session = Session {
                id: self.anchor.session,
                leader_start: self.anchor.leader_start,
                max_uses: sudos.len() as u32,
                command: Some(COMMAND.to_string()),
            };
            let grant = Grant::new(
                (1000, "me"),
                &session,
                &self.leader_argv.borrow(),
                "/work",
                &self.keys[0].key_id,
                until,
                (sudos, uncovered),
            );
            record(&self.dir, &test_fs::policy(), &grant, 100);
        }

        fn take_with(
            &self,
            anchor: Anchor,
            leading: bool,
            args: &[&str],
            run_as: &str,
            cwd: &str,
            now: i64,
        ) -> Result<(), Miss> {
            let args = strings(args);
            let resolved = format!("/usr/bin/{}", args[0]);
            let request = Request {
                uid: 1000,
                user: "me",
                anchor,
                leading,
                args: &args,
                excluded: false,
                resolved_path: Some(&resolved),
                run_as,
                run_as_group: None,
                cwd,
            };
            take(
                &self.dir,
                &test_fs::policy(),
                &request,
                &self.keys,
                now,
                Leader {
                    start: |pid| crate::sys::leader_facts(pid).map(|facts| facts.start),
                    argv: |pid| {
                        (pid == self.anchor.session).then(|| self.leader_argv.borrow().clone())
                    },
                },
            )
        }

        fn take(&self, args: &[&str], now: i64) -> Result<(), Miss> {
            self.take_with(self.anchor, false, args, "root", "/work", now)
        }
    }

    #[test]
    fn a_grant_covers_each_written_call_once() {
        let fixture = fixture();
        assert_eq!(
            fixture.take(&["apt", "update"], 100),
            Err(Miss::NoGrant),
            "nothing recorded yet"
        );
        fixture.record(
            vec![
                covered(&["apt", "update"], "root", false),
                covered(&["systemctl", "restart", "nginx"], "root", true),
            ],
            200,
        );
        let meta = std::fs::metadata(&fixture.dir).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o700);
        assert_eq!(fixture.take(&["ls", "/"], 150), Err(Miss::NotInCommand));
        assert_eq!(
            fixture.take(&["apt"], 150),
            Err(Miss::NotInCommand),
            "only the whole argv"
        );
        assert_eq!(fixture.take(&["apt", "update"], 150), Ok(()));
        assert_eq!(
            fixture.take(&["apt", "update"], 150),
            Err(Miss::Used),
            "once each"
        );
        assert_eq!(
            fixture.take(&["systemctl", "restart", "nginx"], 150),
            Ok(())
        );
        assert!(std::fs::read_dir(&fixture.dir).unwrap().next().is_none());
        assert_eq!(
            fixture.take(&["apt", "update"], 150),
            Err(Miss::NoGrant),
            "a spent grant is no grant"
        );
    }

    #[test]
    fn a_grant_rejects_other_sessions_targets_places_and_late_uses() {
        let fixture = fixture();
        fixture.record(vec![covered(&["apt", "update"], "root", false)], 200);
        let other_session = Anchor {
            session: fixture.anchor.session + 1,
            ..fixture.anchor
        };
        let reused_pid = Anchor {
            leader_start: fixture.anchor.leader_start + 1,
            ..fixture.anchor
        };
        let apt = ["apt", "update"];
        let take = |anchor, run_as, cwd| fixture.take_with(anchor, false, &apt, run_as, cwd, 150);
        assert_eq!(take(other_session, "root", "/work"), Err(Miss::NoGrant));
        assert_eq!(take(reused_pid, "root", "/work"), Err(Miss::LeaderChanged));
        assert_eq!(take(fixture.anchor, "postgres", "/work"), Err(Miss::User));
        assert_eq!(take(fixture.anchor, "root", "/tmp"), Err(Miss::Cwd));
        assert_eq!(fixture.take(&apt, 200), Err(Miss::Expired));
        assert_eq!(
            fixture.take(&apt, 150),
            Err(Miss::NoGrant),
            "expired grants are removed"
        );
    }

    /// The miss log's categories for calls the grant never covered.
    #[test]
    fn a_miss_says_why_the_call_wasnt_covered() {
        let fixture = fixture();
        fixture.record_with(
            vec![covered(&["apt", "update"], "root", false)],
            200,
            Uncovered {
                non_literal: false,
                capped: vec![strings(&["apt", "upgrade"])],
                approved: strings(&["apt", "install", "x"]),
            },
        );
        assert_eq!(fixture.take(&["apt", "install", "x"], 150), Err(Miss::Used));
        assert_eq!(fixture.take(&["apt", "upgrade"], 150), Err(Miss::Cap));
        assert_eq!(
            fixture.take(&["cp", "a", "/etc"], 150),
            Err(Miss::NotInCommand)
        );
        let args = strings(&["apt", "update"]);
        let request = |resolved_path, excluded| Request {
            uid: 1000,
            user: "me",
            anchor: fixture.anchor,
            leading: false,
            args: &args,
            excluded,
            resolved_path,
            run_as: "root",
            run_as_group: None,
            cwd: "/work",
        };
        let take = |request: &Request| {
            take(
                &fixture.dir,
                &test_fs::policy(),
                request,
                &fixture.keys,
                150,
                Leader {
                    start: |pid| crate::sys::leader_facts(pid).map(|facts| facts.start),
                    argv: |_| Some(fixture.leader_argv.borrow().clone()),
                },
            )
        };
        assert_eq!(take(&request(Some("/opt/apt"), false)), Err(Miss::Program));
        assert_eq!(take(&request(None, false)), Err(Miss::Excluded));
        assert_eq!(
            take(&request(Some("/usr/bin/apt"), true)),
            Err(Miss::Excluded)
        );
        assert_eq!(take(&request(Some("/usr/bin/apt"), false)), Ok(()));

        fixture.record_with(
            vec![covered(&["apt", "update"], "root", false)],
            200,
            Uncovered {
                non_literal: true,
                ..Uncovered::default()
            },
        );
        assert_eq!(
            fixture.take(&["cp", "a", "/etc"], 150),
            Err(Miss::NonLiteral)
        );
        assert_eq!(Miss::NoGrant.category(), None);
        assert_eq!(Miss::NonLiteral.category(), Some("non-literal"));
    }

    /// Review H1: an exec'd program leads the session too, and its sudo
    /// passed whatever the session was.
    #[test]
    fn only_the_last_call_may_lead_the_session() {
        let fixture = fixture();
        fixture.record(
            vec![
                covered(&["apt", "update"], "root", false),
                covered(&["systemctl", "restart", "nginx"], "root", true),
            ],
            200,
        );
        // The shell exec'd its last command, so its argv is sudo's now.
        *fixture.leader_argv.borrow_mut() = strings(&["sudo", "systemctl", "restart", "nginx"]);
        assert_eq!(
            fixture.take(&["apt", "update"], 150),
            Err(Miss::LeaderChanged),
            "the leader changed"
        );
        let leading =
            |args: &[&str]| fixture.take_with(fixture.anchor, true, args, "root", "/work", 150);
        assert_eq!(leading(&["apt", "update"]), Err(Miss::LeaderChanged));
        assert_eq!(leading(&["systemctl", "restart", "nginx"]), Ok(()));
    }

    #[test]
    fn a_dead_leader_ends_the_grant() {
        let mut fixture = fixture();
        fixture.record(vec![covered(&["apt", "update"], "root", false)], 200);
        fixture.leader.kill().unwrap();
        fixture.leader.wait().unwrap();
        assert_eq!(
            fixture.take(&["apt", "update"], 150),
            Err(Miss::LeaderChanged)
        );
    }

    #[test]
    fn revoking_the_approving_key_ends_the_grant() {
        let mut fixture = fixture();
        fixture.record(vec![covered(&["apt", "update"], "root", false)], 200);
        fixture.keys.clear();
        assert_eq!(fixture.take(&["apt", "update"], 150), Err(Miss::Key));
    }

    #[test]
    fn unsafe_or_corrupt_state_is_no_grant() {
        let fixture = fixture();
        let apt = || vec![covered(&["apt", "update"], "root", false)];
        fixture.record(apt(), 200);
        let file = fixture.dir.join(file_name(1000, fixture.anchor.session));
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            fixture.take(&["apt", "update"], 150),
            Err(Miss::NoGrant),
            "readable by others"
        );
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&fixture.dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            fixture.take(&["apt", "update"], 150),
            Err(Miss::NoGrant),
            "directory open to others"
        );
        std::fs::set_permissions(&fixture.dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(&file, b"{not json").unwrap();
        assert_eq!(
            fixture.take(&["apt", "update"], 150),
            Err(Miss::NoGrant),
            "corrupt"
        );

        fixture.record(apt(), 200);
        let target = fixture.root.join("planted.json");
        std::fs::rename(&file, &target).unwrap();
        std::os::unix::fs::symlink(&target, &file).unwrap();
        assert_eq!(
            fixture.take(&["apt", "update"], 150),
            Err(Miss::NoGrant),
            "symlinked grant"
        );
        std::fs::remove_file(&file).unwrap();

        std::fs::remove_dir_all(&fixture.dir).unwrap();
        std::os::unix::fs::symlink(&fixture.root, &fixture.dir).unwrap();
        fixture.record(apt(), 200);
        assert!(
            !fixture
                .root
                .join(file_name(1000, fixture.anchor.session))
                .exists(),
            "records never follow a symlinked directory"
        );
    }

    #[test]
    fn no_grant_is_kept_without_calls() {
        let fixture = fixture();
        fixture.record(vec![], 200);
        assert!(!fixture.dir.exists());
    }
}
