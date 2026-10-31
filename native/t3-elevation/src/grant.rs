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
}

const GRANT_VERSION: u32 = 2;

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
        sudos: Vec<Covered>,
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
    pub resolved_path: &'a str,
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
) -> bool
where
    S: Fn(i32) -> Option<u64>,
    A: Fn(i32) -> Option<Vec<String>>,
{
    let Some(locked) = open_dir(dir, policy, false) else {
        return false;
    };
    let name = file_name(request.uid, request.anchor.session);
    let path = locked.dir.join(&name);
    let Some(mut grant) = read(&path, policy) else {
        return false;
    };
    let stale = now >= grant.until
        || grant.sudos.is_empty()
        || (leader.start)(grant.session) != Some(grant.leader_start);
    if stale {
        let _ = std::fs::remove_file(&path);
        return false;
    }
    let matches = grant.uid == request.uid
        && grant.user == request.user
        && grant.session == request.anchor.session
        && grant.leader_start == request.anchor.leader_start
        && grant.cwd == request.cwd
        && keys.iter().any(|key| key.key_id == grant.key_id);
    // A leading sudo replaced the shell, so its argv is sudo's own; only the
    // string's last command can have done that.
    let same_leader = request.leading
        || (leader.argv)(grant.session).is_some_and(|argv| argv_digest(&argv) == grant.leader_argv);
    if !matches || !same_leader {
        return false;
    }
    let Some(position) = grant.sudos.iter().position(|covered| {
        covered.args == request.args
            && covered.resolved_path == request.resolved_path
            && covered.run_as == request.run_as
            && covered.run_as_group.as_deref() == request.run_as_group
            && (covered.exec_tail || !request.leading)
    }) else {
        return false;
    };
    grant.sudos.remove(position);
    // A use that can't be counted isn't granted.
    if grant.sudos.is_empty() {
        return std::fs::remove_file(&path).is_ok();
    }
    write(&locked, &name, &grant)
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
                sudos,
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
        ) -> bool {
            let args = strings(args);
            let resolved = format!("/usr/bin/{}", args[0]);
            let request = Request {
                uid: 1000,
                user: "me",
                anchor,
                leading,
                args: &args,
                resolved_path: &resolved,
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

        fn take(&self, args: &[&str], now: i64) -> bool {
            self.take_with(self.anchor, false, args, "root", "/work", now)
        }
    }

    #[test]
    fn a_grant_covers_each_written_call_once() {
        let fixture = fixture();
        assert!(
            !fixture.take(&["apt", "update"], 100),
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
        assert!(
            !fixture.take(&["ls", "/"], 150),
            "not written in the command"
        );
        assert!(!fixture.take(&["apt"], 150), "only the whole argv");
        assert!(fixture.take(&["apt", "update"], 150));
        assert!(!fixture.take(&["apt", "update"], 150), "once each");
        assert!(fixture.take(&["systemctl", "restart", "nginx"], 150));
        assert!(std::fs::read_dir(&fixture.dir).unwrap().next().is_none());
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
        assert!(!fixture.take_with(other_session, false, &apt, "root", "/work", 150));
        assert!(!fixture.take_with(reused_pid, false, &apt, "root", "/work", 150));
        assert!(!fixture.take_with(fixture.anchor, false, &apt, "postgres", "/work", 150));
        assert!(!fixture.take_with(fixture.anchor, false, &apt, "root", "/tmp", 150));
        assert!(!fixture.take(&apt, 200), "expired");
        assert!(!fixture.take(&apt, 150), "expired grants are removed");
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
        assert!(!fixture.take(&["apt", "update"], 150), "the leader changed");
        let leading =
            |args: &[&str]| fixture.take_with(fixture.anchor, true, args, "root", "/work", 150);
        assert!(!leading(&["apt", "update"]));
        assert!(leading(&["systemctl", "restart", "nginx"]));
    }

    #[test]
    fn a_dead_leader_ends_the_grant() {
        let mut fixture = fixture();
        fixture.record(vec![covered(&["apt", "update"], "root", false)], 200);
        fixture.leader.kill().unwrap();
        fixture.leader.wait().unwrap();
        assert!(!fixture.take(&["apt", "update"], 150));
    }

    #[test]
    fn revoking_the_approving_key_ends_the_grant() {
        let mut fixture = fixture();
        fixture.record(vec![covered(&["apt", "update"], "root", false)], 200);
        fixture.keys.clear();
        assert!(!fixture.take(&["apt", "update"], 150));
    }

    #[test]
    fn unsafe_or_corrupt_state_is_no_grant() {
        let fixture = fixture();
        let apt = || vec![covered(&["apt", "update"], "root", false)];
        fixture.record(apt(), 200);
        let file = fixture.dir.join(file_name(1000, fixture.anchor.session));
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!fixture.take(&["apt", "update"], 150), "readable by others");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&fixture.dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            !fixture.take(&["apt", "update"], 150),
            "directory open to others"
        );
        std::fs::set_permissions(&fixture.dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(&file, b"{not json").unwrap();
        assert!(!fixture.take(&["apt", "update"], 150), "corrupt");

        fixture.record(apt(), 200);
        let target = fixture.root.join("planted.json");
        std::fs::rename(&file, &target).unwrap();
        std::os::unix::fs::symlink(&target, &file).unwrap();
        assert!(!fixture.take(&["apt", "update"], 150), "symlinked grant");
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
