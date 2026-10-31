//! One approval per agent command. Agents run each tool call in a fresh
//! `<shell> -c` that leads its own kernel session, so an approved sudo
//! records a grant bound to that session and its leader's start time, and
//! later sudos in the same session pass without the phone while the leader
//! lives, within the window and under a use cap.
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

const MAX_GRANT_BYTES: u64 = 4096;

/// A session an approval may also cover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub session: i32,
    pub leader_start: u64,
}

const SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "busybox",
];

fn is_shell(exe: Option<&str>) -> bool {
    exe.is_some_and(|exe| SHELLS.contains(&exe.rsplit('/').next().unwrap_or(exe)))
}

/// `sh -c …`, `zsh -lc …`, `bash --norc -c …`: a command string among the
/// options before the first operand.
fn has_command_string(argv: &[String]) -> bool {
    for arg in argv.iter().skip(1) {
        if arg == "--" || !arg.starts_with('-') {
            return false;
        }
        if !arg.starts_with("--") && arg[1..].contains('c') {
            return true;
        }
    }
    false
}

/// The anchor for a sudo in session `session`, from its ancestor chain
/// (`chain[0]` is sudo's parent) and the leader's kernel facts, or None when
/// the session could carry later, unrelated commands.
pub fn qualify(session: i32, chain: &[ChainEntry], leader: Option<LeaderFacts>) -> Option<Anchor> {
    let leader = leader?;
    if leader.has_tty {
        return None;
    }
    let position = chain.iter().position(|entry| entry.pid == session)?;
    let entry = &chain[position];
    // zsh and bash exec a command string's last command, so a bare `sudo …`
    // is the leader itself and never reaches here; a leader that isn't a
    // `-c` shell is a provider process or a shell reading stdin.
    let argv = entry.argv.as_deref()?;
    if entry.argv_truncated || !is_shell(entry.exe.as_deref()) || !has_command_string(argv) {
        return None;
    }
    // `xargs sudo`, `timeout 5 sudo` and the like fall back to one approval
    // per sudo rather than trust a program between sudo and the leader.
    if !chain[..position]
        .iter()
        .all(|entry| is_shell(entry.exe.as_deref()))
    {
        return None;
    }
    Some(Anchor {
        session,
        leader_start: leader.start,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Grant {
    pub version: u32,
    pub uid: u32,
    pub user: String,
    pub session: i32,
    pub leader_start: u64,
    pub run_as: String,
    pub run_as_group: Option<String>,
    pub key_id: String,
    pub until: i64,
    pub max_uses: u32,
    pub uses: u32,
}

impl Grant {
    pub fn new(
        uid: u32,
        user: &str,
        session: &Session,
        target: (&str, Option<&str>),
        key_id: &str,
        until: i64,
    ) -> Self {
        Self {
            version: 1,
            uid,
            user: user.to_string(),
            session: session.id,
            leader_start: session.leader_start,
            run_as: target.0.to_string(),
            run_as_group: target.1.map(str::to_string),
            key_id: key_id.to_string(),
            until,
            max_uses: session.max_uses,
            uses: 0,
        }
    }
}

/// What a later sudo asks a grant for.
pub struct Request<'a> {
    pub uid: u32,
    pub user: &'a str,
    pub anchor: Anchor,
    pub run_as: &'a str,
    pub run_as_group: Option<&'a str>,
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
    (grant.version == 1).then_some(grant)
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
        let keep = read(&path, policy)
            .is_some_and(|grant| grant.until > now && grant.uses < grant.max_uses);
        if !keep {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Records a grant for an approved sudo. Failing only costs later phone
/// prompts, so errors are swallowed.
pub fn record(dir: &Path, policy: &Policy, grant: &Grant, now: i64) {
    if grant.max_uses == 0 {
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

/// Consumes one use of the grant covering `request`, if there is one.
/// `leader_start` re-reads the leader from the kernel, so a dead leader or a
/// reused pid never matches.
pub fn take(
    dir: &Path,
    policy: &Policy,
    request: &Request,
    keys: &[EnrolledKey],
    now: i64,
    leader_start: impl Fn(i32) -> Option<u64>,
) -> bool {
    let Some(locked) = open_dir(dir, policy, false) else {
        return false;
    };
    let name = file_name(request.uid, request.anchor.session);
    let path = locked.dir.join(&name);
    let Some(mut grant) = read(&path, policy) else {
        return false;
    };
    let stale = now >= grant.until
        || grant.uses >= grant.max_uses
        || leader_start(grant.session) != Some(grant.leader_start);
    if stale {
        let _ = std::fs::remove_file(&path);
        return false;
    }
    let matches = grant.uid == request.uid
        && grant.user == request.user
        && grant.session == request.anchor.session
        && grant.leader_start == request.anchor.leader_start
        && grant.run_as == request.run_as
        && grant.run_as_group.as_deref() == request.run_as_group
        && keys.iter().any(|key| key.key_id == grant.key_id);
    if !matches {
        return false;
    }
    grant.uses += 1;
    // A use that can't be counted isn't granted.
    if grant.uses >= grant.max_uses {
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

    #[test]
    fn only_fresh_command_shells_without_a_terminal_qualify() {
        let claude = entry(10, "/bin/bash", &["bash", "-c", "sudo a; sudo b"]);
        let codex = entry(10, "/bin/zsh", &["/bin/zsh", "-lc", "sudo a && sudo b"]);
        let subshell = entry(11, "/bin/bash", &["bash", "-c", "sudo a; sudo b"]);
        let app_server = entry(10, "/opt/homebrew/bin/codex", &["codex", "app-server"]);
        let stdin_shell = entry(10, "/bin/bash", &["bash", "-s"]);
        let interactive = entry(10, "/bin/zsh", &["-zsh"]);
        let xargs = entry(11, "/usr/bin/xargs", &["xargs", "sudo", "rm"]);
        let anchor = Some(Anchor {
            session: 10,
            leader_start: 42,
        });
        let cases = [
            (vec![claude.clone()], NO_TTY, anchor),
            (vec![codex], NO_TTY, anchor),
            (vec![subshell, claude.clone()], NO_TTY, anchor),
            (vec![app_server], NO_TTY, None),
            (vec![stdin_shell], NO_TTY, None),
            (vec![interactive], NO_TTY, None),
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
                vec![entry(12, "/bin/bash", &["bash", "-c", "x"])],
                NO_TTY,
                None,
            ),
        ];
        for (index, (chain, leader, expected)) in cases.into_iter().enumerate() {
            assert_eq!(qualify(10, &chain, leader), expected, "case {index}");
        }
        let mut truncated = claude;
        truncated.argv_truncated = true;
        assert_eq!(qualify(10, &[truncated], NO_TTY), None);
        assert!(has_command_string(&[
            "bash".into(),
            "--norc".into(),
            "-ec".into()
        ]));
        assert!(!has_command_string(&[
            "bash".into(),
            "script.sh".into(),
            "-c".into()
        ]));
    }

    struct Fixture {
        root: PathBuf,
        dir: PathBuf,
        keys: Vec<EnrolledKey>,
        leader: std::process::Child,
        anchor: Anchor,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.leader.kill();
            let _ = self.leader.wait();
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

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
        }
    }

    impl Fixture {
        fn record(&self, run_as: &str, max_uses: u32, until: i64) {
            let session = Session {
                id: self.anchor.session,
                leader_start: self.anchor.leader_start,
                max_uses,
            };
            let grant = Grant::new(
                1000,
                "me",
                &session,
                (run_as, None),
                &self.keys[0].key_id,
                until,
            );
            record(&self.dir, &test_fs::policy(), &grant, 100);
        }

        fn take_as(&self, anchor: Anchor, run_as: &str, now: i64) -> bool {
            let request = Request {
                uid: 1000,
                user: "me",
                anchor,
                run_as,
                run_as_group: None,
            };
            take(
                &self.dir,
                &test_fs::policy(),
                &request,
                &self.keys,
                now,
                |pid| crate::sys::leader_facts(pid).map(|facts| facts.start),
            )
        }

        fn take(&self, now: i64) -> bool {
            self.take_as(self.anchor, "root", now)
        }
    }

    #[test]
    fn a_grant_covers_its_session_until_the_cap() {
        let fixture = fixture();
        assert!(!fixture.take(100), "nothing recorded yet");
        fixture.record("root", 2, 200);
        let meta = std::fs::metadata(&fixture.dir).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o700);
        assert!(fixture.take(150));
        assert!(fixture.take(150));
        assert!(!fixture.take(150), "cap reached");
        assert!(std::fs::read_dir(&fixture.dir).unwrap().next().is_none());
    }

    #[test]
    fn a_grant_rejects_other_sessions_targets_and_late_uses() {
        let fixture = fixture();
        fixture.record("root", 16, 200);
        let other_session = Anchor {
            session: fixture.anchor.session + 1,
            ..fixture.anchor
        };
        let reused_pid = Anchor {
            leader_start: fixture.anchor.leader_start + 1,
            ..fixture.anchor
        };
        assert!(!fixture.take_as(other_session, "root", 150));
        assert!(!fixture.take_as(reused_pid, "root", 150));
        assert!(!fixture.take_as(fixture.anchor, "postgres", 150));
        assert!(fixture.take(150));
        assert!(!fixture.take(200), "expired");
        assert!(!fixture.take(150), "expired grants are removed");
    }

    #[test]
    fn a_dead_leader_ends_the_grant() {
        let mut fixture = fixture();
        fixture.record("root", 16, 200);
        fixture.leader.kill().unwrap();
        fixture.leader.wait().unwrap();
        assert!(!fixture.take(150));
    }

    #[test]
    fn revoking_the_approving_key_ends_the_grant() {
        let mut fixture = fixture();
        fixture.record("root", 16, 200);
        fixture.keys.clear();
        assert!(!fixture.take(150));
    }

    #[test]
    fn unsafe_or_corrupt_state_is_no_grant() {
        let fixture = fixture();
        fixture.record("root", 16, 200);
        let file = fixture.dir.join(file_name(1000, fixture.anchor.session));
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!fixture.take(150), "readable by others");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&fixture.dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!fixture.take(150), "directory open to others");
        std::fs::set_permissions(&fixture.dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(&file, b"{not json").unwrap();
        assert!(!fixture.take(150), "corrupt");

        fixture.record("root", 16, 200);
        let target = fixture.root.join("planted.json");
        std::fs::rename(&file, &target).unwrap();
        std::os::unix::fs::symlink(&target, &file).unwrap();
        assert!(!fixture.take(150), "symlinked grant");
        std::fs::remove_file(&file).unwrap();

        std::fs::remove_dir_all(&fixture.dir).unwrap();
        std::os::unix::fs::symlink(&fixture.root, &fixture.dir).unwrap();
        fixture.record("root", 16, 200);
        assert!(
            !fixture
                .root
                .join(file_name(1000, fixture.anchor.session))
                .exists(),
            "records never follow a symlinked directory"
        );
    }

    #[test]
    fn no_grant_is_kept_without_uses() {
        let fixture = fixture();
        fixture.record("root", 0, 200);
        assert!(!fixture.dir.exists());
    }
}
