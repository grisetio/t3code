//! Fixture roots that pass the root-safety checks the tests exercise: every
//! component from `/` must be owned by root or the test user and not group- or
//! world-writable. A shared `/tmp` (1777) fails that, and a umask of 002 would
//! make the fixture itself group-writable, so modes here never come from the umask.

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use crate::rootsafe::{self, Kind, Policy};

/// The policy the fixtures satisfy: root or the test user.
pub fn policy() -> Policy {
    Policy {
        owners: vec![0, unsafe { libc::getuid() }],
    }
}

/// A fresh, empty 0755 directory, removed by the caller. Its path stays short
/// because flow tests put a socket in it (`MAX_SOCKET_PATH_BYTES`).
pub fn private_dir() -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let base = base();
    let dir = base.join(format!(
        "{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    create_dir(&dir, 0o755);
    dir
}

/// A 0700 folder in the first candidate whose whole path passes the checks:
/// the temp dir (private on macOS), the login session's runtime dir, else the
/// test binary's target dir, which a umask of 002 leaves group-writable.
fn base() -> PathBuf {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    let target = std::env::current_exe()
        .ok()
        .and_then(|exe| Some(exe.parent()?.parent()?.to_path_buf()));
    let parent = [Some(std::env::temp_dir()), runtime, target]
        .into_iter()
        .flatten()
        .find(|candidate| rootsafe::check_path(candidate, &policy(), Kind::Dir).is_ok())
        .expect("no directory safe for root-state fixtures; set TMPDIR to a private one");
    let base = parent.join("t3e-tests");
    if !base.is_dir() {
        let _ = std::fs::DirBuilder::new().mode(0o700).create(&base);
    }
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    base
}

fn create_dir(path: &Path, mode: u32) {
    std::fs::DirBuilder::new().mode(mode).create(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// `create_dir_all` with every new directory 0755.
pub fn create_dirs(path: &Path) {
    if path.is_dir() {
        return;
    }
    if let Some(parent) = path.parent() {
        create_dirs(parent);
    }
    create_dir(path, 0o755);
}

/// Writes a 0644 file.
pub fn write(path: &Path, contents: impl AsRef<[u8]>) {
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
}
