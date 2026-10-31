//! Root-state safety: every component of a path the module or helper trusts
//! must be owned by root and not group- or world-writable.

use std::io::Read as _;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsafe {
    Missing,
    NotOwned,
    Writable,
    WrongType,
    Unreadable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Dir,
    File,
}

#[derive(Clone, Debug)]
pub struct Policy {
    /// Owners accepted for root state. Production: only root. Tests add their
    /// own uid so they can run against a temporary directory.
    pub owners: Vec<u32>,
}

impl Policy {
    pub fn root() -> Self {
        Self { owners: vec![0] }
    }
}

fn check_meta(meta: &std::fs::Metadata, policy: &Policy) -> Result<(), Unsafe> {
    if !policy.owners.contains(&meta.uid()) {
        return Err(Unsafe::NotOwned);
    }
    // A symlink's own mode bits mean nothing; its target is checked through
    // the canonical path.
    if !meta.file_type().is_symlink() && meta.mode() & 0o022 != 0 {
        return Err(Unsafe::Writable);
    }
    Ok(())
}

fn check_components(path: &Path, policy: &Policy) -> Result<(), Unsafe> {
    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component);
        let meta = std::fs::symlink_metadata(&prefix).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => Unsafe::Missing,
            _ => Unsafe::Unreadable,
        })?;
        check_meta(&meta, policy)?;
    }
    Ok(())
}

/// Checks the lexical path and the canonical path, so a root-owned symlink
/// into a writable location is rejected as well as a writable directory.
pub fn check_path(path: &Path, policy: &Policy, kind: Kind) -> Result<(), Unsafe> {
    if !path.is_absolute() {
        return Err(Unsafe::WrongType);
    }
    check_components(path, policy)?;
    let canonical = std::fs::canonicalize(path).map_err(|_| Unsafe::Missing)?;
    check_components(&canonical, policy)?;
    let meta = std::fs::metadata(&canonical).map_err(|_| Unsafe::Unreadable)?;
    match kind {
        Kind::Dir if meta.is_dir() => Ok(()),
        Kind::File if meta.is_file() => Ok(()),
        _ => Err(Unsafe::WrongType),
    }
}

/// For entries of an already-checked directory: a regular file, not a symlink.
pub fn check_leaf(path: &Path, policy: &Policy, kind: Kind) -> Result<(), Unsafe> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| Unsafe::Missing)?;
    check_meta(&meta, policy)?;
    let file_type = meta.file_type();
    match kind {
        Kind::File if file_type.is_file() => Ok(()),
        Kind::Dir if file_type.is_dir() => Ok(()),
        _ => Err(Unsafe::WrongType),
    }
}

pub fn read_limited(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::other("file too large"));
    }
    Ok(bytes)
}

/// The T3 socket: a socket (not a symlink) owned by `uid`, in a directory owned
/// by `uid` or root that is not group- or world-writable.
pub fn check_socket(path: &Path, uid: u32) -> Result<(), Unsafe> {
    if !path.is_absolute() || path.as_os_str().len() > crate::MAX_SOCKET_PATH_BYTES {
        return Err(Unsafe::WrongType);
    }
    let meta = std::fs::symlink_metadata(path).map_err(|_| Unsafe::Missing)?;
    if !meta.file_type().is_socket() {
        return Err(Unsafe::WrongType);
    }
    if meta.uid() != uid {
        return Err(Unsafe::NotOwned);
    }
    let parent = path.parent().ok_or(Unsafe::WrongType)?;
    let dir = std::fs::symlink_metadata(parent).map_err(|_| Unsafe::Missing)?;
    if !dir.is_dir() {
        return Err(Unsafe::WrongType);
    }
    if dir.uid() != uid && dir.uid() != 0 {
        return Err(Unsafe::NotOwned);
    }
    if dir.mode() & 0o022 != 0 {
        return Err(Unsafe::Writable);
    }
    Ok(())
}
