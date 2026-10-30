//! Platform facts: sudo's own argv, the ancestor chain, machine id, users.

use crate::b64;
use sha2::{Digest, Sha256};
use std::ffi::{CStr, CString, c_char, c_int};

pub const MAX_CHAIN: usize = 32;
pub const MAX_CHAIN_ARGV_BYTES: usize = 16 * 1024;
/// Keeps a full chain well under the socket's line limit.
pub const MAX_CHAIN_TOTAL_ARGV_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug)]
pub struct ChainEntry {
    pub pid: i32,
    pub ppid: i32,
    pub start_time: u64,
    pub exe: Option<String>,
    pub argv: Option<Vec<String>>,
    pub argv_truncated: bool,
}

#[cfg(any(target_os = "linux", test))]
fn split_nul(bytes: &[u8]) -> Vec<Vec<u8>> {
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    bytes.split(|b| *b == 0).map(<[u8]>::to_vec).collect()
}

fn lossy(raw: Vec<Vec<u8>>) -> Vec<String> {
    raw.into_iter()
        .map(|arg| String::from_utf8_lossy(&arg).into_owned())
        .collect()
}

/// Keeps whole arguments up to `budget` bytes.
fn truncate_argv(argv: Vec<String>, budget: usize) -> (Vec<String>, bool, usize) {
    let mut used = 0;
    let mut kept = Vec::new();
    for arg in &argv {
        if used + arg.len() > budget {
            return (kept, true, used);
        }
        used += arg.len();
        kept.push(arg.clone());
    }
    (kept, false, used)
}

pub fn chain(start: i32) -> Vec<ChainEntry> {
    let mut entries = Vec::new();
    let mut pid = start;
    let mut budget = MAX_CHAIN_TOTAL_ARGV_BYTES;
    while pid > 0 && entries.len() < MAX_CHAIN {
        let Some((ppid, start_time)) = proc_parent_and_start(pid) else {
            break;
        };
        let (argv, argv_truncated) = match proc_argv(pid) {
            Some(raw) => {
                let (kept, truncated, used) =
                    truncate_argv(lossy(raw), MAX_CHAIN_ARGV_BYTES.min(budget));
                budget -= used;
                (Some(kept), truncated)
            }
            None => (None, false),
        };
        entries.push(ChainEntry {
            pid,
            ppid,
            start_time,
            exe: proc_exe(pid),
            argv,
            argv_truncated,
        });
        if pid == 1 || ppid == pid {
            break;
        }
        pid = ppid;
    }
    entries
}

#[cfg(target_os = "linux")]
pub fn own_argv() -> Option<Vec<Vec<u8>>> {
    std::fs::read("/proc/self/cmdline")
        .ok()
        .map(|bytes| split_nul(&bytes))
}

#[cfg(target_os = "linux")]
fn proc_argv(pid: i32) -> Option<Vec<Vec<u8>>> {
    let bytes = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    (!bytes.is_empty()).then(|| split_nul(&bytes))
}

#[cfg(target_os = "linux")]
fn proc_exe(pid: i32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

/// ppid and field 22 of `/proc/<pid>/stat` (clock ticks since boot).
#[cfg(target_os = "linux")]
fn proc_parent_and_start(pid: i32) -> Option<(i32, u64)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = &stat[stat.rfind(')')? + 2..];
    let fields: Vec<&str> = after_comm.split(' ').collect();
    Some((fields.get(1)?.parse().ok()?, fields.get(19)?.parse().ok()?))
}

#[cfg(target_os = "linux")]
pub fn machine_id() -> Option<String> {
    let text = std::fs::read("/etc/machine-id").ok()?;
    let text = text.strip_suffix(b"\n").unwrap_or(&text);
    (!text.is_empty()).then(|| b64::encode(&Sha256::digest(text)))
}

#[cfg(target_os = "macos")]
fn procargs(pid: i32) -> Option<Vec<Vec<u8>>> {
    unsafe {
        let mut argmax: c_int = 0;
        let mut size = std::mem::size_of::<c_int>();
        let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
        if libc::sysctl(
            mib.as_mut_ptr(),
            2,
            (&raw mut argmax).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return None;
        }
        let mut buffer = vec![0u8; usize::try_from(argmax).ok()?];
        let mut size = buffer.len();
        let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
        if libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buffer.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return None;
        }
        buffer.truncate(size);
        // int argc, exec path, NUL padding, then argc NUL-terminated strings.
        let argc = usize::try_from(i32::from_ne_bytes(buffer.get(..4)?.try_into().ok()?)).ok()?;
        let mut position = 4;
        while position < buffer.len() && buffer[position] != 0 {
            position += 1;
        }
        while position < buffer.len() && buffer[position] == 0 {
            position += 1;
        }
        let mut argv = Vec::with_capacity(argc);
        for _ in 0..argc {
            let end = position + buffer.get(position..)?.iter().position(|b| *b == 0)?;
            argv.push(buffer[position..end].to_vec());
            position = end + 1;
        }
        Some(argv)
    }
}

#[cfg(target_os = "macos")]
pub fn own_argv() -> Option<Vec<Vec<u8>>> {
    procargs(std::process::id() as i32)
}

#[cfg(target_os = "macos")]
fn proc_argv(pid: i32) -> Option<Vec<Vec<u8>>> {
    procargs(pid)
}

#[cfg(target_os = "macos")]
fn proc_exe(pid: i32) -> Option<String> {
    let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let length =
        unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    (length > 0).then(|| String::from_utf8_lossy(&buffer[..length as usize]).into_owned())
}

/// ppid and `p_starttime.tv_sec` (Unix seconds).
#[cfg(target_os = "macos")]
fn proc_parent_and_start(pid: i32) -> Option<(i32, u64)> {
    unsafe {
        let mut info: libc::proc_bsdinfo = std::mem::zeroed();
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as c_int;
        let read = libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size);
        (read == size).then_some((info.pbi_ppid as i32, info.pbi_start_tvsec))
    }
}

/// SHA-256 of the IOPlatformUUID string; `gethostuuid` returns the same UUID.
#[cfg(target_os = "macos")]
pub fn machine_id() -> Option<String> {
    let mut uuid = [0u8; 16];
    let wait = libc::timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    if unsafe { libc::gethostuuid(uuid.as_mut_ptr(), &wait) } != 0 {
        return None;
    }
    let hex: String = uuid.iter().map(|b| format!("{b:02X}")).collect();
    let text = format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    );
    Some(b64::encode(&Sha256::digest(text.as_bytes())))
}

pub fn hostname() -> Option<String> {
    let mut buffer = [0u8; 256];
    if unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) } != 0 {
        return None;
    }
    let end = buffer.iter().position(|b| *b == 0).unwrap_or(buffer.len());
    String::from_utf8(buffer[..end].to_vec()).ok()
}

pub fn cwd() -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStringExt as _;
    std::env::current_dir()
        .ok()
        .map(|path| path.into_os_string().into_vec())
}

#[derive(Clone, Debug)]
pub struct Passwd {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub shell: String,
}

unsafe fn passwd_from(entry: *const libc::passwd) -> Option<Passwd> {
    if entry.is_null() {
        return None;
    }
    unsafe {
        let entry = &*entry;
        let text = |pointer: *const c_char| {
            (!pointer.is_null()).then(|| CStr::from_ptr(pointer).to_string_lossy().into_owned())
        };
        Some(Passwd {
            name: CStr::from_ptr(entry.pw_name).to_str().ok()?.to_string(),
            uid: entry.pw_uid,
            gid: entry.pw_gid,
            shell: text(entry.pw_shell).unwrap_or_default(),
        })
    }
}

pub fn user_by_uid(uid: u32) -> Option<Passwd> {
    unsafe {
        let mut entry: libc::passwd = std::mem::zeroed();
        let mut buffer = vec![0 as c_char; 16 * 1024];
        let mut result = std::ptr::null_mut();
        libc::getpwuid_r(
            uid,
            &mut entry,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        );
        passwd_from(result)
    }
}

pub fn user_by_name(name: &str) -> Option<Passwd> {
    let name = CString::new(name).ok()?;
    unsafe {
        let mut entry: libc::passwd = std::mem::zeroed();
        let mut buffer = vec![0 as c_char; 16 * 1024];
        let mut result = std::ptr::null_mut();
        libc::getpwnam_r(
            name.as_ptr(),
            &mut entry,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        );
        passwd_from(result)
    }
}

/// The user's group ids and names from the group database.
pub fn groups_of(user: &Passwd) -> (Vec<u32>, Vec<String>) {
    let Ok(name) = CString::new(user.name.clone()) else {
        return (vec![user.gid], vec![]);
    };
    let mut count: c_int = 256;
    #[cfg(target_os = "macos")]
    let mut ids = vec![0 as c_int; 256];
    #[cfg(not(target_os = "macos"))]
    let mut ids = vec![0 as libc::gid_t; 256];
    unsafe {
        #[cfg(target_os = "macos")]
        libc::getgrouplist(
            name.as_ptr(),
            user.gid as c_int,
            ids.as_mut_ptr(),
            &mut count,
        );
        #[cfg(not(target_os = "macos"))]
        libc::getgrouplist(name.as_ptr(), user.gid, ids.as_mut_ptr(), &mut count);
    }
    let gids: Vec<u32> = ids[..(count.max(0) as usize).min(ids.len())]
        .iter()
        .map(|id| *id as u32)
        .collect();
    let names = gids
        .iter()
        .filter_map(|gid| unsafe {
            let group = libc::getgrgid(*gid as libc::gid_t);
            (!group.is_null()).then(|| {
                CStr::from_ptr((*group).gr_name)
                    .to_string_lossy()
                    .into_owned()
            })
        })
        .collect();
    (gids, names)
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_argv_and_chain_are_readable() {
        let argv = own_argv().unwrap();
        assert!(!argv.is_empty());
        let chain = chain(std::process::id() as i32);
        assert_eq!(chain[0].pid, std::process::id() as i32);
        assert!(chain[0].start_time > 0);
        assert!(chain.len() <= MAX_CHAIN);
        assert!(machine_id().is_some_and(|id| id.len() == 43));
    }

    #[test]
    fn truncation_keeps_whole_arguments() {
        let (kept, truncated, used) = truncate_argv(vec!["ab".into(), "cd".into(), "ef".into()], 5);
        assert_eq!(
            (kept, truncated, used),
            (vec!["ab".to_string(), "cd".to_string()], true, 4)
        );
    }

    #[test]
    fn split_keeps_empty_arguments() {
        assert_eq!(
            split_nul(b"sudo\0\0x\0"),
            vec![b"sudo".to_vec(), vec![], b"x".to_vec()]
        );
    }
}
