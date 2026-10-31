//! Root-side device approval for agent `sudo` (docs/internals/device-approval.md).
//!
//! Shared by the PAM module (`pam/`) and the `t3-elevation` helper. The contract
//! document is authoritative for every format in this crate.

pub mod attestation;
pub mod b64;
pub mod config;
pub mod der;
pub mod enroll;
pub mod escape;
#[cfg(any(test, feature = "fixtures"))]
pub mod fixture_server;
pub mod flow;
pub mod install;
pub mod json;
pub mod keys;
pub mod payload;
pub mod rootsafe;
pub mod socket;
pub mod sudo_argv;
pub mod sudoers;
pub mod sys;
#[cfg(test)]
mod test_fs;
pub mod verify;

pub const PROTOCOL_VERSION: u32 = 1;
pub const HELPER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Signature context: `t3-elevation-v1` followed by one NUL.
pub const SIGNATURE_CONTEXT: &[u8; 16] = b"t3-elevation-v1\0";

/// Bytes that verification finds in the module file without loading it.
pub const PROTOCOL_MARKER: &[u8] = b"\0t3-elevation-module protocol=1\0";

pub const MAX_PAYLOAD_BYTES: usize = 16384;
pub const MAX_LINE_BYTES: usize = 262_144;
pub const MAX_SOCKET_PATH_BYTES: usize = 100;

pub const STATE_DIR: &str = "/etc/t3-elevation";

#[cfg(target_os = "macos")]
pub const MODULE_INSTALL_PATH: &str = "/usr/local/lib/pam/pam_t3_elevation.so";
#[cfg(not(target_os = "macos"))]
pub const MODULE_INSTALL_PATH: &str = "/usr/local/lib/t3-elevation/pam_t3_elevation.so";

pub const HELPER_INSTALL_PATH: &str = "/usr/local/lib/t3-elevation/t3-elevation";
