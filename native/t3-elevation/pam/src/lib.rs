//! `pam_t3_elevation`: approves one `sudo` with a signature from an enrolled
//! device. It only adds a way to authenticate. Anything not from T3 returns
//! PAM_IGNORE and sudo continues unchanged. The PAM conversation is never
//! used: on classic sudo and macOS its text lands in the command's stdout.
//!
//! Linux-PAM: `auth [success=done ignore=ignore default=die] <path>` first.
//! macOS (`/etc/pam.d/sudo_local`): `auth sufficient <path>` then
//! `auth requisite <path> mode=gate`; the gate replays the first line's result
//! so a deny ends the whole stack before Touch ID or the password.

use libpam_sys as pam;
use std::ffi::{CStr, c_char, c_int, c_void};
use t3_elevation::flow::{self, Environment, Invocation, Outcome};

/// Found by `t3-elevation status` and external verifiers without loading the
/// library. Exported so the linker can't drop it.
#[unsafe(no_mangle)]
#[used]
pub static T3_ELEVATION_PROTOCOL_MARKER: [u8; 32] = *b"\0t3-elevation-module protocol=1\0";

const _: () = assert!(T3_ELEVATION_PROTOCOL_MARKER.len() == t3_elevation::PROTOCOL_MARKER.len());

/// sudo reuses one PAM handle for a whole invocation, including its password
/// retries, and Fedora's `sudo-i` includes `sudo`. The first result is stored
/// on the handle and every later call returns it unchanged.
const RESULT_KEY: &CStr = c"t3-elevation-result";

unsafe extern "C" fn free_result(_pamh: *mut pam::pam_handle, data: *mut c_void, _status: c_int) {
    unsafe { libc::free(data) };
}

unsafe fn stored_result(pamh: *mut pam::pam_handle) -> Option<c_int> {
    let mut data: *const c_void = std::ptr::null();
    let status = unsafe { pam::pam_get_data(pamh, RESULT_KEY.as_ptr(), &mut data) };
    (status == pam::PAM_SUCCESS && !data.is_null()).then(|| unsafe { *(data as *const c_int) })
}

unsafe fn store_result(pamh: *mut pam::pam_handle, code: c_int) {
    unsafe {
        let data = libc::malloc(std::mem::size_of::<c_int>()) as *mut c_int;
        if data.is_null() {
            return;
        }
        *data = code;
        if pam::pam_set_data(pamh, RESULT_KEY.as_ptr(), data.cast(), free_result)
            != pam::PAM_SUCCESS
        {
            libc::free(data.cast());
        }
    }
}

unsafe fn item(pamh: *mut pam::pam_handle, item_type: c_int) -> Option<String> {
    let mut value: *const c_void = std::ptr::null();
    let status = unsafe { pam::pam_get_item(pamh, item_type, &mut value) };
    if status != pam::PAM_SUCCESS || value.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(value as *const c_char) }
        .to_str()
        .ok()
        .map(str::to_string)
}

unsafe fn has_arg(argc: c_int, argv: *const *const c_char, wanted: &str) -> bool {
    if argv.is_null() {
        return false;
    }
    (0..argc.max(0) as usize).any(|index| {
        let arg = unsafe { *argv.add(index) };
        !arg.is_null() && unsafe { CStr::from_ptr(arg) }.to_bytes() == wanted.as_bytes()
    })
}

unsafe fn authenticate(
    pamh: *mut pam::pam_handle,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    std::hint::black_box(&T3_ELEVATION_PROTOCOL_MARKER);
    if let Some(code) = unsafe { stored_result(pamh) } {
        return code;
    }
    if unsafe { has_arg(argc, argv, "mode=gate") } {
        return pam::PAM_IGNORE;
    }
    let invocation = Invocation {
        argv: t3_elevation::sys::own_argv().unwrap_or_default(),
        uid: unsafe { libc::getuid() },
        service: unsafe { item(pamh, pam::PAM_SERVICE) },
        pam_user: unsafe { item(pamh, pam::PAM_USER) },
        cwd: t3_elevation::sys::cwd(),
        env_shell: std::env::var("SHELL").ok(),
        env_path: std::env::var("PATH").ok(),
    };
    let code = match flow::authenticate(&invocation, &Environment::system()) {
        Outcome::Approved => pam::PAM_SUCCESS,
        Outcome::Ignore => pam::PAM_IGNORE,
        Outcome::Fail => pam::PAM_CRED_INSUFFICIENT,
    };
    unsafe { store_result(pamh, code) };
    code
}

/// # Safety
/// libpam calls this with a live handle and `argc` NUL-terminated strings in `argv`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut pam::pam_handle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    std::panic::catch_unwind(|| unsafe { authenticate(pamh, argc, argv) })
        .unwrap_or(pam::PAM_IGNORE)
}

/// Other modules' setcred keeps running: an auth-only module has no
/// credentials to set.
///
/// # Safety
/// Touches none of its arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut pam::pam_handle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    pam::PAM_IGNORE
}
