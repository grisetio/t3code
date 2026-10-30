//! The module's side of the NDJSON socket. Every read and write has a
//! deadline, the fd is close-on-exec so the command sudo runs never inherits
//! it, and writes never raise SIGPIPE inside sudo.

use crate::MAX_LINE_BYTES;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::time::{Duration, Instant};

pub struct Connection {
    fd: OwnedFd,
    buffer: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReadError {
    Closed,
    Timeout,
    TooLong,
}

fn remaining_ms(deadline: Instant) -> Option<i32> {
    let left = deadline.checked_duration_since(Instant::now())?;
    if left.is_zero() {
        return None;
    }
    Some(left.as_millis().clamp(1, i32::MAX as u128) as i32)
}

fn poll(fd: i32, events: i16, deadline: Instant) -> bool {
    loop {
        let Some(timeout) = remaining_ms(deadline) else {
            return false;
        };
        let mut entry = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut entry, 1, timeout) };
        if ready > 0 {
            return true;
        }
        if ready == 0 {
            return false;
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return false;
        }
    }
}

impl Connection {
    pub fn connect(path: &str, deadline: Instant) -> Option<Self> {
        let bytes = path.as_bytes();
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        if bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
            return None;
        }
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (slot, byte) in address.sun_path.iter_mut().zip(bytes) {
            *slot = *byte as libc::c_char;
        }
        let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        if raw < 0 {
            return None;
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        unsafe {
            libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC);
            let flags = libc::fcntl(raw, libc::F_GETFL);
            libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK);
            #[cfg(target_os = "macos")]
            {
                let on: libc::c_int = 1;
                libc::setsockopt(
                    raw,
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    (&raw const on).cast(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }
        let length = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
        let result = unsafe { libc::connect(raw, (&raw const address).cast(), length) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINPROGRESS)
                || !poll(raw, libc::POLLOUT, deadline)
            {
                return None;
            }
            let mut status: libc::c_int = 0;
            let mut size = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            unsafe {
                libc::getsockopt(
                    raw,
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&raw mut status).cast(),
                    &mut size,
                );
            }
            if status != 0 {
                return None;
            }
        }
        Some(Self {
            fd,
            buffer: Vec::new(),
        })
    }

    /// SO_PEERCRED on Linux, getpeereid on macOS.
    pub fn peer_uid(&self) -> Option<u32> {
        let raw = self.fd.as_raw_fd();
        #[cfg(target_os = "linux")]
        unsafe {
            let mut credentials: libc::ucred = std::mem::zeroed();
            let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            let result = libc::getsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&raw mut credentials).cast(),
                &mut length,
            );
            (result == 0).then_some(credentials.uid)
        }
        #[cfg(target_os = "macos")]
        unsafe {
            let (mut uid, mut gid) = (0, 0);
            (libc::getpeereid(raw, &mut uid, &mut gid) == 0).then_some(uid)
        }
    }

    pub fn write_line(&mut self, line: &str, deadline: Instant) -> bool {
        let mut data = Vec::with_capacity(line.len() + 1);
        data.extend_from_slice(line.as_bytes());
        data.push(b'\n');
        let mut written = 0;
        #[cfg(target_os = "linux")]
        let flags = libc::MSG_NOSIGNAL;
        #[cfg(not(target_os = "linux"))]
        let flags = 0;
        while written < data.len() {
            let sent = unsafe {
                libc::send(
                    self.fd.as_raw_fd(),
                    data[written..].as_ptr().cast(),
                    data.len() - written,
                    flags,
                )
            };
            if sent > 0 {
                written += sent as usize;
                continue;
            }
            let error = std::io::Error::last_os_error();
            match error.kind() {
                std::io::ErrorKind::Interrupted => continue,
                std::io::ErrorKind::WouldBlock => {
                    if !poll(self.fd.as_raw_fd(), libc::POLLOUT, deadline) {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        true
    }

    /// One line without its newline. A line over the contract's limit ends
    /// the connection.
    pub fn read_line(&mut self, deadline: Instant) -> Result<Vec<u8>, ReadError> {
        loop {
            if let Some(end) = self.buffer.iter().position(|b| *b == b'\n') {
                if end > MAX_LINE_BYTES {
                    return Err(ReadError::TooLong);
                }
                let line = self.buffer[..end].to_vec();
                self.buffer.drain(..=end);
                return Ok(line);
            }
            if self.buffer.len() > MAX_LINE_BYTES {
                return Err(ReadError::TooLong);
            }
            if !poll(self.fd.as_raw_fd(), libc::POLLIN, deadline) {
                return Err(ReadError::Timeout);
            }
            let mut chunk = [0u8; 8192];
            let read =
                unsafe { libc::read(self.fd.as_raw_fd(), chunk.as_mut_ptr().cast(), chunk.len()) };
            if read > 0 {
                self.buffer.extend_from_slice(&chunk[..read as usize]);
                continue;
            }
            if read == 0 {
                return Err(ReadError::Closed);
            }
            let kind = std::io::Error::last_os_error().kind();
            if kind != std::io::ErrorKind::Interrupted && kind != std::io::ErrorKind::WouldBlock {
                return Err(ReadError::Closed);
            }
        }
    }
}

pub fn deadline_in(duration: Duration) -> Instant {
    Instant::now() + duration
}
