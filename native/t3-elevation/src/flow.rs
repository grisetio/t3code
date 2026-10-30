//! The module's decision (spec §4), independent of the PAM ABI so it can be
//! tested in-process. Only a signature that verifies against an enrolled key
//! approves; everything from the socket is otherwise untrusted.

use crate::config::{self, UserConfig};
use crate::keys::{self, EnrolledKey};
use crate::payload::{self, Payload};
use crate::rootsafe::{self, Policy};
use crate::socket::{Connection, deadline_in};
use crate::sudo_argv::{self, SearchPath};
use crate::sys::{self, ChainEntry};
use crate::verify::{self, Response};
use crate::{MAX_LINE_BYTES, MAX_PAYLOAD_BYTES, json};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// PAM_SUCCESS.
    Approved,
    /// PAM_IGNORE: not ours; sudo continues as if the module weren't there.
    Ignore,
    /// PAM_CRED_INSUFFICIENT: ends the stack without reaching password
    /// modules or lockout counters.
    Fail,
}

pub const HELLO_TIMEOUT: Duration = Duration::from_secs(3);
const RESULT_WRITE_TIMEOUT: Duration = Duration::from_secs(1);

/// What sudo's process knows about itself.
pub struct Invocation {
    pub argv: Vec<Vec<u8>>,
    pub uid: u32,
    pub service: Option<String>,
    pub pam_user: Option<String>,
    pub cwd: Option<Vec<u8>>,
    pub env_shell: Option<String>,
    pub env_path: Option<String>,
}

/// Where the module looks and how strict it is. Tests swap these out.
pub struct Environment {
    pub state_dir: PathBuf,
    pub policy: Policy,
    pub sudoers: PathBuf,
    pub shells: PathBuf,
    pub chain_start: i32,
    pub window_override: Option<i64>,
}

impl Environment {
    pub fn system() -> Self {
        Self {
            state_dir: PathBuf::from(crate::STATE_DIR),
            policy: Policy::root(),
            sudoers: PathBuf::from("/etc/sudoers"),
            shells: PathBuf::from("/etc/shells"),
            chain_start: unsafe { libc::getppid() },
            window_override: None,
        }
    }
}

pub fn authenticate(invocation: &Invocation, environment: &Environment) -> Outcome {
    let argv_lossy: Vec<String> = invocation
        .argv
        .iter()
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect();
    let parsed = sudo_argv::parse(&argv_lossy);
    let Some(user) = sys::user_by_uid(invocation.uid) else {
        return Outcome::Ignore;
    };
    if !config::is_safe_user_name(&user.name) {
        return Outcome::Ignore;
    }
    let config_path = environment.state_dir.join("users").join(format!("{}.toml", user.name));
    if std::fs::symlink_metadata(&config_path).is_err() {
        return Outcome::Ignore;
    }
    // From here the user is configured. `noninteractive_auth` lets any
    // program's `sudo -n` reach PAM, so with -n every outcome that would be
    // IGNORE fails instead; otherwise it would reach pam_unix, faillock or
    // Touch ID.
    let soft = if parsed.non_interactive { Outcome::Fail } else { Outcome::Ignore };
    let Some(prepared) = prepare(invocation, environment, &user, &config_path) else {
        return soft;
    };
    match exchange(invocation, environment, &user, &argv_lossy, &parsed, prepared) {
        Exchange::NotOurs => soft,
        Exchange::Decided(outcome) => outcome,
    }
}

struct Prepared {
    config: UserConfig,
    keys: Vec<EnrolledKey>,
    machine_id: String,
    host_name: String,
    chain: Vec<ChainEntry>,
}

fn prepare(invocation: &Invocation, environment: &Environment, user: &sys::Passwd, config_path: &Path) -> Option<Prepared> {
    rootsafe::check_path(config_path, &environment.policy, rootsafe::Kind::File).ok()?;
    let text = rootsafe::read_limited(config_path, 64 * 1024).ok()?;
    let config = config::parse(std::str::from_utf8(&text).ok()?)?;
    if !config.enabled {
        return None;
    }
    // sudo authenticates the invoking user; `rootpw`/`targetpw` setups ask
    // for someone else's credentials, which a phone approval doesn't stand in for.
    if invocation.pam_user.as_deref() != Some(user.name.as_str()) {
        return None;
    }
    if !matches!(invocation.service.as_deref(), Some("sudo" | "sudo-i")) {
        return None;
    }
    let keys = keys::load_dir(&environment.state_dir.join("keys").join(&user.name), &environment.policy).ok()?;
    if keys.is_empty() {
        return None;
    }
    Some(Prepared {
        config,
        keys,
        machine_id: sys::machine_id()?,
        host_name: sys::hostname()?,
        chain: sys::chain(environment.chain_start),
    })
}

enum Exchange {
    NotOurs,
    Decided(Outcome),
}

fn hello_line(invocation: &Invocation, user: &str, host: (&str, &str), argv: &[String], chain: &[ChainEntry]) -> String {
    let mut out = String::from("{\"type\":\"hello\",\"v\":1,\"user\":");
    json::push_str(&mut out, user);
    out.push_str(&format!(",\"uid\":{},\"service\":", invocation.uid));
    json::push_opt_str(&mut out, invocation.service.as_deref());
    out.push_str(",\"host\":{\"name\":");
    json::push_str(&mut out, host.0);
    out.push_str(",\"machineId\":");
    json::push_str(&mut out, host.1);
    out.push_str("},\"argv\":");
    json::push_str_array(&mut out, argv);
    out.push_str(",\"cwd\":");
    let cwd = invocation.cwd.as_ref().map(|cwd| String::from_utf8_lossy(cwd).into_owned());
    json::push_opt_str(&mut out, cwd.as_deref());
    out.push_str(",\"chain\":[");
    for (index, entry) in chain.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"pid\":{},\"ppid\":{},\"startTime\":{},\"exe\":",
            entry.pid, entry.ppid, entry.start_time
        ));
        json::push_opt_str(&mut out, entry.exe.as_deref());
        out.push_str(",\"argv\":");
        match &entry.argv {
            Some(argv) => json::push_str_array(&mut out, argv),
            None => out.push_str("null"),
        }
        out.push_str(&format!(",\"argvTruncated\":{}}}", entry.argv_truncated));
    }
    out.push_str("]}");
    out
}

fn parse_message(line: &[u8]) -> Option<serde_json::Map<String, Value>> {
    match serde_json::from_slice::<Value>(line).ok()? {
        Value::Object(object) if object.get("type").is_some_and(Value::is_string) => Some(object),
        _ => None,
    }
}

fn send_result(connection: &mut Connection, outcome: &str) {
    let line = format!("{{\"type\":\"result\",\"outcome\":\"{outcome}\"}}");
    connection.write_line(&line, deadline_in(RESULT_WRITE_TIMEOUT));
}

fn exchange(
    invocation: &Invocation,
    environment: &Environment,
    user: &sys::Passwd,
    argv_lossy: &[String],
    parsed: &sudo_argv::Parsed,
    prepared: Prepared,
) -> Exchange {
    let socket = Path::new(&prepared.config.socket);
    if rootsafe::check_socket(socket, invocation.uid).is_err() {
        return Exchange::NotOurs;
    }
    let hello = hello_line(
        invocation,
        &user.name,
        (&prepared.host_name, &prepared.machine_id),
        argv_lossy,
        &prepared.chain,
    );
    if hello.len() > MAX_LINE_BYTES {
        return Exchange::NotOurs;
    }
    let hello_deadline = deadline_in(HELLO_TIMEOUT);
    let Some(mut connection) = Connection::connect(&prepared.config.socket, hello_deadline) else {
        return Exchange::NotOurs;
    };
    if connection.peer_uid() != Some(invocation.uid) {
        return Exchange::NotOurs;
    }
    if !connection.write_line(&hello, hello_deadline) {
        return Exchange::NotOurs;
    }
    // Anything but a well-formed `mine` before the request counts as "T3 down":
    // failing there would only take the password path away from the user.
    let Ok(reply) = connection.read_line(hello_deadline) else {
        return Exchange::NotOurs;
    };
    let Some(reply) = parse_message(&reply) else {
        return Exchange::NotOurs;
    };
    if reply.get("type").and_then(Value::as_str) != Some("hello_reply")
        || reply.get("v") != Some(&Value::from(1))
        || reply.get("decision").and_then(Value::as_str) != Some("mine")
    {
        return Exchange::NotOurs;
    }

    let Some(payload) = build_payload(invocation, environment, user, parsed, &prepared) else {
        send_result(&mut connection, "invalid_encoding");
        return Exchange::Decided(Outcome::Fail);
    };
    let bytes = payload.to_bytes();
    if bytes.len() > MAX_PAYLOAD_BYTES {
        send_result(&mut connection, "too_large");
        return Exchange::Decided(Outcome::Fail);
    }
    let request = format!("{{\"type\":\"request\",\"payload\":\"{}\"}}", crate::b64::encode(&bytes));
    let seconds_left = (payload.expires_at - sys::now()).max(0) as u64;
    let deadline = Instant::now() + Duration::from_secs(seconds_left);
    if !connection.write_line(&request, deadline) {
        return Exchange::Decided(Outcome::Fail);
    }
    let message = match connection.read_line(deadline) {
        Ok(line) => parse_message(&line),
        Err(crate::socket::ReadError::Timeout) => {
            send_result(&mut connection, "expired");
            return Exchange::Decided(Outcome::Fail);
        }
        Err(_) => return Exchange::Decided(Outcome::Fail),
    };
    let Some(message) = message else {
        return Exchange::Decided(Outcome::Fail);
    };
    let text = |key: &str| message.get(key).and_then(Value::as_str);
    match (text("type"), text("decision")) {
        (Some("response"), Some("deny")) => {
            send_result(&mut connection, "denied");
            Exchange::Decided(Outcome::Fail)
        }
        (Some("response"), Some("approve")) => {
            let response = Response {
                key_id: text("keyId").unwrap_or_default(),
                alg: text("alg").unwrap_or_default(),
                signature: text("signature").unwrap_or_default(),
            };
            match verify::verify(&bytes, payload.expires_at, &response, &prepared.keys, sys::now()) {
                Ok(_) => {
                    send_result(&mut connection, "approved");
                    Exchange::Decided(Outcome::Approved)
                }
                Err(verify::VerifyError::Expired) => {
                    send_result(&mut connection, "expired");
                    Exchange::Decided(Outcome::Fail)
                }
                Err(_) => {
                    send_result(&mut connection, "bad_signature");
                    Exchange::Decided(Outcome::Fail)
                }
            }
        }
        // `cancel`, unknown types and decisions: close without a result.
        _ => Exchange::Decided(Outcome::Fail),
    }
}

fn build_payload(
    invocation: &Invocation,
    environment: &Environment,
    user: &sys::Passwd,
    parsed: &sudo_argv::Parsed,
    prepared: &Prepared,
) -> Option<Payload> {
    let argv = payload::utf8_strings(&invocation.argv)?;
    let cwd = String::from_utf8(invocation.cwd.clone()?).ok()?;
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).ok()?;
    let (gids, group_names) = sys::groups_of(user);
    let run_as_for_sudoers = match (&parsed.user, &parsed.group) {
        (Some(target), _) => target.clone(),
        (None, Some(_)) => user.name.clone(),
        (None, None) => "root".to_string(),
    };
    let subject = crate::sudoers::Subject {
        user: &user.name,
        uid: user.uid,
        groups: &group_names,
        host: &prepared.host_name,
        run_as: &run_as_for_sudoers,
    };
    let caller_path = invocation.env_path.clone().unwrap_or_default();
    let alternatives: Vec<String> = crate::sudoers::secure_path(&environment.sudoers, &subject)
        .into_iter()
        .map(|value| value.unwrap_or_else(|| caller_path.clone()))
        .collect();
    let search = if alternatives.len() == 1 {
        SearchPath::Known(alternatives[0].clone())
    } else {
        SearchPath::Uncertain(alternatives)
    };
    let target_shell = target_login_shell(&run_as_for_sudoers);
    let caller_shell = invocation.env_shell.clone().or_else(|| Some(user.shell.clone()).filter(|s| !s.is_empty()));
    let shells: Vec<String> = std::fs::read_to_string(&environment.shells)
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('/'))
        .map(str::to_string)
        .collect();
    let context = sudo_argv::Context {
        user: &user.name,
        uid: user.uid,
        gids: &gids,
        cwd: &cwd,
        caller_shell: caller_shell.as_deref(),
        target_shell: target_shell.as_deref(),
        search,
        shells: &shells,
    };
    let described = sudo_argv::describe(&argv, parsed, &context);
    let issued_at = sys::now();
    let window = environment
        .window_override
        .unwrap_or(prepared.config.approval_window_seconds);
    Some(Payload {
        nonce,
        issued_at,
        expires_at: issued_at + window,
        host_name: prepared.host_name.clone(),
        machine_id: prepared.machine_id.clone(),
        user: user.name.clone(),
        uid: invocation.uid,
        run_as: described.run_as,
        run_as_group: described.run_as_group,
        argv,
        command: described.command,
        cwd,
        service: invocation.service.clone().unwrap_or_default(),
        key_ids: prepared.keys.iter().map(|key| key.key_id.clone()).collect(),
    })
}

fn target_login_shell(run_as: &str) -> Option<String> {
    let entry = match run_as.strip_prefix('#') {
        Some(uid) => sys::user_by_uid(uid.parse().ok()?),
        None => sys::user_by_name(run_as),
    }?;
    Some(entry.shell).filter(|shell| !shell.is_empty())
}
