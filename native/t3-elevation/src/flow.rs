//! The module's decision (spec §4), independent of the PAM ABI so it can be
//! tested in-process. Only a signature that verifies against an enrolled key
//! approves; everything from the socket is otherwise untrusted.

use crate::config::{self, UserConfig};
use crate::decline;
use crate::grant::{self, Anchor, Scope, Shells};
use crate::keys::{self, EnrolledKey};
use crate::payload::{self, Payload};
use crate::rootsafe::{self, Policy};
use crate::socket::{Connection, deadline_in};
use crate::sudo_argv::{self, Flavor, Search};
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

/// The outcome, and a line for sudo's stderr when the agent should know why.
/// The PAM conversation can't carry it: sudo-rs drops it without a terminal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub outcome: Outcome,
    pub notice: Option<String>,
}

impl From<Outcome> for Decision {
    fn from(outcome: Outcome) -> Self {
        Self {
            outcome,
            notice: None,
        }
    }
}

fn fail_with(notice: impl Into<String>) -> Decision {
    Decision {
        outcome: Outcome::Fail,
        notice: Some(notice.into()),
    }
}

/// Where the sudo's session comes from. Tests pin it to a process they own
/// and the argv its leader is taken to run.
#[derive(Clone)]
pub enum SessionSource {
    Kernel,
    Fixed(Option<(Anchor, Vec<String>)>),
    /// As the kernel reports a sudo its shell exec'd: sudo leads the session.
    Leading(Anchor),
}

/// A sudo's session. `scope` is set when an approval may start a grant there.
struct Grouping {
    anchor: Anchor,
    leading: bool,
    scope: Option<Scope>,
}

pub const HELLO_TIMEOUT: Duration = Duration::from_secs(3);
const RESULT_WRITE_TIMEOUT: Duration = Duration::from_secs(1);

/// What sudo's process knows about itself.
#[derive(Clone)]
pub struct Invocation {
    pub argv: Vec<Vec<u8>>,
    pub uid: u32,
    pub service: Option<String>,
    pub pam_user: Option<String>,
    pub cwd: Option<Vec<u8>>,
    pub env_shell: Option<String>,
    /// Every `PATH=` value in sudo's environment, in order. sudo.ws and
    /// sudo-rs pick different ones when there are several.
    pub env_paths: Vec<Vec<u8>>,
    /// sudo's whole environment, which sudoers may pass on to the command.
    pub env: Vec<(String, String)>,
}

/// Where the module looks and how strict it is. Tests swap these out.
#[derive(Clone)]
pub struct Environment {
    pub state_dir: PathBuf,
    pub policy: Policy,
    pub sudoers: PathBuf,
    pub shells: PathBuf,
    pub chain_start: i32,
    pub window_override: Option<i64>,
    pub grants_dir: PathBuf,
    pub session: SessionSource,
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
            grants_dir: PathBuf::from(grant::GRANTS_DIR),
            session: SessionSource::Kernel,
        }
    }

    fn grouping(&self, chain: &[ChainEntry], shells: &Shells) -> Option<Grouping> {
        let leading = |anchor| Grouping {
            anchor,
            leading: true,
            scope: None,
        };
        let scoped = |scope: Scope| Grouping {
            anchor: scope.anchor,
            leading: false,
            scope: Some(scope),
        };
        match &self.session {
            SessionSource::Fixed(fixed) => {
                let (anchor, argv) = fixed.clone()?;
                Scope::new(anchor, argv).map(scoped)
            }
            SessionSource::Leading(anchor) => Some(leading(*anchor)),
            SessionSource::Kernel => {
                let session = sys::session_id()?;
                if session != std::process::id() as i32 {
                    return grant::qualify(session, chain, sys::leader_facts(session), shells)
                        .map(scoped);
                }
                // zsh and bash exec a command string's last command, so in
                // `sudo a && sudo b` the second sudo is the shell itself, with
                // its pid and start time. Nothing shows what the shell was any
                // more, so this sudo can only be the last call of a grant an
                // earlier sudo started under the qualified shell.
                let facts = sys::leader_facts(session)?;
                (!facts.has_tty).then(|| {
                    leading(Anchor {
                        session,
                        leader_start: facts.start,
                    })
                })
            }
        }
    }

    /// The session leader's argv now, read from the kernel.
    fn leader_argv(&self, pid: i32) -> Option<Vec<String>> {
        match &self.session {
            SessionSource::Fixed(fixed) => fixed
                .as_ref()
                .filter(|(anchor, _)| anchor.session == pid)
                .map(|(_, argv)| argv.clone()),
            _ => sys::process_argv(pid),
        }
    }
}

/// sudo decides what to run from its own argv. If argv[0] isn't sudo's name,
/// the argv read back may not be the one sudo parsed (an empty argv[0] once
/// shifted the macOS parse), so the payload could describe another command.
/// `sudo.ws` is sudo.ws's own name where sudo-rs is `sudo` (Ubuntu 25.10+).
fn invoked_as_sudo(argv: &[Vec<u8>]) -> bool {
    argv.first().is_some_and(|arg0| {
        let name = arg0.rsplit(|b| *b == b'/').next().unwrap_or(arg0);
        matches!(name, b"sudo" | b"sudoedit" | b"sudo.ws")
    })
}

pub fn authenticate(invocation: &Invocation, environment: &Environment) -> Decision {
    if !invoked_as_sudo(&invocation.argv) {
        return Outcome::Ignore.into();
    }
    let argv_lossy: Vec<String> = invocation
        .argv
        .iter()
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect();
    let parsed = sudo_argv::parse(&argv_lossy);
    let Some(user) = sys::user_by_uid(invocation.uid) else {
        return Outcome::Ignore.into();
    };
    if !config::is_safe_user_name(&user.name) {
        return Outcome::Ignore.into();
    }
    let config_path = environment
        .state_dir
        .join("users")
        .join(format!("{}.toml", user.name));
    if std::fs::symlink_metadata(&config_path).is_err() {
        return Outcome::Ignore.into();
    }
    // From here the user is configured. `noninteractive_auth` lets any
    // program's `sudo -n` reach PAM, so with -n every outcome that would be
    // IGNORE fails instead; otherwise it would reach pam_unix, faillock or
    // Touch ID.
    let soft = if parsed.non_interactive {
        Outcome::Fail
    } else {
        Outcome::Ignore
    };
    let Some(prepared) = prepare(invocation, environment, &user, &config_path) else {
        return soft.into();
    };
    let grouping = (prepared.config.session_max_uses > 0)
        .then(|| {
            let (gids, _) = sys::groups_of(&user);
            let shells = Shells::load(&environment.shells, &environment.policy, user.uid, &gids);
            environment.grouping(&prepared.chain, &shells)
        })
        .flatten();
    if let Some(grouping) = &grouping
        && grant::present(
            &environment.grants_dir,
            invocation.uid,
            grouping.anchor.session,
        )
        && let Some(decision) =
            use_grant(invocation, environment, &user, &parsed, &prepared, grouping)
    {
        return decision;
    }
    let scope = grouping.and_then(|grouping| grouping.scope);
    match exchange(
        invocation,
        environment,
        &user,
        &argv_lossy,
        &parsed,
        prepared,
        scope,
    ) {
        Exchange::NotOurs => soft.into(),
        Exchange::Decided(decision) => decision,
    }
}

/// The helper changes which devices approve; enrolling one always needs a
/// device or the password, never an earlier approval.
fn is_helper(command: &payload::Command) -> bool {
    command
        .resolved_path
        .as_deref()
        .or(command.argv.first().map(String::as_str))
        .is_some_and(|program| program.rsplit('/').next() == Some("t3-elevation"))
}

/// A sudo in a session an earlier approval covers. Declines still apply, so
/// an agent sees the same rules inside an approved command; None falls back
/// to asking the phone, as for anything the phone didn't show: a warning, an
/// unresolved program, or the helper.
fn use_grant(
    invocation: &Invocation,
    environment: &Environment,
    user: &sys::Passwd,
    parsed: &sudo_argv::Parsed,
    prepared: &Prepared,
    grouping: &Grouping,
) -> Option<Decision> {
    let request = describe_request(invocation, environment, user, parsed, prepared)?;
    if let Some(hint) = request.decline {
        return Some(fail_with(hint));
    }
    let command = &request.described.command;
    if is_helper(command) || !command.warnings.is_empty() {
        return None;
    }
    let taken = grant::take(
        &environment.grants_dir,
        &environment.policy,
        &grant::Request {
            uid: invocation.uid,
            user: &user.name,
            anchor: grouping.anchor,
            leading: grouping.leading,
            args: request.argv.get(1..)?,
            resolved_path: command.resolved_path.as_deref()?,
            run_as: &request.described.run_as,
            run_as_group: request.described.run_as_group.as_deref(),
            cwd: &request.cwd,
        },
        &prepared.keys,
        sys::now(),
        grant::Leader {
            start: |pid| sys::leader_facts(pid).map(|facts| facts.start),
            argv: |pid| environment.leader_argv(pid),
        },
    );
    taken.then(|| Outcome::Approved.into())
}

/// The session an approval of `request` would also cover: the other sudos
/// written in the leader's command string, described as their own requests
/// would be, keeping those a grant could pass. None when `request` itself
/// isn't one of the written sudos (a startup file's or a script's), or
/// nothing else would be covered.
fn plan_session(
    invocation: &Invocation,
    environment: &Environment,
    user: &sys::Passwd,
    prepared: &Prepared,
    request: &Described,
    scope: Scope,
) -> Option<Planned> {
    let mut calls = crate::shell_words::sudo_calls(&scope.command)?;
    let own = calls.iter().position(|call| call.is(&request.argv[1..]))?;
    calls.remove(own);
    let covered: Vec<grant::Covered> = calls
        .into_iter()
        .filter_map(|call| {
            let args: Vec<String> = call.args.into_iter().collect::<Option<_>>()?;
            let argv: Vec<String> = request.argv[..1].iter().chain(&args).cloned().collect();
            let other = Invocation {
                argv: argv.iter().map(|arg| arg.as_bytes().to_vec()).collect(),
                ..invocation.clone()
            };
            let parsed = sudo_argv::parse(&argv);
            let described = describe_request(&other, environment, user, &parsed, prepared)?;
            let command = described.described.command;
            if described.decline.is_some() || is_helper(&command) || !command.warnings.is_empty() {
                return None;
            }
            Some(grant::Covered {
                args,
                resolved_path: command.resolved_path?,
                run_as: described.described.run_as,
                run_as_group: described.described.run_as_group,
                exec_tail: call.exec_tail,
            })
        })
        .take(prepared.config.session_max_uses as usize)
        .collect();
    if covered.is_empty() {
        return None;
    }
    Some(Planned {
        session: payload::Session {
            id: scope.anchor.session,
            leader_start: scope.anchor.leader_start,
            max_uses: covered.len() as u32,
            command: Some(scope.command),
        },
        covered,
        leader_argv: scope.leader_argv,
    })
}

struct Planned {
    session: payload::Session,
    covered: Vec<grant::Covered>,
    leader_argv: Vec<String>,
}

struct Prepared {
    config: UserConfig,
    keys: Vec<EnrolledKey>,
    machine_id: String,
    host_name: String,
    chain: Vec<ChainEntry>,
}

fn prepare(
    invocation: &Invocation,
    environment: &Environment,
    user: &sys::Passwd,
    config_path: &Path,
) -> Option<Prepared> {
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
    // The payload can't show the environment; it is faithful only while
    // sudoers keeps the caller's HOME, editors and PATH away from root. An
    // install that lacks those lines would otherwise pass every static check.
    if !crate::install::sudoers_has_settings(&environment.sudoers, &user.name) {
        return None;
    }
    let keys = keys::load_dir(
        &environment.state_dir.join("keys").join(&user.name),
        &environment.policy,
    )
    .ok()?;
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
    Decided(Decision),
}

fn hello_line(
    invocation: &Invocation,
    user: &str,
    host: (&str, &str),
    argv: &[String],
    chain: &[ChainEntry],
) -> String {
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
    let cwd = invocation
        .cwd
        .as_ref()
        .map(|cwd| String::from_utf8_lossy(cwd).into_owned());
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
    scope: Option<Scope>,
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
    // The server's own sudo (its live test, the helper) has no agent to read
    // a hint, and grouping it would let it cover the server's later sudo.
    // The flag is the server's word, so it only lets through what the server
    // itself runs: a probe, or the helper.
    let own_sudo = reply.get("ownSudo") == Some(&Value::Bool(true));

    let Some(request) = describe_request(invocation, environment, user, parsed, &prepared) else {
        send_result(&mut connection, "invalid_encoding");
        return Exchange::Decided(Outcome::Fail.into());
    };
    let servers_own =
        own_sudo && (decline::is_probe(parsed) || is_helper(&request.described.command));
    if !servers_own && let Some(hint) = request.decline.clone() {
        // Closing without a request leaves nothing for the server to show.
        return Exchange::Decided(fail_with(hint));
    }
    let mut planned = scope
        .filter(|_| !own_sudo && !is_helper(&request.described.command))
        .and_then(|scope| plan_session(invocation, environment, user, &prepared, &request, scope));
    let Some(mut payload) = build_payload(
        invocation,
        environment,
        user,
        &prepared,
        request.clone(),
        planned.as_ref().map(|planned| planned.session.clone()),
    ) else {
        return Exchange::Decided(Outcome::Fail.into());
    };
    let mut bytes = payload.to_bytes();
    // A long command string costs the grant, not the request.
    if bytes.len() > MAX_PAYLOAD_BYTES && planned.take().is_some() {
        let Some(alone) = build_payload(invocation, environment, user, &prepared, request, None)
        else {
            return Exchange::Decided(Outcome::Fail.into());
        };
        payload = alone;
        bytes = payload.to_bytes();
    }
    if bytes.len() > MAX_PAYLOAD_BYTES {
        send_result(&mut connection, "too_large");
        return Exchange::Decided(Outcome::Fail.into());
    }
    let request = format!(
        "{{\"type\":\"request\",\"payload\":\"{}\"}}",
        crate::b64::encode(&bytes)
    );
    let seconds_left = (payload.expires_at - sys::now()).max(0) as u64;
    let deadline = Instant::now() + Duration::from_secs(seconds_left);
    if !connection.write_line(&request, deadline) {
        return Exchange::Decided(Outcome::Fail.into());
    }
    let message = match connection.read_line(deadline) {
        Ok(line) => parse_message(&line),
        Err(crate::socket::ReadError::Timeout) => {
            send_result(&mut connection, "expired");
            return Exchange::Decided(fail_with(decline::EXPIRED));
        }
        Err(_) => return Exchange::Decided(Outcome::Fail.into()),
    };
    let Some(message) = message else {
        return Exchange::Decided(Outcome::Fail.into());
    };
    let text = |key: &str| message.get(key).and_then(Value::as_str);
    match (text("type"), text("decision")) {
        (Some("response"), Some("deny")) => {
            send_result(&mut connection, "denied");
            Exchange::Decided(fail_with(decline::DENIED))
        }
        (Some("response"), Some("approve")) => {
            let response = Response {
                key_id: text("keyId").unwrap_or_default(),
                alg: text("alg").unwrap_or_default(),
                signature: text("signature").unwrap_or_default(),
            };
            match verify::verify(
                &bytes,
                payload.expires_at,
                &response,
                &prepared.keys,
                sys::now(),
            ) {
                Ok(_) => {
                    if let Some(planned) = planned {
                        // The window counts from the request, so a late
                        // approval doesn't stretch the grant past it.
                        let grant = grant::Grant::new(
                            (invocation.uid, &user.name),
                            &planned.session,
                            &planned.leader_argv,
                            &payload.cwd,
                            response.key_id,
                            payload.expires_at,
                            planned.covered,
                        );
                        grant::record(
                            &environment.grants_dir,
                            &environment.policy,
                            &grant,
                            sys::now(),
                        );
                    }
                    send_result(&mut connection, "approved");
                    Exchange::Decided(Outcome::Approved.into())
                }
                Err(verify::VerifyError::Expired) => {
                    send_result(&mut connection, "expired");
                    Exchange::Decided(fail_with(decline::EXPIRED))
                }
                Err(_) => {
                    send_result(&mut connection, "bad_signature");
                    Exchange::Decided(Outcome::Fail.into())
                }
            }
        }
        // `cancel`, unknown types and decisions: close without a result.
        _ => Exchange::Decided(Outcome::Fail.into()),
    }
}

/// What sudo will run, as the payload shows it, and the hint when it
/// shouldn't reach the phone. None when argv or cwd isn't UTF-8.
#[derive(Clone)]
struct Described {
    argv: Vec<String>,
    cwd: String,
    described: sudo_argv::Described,
    decline: Option<String>,
}

fn describe_request(
    invocation: &Invocation,
    environment: &Environment,
    user: &sys::Passwd,
    parsed: &sudo_argv::Parsed,
    prepared: &Prepared,
) -> Option<Described> {
    let argv = payload::utf8_strings(&invocation.argv)?;
    let cwd = String::from_utf8(invocation.cwd.clone()?).ok()?;
    let (gids, group_names) = sys::groups_of(user);
    let run_as_for_sudoers = match (&parsed.user, &parsed.group) {
        (Some(target), _) => sudo_argv::numeric_id(target)
            .and_then(sys::user_by_uid)
            .map_or_else(|| target.clone(), |target| target.name),
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
    let setting = |name| crate::sudoers::setting(&environment.sudoers, &subject, name);
    let search = Search {
        secure_path: crate::sudoers::secure_path(&environment.sudoers, &subject),
        // sudo.ws is built with ignore_dot on by default (checked with `sudo -V`
        // on macOS, Ubuntu, Fedora and Arch).
        ignore_dot: setting("ignore_dot")
            .into_iter()
            .map(|value| value != crate::sudoers::Setting::Negated)
            .collect(),
        chroot: setting("runchroot")
            .iter()
            .any(|value| matches!(value, crate::sudoers::Setting::Value(root) if root != "*")),
        env_paths: invocation
            .env_paths
            .iter()
            .map(|path| String::from_utf8(path.clone()).ok())
            .collect(),
        flavors: Flavor::platform(),
    };
    let secure_path_set = search.secure_path.iter().all(Option::is_some);
    let target_shell = target_login_shell(&run_as_for_sudoers);
    let caller_shell = invocation
        .env_shell
        .clone()
        .or_else(|| Some(user.shell.clone()).filter(|s| !s.is_empty()));
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
    let mut described = sudo_argv::describe(&argv, parsed, &context);
    // sudoedit's editor runs as the caller, with the caller's environment.
    if !matches!(parsed.mode, sudo_argv::Mode::Edit(_))
        && !crate::sudoers::kept_variables(
            &environment.sudoers,
            &subject,
            described.command.resolved_path.as_deref().map(Path::new),
            &invocation.env,
            secure_path_set,
        )
        .is_empty()
    {
        described
            .command
            .warnings
            .push(crate::payload::Warning::new("user_environment"));
    }
    let decline = decline::decline(parsed, &described.command, &context);
    Some(Described {
        argv,
        cwd,
        described,
        decline,
    })
}

fn build_payload(
    invocation: &Invocation,
    environment: &Environment,
    user: &sys::Passwd,
    prepared: &Prepared,
    request: Described,
    session: Option<payload::Session>,
) -> Option<Payload> {
    let Described {
        argv,
        cwd,
        described,
        ..
    } = request;
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).ok()?;
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
        session,
    })
}

fn target_login_shell(run_as: &str) -> Option<String> {
    let entry = match run_as.strip_prefix('#') {
        Some(uid) => sys::user_by_uid(uid.parse().ok()?),
        None => sys::user_by_name(run_as),
    }?;
    Some(entry.shell).filter(|shell| !shell.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture_server::{self, Mode, vector_key};
    use crate::test_fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;

    struct Setup {
        dir: PathBuf,
        environment: Environment,
        user: String,
    }

    impl Drop for Setup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn setup() -> Setup {
        let uid = unsafe { libc::getuid() };
        let user = sys::user_by_uid(uid).unwrap().name;
        let dir = test_fs::private_dir();
        let state = dir.join("state");
        test_fs::create_dirs(&state.join("users"));
        test_fs::create_dirs(&state.join("keys").join(&user));
        let config = format!(
            "version = 1\nenabled = true\nsocket = \"{}\"\n",
            dir.join("s.sock").display()
        );
        test_fs::write(&state.join("users").join(format!("{user}.toml")), config);
        let key = vector_key("enrolled");
        let file = serde_json::json!({
            "version": 1, "keyId": key.key_id, "alg": "es256", "publicKey": crate::b64::encode(&key.spki),
            "label": "test", "securityLevel": "tee", "enrolledAt": "2026-10-30T12:00:00Z",
            "attestationSummary": { "packageName": "p", "signingCertDigest": "d", "devAttestation": true }
        });
        test_fs::write(
            &state
                .join("keys")
                .join(&user)
                .join(format!("{}.json", key.key_id)),
            file.to_string(),
        );
        let sudoers = dir.join("sudoers");
        test_fs::write(&sudoers, crate::install::sudoers_drop_in(&user));
        let environment = Environment {
            state_dir: state,
            policy: test_fs::policy(),
            sudoers,
            shells: PathBuf::from("/etc/shells"),
            chain_start: unsafe { libc::getppid() },
            window_override: None,
            grants_dir: dir.join("grants"),
            session: SessionSource::Fixed(None),
        };
        Setup {
            dir,
            environment,
            user,
        }
    }

    impl Setup {
        fn invocation(&self, argv: &[&str]) -> Invocation {
            Invocation {
                argv: argv.iter().map(|arg| arg.as_bytes().to_vec()).collect(),
                uid: unsafe { libc::getuid() },
                service: Some("sudo".into()),
                pam_user: Some(self.user.clone()),
                cwd: Some(self.dir.as_os_str().as_encoded_bytes().to_vec()),
                env_shell: None,
                env_paths: vec![b"/usr/bin:/bin".to_vec()],
                env: vec![("PYTHONPATH".into(), "/home/me/lib".into())],
            }
        }

        /// Runs one authentication against a fixture server in `mode`.
        fn run(&self, mode: Mode, invocation: &Invocation) -> (Outcome, fixture_server::Exchange) {
            let (decision, exchange) = self.run_decision(mode, invocation);
            (decision.outcome, exchange)
        }

        fn run_decision(
            &self,
            mode: Mode,
            invocation: &Invocation,
        ) -> (Decision, fixture_server::Exchange) {
            let path = self.dir.join("s.sock");
            let _ = std::fs::remove_file(&path);
            let listener = UnixListener::bind(&path).unwrap();
            let server = std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                fixture_server::handle(stream, mode)
            });
            let outcome = authenticate(invocation, &self.environment);
            // Wakes the accept when the module never connected; when it did,
            // this connection just sits in the backlog.
            drop(std::os::unix::net::UnixStream::connect(&path));
            (outcome, server.join().unwrap())
        }
    }

    #[test]
    fn approves_only_a_valid_signature() {
        let setup = setup();
        let (outcome, exchange) = setup.run(Mode::Approve, &setup.invocation(&["sudo", "id"]));
        assert_eq!(outcome, Outcome::Approved);
        assert_eq!(exchange.result.as_deref(), Some("approved"));
        let payload = exchange.payload.unwrap();
        assert_eq!(payload["user"], setup.user.as_str());
        assert_eq!(payload["command"]["argv"], serde_json::json!(["id"]));
        assert_eq!(
            payload["expiresAt"].as_i64().unwrap() - payload["issuedAt"].as_i64().unwrap(),
            100
        );
        let hello = exchange.hello.unwrap();
        assert_eq!(hello["type"], "hello");
        assert!(!hello["chain"].as_array().unwrap().is_empty());
    }

    #[test]
    fn deny_and_bad_signatures_fail_the_stack() {
        for (name, mode, result) in [
            ("deny", Mode::Deny, Some("denied")),
            ("badsig", Mode::BadSignature, Some("bad_signature")),
            ("wrongpl", Mode::WrongPayload, Some("bad_signature")),
            ("cancel", Mode::Cancel, None),
            ("close", Mode::Close, None),
        ] {
            let setup = setup();
            let (outcome, exchange) = setup.run(mode, &setup.invocation(&["sudo", "id"]));
            assert_eq!(outcome, Outcome::Fail, "{name}");
            assert_eq!(exchange.result.as_deref(), result, "{name}");
        }
    }

    #[test]
    fn expiry_fails_the_stack() {
        let mut setup = setup();
        setup.environment.window_override = Some(1);
        let (outcome, exchange) = setup.run(Mode::Expire, &setup.invocation(&["sudo", "id"]));
        assert_eq!(outcome, Outcome::Fail);
        assert_eq!(exchange.result.as_deref(), Some("expired"));
    }

    #[test]
    fn not_ours_is_ignored_unless_non_interactive() {
        for (name, mode) in [("notmine", Mode::NotMine), ("garbage", Mode::Garbage)] {
            let setup = setup();
            assert_eq!(
                setup.run(mode, &setup.invocation(&["sudo", "id"])).0,
                Outcome::Ignore,
                "{name}"
            );
            assert_eq!(
                setup.run(mode, &setup.invocation(&["sudo", "-n", "id"])).0,
                Outcome::Fail,
                "{name}"
            );
        }
        let setup = setup();
        assert_eq!(
            authenticate(&setup.invocation(&["sudo", "id"]), &setup.environment).outcome,
            Outcome::Ignore
        );
        assert_eq!(
            authenticate(&setup.invocation(&["sudo", "-n", "id"]), &setup.environment).outcome,
            Outcome::Fail
        );
    }

    #[test]
    fn argv_not_from_sudo_is_ignored() {
        for argv in [
            &["", "/tmp/evil", "-n", "/usr/bin/true"][..],
            &["/tmp/evil", "-n", "true"],
            &["sudo-rs", "-n", "true"],
            &[],
        ] {
            let setup = setup();
            assert_eq!(
                setup.run(Mode::Approve, &setup.invocation(argv)).0,
                Outcome::Ignore,
                "{argv:?}"
            );
        }
        let setup = setup();
        assert_eq!(
            setup
                .run(
                    Mode::Approve,
                    &setup.invocation(&["/usr/bin/sudoedit", "/etc/hosts"])
                )
                .0,
            Outcome::Approved
        );
    }

    /// Review 2, G6: where sudo is sudo-rs (Ubuntu 25.10+), sudo.ws is
    /// installed as `sudo.ws`. Ignoring that name sent `sudo.ws -n` on to the
    /// password modules, which a faillock config counts.
    #[test]
    fn sudo_ws_by_its_own_name_is_sudo() {
        let setup = setup();
        assert_eq!(
            setup
                .run(
                    Mode::Approve,
                    &setup.invocation(&["/usr/bin/sudo.ws", "id"])
                )
                .0,
            Outcome::Approved
        );
        assert_eq!(
            setup
                .run(Mode::NotMine, &setup.invocation(&["sudo.ws", "-n", "id"]))
                .0,
            Outcome::Fail
        );
    }

    #[test]
    fn unconfigured_users_are_always_ignored() {
        let setup = setup();
        std::fs::remove_file(
            setup
                .environment
                .state_dir
                .join("users")
                .join(format!("{}.toml", setup.user)),
        )
        .unwrap();
        assert_eq!(
            authenticate(&setup.invocation(&["sudo", "-n", "id"]), &setup.environment).outcome,
            Outcome::Ignore
        );
    }

    #[test]
    fn unsafe_or_foreign_contexts_never_reach_the_socket() {
        let setup = setup();
        let config = setup
            .environment
            .state_dir
            .join("users")
            .join(format!("{}.toml", setup.user));
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o666)).unwrap();
        // No server is listening: reaching the socket would also be IGNORE, so
        // check -n, which only fails when the module got as far as deciding.
        assert_eq!(
            authenticate(&setup.invocation(&["sudo", "id"]), &setup.environment).outcome,
            Outcome::Ignore
        );
        assert_eq!(
            authenticate(&setup.invocation(&["sudo", "-n", "id"]), &setup.environment).outcome,
            Outcome::Fail
        );
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644)).unwrap();

        let mut invocation = setup.invocation(&["sudo", "id"]);
        invocation.service = Some("login".into());
        assert_eq!(setup.run(Mode::Approve, &invocation).0, Outcome::Ignore);
        let mut invocation = setup.invocation(&["sudo", "id"]);
        invocation.pam_user = Some("root".into());
        assert_eq!(setup.run(Mode::Approve, &invocation).0, Outcome::Ignore);
        let keys = setup.environment.state_dir.join("keys").join(&setup.user);
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            setup
                .run(Mode::Approve, &setup.invocation(&["sudo", "id"]))
                .0,
            Outcome::Ignore
        );
    }

    /// Review 2, G5: an install written to the original three-line drop-in
    /// verified as "Ready", and on macOS root inherited the caller's HOME,
    /// editors and PATH. Without every setting the payload relies on, the
    /// module stays out of the way, so the live `sudo -n true` test fails.
    #[test]
    fn sudoers_without_the_environment_settings_never_reach_the_device() {
        let mut setup = setup();
        let sudoers = setup.dir.join("old-sudoers");
        let user = &setup.user;
        test_fs::write(
            &sudoers,
            format!(
                "Defaults:{user} noninteractive_auth\nDefaults:{user} !requiretty\nDefaults:{user} timestamp_timeout=0\n"
            ),
        );
        setup.environment.sudoers = sudoers;
        assert_eq!(
            setup
                .run(Mode::Approve, &setup.invocation(&["sudo", "id"]))
                .0,
            Outcome::Ignore
        );
        assert_eq!(
            setup
                .run(Mode::Approve, &setup.invocation(&["sudo", "-n", "id"]))
                .0,
            Outcome::Fail
        );
    }

    /// The layout an external installer such as nix-darwin writes: the six
    /// contract lines in a file of their own under an included directory.
    #[test]
    fn contract_lines_in_an_included_file_are_enough() {
        let mut setup = setup();
        let root = setup.dir.join("etc");
        test_fs::create_dirs(&root.join("sudoers.d"));
        test_fs::write(
            &root.join("sudoers"),
            format!(
                "Defaults env_reset\nroot ALL=(ALL) ALL\n#includedir {}\n",
                root.join("sudoers.d").display()
            ),
        );
        let user = &setup.user;
        test_fs::write(
            &root.join("sudoers.d").join("10-nix-darwin-extra-config"),
            format!(
                "Defaults:{user} noninteractive_auth\n\
                 Defaults:{user} !requiretty\n\
                 Defaults:{user} timestamp_timeout=0\n\
                 Defaults:{user} always_set_home\n\
                 Defaults:{user} !env_editor\n\
                 Defaults:{user} env_keep -= \"HOME EDITOR VISUAL SUDO_EDITOR PATH KDEDIR QTDIR\"\n"
            ),
        );
        setup.environment.sudoers = root.join("sudoers");
        assert_eq!(
            setup
                .run(Mode::Approve, &setup.invocation(&["sudo", "id"]))
                .0,
            Outcome::Approved
        );
    }

    /// Review 2, G4: an admin's `env_keep += "PYTHONPATH"` let
    /// `PYTHONPATH=~/lib sudo python3 -c pass` run the user's sitecustomize
    /// as root with nothing in red.
    #[test]
    fn variables_sudoers_keeps_are_warned() {
        let has_warning = |extra: &str| {
            let setup = setup();
            let user = &setup.user;
            test_fs::write(
                &setup.environment.sudoers,
                format!("{extra}\n{}", crate::install::sudoers_drop_in(user)),
            );
            let (outcome, exchange) =
                setup.run(Mode::Approve, &setup.invocation(&["sudo", "/usr/bin/id"]));
            assert_eq!(outcome, Outcome::Approved);
            exchange.payload.unwrap()["command"]["warnings"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!({ "code": "user_environment" }))
        };
        assert_eq!(
            [
                has_warning("Defaults env_keep += \"PYTHONPATH\""),
                has_warning("Defaults env_reset"),
            ],
            [true, false]
        );
    }

    #[test]
    fn unrepresentable_or_huge_requests_fail_with_a_result() {
        let setup = setup();
        let mut invocation = setup.invocation(&["sudo", "id"]);
        invocation.argv.push(vec![0xff, 0xfe]);
        let (outcome, exchange) = setup.run(Mode::Approve, &invocation);
        assert_eq!(
            (outcome, exchange.result.as_deref()),
            (Outcome::Fail, Some("invalid_encoding"))
        );

        let big = "x".repeat(MAX_PAYLOAD_BYTES);
        let (outcome, exchange) =
            setup.run(Mode::Approve, &setup.invocation(&["sudo", "echo", &big]));
        assert_eq!(
            (outcome, exchange.result.as_deref()),
            (Outcome::Fail, Some("too_large"))
        );
    }

    #[test]
    fn deny_and_expiry_tell_the_agent_on_stderr() {
        let setup = setup();
        let (decision, _) = setup.run_decision(Mode::Deny, &setup.invocation(&["sudo", "id"]));
        assert_eq!(decision, fail_with(decline::DENIED));
        let mut setup = setup;
        setup.environment.window_override = Some(1);
        let (decision, _) = setup.run_decision(Mode::Expire, &setup.invocation(&["sudo", "id"]));
        assert_eq!(decision, fail_with(decline::EXPIRED));
        let (decision, _) = setup.run_decision(Mode::Close, &setup.invocation(&["sudo", "id"]));
        assert_eq!(decision, Outcome::Fail.into());
    }

    #[test]
    fn declines_never_reach_the_server_and_only_apply_to_t3_sudo() {
        let setup = setup();
        let (decision, exchange) =
            setup.run_decision(Mode::Approve, &setup.invocation(&["sudo", "python3", "-"]));
        assert_eq!(decision.outcome, Outcome::Fail);
        assert!(decision.notice.unwrap().starts_with(decline::PREFIX));
        assert_eq!((exchange.payload, exchange.result), (None, None));
        // Someone's own sudo keeps its password prompt.
        let (decision, _) =
            setup.run_decision(Mode::NotMine, &setup.invocation(&["sudo", "python3", "-"]));
        assert_eq!(decision, Outcome::Ignore.into());
        let (decision, exchange) = setup.run_decision(
            Mode::Approve,
            &setup.invocation(&["sudo", "sh", "-c", "echo x > /etc/f"]),
        );
        assert_eq!(decision, Outcome::Approved.into());
        assert_eq!(
            exchange.payload.unwrap()["command"]["warnings"],
            serde_json::json!([])
        );
    }

    /// Review M1: `ownSudo` is the server's word, and it switched off every
    /// decline, so an agent could get `sudo -S` or a stdin-fed interpreter
    /// in front of the phone.
    #[test]
    fn the_servers_word_only_lifts_the_probe_decline() {
        let setup = setup();
        for argv in [&["sudo", "python3", "-"][..], &["sudo", "-S", "id"]] {
            let (decision, exchange) =
                setup.run_decision(Mode::ApproveOwn, &setup.invocation(argv));
            assert_eq!(decision.outcome, Outcome::Fail, "{argv:?}");
            assert!(decision.notice.is_some(), "{argv:?}");
            assert_eq!(exchange.payload, None, "{argv:?}");
        }
    }

    /// A process standing in for the tool call's shell.
    struct Leader {
        child: std::process::Child,
        anchor: Anchor,
    }

    impl Leader {
        fn spawn() -> Self {
            let child = std::process::Command::new("/bin/sleep")
                .arg("60")
                .spawn()
                .unwrap();
            let pid = child.id() as i32;
            let anchor = Anchor {
                session: pid,
                leader_start: sys::leader_facts(pid).unwrap().start,
            };
            Self { child, anchor }
        }

        /// The session as if this leader were `zsh -lc <command>`.
        fn running(&self, command: &str) -> SessionSource {
            SessionSource::Fixed(Some((
                self.anchor,
                vec!["/bin/zsh".into(), "-lc".into(), command.into()],
            )))
        }
    }

    impl Drop for Leader {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl Setup {
        fn later(&self, argv: &[&str]) -> Decision {
            authenticate(&self.invocation(argv), &self.environment)
        }

        /// A sudo from the same place in another session.
        fn later_in(&self, session: SessionSource, argv: &[&str]) -> Decision {
            let environment = Environment {
                session,
                ..self.environment.clone()
            };
            authenticate(&self.invocation(argv), &environment)
        }
    }

    /// T3's live test is `sudo -n true` from the server itself; it must reach
    /// the phone, and it never covers the server's later sudo.
    #[test]
    fn the_servers_own_probe_reaches_the_phone_ungrouped() {
        let leader = Leader::spawn();
        let mut setup = setup();
        setup.environment.session = leader.running("sudo -n true && sudo -n id");
        let invocation = setup.invocation(&["sudo", "-n", "true"]);
        let (decision, exchange) = setup.run_decision(Mode::ApproveOwn, &invocation);
        assert_eq!(decision, Outcome::Approved.into());
        assert!(exchange.payload.unwrap().get("session").is_none());
        assert!(!setup.environment.grants_dir.exists());
        let (decision, _) = setup.run_decision(Mode::Approve, &invocation);
        assert_eq!(decision.outcome, Outcome::Fail);
        assert!(decision.notice.unwrap().contains("approve nothing"));
    }

    const COMMAND: &str = "sudo id && sudo -n ls / && sudo -n whoami && sudo -n python3 - \
         && sudo -n /usr/local/lib/t3-elevation/t3-elevation revoke";

    #[test]
    fn one_approval_covers_the_other_sudos_written_in_the_command() {
        let mut leader = Leader::spawn();
        let mut setup = setup();
        setup.environment.session = leader.running(COMMAND);
        let (outcome, exchange) = setup.run(Mode::Approve, &setup.invocation(&["sudo", "id"]));
        assert_eq!(outcome, Outcome::Approved);
        // A declined call and the helper (here unresolved) aren't covered.
        assert_eq!(
            exchange.payload.unwrap()["session"],
            serde_json::json!({
                "id": leader.anchor.session,
                "leaderStart": leader.anchor.leader_start,
                "maxUses": 2,
                "command": COMMAND,
            })
        );
        // No server is listening now: only the grant can approve.
        assert_eq!(
            setup.later(&["sudo", "-n", "ls", "/"]),
            Outcome::Approved.into()
        );
        assert_eq!(
            setup.later(&["sudo", "-n", "ls", "/"]),
            Outcome::Fail.into(),
            "each call once"
        );
        assert_eq!(setup.later(&["sudo", "-n", "id"]), Outcome::Fail.into());
        // Declines still apply inside an approved command.
        assert!(
            setup
                .later(&["sudo", "-n", "python3", "-"])
                .notice
                .is_some()
        );
        assert_eq!(
            setup.later(&["sudo", "-n", "-u", "nobody", "whoami"]),
            Outcome::Fail.into()
        );
        // Another session, or the leader gone, isn't covered.
        let other = Leader::spawn();
        assert_eq!(
            setup.later_in(other.running(COMMAND), &["sudo", "-n", "whoami"]),
            Outcome::Fail.into()
        );
        leader.child.kill().unwrap();
        leader.child.wait().unwrap();
        assert_eq!(setup.later(&["sudo", "-n", "whoami"]), Outcome::Fail.into());
    }

    /// zsh and bash exec the string's last command, so its sudo leads the
    /// session and can still be covered.
    #[test]
    fn the_exec_d_last_sudo_is_covered() {
        let leader = Leader::spawn();
        let mut setup = setup();
        setup.environment.session = leader.running("sudo id && sudo -n whoami");
        let (outcome, _) = setup.run(Mode::Approve, &setup.invocation(&["sudo", "id"]));
        assert_eq!(outcome, Outcome::Approved);
        let exec_d = SessionSource::Leading(leader.anchor);
        assert_eq!(
            setup.later_in(exec_d, &["sudo", "-n", "whoami"]),
            Outcome::Approved.into()
        );
        assert!(
            !setup
                .environment
                .grants_dir
                .join(format!(
                    "{}-{}.json",
                    unsafe { libc::getuid() },
                    leader.anchor.session
                ))
                .exists()
        );
    }

    /// Review H1: a grant covered any sudo the session ran, so a startup
    /// file, a script, or text the command only echoes could run another
    /// program as root on the first approval.
    #[test]
    fn later_sudos_outside_the_approved_command_ask_the_phone() {
        let approve = |command: &str, first: &[&str]| {
            let leader = Leader::spawn();
            let mut setup = setup();
            setup.environment.session = leader.running(command);
            let (outcome, exchange) = setup.run(Mode::Approve, &setup.invocation(first));
            assert_eq!(outcome, Outcome::Approved);
            (leader, setup, exchange.payload.unwrap())
        };
        // Not written in the command (a startup file's, a script's).
        let (_leader, setup, _) = approve("sudo id && sudo -n whoami", &["sudo", "id"]);
        assert_eq!(
            setup.later(&["sudo", "-n", "ls", "/"]),
            Outcome::Fail.into()
        );
        // A first sudo that isn't the command's starts nothing.
        let (_leader, setup, payload) = approve("sudo id && sudo -n whoami", &["sudo", "ls", "/"]);
        assert!(payload.get("session").is_none());
        assert_eq!(setup.later(&["sudo", "-n", "whoami"]), Outcome::Fail.into());
        // Only text: echoed, or a heredoc body.
        let (_leader, setup, payload) = approve(
            "echo sudo -n ls / && sudo id\ncat <<EOF\nsudo -n whoami\nEOF",
            &["sudo", "id"],
        );
        assert!(payload.get("session").is_none());
        assert_eq!(
            setup.later(&["sudo", "-n", "ls", "/"]),
            Outcome::Fail.into()
        );
        // Written for another target.
        let (_leader, setup, _) = approve(
            "sudo id && sudo -n -u nobody whoami && sudo -n ls /",
            &["sudo", "id"],
        );
        assert_eq!(setup.later(&["sudo", "-n", "whoami"]), Outcome::Fail.into());
        // The leader now runs something else (it exec'd a script).
        let (leader, mut setup, _) = approve("sudo id && sudo -n whoami", &["sudo", "id"]);
        setup.environment.session = SessionSource::Fixed(Some((
            leader.anchor,
            vec!["/bin/bash".into(), "./install.sh".into()],
        )));
        assert_eq!(setup.later(&["sudo", "-n", "whoami"]), Outcome::Fail.into());
        // Unreadable strings cover nothing.
        let (_leader, _, payload) = approve("sudo id && sudo -n whoami $(true)", &["sudo", "id"]);
        assert!(payload.get("session").is_none());
    }

    /// Review H1: a program the shell exec'd leads the session too, and its
    /// sudo used the grant without any check of what the session was.
    #[test]
    fn a_leading_sudo_that_isnt_the_commands_last_asks_the_phone() {
        let leader = Leader::spawn();
        let mut setup = setup();
        setup.environment.session = leader.running("sudo id && sudo -n ls / && ./x");
        let (outcome, _) = setup.run(Mode::Approve, &setup.invocation(&["sudo", "id"]));
        assert_eq!(outcome, Outcome::Approved);
        let exec_d = SessionSource::Leading(leader.anchor);
        assert_eq!(
            setup.later_in(exec_d, &["sudo", "-n", "ls", "/"]),
            Outcome::Fail.into()
        );
        assert_eq!(
            setup.later(&["sudo", "-n", "ls", "/"]),
            Outcome::Approved.into()
        );
    }

    /// What the phone didn't show isn't covered: a call with a warning of
    /// its own asks again.
    #[test]
    fn calls_with_their_own_warnings_ask_the_phone() {
        let leader = Leader::spawn();
        let mut setup = setup();
        test_fs::write(&setup.dir.join("f"), "x");
        setup.environment.session = leader.running("sudo id && sudo -n cat ./f");
        let (outcome, exchange) = setup.run(Mode::Approve, &setup.invocation(&["sudo", "id"]));
        assert_eq!(outcome, Outcome::Approved);
        assert!(exchange.payload.unwrap().get("session").is_none());
        assert_eq!(
            setup.later(&["sudo", "-n", "cat", "./f"]),
            Outcome::Fail.into()
        );
    }

    #[test]
    fn a_command_too_long_to_sign_asks_per_sudo() {
        let leader = Leader::spawn();
        let mut setup = setup();
        let command = format!(
            "sudo id && sudo -n whoami # {}",
            "x".repeat(MAX_PAYLOAD_BYTES)
        );
        setup.environment.session = leader.running(&command);
        let (outcome, exchange) = setup.run(Mode::Approve, &setup.invocation(&["sudo", "id"]));
        assert_eq!(outcome, Outcome::Approved);
        assert!(exchange.payload.unwrap().get("session").is_none());
        assert_eq!(setup.later(&["sudo", "-n", "whoami"]), Outcome::Fail.into());
    }

    /// A sudo leading its own session asks the phone and never starts a grant.
    #[test]
    fn a_sudo_leading_its_session_starts_no_grant() {
        let leader = Leader::spawn();
        let mut setup = setup();
        setup.environment.session = SessionSource::Leading(leader.anchor);
        let (outcome, exchange) = setup.run(Mode::Approve, &setup.invocation(&["sudo", "id"]));
        assert_eq!(outcome, Outcome::Approved);
        assert!(exchange.payload.unwrap().get("session").is_none());
        assert!(!setup.environment.grants_dir.exists());
    }

    #[test]
    fn a_session_max_of_zero_asks_for_every_sudo() {
        let leader = Leader::spawn();
        let mut setup = setup();
        let config = setup
            .environment
            .state_dir
            .join("users")
            .join(format!("{}.toml", setup.user));
        test_fs::write(
            &config,
            format!(
                "version = 1\nenabled = true\nsocket = \"{}\"\nsession_max_uses = 0\n",
                setup.dir.join("s.sock").display()
            ),
        );
        setup.environment.session = leader.running("sudo id && sudo -n id");
        let (outcome, exchange) = setup.run(Mode::Approve, &setup.invocation(&["sudo", "id"]));
        assert_eq!(outcome, Outcome::Approved);
        assert!(exchange.payload.unwrap().get("session").is_none());
        assert_eq!(setup.later(&["sudo", "-n", "id"]), Outcome::Fail.into());
    }
}
