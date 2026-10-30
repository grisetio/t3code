//! `t3-elevation`: the root-side helper. Every command prints one JSON object
//! on stdout (docs/internals/device-approval.md, "Helper CLI").

use serde_json::{Value, json};
use std::io::{IsTerminal as _, Read as _, Write as _};
use t3_elevation::attestation::{self, Enrollment, Pins};
use t3_elevation::install::{self, KeyError, Layout, Sources};
use t3_elevation::{HELPER_VERSION, PROTOCOL_VERSION, b64, config, keys, sys};

const MAX_ENROLLMENT_BYTES: u64 = 256 * 1024;

struct Failure {
    code: &'static str,
    message: String,
    extra: Option<Value>,
}

fn fail(code: &'static str, message: impl Into<String>) -> Failure {
    Failure {
        code,
        message: message.into(),
        extra: None,
    }
}

type Outcome = Result<Value, Failure>;

/// Options as `--name value` pairs or bare flags; each at most once,
/// nothing unknown, nothing positional.
struct Options {
    values: Vec<(&'static str, Option<String>)>,
}

impl Options {
    fn parse(
        args: &[String],
        with_value: &[&'static str],
        flags: &[&'static str],
    ) -> Result<Self, Failure> {
        let mut values: Vec<(&'static str, Option<String>)> = Vec::new();
        let mut rest = args.iter();
        while let Some(arg) = rest.next() {
            let name = if let Some(name) = with_value.iter().find(|name| arg == *name) {
                let value = rest
                    .next()
                    .ok_or_else(|| fail("usage", format!("{arg} needs a value")))?;
                values.push((name, Some(value.clone())));
                *name
            } else if let Some(name) = flags.iter().find(|name| arg == *name) {
                values.push((name, None));
                *name
            } else {
                return Err(fail("usage", format!("unexpected argument {arg:?}")));
            };
            if values.iter().filter(|(seen, _)| *seen == name).count() > 1 {
                return Err(fail("usage", format!("{name} given twice")));
            }
        }
        Ok(Self { values })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(seen, _)| *seen == name)
            .and_then(|(_, value)| value.as_deref())
    }

    fn require(&self, name: &str) -> Result<&str, Failure> {
        self.get(name)
            .ok_or_else(|| fail("usage", format!("{name} is required")))
    }

    fn flag(&self, name: &str) -> bool {
        self.values.iter().any(|(seen, _)| *seen == name)
    }
}

fn require_root() -> Result<(), Failure> {
    if sys::is_root() {
        Ok(())
    } else {
        Err(fail(
            "not_root",
            "this command needs root; run it with sudo",
        ))
    }
}

fn user(options: &Options) -> Result<String, Failure> {
    known_user(options.require("--user")?)
}

fn known_user(user: &str) -> Result<String, Failure> {
    if !config::is_safe_user_name(user) || sys::user_by_name(user).is_none() {
        return Err(fail(
            "unknown_user",
            format!("{user:?} isn't a user on this machine"),
        ));
    }
    Ok(user.to_string())
}

fn read_enrollment(source: &str) -> Result<Enrollment, Failure> {
    let mut bytes = Vec::new();
    let read = if source == "-" {
        std::io::stdin()
            .take(MAX_ENROLLMENT_BYTES + 1)
            .read_to_end(&mut bytes)
    } else {
        std::fs::File::open(source)
            .and_then(|file| file.take(MAX_ENROLLMENT_BYTES + 1).read_to_end(&mut bytes))
    };
    read.map_err(|error| {
        fail(
            "invalid_enrollment",
            format!("can't read the enrollment: {error}"),
        )
    })?;
    if bytes.len() as u64 > MAX_ENROLLMENT_BYTES {
        return Err(fail("invalid_enrollment", "the enrollment is too large"));
    }
    serde_json::from_slice(&bytes).map_err(|error| {
        fail(
            "invalid_enrollment",
            format!("the enrollment isn't valid: {error}"),
        )
    })
}

fn verify_enrollment(
    enrollment: &Enrollment,
    allow_dev: bool,
) -> Result<(Vec<u8>, attestation::Verified), Failure> {
    let verified = attestation::verify(enrollment, sys::now(), &Pins::release(), allow_dev)
        .map_err(|rejected| fail(rejected.code, rejected.message))?;
    let spki = b64::decode(&enrollment.public_key)
        .ok_or_else(|| fail("invalid_enrollment", "publicKey isn't base64url"))?;
    Ok((spki, verified))
}

fn key_error(error: KeyError) -> Failure {
    match error {
        KeyError::NotInstalled => fail(
            "not_installed",
            "the keys directory is missing or not root-owned; run install first",
        ),
        KeyError::AlreadyEnrolled => fail("already_enrolled", "this key is already enrolled"),
        KeyError::UnknownKey => fail("unknown_key", "no enrolled key has that keyId"),
        KeyError::Io(message) => fail("io", message),
    }
}

fn key_result(key_id: &str, spki: &[u8], label: &str, verified: &attestation::Verified) -> Value {
    json!({
        "keyId": key_id,
        "label": label,
        "comparisonCode": keys::comparison_code(spki),
        "securityLevel": verified.security_level,
        "devAttestation": verified.dev_attestation,
    })
}

/// A person at a terminal confirms the device by its comparison code. T3
/// runs install without a terminal and shows the code in its own UI.
fn confirm(label: &str, code: &str) -> Result<(), Failure> {
    if !std::io::stdin().is_terminal() {
        return Ok(());
    }
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|error| fail("io", format!("can't open the terminal: {error}")))?;
    let _ = write!(
        tty,
        "Enroll {}, comparison code {code}? It must match the phone. [y/N] ",
        escape(label)
    );
    let mut answer = [0u8; 64];
    let read = tty.read(&mut answer).unwrap_or(0);
    match answer[..read].trim_ascii() {
        b"y" | b"Y" | b"yes" => Ok(()),
        _ => Err(fail("cancelled", "not confirmed")),
    }
}

fn escape(text: &str) -> String {
    t3_elevation::escape::display(text)
}

/// The module and helper binaries this helper was shipped with.
fn bundled() -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let exe = std::env::current_exe().ok();
    let module = exe
        .as_ref()
        .and_then(|exe| exe.parent().map(|dir| dir.join("pam_t3_elevation.so")))
        .and_then(|path| std::fs::read(path).ok());
    let helper = exe.and_then(|exe| std::fs::read(exe).ok());
    (module, helper)
}

fn status(args: &[String]) -> Outcome {
    let options = Options::parse(args, &["--user"], &[])?;
    let user = user(&options)?;
    let (module, helper) = bundled();
    let layout = Layout::system(&user);
    let status = install::status(
        &layout,
        &user,
        &Sources {
            module: module.as_deref(),
            helper: helper.as_deref(),
        },
    );
    serde_json::to_value(status).map_err(|error| fail("io", error.to_string()))
}

fn install(args: &[String]) -> Outcome {
    let options = Options::parse(
        args,
        &["--user", "--socket", "--key", "--window"],
        &["--allow-dev-attestation"],
    )?;
    require_root()?;
    let user = user(&options)?;
    let socket = options.require("--socket")?;
    if !socket.starts_with('/')
        || socket.len() > t3_elevation::MAX_SOCKET_PATH_BYTES
        || socket.contains(['\n', '"', '\\'])
    {
        return Err(fail(
            "usage",
            "--socket must be an absolute path of at most 100 bytes",
        ));
    }
    let window = match options.get("--window") {
        Some(text) => text
            .parse::<i64>()
            .map_err(|_| fail("usage", "--window must be a number of seconds"))?,
        None => config::DEFAULT_WINDOW_SECONDS,
    }
    .clamp(config::MIN_WINDOW_SECONDS, config::MAX_WINDOW_SECONDS);
    let layout = Layout::system(&user);
    if layout.selinux_confined {
        return Err(fail(
            "selinux_confined",
            "device approval isn't supported for confined SELinux users",
        ));
    }
    // Verify the device before changing anything.
    let enrollment = read_enrollment(options.require("--key")?)?;
    let (spki, verified) = verify_enrollment(&enrollment, options.flag("--allow-dev-attestation"))?;
    let (module, helper) = bundled();
    let plan = install::plan_install(
        &layout,
        &user,
        socket,
        window,
        &Sources {
            module: module.as_deref(),
            helper: helper.as_deref(),
        },
    );
    if !plan.blocked.is_empty() {
        let mut failure = fail(
            "blocked",
            "some files can't be changed safely; nothing was changed",
        );
        failure.extra = Some(json!({ "blocked": plan.blocked }));
        return Err(failure);
    }
    confirm(&enrollment.label, &keys::comparison_code(&spki))?;
    let changes = install::apply(&layout, &user, &plan, sys::now())
        .map_err(|message| fail("install_failed", message))?;
    let (key_id, bytes) = install::key_file_bytes(&spki, &enrollment.label, &verified, sys::now());
    match install::write_key(&layout, &user, &key_id, &bytes) {
        Ok(()) | Err(KeyError::AlreadyEnrolled) => {}
        Err(error) => return Err(key_error(error)),
    }
    Ok(json!({
        "ok": true,
        "changes": changes.iter().map(|change| json!({ "path": change.path, "action": change.action })).collect::<Vec<_>>(),
        "alreadyPresent": plan.satisfied,
        "key": key_result(&key_id, &spki, &enrollment.label, &verified),
    }))
}

fn enroll(args: &[String]) -> Outcome {
    let command = t3_elevation::enroll::parse_options(args).ok_or_else(|| {
        fail("usage", "usage: t3-elevation enroll --user U --label L --public-key K --challenge C [--allow-dev-attestation]")
    })?;
    require_root()?;
    let user = known_user(&command.user)?;
    let enrollment = read_enrollment("-")?;
    // The approval showed these argv values; the device must be that one.
    if enrollment.label != command.label
        || enrollment.public_key != command.public_key
        || enrollment.challenge != command.challenge
    {
        return Err(fail(
            "mismatch",
            "the enrollment doesn't match the approved command",
        ));
    }
    let (spki, verified) = verify_enrollment(&enrollment, command.allow_dev_attestation)?;
    let layout = Layout::system(&user);
    let (key_id, bytes) = install::key_file_bytes(&spki, &enrollment.label, &verified, sys::now());
    install::write_key(&layout, &user, &key_id, &bytes).map_err(key_error)?;
    Ok(json!({ "ok": true, "key": key_result(&key_id, &spki, &enrollment.label, &verified) }))
}

fn revoke(args: &[String]) -> Outcome {
    let options = Options::parse(args, &["--user", "--key-id"], &["--all"])?;
    if options.get("--key-id").is_some() == options.flag("--all") {
        return Err(fail("usage", "give exactly one of --key-id or --all"));
    }
    require_root()?;
    let user = user(&options)?;
    let removed = install::revoke(&Layout::system(&user), &user, options.get("--key-id"))
        .map_err(key_error)?;
    Ok(json!({ "ok": true, "revoked": removed }))
}

fn uninstall(args: &[String]) -> Outcome {
    let options = Options::parse(args, &["--user"], &[])?;
    require_root()?;
    let user = user(&options)?;
    let result = install::uninstall(&Layout::system(&user), &user)
        .map_err(|message| fail("not_installed", message))?;
    Ok(
        json!({ "ok": true, "restored": result.restored, "removed": result.removed, "kept": result.kept }),
    )
}

fn main() {
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.into_string())
        .collect::<Result<_, _>>()
        .unwrap_or_default();
    let (command, rest) = args
        .split_first()
        .map_or(("", &[][..]), |(command, rest)| (command.as_str(), rest));
    let outcome = match command {
        "version" if rest.is_empty() => {
            Ok(json!({ "ok": true, "protocol": PROTOCOL_VERSION, "version": HELPER_VERSION }))
        }
        "status" => status(rest),
        "install" => install(rest),
        "enroll" => enroll(rest),
        "revoke" => revoke(rest),
        "uninstall" => uninstall(rest),
        _ => Err(fail(
            "usage",
            "usage: t3-elevation version|status|install|enroll|revoke|uninstall ...",
        )),
    };
    let (value, code) = match outcome {
        Ok(value) => (value, 0),
        Err(failure) => {
            let mut value = json!({ "ok": false, "error": { "code": failure.code, "message": failure.message } });
            if let (Some(Value::Object(extra)), Some(object)) =
                (failure.extra, value.as_object_mut())
            {
                object.extend(extra);
            }
            (value, 1)
        }
    };
    let mut stdout = std::io::stdout().lock();
    let _ = serde_json::to_writer(&mut stdout, &value);
    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();
    std::process::exit(code);
}
