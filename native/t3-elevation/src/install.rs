//! Installed state (spec §7, §7.1): plan, apply, verify, and revert the PAM,
//! sudoers, config and key-directory changes. Install only writes what is
//! missing and writable; everything it writes is recorded with a backup in
//! `installed-by-t3.json` so uninstall can restore files byte for byte.

use crate::config::{self, UserConfig};
use crate::rootsafe::{self, Policy};
use crate::{MODULE_INSTALL_PATH, PROTOCOL_MARKER, keys};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Linux,
    Macos,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(target_os = "macos") { Self::Macos } else { Self::Linux }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Macos => "macos",
        }
    }
}

/// Where install looks and writes. Production uses `/`; tests use a
/// temporary root with their own uid as the trusted owner.
#[derive(Clone, Debug)]
pub struct Layout {
    pub root: PathBuf,
    pub policy: Policy,
    pub platform: Platform,
    pub chown_root: bool,
    pub visudo: Option<PathBuf>,
    /// Whether SELinux maps the user to a confined SELinux user.
    pub selinux_confined: bool,
}

impl Layout {
    pub fn system(user: &str) -> Self {
        let visudo = ["/usr/sbin/visudo", "/usr/bin/visudo", "/run/current-system/sw/bin/visudo"]
            .iter()
            .map(PathBuf::from)
            .find(|path| path.exists());
        Self {
            root: PathBuf::from("/"),
            policy: Policy::root(),
            platform: Platform::current(),
            chown_root: true,
            visudo,
            selinux_confined: selinux_confined(Path::new("/"), user),
        }
    }

    pub fn path(&self, absolute: &str) -> PathBuf {
        self.root.join(absolute.trim_start_matches('/'))
    }

    fn state(&self, relative: &str) -> String {
        format!("{}/{relative}", crate::STATE_DIR)
    }
}

pub const SUDOERS_DROP_IN: &str = "/etc/sudoers.d/t3-elevation";
pub const MANIFEST: &str = "/etc/t3-elevation/installed-by-t3.json";
const BACKUP_DIR: &str = "/etc/t3-elevation/backup";

pub fn linux_pam_line(module: &str) -> String {
    format!("auth [success=done ignore=ignore default=die] {module}")
}

pub fn macos_pam_lines(module: &str) -> [String; 2] {
    [format!("auth sufficient {module}"), format!("auth requisite {module} mode=gate")]
}

pub fn sudoers_drop_in(user: &str) -> String {
    format!(
        "# Written by t3-elevation for device approval; `t3-elevation uninstall` removes it.\n\
         Defaults:{user} noninteractive_auth\n\
         Defaults:{user} !requiretty\n\
         Defaults:{user} timestamp_timeout=0\n"
    )
}

// ---------------------------------------------------------------------------
// PAM files

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PamRule {
    pub line: usize,
    pub kind: String,
    pub control: String,
    pub module: String,
    pub args: Vec<String>,
}

pub fn pam_rules(text: &str) -> Vec<PamRule> {
    let mut rules = Vec::new();
    for (line, raw) in text.lines().enumerate() {
        let content = raw.split('#').next().unwrap_or_default().trim();
        if content.is_empty() {
            continue;
        }
        let (kind, rest) = content.split_once(char::is_whitespace).unwrap_or((content, ""));
        let rest = rest.trim_start();
        if kind == "@include" {
            rules.push(PamRule { line, kind: kind.into(), control: String::new(), module: rest.trim().into(), args: vec![] });
            continue;
        }
        let (control, rest) = if rest.starts_with('[') {
            match rest.find(']') {
                Some(end) => (rest[..=end].to_string(), rest[end + 1..].trim_start()),
                None => (rest.to_string(), ""),
            }
        } else {
            let (control, rest) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
            (control.to_string(), rest.trim_start())
        };
        let mut words = rest.split_whitespace();
        let module = words.next().unwrap_or_default().to_string();
        rules.push(PamRule { line, kind: kind.into(), control, module, args: words.map(str::to_string).collect() });
    }
    rules
}

/// Rules that take part in authentication, in order.
fn auth_rules(text: &str) -> Vec<PamRule> {
    pam_rules(text)
        .into_iter()
        .filter(|rule| matches!(rule.kind.as_str(), "auth" | "-auth" | "@include"))
        .collect()
}

fn is_t3_module(module: &str) -> bool {
    module.starts_with('/') && module.ends_with("/pam_t3_elevation.so")
}

fn is_bracket_line(rule: &PamRule) -> bool {
    let inner = rule.control.trim_start_matches('[').trim_end_matches(']');
    let mut tokens: Vec<&str> = inner.split_whitespace().collect();
    tokens.sort_unstable();
    rule.kind == "auth" && tokens == ["default=die", "ignore=ignore", "success=done"] && is_t3_module(&rule.module)
}

/// The module path when the first auth rule is the Linux bracket line.
pub fn linux_pam_ok(text: &str) -> Option<String> {
    let first = auth_rules(text).into_iter().next()?;
    is_bracket_line(&first).then_some(first.module)
}

/// The module path when sudo_local begins with the two-line gate.
pub fn macos_pam_ok(text: &str) -> Option<String> {
    let rules = auth_rules(text);
    let (first, second) = (rules.first()?, rules.get(1)?);
    let ok = first.kind == "auth"
        && first.control == "sufficient"
        && is_t3_module(&first.module)
        && second.kind == "auth"
        && second.control == "requisite"
        && second.module == first.module
        && second.args == ["mode=gate"];
    ok.then(|| first.module.clone())
}

fn mentions_t3(text: &str) -> bool {
    pam_rules(text).iter().any(|rule| rule.module.ends_with("pam_t3_elevation.so"))
}

pub fn includes_service(text: &str, service: &str) -> bool {
    pam_rules(text).iter().any(|rule| {
        (rule.kind == "@include" && rule.module == service)
            || (matches!(rule.kind.as_str(), "auth" | "-auth")
                && matches!(rule.control.as_str(), "include" | "substack")
                && rule.module == service)
    })
}

/// Inserts lines before the first rule, after the header comments.
pub fn insert_lines(text: &str, lines: &[String]) -> String {
    let mut out = String::with_capacity(text.len() + 200);
    let mut inserted = false;
    for raw in text.split_inclusive('\n') {
        let content = raw.split('#').next().unwrap_or_default().trim();
        if !inserted && !content.is_empty() {
            for line in lines {
                out.push_str(line);
                out.push('\n');
            }
            inserted = true;
        }
        out.push_str(raw);
    }
    if !inserted {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        for line in lines {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

pub fn module_protocol(path: &Path) -> Option<u32> {
    let bytes = std::fs::read(path).ok()?;
    let prefix = &PROTOCOL_MARKER[..PROTOCOL_MARKER.len() - 2];
    let prefix = &prefix[..prefix.len() - 1];
    let start = bytes.windows(prefix.len()).position(|window| window == prefix)? + prefix.len();
    let digits: String = bytes[start..]
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .map(|b| *b as char)
        .collect();
    let end = start + digits.len();
    (bytes.get(end) == Some(&0)).then(|| digits.parse().ok()).flatten()
}

// ---------------------------------------------------------------------------
// SELinux

/// A user whose SELinux login mapping is not `unconfined_u`. Measured: for
/// confined users (`staff_u` …) sudo's PAM can't reach the user's socket.
pub fn selinux_confined(root: &Path, user: &str) -> bool {
    if !root.join("sys/fs/selinux/enforce").exists() {
        return false;
    }
    let policy = std::fs::read_to_string(root.join("etc/selinux/config"))
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.trim().strip_prefix("SELINUXTYPE=").map(|value| value.trim().to_string()))
        })
        .unwrap_or_else(|| "targeted".into());
    let seusers = std::fs::read_to_string(root.join(format!("etc/selinux/{policy}/seusers"))).unwrap_or_default();
    let groups = crate::sys::user_by_name(user)
        .map(|entry| crate::sys::groups_of(&entry).1)
        .unwrap_or_default();
    seuser_for(&seusers, user, &groups).is_some_and(|seuser| seuser != "unconfined_u")
}

pub fn seuser_for(seusers: &str, user: &str, groups: &[String]) -> Option<String> {
    let mut default = None;
    let mut group_match = None;
    for line in seusers.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        let mut fields = line.split(':');
        let (Some(name), Some(seuser)) = (fields.next(), fields.next()) else { continue };
        if name == user {
            return Some(seuser.to_string());
        }
        if let Some(group) = name.strip_prefix('%')
            && groups.iter().any(|g| g == group)
            && group_match.is_none()
        {
            group_match = Some(seuser.to_string());
        }
        if name == "__default__" {
            default = Some(seuser.to_string());
        }
    }
    group_match.or(default)
}

// ---------------------------------------------------------------------------
// Planning

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    CreateDir { path: String, mode: u32 },
    CreateFile { path: String, contents: Vec<u8>, mode: u32, sudoers: bool },
    ModifyFile { path: String, before: Vec<u8>, after: Vec<u8> },
}

impl Step {
    pub fn path(&self) -> &str {
        match self {
            Self::CreateDir { path, .. } | Self::CreateFile { path, .. } | Self::ModifyFile { path, .. } => path,
        }
    }
    pub fn summary(&self) -> String {
        match self {
            Self::CreateDir { .. } => "create directory".into(),
            Self::CreateFile { path, .. } if path == SUDOERS_DROP_IN => {
                "add sudoers drop-in: noninteractive_auth, !requiretty, timestamp_timeout=0".into()
            }
            Self::CreateFile { path, .. } if path.ends_with(".toml") => "create device approval config".into(),
            Self::CreateFile { path, .. } if path.ends_with(".so") => "install the PAM module".into(),
            Self::CreateFile { .. } => "install the t3-elevation helper".into(),
            Self::ModifyFile { .. } => "add the pam_t3_elevation auth line first".into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Blocked {
    pub path: String,
    pub message: String,
}

#[derive(Clone, Debug, Default)]
pub struct Plan {
    pub steps: Vec<Step>,
    pub blocked: Vec<Blocked>,
    /// Paths already in the installed state, whoever put them there.
    pub satisfied: Vec<String>,
}

pub struct Sources<'a> {
    pub module: Option<&'a [u8]>,
    pub helper: Option<&'a [u8]>,
}

struct Planner<'a> {
    layout: &'a Layout,
    plan: Plan,
}

impl Planner<'_> {
    fn block(&mut self, path: &str, message: impl Into<String>) {
        self.plan.blocked.push(Blocked { path: path.into(), message: message.into() });
    }

    fn dir(&mut self, path: &str) {
        if self.plan.steps.iter().any(|step| step.path() == path) {
            return;
        }
        let full = self.layout.path(path);
        match std::fs::symlink_metadata(&full) {
            Err(_) => {
                if let Some(parent) = Path::new(path).parent().and_then(Path::to_str)
                    && parent != "/"
                {
                    self.dir(parent);
                }
                self.plan.steps.push(Step::CreateDir { path: path.into(), mode: 0o755 });
            }
            Ok(_) => {
                if rootsafe::check_path(&full, &self.layout.policy, rootsafe::Kind::Dir).is_err() {
                    self.block(path, "exists but is not a root-owned directory that only root can write");
                }
            }
        }
    }

    /// A file install owns entirely: created when missing, accepted when it
    /// already has exactly these bytes, reported otherwise.
    fn owned_file(&mut self, path: &str, contents: &[u8], mode: u32, sudoers: bool) {
        let full = self.layout.path(path);
        match std::fs::symlink_metadata(&full) {
            Err(_) => self.plan.steps.push(Step::CreateFile { path: path.into(), contents: contents.to_vec(), mode, sudoers }),
            Ok(_) => match std::fs::read(&full) {
                Ok(existing) if existing == contents => self.plan.satisfied.push(path.into()),
                Ok(_) => self.block(path, "already exists and differs from what T3 would write"),
                Err(_) => self.block(path, "exists but can't be read"),
            },
        }
    }

    /// A shared file install edits by inserting lines: it must be a regular,
    /// root-owned file that only root can write. A symlink (for example into a
    /// read-only store) means another tool manages it.
    fn editable(&mut self, path: &str) -> Option<String> {
        let full = self.layout.path(path);
        let Ok(meta) = std::fs::symlink_metadata(&full) else {
            self.block(path, "missing");
            return None;
        };
        if meta.file_type().is_symlink() {
            self.block(path, "is a symlink, so it is managed outside T3; add the device approval lines there");
            return None;
        }
        let parent_safe = full
            .parent()
            .is_some_and(|parent| rootsafe::check_path(parent, &self.layout.policy, rootsafe::Kind::Dir).is_ok());
        if !meta.is_file() || !self.layout.policy.owners.contains(&meta.uid()) || meta.mode() & 0o022 != 0 || !parent_safe {
            self.block(path, "is not a regular root-owned file that only root can write");
            return None;
        }
        match std::fs::read(&full).ok().and_then(|bytes| String::from_utf8(bytes).ok()) {
            Some(text) => Some(text),
            None => {
                self.block(path, "can't be read as text");
                None
            }
        }
    }

    fn pam(&mut self) -> bool {
        let mut needs_module = false;
        match self.layout.platform {
            Platform::Linux => {
                let mut files = vec!["/etc/pam.d/sudo".to_string()];
                let sudo_i = self.layout.path("/etc/pam.d/sudo-i");
                if std::fs::symlink_metadata(&sudo_i).is_ok() {
                    let text = std::fs::read_to_string(&sudo_i).unwrap_or_default();
                    if !includes_service(&text, "sudo") {
                        files.push("/etc/pam.d/sudo-i".into());
                    }
                }
                for file in files {
                    let Some(text) = self.editable(&file) else { continue };
                    if linux_pam_ok(&text).is_some() {
                        self.plan.satisfied.push(file);
                    } else if mentions_t3(&text) {
                        self.block(&file, "has a pam_t3_elevation line that isn't the first auth line");
                    } else {
                        let after = insert_lines(&text, &[linux_pam_line(MODULE_INSTALL_PATH)]);
                        self.plan.steps.push(Step::ModifyFile { path: file, before: text.into_bytes(), after: after.into_bytes() });
                        needs_module = true;
                    }
                }
            }
            Platform::Macos => {
                let sudo = std::fs::read_to_string(self.layout.path("/etc/pam.d/sudo")).unwrap_or_default();
                let first = auth_rules(&sudo).into_iter().next();
                if !first.is_some_and(|rule| rule.kind == "auth" && rule.control == "include" && rule.module == "sudo_local") {
                    self.block("/etc/pam.d/sudo", "doesn't include sudo_local first; this macOS version isn't supported");
                    return false;
                }
                let path = "/etc/pam.d/sudo_local";
                let lines = macos_pam_lines(MODULE_INSTALL_PATH);
                if std::fs::symlink_metadata(self.layout.path(path)).is_err() {
                    let contents = format!("{}\n{}\n", lines[0], lines[1]);
                    self.plan.steps.push(Step::CreateFile { path: path.into(), contents: contents.into_bytes(), mode: 0o444, sudoers: false });
                    return true;
                }
                let Some(text) = self.editable(path) else { return false };
                if macos_pam_ok(&text).is_some() {
                    self.plan.satisfied.push(path.into());
                } else if mentions_t3(&text) {
                    self.block(path, "has pam_t3_elevation lines that aren't the first two auth lines");
                } else {
                    let after = insert_lines(&text, &lines);
                    self.plan.steps.push(Step::ModifyFile { path: path.into(), before: text.into_bytes(), after: after.into_bytes() });
                    needs_module = true;
                }
            }
        }
        needs_module
    }

    fn sudoers(&mut self, user: &str) {
        let wanted = sudoers_drop_in(user);
        let drop_in = self.layout.path(SUDOERS_DROP_IN);
        if std::fs::symlink_metadata(&drop_in).is_ok() {
            self.owned_file(SUDOERS_DROP_IN, wanted.as_bytes(), 0o440, true);
            return;
        }
        let sudoers = self.layout.path("/etc/sudoers");
        if sudoers_has_settings(&sudoers, user) {
            self.plan.satisfied.push("/etc/sudoers".into());
            return;
        }
        let main = std::fs::read_to_string(&sudoers).unwrap_or_default();
        let includes_dir = main.lines().any(|line| {
            let line = line.trim();
            ["#includedir", "@includedir"].iter().any(|directive| {
                line.strip_prefix(directive).is_some_and(|rest| {
                    matches!(rest.trim(), "/etc/sudoers.d" | "/private/etc/sudoers.d" | "sudoers.d")
                })
            })
        });
        if !includes_dir {
            self.block("/etc/sudoers", "doesn't include /etc/sudoers.d; add noninteractive_auth, !requiretty and timestamp_timeout=0 for this user there");
            return;
        }
        if self.layout.root == Path::new("/") && self.layout.visudo.is_none() {
            self.block(SUDOERS_DROP_IN, "visudo was not found, so the drop-in can't be validated");
            return;
        }
        self.plan.steps.push(Step::CreateFile { path: SUDOERS_DROP_IN.into(), contents: wanted.into_bytes(), mode: 0o440, sudoers: true });
    }
}

/// Whether some sudoers file already sets all three settings for the user.
pub fn sudoers_has_settings(sudoers: &Path, user: &str) -> bool {
    let lines = crate::sudoers::defaults_lines(sudoers);
    ["noninteractive_auth", "!requiretty", "timestamp_timeout=0"].iter().all(|setting| {
        lines.iter().any(|line| {
            let (binding, params) = match line.strip_prefix("Defaults:") {
                Some(rest) => rest.split_once(char::is_whitespace).unwrap_or((rest, "")),
                None => match line.strip_prefix("Defaults") {
                    Some(rest) if rest.starts_with(char::is_whitespace) => ("", rest),
                    _ => return false,
                },
            };
            (binding.is_empty() || binding == user)
                && params.split(',').any(|param| param.split_whitespace().collect::<String>() == *setting)
        })
    })
}

pub fn plan_install(layout: &Layout, user: &str, socket: &str, window: i64, sources: &Sources) -> Plan {
    let mut planner = Planner { layout, plan: Plan::default() };
    if layout.selinux_confined {
        planner.block("/etc/selinux", "device approval isn't supported for confined SELinux users");
    }
    let needs_module = planner.pam();
    if needs_module {
        let module_dir = Path::new(MODULE_INSTALL_PATH).parent().and_then(Path::to_str).unwrap_or("/");
        planner.dir(module_dir);
        match sources.module {
            Some(bytes) => planner.owned_file(MODULE_INSTALL_PATH, bytes, 0o644, false),
            None => planner.block(MODULE_INSTALL_PATH, "pam_t3_elevation.so was not found next to the helper"),
        }
    }
    if needs_module && let Some(helper) = sources.helper {
        let helper_dir = Path::new(crate::HELPER_INSTALL_PATH).parent().and_then(Path::to_str).unwrap_or("/");
        planner.dir(helper_dir);
        planner.owned_file(crate::HELPER_INSTALL_PATH, helper, 0o755, false);
    }
    planner.dir(&layout.state("users"));
    let config = UserConfig { enabled: true, socket: socket.into(), approval_window_seconds: window };
    let config_path = layout.state(&format!("users/{user}.toml"));
    match std::fs::read_to_string(layout.path(&config_path)) {
        Err(_) if std::fs::symlink_metadata(layout.path(&config_path)).is_err() => {
            planner.plan.steps.push(Step::CreateFile { path: config_path, contents: config::render(&config).into_bytes(), mode: 0o644, sudoers: false });
        }
        Ok(text) if config::parse(&text).is_some_and(|existing| existing.enabled && existing.socket == socket) => {
            planner.plan.satisfied.push(config_path);
        }
        _ => planner.block(&config_path, "already exists and points elsewhere or is disabled"),
    }
    planner.dir(&layout.state(&format!("keys/{user}")));
    planner.sudoers(user);
    // Order: directories, then files, then sudoers, then PAM last, so PAM
    // never references a module or relies on settings that aren't there yet.
    planner.plan.steps.sort_by_key(|step| match step {
        Step::CreateDir { path, .. } => (0, path.matches('/').count()),
        Step::CreateFile { sudoers: false, path, .. } if !path.starts_with("/etc/pam.d") => (1, 0),
        Step::CreateFile { sudoers: true, .. } => (2, 0),
        _ => (3, 0),
    });
    planner.plan
}

// ---------------------------------------------------------------------------
// Applying and the manifest

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Change {
    pub path: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub backup: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sha256_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sha256_after: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub version: u32,
    pub installed_at: String,
    pub helper_version: String,
    pub user: String,
    pub changes: Vec<Change>,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

pub fn rfc3339(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let seconds = unix.rem_euclid(86_400);
    // Civil from days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3600,
        seconds % 3600 / 60,
        seconds % 60
    )
}

/// Writes through a temporary file in the same directory and renames it into
/// place, so a crash never leaves a half-written PAM or sudoers file.
pub fn write_atomic(layout: &Layout, path: &Path, contents: &[u8], mode: u32, owner: Option<(u32, u32)>) -> std::io::Result<()> {
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("file");
    let temp = path.with_file_name(format!(".{name}.t3-elevation-tmp"));
    let _ = std::fs::remove_file(&temp);
    {
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&temp)?;
        file.write_all(contents)?;
        file.sync_all()?;
    }
    std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(mode))?;
    if layout.chown_root {
        let (uid, gid) = owner.unwrap_or((0, 0));
        std::os::unix::fs::chown(&temp, Some(uid), Some(gid))?;
    }
    std::fs::rename(&temp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&temp);
    })
}

fn validate_sudoers(layout: &Layout, path: &Path, contents: &[u8]) -> Result<(), String> {
    let Some(visudo) = &layout.visudo else {
        return if layout.root == Path::new("/") { Err("visudo not found".into()) } else { Ok(()) };
    };
    // A name with a dot is skipped by `includedir`, so the candidate is never live.
    let candidate = path.with_file_name(".t3-elevation.check");
    std::fs::write(&candidate, contents).map_err(|error| error.to_string())?;
    let output = std::process::Command::new(visudo).arg("-cf").arg(&candidate).output();
    let _ = std::fs::remove_file(&candidate);
    match output {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => Err(format!("visudo rejected the drop-in: {}", String::from_utf8_lossy(&output.stderr).trim())),
        Err(error) => Err(format!("visudo failed to run: {error}")),
    }
}

fn apply_step(layout: &Layout, step: &Step) -> Result<Change, String> {
    match step {
        Step::CreateDir { path, mode } => {
            let full = layout.path(path);
            std::fs::create_dir(&full).map_err(|error| format!("{path}: {error}"))?;
            std::fs::set_permissions(&full, std::fs::Permissions::from_mode(*mode)).map_err(|error| error.to_string())?;
            if layout.chown_root {
                std::os::unix::fs::chown(&full, Some(0), Some(0)).map_err(|error| error.to_string())?;
            }
            Ok(Change { path: path.clone(), action: "created_dir".into(), backup: None, sha256_before: None, sha256_after: None })
        }
        Step::CreateFile { path, contents, mode, sudoers } => {
            let full = layout.path(path);
            if *sudoers {
                validate_sudoers(layout, &full, contents)?;
            }
            write_atomic(layout, &full, contents, *mode, None).map_err(|error| format!("{path}: {error}"))?;
            Ok(Change { path: path.clone(), action: "created".into(), backup: None, sha256_before: None, sha256_after: Some(sha256_hex(contents)) })
        }
        Step::ModifyFile { path, before, after } => {
            let full = layout.path(path);
            let current = std::fs::read(&full).map_err(|error| format!("{path}: {error}"))?;
            if current != *before {
                return Err(format!("{path} changed while installing"));
            }
            let meta = std::fs::metadata(&full).map_err(|error| error.to_string())?;
            let backup = format!("{BACKUP_DIR}{path}");
            let backup_full = layout.path(&backup);
            if let Some(parent) = backup_full.parent() {
                std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            }
            write_atomic(layout, &backup_full, before, meta.mode() & 0o7777, Some((meta.uid(), meta.gid())))
                .map_err(|error| format!("{backup}: {error}"))?;
            write_atomic(layout, &full, after, meta.mode() & 0o7777, Some((meta.uid(), meta.gid())))
                .map_err(|error| format!("{path}: {error}"))?;
            Ok(Change {
                path: path.clone(),
                action: "modified".into(),
                backup: Some(backup),
                sha256_before: Some(sha256_hex(before)),
                sha256_after: Some(sha256_hex(after)),
            })
        }
    }
}

pub fn read_manifest(layout: &Layout) -> Option<Manifest> {
    let bytes = std::fs::read(layout.path(MANIFEST)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_manifest(layout: &Layout, manifest: &Manifest) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(manifest).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    write_atomic(layout, &layout.path(MANIFEST), &bytes, 0o644, None).map_err(|error| error.to_string())
}

/// Applies every step or none: a failure reverts what this run changed.
pub fn apply(layout: &Layout, user: &str, plan: &Plan, now: i64) -> Result<Vec<Change>, String> {
    let existing = read_manifest(layout);
    if let Some(manifest) = &existing
        && manifest.user != user
    {
        return Err(format!("already installed for {}; uninstall that first", manifest.user));
    }
    let mut done = Vec::new();
    for step in &plan.steps {
        match apply_step(layout, step) {
            Ok(change) => done.push(change),
            Err(error) => {
                revert(layout, &done, user);
                return Err(error);
            }
        }
    }
    let mut manifest = existing.unwrap_or(Manifest {
        version: 1,
        installed_at: rfc3339(now),
        helper_version: crate::HELPER_VERSION.into(),
        user: user.into(),
        changes: vec![],
    });
    manifest.changes.extend(done.iter().cloned());
    if !manifest.changes.is_empty()
        && let Err(error) = write_manifest(layout, &manifest)
    {
        revert(layout, &done, user);
        return Err(error);
    }
    Ok(done)
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Reverted {
    pub restored: Vec<String>,
    pub removed: Vec<String>,
    pub kept: Vec<Blocked>,
}

fn current_hash(layout: &Layout, path: &str) -> Option<String> {
    std::fs::read(layout.path(path)).ok().map(|bytes| sha256_hex(&bytes))
}

/// Walks changes in reverse and touches a path only if it is still exactly
/// what install wrote.
pub fn revert(layout: &Layout, changes: &[Change], user: &str) -> Reverted {
    let mut result = Reverted::default();
    let keys_dir = layout.state(&format!("keys/{user}"));
    for change in changes.iter().rev() {
        let full = layout.path(&change.path);
        let unchanged = current_hash(layout, &change.path) == change.sha256_after;
        match change.action.as_str() {
            "modified" => {
                let Some(backup) = &change.backup else { continue };
                let backup_full = layout.path(backup);
                let restored = unchanged
                    && std::fs::read(&backup_full).ok().is_some_and(|bytes| {
                        let meta = std::fs::metadata(&backup_full).ok();
                        let owner = meta.as_ref().map(|meta| (meta.uid(), meta.gid()));
                        let mode = meta.map(|meta| meta.mode() & 0o7777).unwrap_or(0o644);
                        Some(sha256_hex(&bytes)) == change.sha256_before
                            && write_atomic(layout, &full, &bytes, mode, owner).is_ok()
                    });
                if restored {
                    let _ = std::fs::remove_file(&backup_full);
                    result.restored.push(change.path.clone());
                } else {
                    result.kept.push(Blocked { path: change.path.clone(), message: "changed since install; left as is".into() });
                }
            }
            "created" => {
                if unchanged && std::fs::remove_file(&full).is_ok() {
                    result.removed.push(change.path.clone());
                } else {
                    result.kept.push(Blocked { path: change.path.clone(), message: "changed since install; left as is".into() });
                }
            }
            "created_dir" => {
                if change.path == keys_dir {
                    remove_key_files(&full);
                }
                if change.path == crate::STATE_DIR {
                    let _ = std::fs::remove_dir_all(layout.path(BACKUP_DIR));
                    let _ = std::fs::remove_file(layout.path(MANIFEST));
                }
                if std::fs::remove_dir(&full).is_ok() {
                    result.removed.push(change.path.clone());
                } else {
                    result.kept.push(Blocked { path: change.path.clone(), message: "not empty; left as is".into() });
                }
            }
            _ => {}
        }
    }
    result
}

/// Keys are runtime state the helper writes; they go with the directory.
fn remove_key_files(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_str().and_then(|name| name.strip_suffix(".json")).is_some_and(keys::is_key_id) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

pub fn uninstall(layout: &Layout, user: &str) -> Result<Reverted, String> {
    let manifest = read_manifest(layout).ok_or("nothing was installed by T3 (no installed-by-t3.json)")?;
    if manifest.user != user {
        return Err(format!("installed for {}, not {user}", manifest.user));
    }
    let result = revert(layout, &manifest.changes, user);
    // Gone already when T3 created the state directory itself.
    let _ = std::fs::remove_dir_all(layout.path(BACKUP_DIR));
    let _ = std::fs::remove_file(layout.path(MANIFEST));
    Ok(result)
}

// ---------------------------------------------------------------------------
// Status

#[derive(Clone, Debug, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub ok: bool,
    pub message: String,
}

fn check(id: &'static str, ok: bool, message: impl Into<String>) -> Check {
    Check { id, ok, message: message.into() }
}

fn module_check(layout: &Layout, module: &str) -> Check {
    match module_protocol(&layout.path(module)) {
        Some(protocol) if protocol == crate::PROTOCOL_VERSION => check("module", true, format!("{module} speaks protocol {protocol}")),
        Some(protocol) => check("module", false, format!("{module} speaks protocol {protocol}, not {}", crate::PROTOCOL_VERSION)),
        None => check("module", false, format!("{module} is missing or isn't pam_t3_elevation")),
    }
}

pub fn pam_checks(layout: &Layout) -> Vec<Check> {
    let mut checks = Vec::new();
    let mut module = None;
    match layout.platform {
        Platform::Linux => {
            let mut files = vec![("pam_sudo", "/etc/pam.d/sudo")];
            let sudo_i = std::fs::read_to_string(layout.path("/etc/pam.d/sudo-i"));
            if sudo_i.as_ref().is_ok_and(|text| !includes_service(text, "sudo")) {
                files.push(("pam_sudo_i", "/etc/pam.d/sudo-i"));
            }
            for (id, file) in files {
                let text = std::fs::read_to_string(layout.path(file)).unwrap_or_default();
                match linux_pam_ok(&text) {
                    Some(path) => {
                        checks.push(check(id, true, format!("{file} starts with the device approval line")));
                        module.get_or_insert(path);
                    }
                    None => checks.push(check(id, false, format!("PAM line missing in {file}"))),
                }
            }
        }
        Platform::Macos => {
            let sudo = std::fs::read_to_string(layout.path("/etc/pam.d/sudo")).unwrap_or_default();
            let includes = auth_rules(&sudo)
                .first()
                .is_some_and(|rule| rule.control == "include" && rule.module == "sudo_local");
            checks.push(check("pam_sudo", includes, if includes { "/etc/pam.d/sudo includes sudo_local first" } else { "/etc/pam.d/sudo doesn't include sudo_local first" }));
            let text = std::fs::read_to_string(layout.path("/etc/pam.d/sudo_local")).unwrap_or_default();
            match macos_pam_ok(&text) {
                Some(path) => {
                    checks.push(check("pam_sudo_local", true, "/etc/pam.d/sudo_local starts with the device approval lines"));
                    module = Some(path);
                }
                None => checks.push(check("pam_sudo_local", false, "PAM lines missing in /etc/pam.d/sudo_local")),
            }
        }
    }
    checks.push(module_check(layout, module.as_deref().unwrap_or(MODULE_INSTALL_PATH)));
    checks
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusConfig {
    pub enabled: bool,
    pub socket: String,
    pub approval_window_seconds: i64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusKey {
    pub key_id: String,
    pub label: String,
    pub security_level: String,
    pub enrolled_at: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlannedChange {
    pub path: String,
    pub summary: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub ok: bool,
    pub protocol: u32,
    pub platform: &'static str,
    pub checks: Vec<Check>,
    pub config: Option<StatusConfig>,
    pub keys: Vec<StatusKey>,
    pub planned_changes: Vec<PlannedChange>,
    #[serde(rename = "setupOutsideT3")]
    pub setup_outside_t3: bool,
}

/// Unprivileged static checks over world-readable files. Sudoers can't be
/// read without root; T3's live `sudo -n true` proves those settings.
pub fn status(layout: &Layout, user: &str, sources: &Sources) -> Status {
    let mut checks = pam_checks(layout);
    let config_path = layout.path(&layout.state(&format!("users/{user}.toml")));
    let config = rootsafe::check_path(&config_path, &layout.policy, rootsafe::Kind::File)
        .ok()
        .and_then(|_| std::fs::read_to_string(&config_path).ok())
        .and_then(|text| config::parse(&text));
    checks.push(match &config {
        Some(config) if config.enabled => check("config", true, format!("users/{user}.toml points at {}", config.socket)),
        Some(_) => check("config", false, format!("users/{user}.toml is disabled")),
        None => check("config", false, format!("users/{user}.toml is missing, unsafe or invalid")),
    });
    let keys_dir = layout.path(&layout.state(&format!("keys/{user}")));
    let keys = keys::load_dir(&keys_dir, &layout.policy);
    checks.push(check(
        "keys_dir",
        keys.is_ok(),
        if keys.is_ok() { format!("keys/{user} is root-owned") } else { format!("keys/{user} is missing or not root-owned") },
    ));
    if layout.selinux_confined {
        checks.push(check("selinux", false, "device approval isn't supported for confined SELinux users"));
    }
    if crate::sys::is_root() || layout.root != Path::new("/") {
        let present = sudoers_has_settings(&layout.path("/etc/sudoers"), user);
        checks.push(check("sudoers", present, if present { "sudoers sets noninteractive_auth, !requiretty and timestamp_timeout=0" } else { "sudoers settings for device approval are missing" }));
    }
    let socket = config.as_ref().map(|config| config.socket.clone()).unwrap_or_else(|| "<socket>".into());
    let window = config.as_ref().map_or(config::DEFAULT_WINDOW_SECONDS, |config| config.approval_window_seconds);
    let plan = plan_install(layout, user, &socket, window, sources);
    let recorded: Vec<String> = read_manifest(layout)
        .map(|manifest| manifest.changes.into_iter().map(|change| change.path).collect())
        .unwrap_or_default();
    let setup_outside_t3 = plan
        .satisfied
        .iter()
        .chain(
            [&layout.state(&format!("users/{user}.toml")), &layout.state(&format!("keys/{user}"))]
                .into_iter()
                .filter(|path| std::fs::symlink_metadata(layout.path(path)).is_ok()),
        )
        .any(|path| !recorded.contains(path));
    Status {
        ok: true,
        protocol: crate::PROTOCOL_VERSION,
        platform: layout.platform.name(),
        checks,
        config: config.map(|config| StatusConfig {
            enabled: config.enabled,
            socket: config.socket,
            approval_window_seconds: config.approval_window_seconds,
        }),
        keys: keys
            .unwrap_or_default()
            .into_iter()
            .map(|key| StatusKey {
                key_id: key.key_id,
                label: key.file.label,
                security_level: key.file.security_level,
                enrolled_at: key.file.enrolled_at,
            })
            .collect(),
        planned_changes: plan
            .steps
            .iter()
            .map(|step| PlannedChange { path: step.path().to_string(), summary: step.summary() })
            .chain(plan.blocked.iter().map(|blocked| PlannedChange { path: blocked.path.clone(), summary: format!("can't change: {}", blocked.message) }))
            .collect(),
        setup_outside_t3,
    }
}

// ---------------------------------------------------------------------------
// Keys

pub fn key_file_bytes(spki: &[u8], label: &str, verified: &crate::attestation::Verified, now: i64) -> (String, Vec<u8>) {
    let key_id = keys::key_id(spki);
    let file = keys::KeyFile {
        version: 1,
        key_id: key_id.clone(),
        alg: "es256".into(),
        public_key: crate::b64::encode(spki),
        label: label.into(),
        security_level: verified.security_level.into(),
        enrolled_at: rfc3339(now),
        attestation_summary: keys::AttestationSummary {
            package_name: verified.package_name.clone(),
            signing_cert_digest: verified.signing_cert_digest.clone(),
            dev_attestation: verified.dev_attestation,
        },
    };
    let mut bytes = serde_json::to_vec(&file).unwrap_or_default();
    bytes.push(b'\n');
    (key_id, bytes)
}

#[derive(Debug, PartialEq, Eq)]
pub enum KeyError {
    NotInstalled,
    AlreadyEnrolled,
    UnknownKey,
    Io(String),
}

fn keys_dir(layout: &Layout, user: &str) -> Result<PathBuf, KeyError> {
    let dir = layout.path(&layout.state(&format!("keys/{user}")));
    rootsafe::check_path(&dir, &layout.policy, rootsafe::Kind::Dir).map_err(|_| KeyError::NotInstalled)?;
    Ok(dir)
}

pub fn write_key(layout: &Layout, user: &str, key_id: &str, bytes: &[u8]) -> Result<(), KeyError> {
    let path = keys_dir(layout, user)?.join(format!("{key_id}.json"));
    if std::fs::symlink_metadata(&path).is_ok() {
        return Err(KeyError::AlreadyEnrolled);
    }
    write_atomic(layout, &path, bytes, 0o644, None).map_err(|error| KeyError::Io(error.to_string()))
}

/// Removes one key, or every key file when `key_id` is `None`.
pub fn revoke(layout: &Layout, user: &str, key_id: Option<&str>) -> Result<Vec<String>, KeyError> {
    let dir = keys_dir(layout, user)?;
    let mut removed = Vec::new();
    let entries = std::fs::read_dir(&dir).map_err(|error| KeyError::Io(error.to_string()))?;
    let mut names: Vec<String> = entries.flatten().filter_map(|entry| entry.file_name().into_string().ok()).collect();
    names.sort();
    for name in names {
        let Some(id) = name.strip_suffix(".json").filter(|id| keys::is_key_id(id)) else { continue };
        if key_id.is_none_or(|wanted| wanted == id) {
            std::fs::remove_file(dir.join(&name)).map_err(|error| KeyError::Io(error.to_string()))?;
            removed.push(id.to_string());
        }
    }
    if key_id.is_some() && removed.is_empty() {
        return Err(KeyError::UnknownKey);
    }
    Ok(removed)
}
