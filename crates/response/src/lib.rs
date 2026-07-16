mod capture;
mod errors;
mod kill;
mod quarantine;

use std::collections::VecDeque;
#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};
#[cfg(windows)]
use std::path::{Prefix, PrefixComponent};
use std::time::{Duration, Instant};

use regex::Regex;
use serde::{Deserialize, Serialize};

use detection::Confidence;

pub use capture::{capture_script_content, ScriptCapture};
pub use errors::{ResponseError, ResponseResult};
pub use kill::{kill_process_tree, KillReport, ProcessIntrospector, Signal, SignalSender};
pub use quarantine::{
    quarantine_file, quarantine_file_with_dir, restore_quarantined, restore_quarantined_with_dir,
    QuarantineReport, RestoreReport,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePolicy {
    pub kill: bool,
    pub quarantine: bool,
    pub capture_script: bool,
}

impl ResponsePolicy {
    pub const fn new(kill: bool, quarantine: bool, capture_script: bool) -> Self {
        Self {
            kill,
            quarantine,
            capture_script,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseConfig {
    pub autonomous_response: bool,
    pub dry_run: bool,
    #[serde(default)]
    pub allow_remote_uninstall: bool,
    pub max_kills_per_minute: usize,
    pub max_quarantines_per_minute: usize,
    pub auto_isolation: AutoIsolationPolicy,
    pub definite: ResponsePolicy,
    pub very_high: ResponsePolicy,
    pub high: ResponsePolicy,
    pub medium: ResponsePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoIsolationPolicy {
    pub enabled: bool,
    pub min_incidents_in_window: usize,
    pub window_secs: u64,
    pub max_isolations_per_hour: usize,
}

impl Default for AutoIsolationPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            min_incidents_in_window: 3,
            window_secs: 300,
            max_isolations_per_hour: 2,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AutoIsolationState {
    incident_timestamps: VecDeque<i64>,
    isolation_timestamps: VecDeque<i64>,
}

impl Default for ResponseConfig {
    fn default() -> Self {
        // Destructive autonomy must be explicitly enabled by config or server policy,
        // never by the compiled fallback.
        Self {
            autonomous_response: false,
            dry_run: false,
            allow_remote_uninstall: false,
            max_kills_per_minute: 10,
            max_quarantines_per_minute: 5,
            auto_isolation: AutoIsolationPolicy::default(),
            //              kill  quarantine  capture_script
            definite: ResponsePolicy::new(true, true, true),
            very_high: ResponsePolicy::new(true, true, true),
            high: ResponsePolicy::new(false, false, true),
            medium: ResponsePolicy::new(false, false, false),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProtectedList {
    process_patterns: Vec<Regex>,
    protected_paths: Vec<PathBuf>,
}

impl ProtectedList {
    pub fn default_linux() -> Self {
        let process_patterns = [
            "^systemd",
            "init",
            "sshd",
            "dbus-daemon",
            "journald",
            "eguard-agent",
            "containerd",
            "dockerd",
        ]
        .into_iter()
        .map(compile_process_pattern)
        .collect();

        let protected_paths = vec![
            PathBuf::from("/bin"),
            PathBuf::from("/sbin"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/usr/sbin"),
            PathBuf::from("/lib"),
            PathBuf::from("/lib64"),
            PathBuf::from("/usr/lib"),
            PathBuf::from("/usr/lib64"),
            PathBuf::from("/usr/lib32"),
            PathBuf::from("/usr/libx32"),
            PathBuf::from("/usr/libexec"),
            PathBuf::from("/boot"),
            PathBuf::from("/etc"),
            PathBuf::from("/root"),
            PathBuf::from("/proc"),
            PathBuf::from("/sys"),
            PathBuf::from("/dev"),
            PathBuf::from("/run"),
            PathBuf::from("/var/run"),
            PathBuf::from("/usr/local/eg"),
            PathBuf::from("/var/lib/eguard-agent"),
            PathBuf::from("/var/lib/rpm"),
            PathBuf::from("/var/lib/dnf"),
            PathBuf::from("/var/lib/dpkg"),
            PathBuf::from("/var/lib/apt"),
            PathBuf::from("/var/lib/systemd"),
            PathBuf::from("/var/lib/NetworkManager"),
            PathBuf::from("/var/lib/dbus"),
        ];

        Self {
            process_patterns,
            protected_paths,
        }
    }

    pub fn default_windows() -> Self {
        #[cfg(target_os = "windows")]
        let system_root = windows_directory().unwrap_or_else(|| r"C:\Windows".to_string());
        #[cfg(target_os = "windows")]
        let system_drive =
            windows_drive_from_root(&system_root).unwrap_or_else(|| "C:".to_string());

        #[cfg(not(target_os = "windows"))]
        let (system_drive, system_root) = ("C:".to_string(), r"C:\Windows".to_string());

        Self::default_windows_with_roots(&system_drive, &system_root)
    }

    fn default_windows_with_roots(system_drive: &str, system_root: &str) -> Self {
        let (system_drive, system_root) =
            valid_windows_roots(system_drive, system_root).unwrap_or(("C:", r"C:\Windows"));

        let process_patterns = [
            "^System$",
            "^csrss(\\.exe)?$",
            "^wininit(\\.exe)?$",
            "^winlogon(\\.exe)?$",
            "^services(\\.exe)?$",
            "^lsass(\\.exe)?$",
            "^svchost(\\.exe)?$",
            "^smss(\\.exe)?$",
            // conhost/logonui are Microsoft-documented built-in critical
            // processes: terminating either can trigger bugcheck 0xEF
            // (CRITICAL_PROCESS_DIED). The OS-level IsProcessCritical query in
            // the Windows kill path is the authoritative guard; these names are
            // a defense-in-depth backstop for when that query is unavailable.
            "^conhost(\\.exe)?$",
            "^logonui(\\.exe)?$",
            "^eguard-agent(\\.exe)?$",
        ]
        .into_iter()
        .map(compile_windows_process_pattern)
        .collect();

        let protected_paths = vec![
            PathBuf::from(format!(r"{system_root}\System32")),
            PathBuf::from(format!(r"{system_root}\System32\config")),
            PathBuf::from(format!(r"{system_root}\SysWOW64")),
            PathBuf::from(format!(r"{system_drive}\ProgramData\eGuard")),
            PathBuf::from(system_root),
            PathBuf::from(format!(r"{system_drive}\Program Files")),
            PathBuf::from(format!(r"{system_drive}\Program Files (x86)")),
            PathBuf::from(format!(r"{system_drive}\ProgramData\Microsoft")),
            PathBuf::from(format!(r"{system_drive}\Boot")),
            // Boot/ESP artifacts (P1-3): quarantining any of these can leave the
            // machine unbootable, so they must be protected alongside the rest
            // of the boot volume regardless of which drive letter it is.
            PathBuf::from(format!(r"{system_drive}\bootmgr")),
            PathBuf::from(format!(r"{system_drive}\BOOTNXT")),
            PathBuf::from(format!(r"{system_drive}\EFI\Microsoft")),
        ];

        Self {
            process_patterns,
            protected_paths,
        }
    }

    pub fn default_macos() -> Self {
        let process_patterns = [
            "^launchd",
            "kernel_task",
            "sshd",
            "coreaudiod",
            "WindowServer",
            "eguard-agent",
            "mds",
            "fseventsd",
        ]
        .into_iter()
        .map(compile_process_pattern)
        .collect();

        let protected_paths = vec![
            PathBuf::from("/bin"),
            PathBuf::from("/sbin"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/usr/sbin"),
            PathBuf::from("/usr/lib"),
            PathBuf::from("/etc"),
            PathBuf::from("/private/etc"),
            PathBuf::from("/var/run"),
            PathBuf::from("/private/var/run"),
            PathBuf::from("/var/db/dslocal"),
            PathBuf::from("/private/var/db/dslocal"),
            PathBuf::from("/var/db/opendirectory"),
            PathBuf::from("/private/var/db/opendirectory"),
            PathBuf::from("/Library/Keychains"),
            PathBuf::from("/System"),
            // Do not protect all of /Library/LaunchDaemons: malicious launch
            // daemons must stay quarantinable. Only the agent's own binary and
            // its LaunchDaemon plist are protected, matching the paths the
            // installer writes (installer/macos/scripts/postinstall).
            PathBuf::from("/usr/local/bin/eguard-agent"),
            PathBuf::from("/Library/LaunchDaemons/com.eguard.agent.plist"),
            PathBuf::from("/Library/Application Support/eGuard"),
        ];

        Self {
            process_patterns,
            protected_paths,
        }
    }

    pub fn is_protected_process(&self, process_name: &str) -> bool {
        self.process_patterns
            .iter()
            .any(|pattern| pattern.is_match(process_name))
    }

    pub fn is_protected_path(&self, path: &Path) -> bool {
        let normalized = normalize_path(path);
        let macos_variant = macos_private_path_variant(&normalized);
        self.protected_paths.iter().any(|p| {
            let protected = normalize_path(p);
            path_starts_with(&normalized, &protected)
                || macos_variant
                    .as_ref()
                    .is_some_and(|variant| path_starts_with(variant, &protected))
        })
    }
}

fn valid_windows_roots<'a>(
    system_drive: &'a str,
    system_root: &'a str,
) -> Option<(&'a str, &'a str)> {
    let drive = system_drive.as_bytes();
    let root = system_root.as_bytes();
    (drive.len() == 2
        && drive[0].is_ascii_alphabetic()
        && drive[1] == b':'
        && root.len() > 3
        && root[0].eq_ignore_ascii_case(&drive[0])
        && root[1] == b':'
        && matches!(root[2], b'\\' | b'/'))
    .then_some((system_drive, system_root))
}

#[cfg(target_os = "windows")]
fn windows_drive_from_root(system_root: &str) -> Option<String> {
    let root = system_root.as_bytes();
    (root.len() > 3
        && root[0].is_ascii_alphabetic()
        && root[1] == b':'
        && matches!(root[2], b'\\' | b'/'))
    .then(|| system_root[..2].to_string())
}

#[cfg(target_os = "windows")]
fn windows_directory() -> Option<String> {
    use windows::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;

    let mut buffer = vec![0u16; 260];
    loop {
        let len = unsafe { GetSystemWindowsDirectoryW(Some(&mut buffer)) } as usize;
        if len == 0 {
            return None;
        }
        if len < buffer.len() {
            return String::from_utf16(&buffer[..len]).ok();
        }
        buffer.resize(len + 1, 0);
    }
}

fn macos_private_path_variant(path: &Path) -> Option<PathBuf> {
    let path = path.to_str()?;
    for (private, public) in [("/private/var", "/var"), ("/private/etc", "/etc")] {
        if let Some(rest) = path.strip_prefix(private) {
            if rest.is_empty() || rest.starts_with('/') {
                return Some(PathBuf::from(format!("{public}{rest}")));
            }
        }
        if let Some(rest) = path.strip_prefix(public) {
            if rest.is_empty() || rest.starts_with('/') {
                return Some(PathBuf::from(format!("{private}{rest}")));
            }
        }
    }
    None
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => {
                #[cfg(windows)]
                normalized.push(normalize_windows_prefix(prefix));
                #[cfg(not(windows))]
                normalized.push(prefix.as_os_str());
            }
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
}

#[cfg(windows)]
fn normalize_windows_prefix(prefix: PrefixComponent<'_>) -> OsString {
    match prefix.kind() {
        Prefix::VerbatimDisk(drive) => OsString::from_wide(&[drive as u16, b':' as u16]),
        Prefix::VerbatimUNC(server, share) => {
            let mut normalized = vec![b'\\' as u16, b'\\' as u16];
            normalized.extend(server.encode_wide());
            normalized.push(b'\\' as u16);
            normalized.extend(share.encode_wide());
            OsString::from_wide(&normalized)
        }
        _ => prefix.as_os_str().to_os_string(),
    }
}

#[cfg(windows)]
fn path_starts_with(path: &Path, base: &Path) -> bool {
    let mut path_components = path.components();
    base.components().all(|base_component| {
        path_components.next().is_some_and(|path_component| {
            path_component
                .as_os_str()
                .to_string_lossy()
                .eq_ignore_ascii_case(&base_component.as_os_str().to_string_lossy())
        })
    })
}

#[cfg(not(windows))]
fn path_starts_with(path: &Path, base: &Path) -> bool {
    path.starts_with(base)
}

fn compile_process_pattern(raw: &str) -> Regex {
    let pattern = if looks_like_regex(raw) {
        raw.to_string()
    } else {
        format!("^{}$", regex::escape(raw))
    };
    Regex::new(&pattern).unwrap_or_else(|_| {
        Regex::new(&format!("^{}$", regex::escape(raw))).expect("fallback regex should compile")
    })
}

fn compile_windows_process_pattern(raw: &str) -> Regex {
    let pattern = if looks_like_regex(raw) {
        raw.to_string()
    } else {
        format!("^{}$", regex::escape(raw))
    };
    regex::RegexBuilder::new(&pattern)
        .case_insensitive(true)
        .build()
        .unwrap_or_else(|_| {
            regex::RegexBuilder::new(&format!("^{}$", regex::escape(raw)))
                .case_insensitive(true)
                .build()
                .expect("fallback regex should compile")
        })
}

fn looks_like_regex(raw: &str) -> bool {
    raw.chars().any(|c| {
        matches!(
            c,
            '^' | '$' | '*' | '+' | '?' | '[' | ']' | '(' | ')' | '{' | '}' | '|'
        )
    })
}

/// Hard compiled ceiling on the per-minute rate of any response limiter (kills
/// or quarantines). This is the single, authoritative upper bound: because it
/// is enforced inside the limiter constructor/setter, NO configuration source
/// — file, environment, or remote policy — can raise the effective rate above
/// it, only lower it. Bounds the blast radius of a storm regardless of config.
pub const MAX_RESPONSE_RATE_PER_MINUTE: usize = 120;

#[derive(Debug)]
pub struct KillRateLimiter {
    max_kills_per_minute: usize,
    kill_timestamps: VecDeque<Instant>,
}

impl KillRateLimiter {
    pub fn new(max_kills_per_minute: usize) -> Self {
        Self {
            max_kills_per_minute: max_kills_per_minute.min(MAX_RESPONSE_RATE_PER_MINUTE),
            kill_timestamps: VecDeque::new(),
        }
    }

    pub fn set_max_per_minute(&mut self, max_per_minute: usize) {
        self.max_kills_per_minute = max_per_minute.min(MAX_RESPONSE_RATE_PER_MINUTE);
    }

    pub fn allow(&mut self, now: Instant) -> bool {
        while let Some(ts) = self.kill_timestamps.front() {
            if now.duration_since(*ts) > Duration::from_secs(60) {
                let _ = self.kill_timestamps.pop_front();
            } else {
                break;
            }
        }

        if self.kill_timestamps.len() >= self.max_kills_per_minute {
            return false;
        }

        self.kill_timestamps.push_back(now);
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlannedAction {
    None,
    AlertOnly,
    CaptureScript,
    KillOnly,
    QuarantineOnly,
    KillAndQuarantine,
}

pub fn plan_action(confidence: Confidence, config: &ResponseConfig) -> PlannedAction {
    if !config.autonomous_response {
        return PlannedAction::AlertOnly;
    }

    if config.dry_run {
        return PlannedAction::AlertOnly;
    }

    let policy = config.policy_for(confidence);

    match (policy.kill, policy.quarantine, policy.capture_script) {
        (true, true, _) => PlannedAction::KillAndQuarantine,
        (true, false, _) => PlannedAction::KillOnly,
        (false, true, _) => PlannedAction::QuarantineOnly,
        (false, false, true) => PlannedAction::CaptureScript,
        (false, false, false) => PlannedAction::AlertOnly,
    }
}

pub fn evaluate_auto_isolation(
    confidence: Confidence,
    now_unix: i64,
    config: &ResponseConfig,
    state: &mut AutoIsolationState,
) -> bool {
    if !config.autonomous_response || config.dry_run {
        return false;
    }

    if !config.auto_isolation.enabled {
        return false;
    }

    if !matches!(confidence, Confidence::Definite | Confidence::VeryHigh) {
        return false;
    }

    if config.auto_isolation.max_isolations_per_hour == 0 {
        return false;
    }

    let window_secs = config.auto_isolation.window_secs.max(1) as i64;
    let min_incidents = config.auto_isolation.min_incidents_in_window.max(1);

    prune_old(
        &mut state.incident_timestamps,
        now_unix.saturating_sub(window_secs),
    );
    prune_old(
        &mut state.isolation_timestamps,
        now_unix.saturating_sub(3600),
    );

    state.incident_timestamps.push_back(now_unix);
    if state.incident_timestamps.len() < min_incidents {
        return false;
    }

    if state.isolation_timestamps.len() >= config.auto_isolation.max_isolations_per_hour {
        return false;
    }

    state.isolation_timestamps.push_back(now_unix);
    state.incident_timestamps.clear();
    true
}

fn prune_old(queue: &mut VecDeque<i64>, cutoff_ts: i64) {
    while let Some(ts) = queue.front() {
        if *ts < cutoff_ts {
            let _ = queue.pop_front();
        } else {
            break;
        }
    }
}

impl ResponseConfig {
    pub fn policy_for(&self, confidence: Confidence) -> &ResponsePolicy {
        match confidence {
            Confidence::Definite => &self.definite,
            Confidence::VeryHigh => &self.very_high,
            Confidence::High => &self.high,
            Confidence::Medium | Confidence::Low | Confidence::None => &self.medium,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerCommand {
    Isolate,
    Unisolate,
    Scan,
    Update,
    Forensics,
    ConfigChange,
    Uninstall,
    RestoreQuarantine,
    EmergencyRulePush,
    KillProcess,
    LockDevice,
    WipeDevice,
    RetireDevice,
    RestartDevice,
    LostMode,
    LocateDevice,
    InstallApp,
    RemoveApp,
    UpdateApp,
    ApplyProfile,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandOutcome {
    Applied,
    Ignored,
}

#[derive(Debug, Clone, Default)]
pub struct HostControlState {
    pub isolated: bool,
    pub last_scan_unix: Option<i64>,
    pub last_update_unix: Option<i64>,
    pub uninstall_requested: bool,
    pub last_lock_unix: Option<i64>,
    pub last_wipe_unix: Option<i64>,
    pub last_retire_unix: Option<i64>,
    pub last_restart_unix: Option<i64>,
    pub lost_mode_enabled: bool,
    pub last_locate_unix: Option<i64>,
    pub last_app_action_unix: Option<i64>,
    pub last_profile_apply_unix: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct CommandExecution {
    pub outcome: CommandOutcome,
    pub status: &'static str,
    pub detail: String,
}

pub fn parse_server_command(raw: &str) -> ServerCommand {
    match raw.trim().to_ascii_lowercase().as_str() {
        "isolate" | "isolate_host" => ServerCommand::Isolate,
        "unisolate" | "unisolate_host" => ServerCommand::Unisolate,
        "scan" | "run_scan" => ServerCommand::Scan,
        "update" | "update_rules" => ServerCommand::Update,
        "forensics" | "forensics_collect" => ServerCommand::Forensics,
        "config_change" => ServerCommand::ConfigChange,
        "uninstall" => ServerCommand::Uninstall,
        "restore_quarantine" => ServerCommand::RestoreQuarantine,
        "emergency_rule_push" | "push_emergency_rule" => ServerCommand::EmergencyRulePush,
        "kill_process" | "kill_tree" | "kill" => ServerCommand::KillProcess,
        "lock_device" | "lock" => ServerCommand::LockDevice,
        "wipe_device" | "wipe" => ServerCommand::WipeDevice,
        "retire_device" | "retire" => ServerCommand::RetireDevice,
        "restart_device" | "restart" => ServerCommand::RestartDevice,
        "lost_mode" => ServerCommand::LostMode,
        "locate_device" | "locate" => ServerCommand::LocateDevice,
        "install_app" => ServerCommand::InstallApp,
        "remove_app" => ServerCommand::RemoveApp,
        "update_app" => ServerCommand::UpdateApp,
        "apply_profile" => ServerCommand::ApplyProfile,
        _ => ServerCommand::Unknown,
    }
}

pub fn execute_server_command(cmd: ServerCommand) -> CommandOutcome {
    let mut state = HostControlState::default();
    execute_server_command_with_state(cmd, 0, &mut state).outcome
}

pub fn execute_server_command_with_state(
    cmd: ServerCommand,
    now_unix: i64,
    state: &mut HostControlState,
) -> CommandExecution {
    match cmd {
        ServerCommand::Isolate => {
            state.isolated = true;
            CommandExecution {
                outcome: CommandOutcome::Applied,
                status: "completed",
                detail: "host switched to isolated mode".to_string(),
            }
        }
        ServerCommand::Unisolate => {
            state.isolated = false;
            CommandExecution {
                outcome: CommandOutcome::Applied,
                status: "completed",
                detail: "host isolation removed".to_string(),
            }
        }
        ServerCommand::Scan => {
            state.last_scan_unix = Some(now_unix);
            CommandExecution {
                outcome: CommandOutcome::Applied,
                status: "completed",
                detail: "quick scan scheduled".to_string(),
            }
        }
        ServerCommand::Update => {
            state.last_update_unix = Some(now_unix);
            CommandExecution {
                outcome: CommandOutcome::Applied,
                status: "completed",
                detail: "agent update check scheduled".to_string(),
            }
        }
        ServerCommand::Forensics => CommandExecution {
            outcome: CommandOutcome::Applied,
            status: "completed",
            detail: "forensics snapshot requested".to_string(),
        },
        ServerCommand::ConfigChange => CommandExecution {
            outcome: CommandOutcome::Applied,
            status: "completed",
            detail: "configuration change accepted".to_string(),
        },
        ServerCommand::Uninstall => {
            // The default behavior does not self-remove: a remotely triggered
            // uninstall of the security agent can be a fleet-wide EDR kill switch
            // (MITRE ATT&CK T1562.001). Record the request but report honestly that
            // nothing was executed; an explicit agent-side opt-in may override this.
            state.uninstall_requested = true;
            CommandExecution {
                outcome: CommandOutcome::Ignored,
                status: "failed",
                detail: "remote uninstall not executed: agent does not self-remove; decommission locally (e.g. apt purge eguard-agent)".to_string(),
            }
        }
        ServerCommand::RestoreQuarantine => CommandExecution {
            outcome: CommandOutcome::Applied,
            status: "completed",
            detail: "quarantine restore requested".to_string(),
        },
        ServerCommand::EmergencyRulePush => CommandExecution {
            outcome: CommandOutcome::Applied,
            status: "completed",
            detail: "emergency rule push received".to_string(),
        },
        ServerCommand::KillProcess => CommandExecution {
            outcome: CommandOutcome::Applied,
            status: "completed",
            detail: "kill process command received".to_string(),
        },
        ServerCommand::LockDevice => {
            state.last_lock_unix = Some(now_unix);
            CommandExecution {
                outcome: CommandOutcome::Applied,
                status: "completed",
                detail: "device lock requested".to_string(),
            }
        }
        ServerCommand::WipeDevice => {
            state.last_wipe_unix = Some(now_unix);
            CommandExecution {
                outcome: CommandOutcome::Applied,
                status: "completed",
                detail: "device wipe requested".to_string(),
            }
        }
        ServerCommand::RetireDevice => {
            state.last_retire_unix = Some(now_unix);
            CommandExecution {
                outcome: CommandOutcome::Applied,
                status: "completed",
                detail: "device retire requested".to_string(),
            }
        }
        ServerCommand::RestartDevice => {
            state.last_restart_unix = Some(now_unix);
            CommandExecution {
                outcome: CommandOutcome::Applied,
                status: "completed",
                detail: "device restart requested".to_string(),
            }
        }
        ServerCommand::LostMode => {
            state.lost_mode_enabled = true;
            CommandExecution {
                outcome: CommandOutcome::Applied,
                status: "completed",
                detail: "lost mode enabled".to_string(),
            }
        }
        ServerCommand::LocateDevice => {
            state.last_locate_unix = Some(now_unix);
            CommandExecution {
                outcome: CommandOutcome::Applied,
                status: "completed",
                detail: "device locate requested".to_string(),
            }
        }
        ServerCommand::InstallApp => {
            state.last_app_action_unix = Some(now_unix);
            CommandExecution {
                outcome: CommandOutcome::Applied,
                status: "completed",
                detail: "app install requested".to_string(),
            }
        }
        ServerCommand::RemoveApp => {
            state.last_app_action_unix = Some(now_unix);
            CommandExecution {
                outcome: CommandOutcome::Applied,
                status: "completed",
                detail: "app removal requested".to_string(),
            }
        }
        ServerCommand::UpdateApp => {
            state.last_app_action_unix = Some(now_unix);
            CommandExecution {
                outcome: CommandOutcome::Applied,
                status: "completed",
                detail: "app update requested".to_string(),
            }
        }
        ServerCommand::ApplyProfile => {
            state.last_profile_apply_unix = Some(now_unix);
            CommandExecution {
                outcome: CommandOutcome::Applied,
                status: "completed",
                detail: "profile apply requested".to_string(),
            }
        }
        ServerCommand::Unknown => CommandExecution {
            outcome: CommandOutcome::Ignored,
            status: "failed",
            detail: "unknown command type".to_string(),
        },
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_commands;
