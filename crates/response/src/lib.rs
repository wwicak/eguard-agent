mod capture;
mod errors;
mod kill;
mod quarantine;

use std::collections::VecDeque;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use regex::Regex;
use serde::{Deserialize, Serialize};

use detection::Confidence;

pub use capture::{capture_script_content, ScriptCapture};
pub use errors::{ResponseError, ResponseResult};
pub use kill::{
    kill_process_tree, kill_process_tree_with, KillReport, NixSignalSender, ProcessIntrospector,
    ProcfsIntrospector, SignalSender,
};
pub use quarantine::{
    quarantine_file, quarantine_file_with_dir, restore_quarantined, QuarantineReport, RestoreReport,
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
    pub max_kills_per_minute: usize,
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
        Self {
            autonomous_response: false,
            dry_run: false,
            max_kills_per_minute: 10,
            auto_isolation: AutoIsolationPolicy::default(),
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
            PathBuf::from("/usr/bin"),
            PathBuf::from("/usr/sbin"),
            PathBuf::from("/lib"),
            PathBuf::from("/usr/lib"),
            PathBuf::from("/boot"),
            PathBuf::from("/usr/local/eg"),
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
        self.protected_paths
            .iter()
            .any(|p| normalized.starts_with(normalize_path(p)))
    }
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
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

fn looks_like_regex(raw: &str) -> bool {
    raw.chars().any(|c| {
        matches!(
            c,
            '^' | '$' | '.' | '*' | '+' | '?' | '[' | ']' | '(' | ')' | '{' | '}' | '|'
        )
    })
}

#[derive(Debug)]
pub struct KillRateLimiter {
    max_kills_per_minute: usize,
    kill_timestamps: VecDeque<Instant>,
}

impl KillRateLimiter {
    pub fn new(max_kills_per_minute: usize) -> Self {
        Self {
            max_kills_per_minute,
            kill_timestamps: VecDeque::new(),
        }
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
}

#[derive(Debug, Clone)]
pub struct CommandExecution {
    pub outcome: CommandOutcome,
    pub status: &'static str,
    pub detail: String,
}

pub fn parse_server_command(raw: &str) -> ServerCommand {
    match raw.trim().to_ascii_lowercase().as_str() {
        "isolate" => ServerCommand::Isolate,
        "unisolate" => ServerCommand::Unisolate,
        "scan" => ServerCommand::Scan,
        "update" => ServerCommand::Update,
        "forensics" => ServerCommand::Forensics,
        "config_change" => ServerCommand::ConfigChange,
        "uninstall" => ServerCommand::Uninstall,
        "restore_quarantine" => ServerCommand::RestoreQuarantine,
        "emergency_rule_push" | "push_emergency_rule" => ServerCommand::EmergencyRulePush,
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
            state.uninstall_requested = true;
            CommandExecution {
                outcome: CommandOutcome::Applied,
                status: "completed",
                detail: "uninstall request flagged".to_string(),
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
