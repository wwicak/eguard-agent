use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use detection::Confidence;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseConfig {
    pub autonomous_response: bool,
    pub dry_run: bool,
    pub max_kills_per_minute: usize,
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            autonomous_response: false,
            dry_run: false,
            max_kills_per_minute: 10,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProtectedList {
    process_names: HashSet<String>,
    protected_paths: Vec<PathBuf>,
}

impl ProtectedList {
    pub fn default_linux() -> Self {
        let process_names = [
            "systemd",
            "init",
            "sshd",
            "dbus-daemon",
            "journald",
            "eguard-agent",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();

        let protected_paths = vec![
            PathBuf::from("/usr/bin"),
            PathBuf::from("/lib"),
            PathBuf::from("/usr/lib"),
        ];

        Self {
            process_names,
            protected_paths,
        }
    }

    pub fn is_protected_process(&self, process_name: &str) -> bool {
        self.process_names.contains(process_name)
    }

    pub fn is_protected_path(&self, path: &Path) -> bool {
        self.protected_paths.iter().any(|p| path.starts_with(p))
    }
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
    KillAndQuarantine,
}

pub fn plan_action(confidence: Confidence, config: &ResponseConfig) -> PlannedAction {
    if !config.autonomous_response {
        return PlannedAction::AlertOnly;
    }

    match confidence {
        Confidence::Definite | Confidence::VeryHigh => PlannedAction::KillAndQuarantine,
        Confidence::High => PlannedAction::CaptureScript,
        Confidence::Medium | Confidence::Low | Confidence::None => PlannedAction::AlertOnly,
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
        "emergency_rule_push" => ServerCommand::EmergencyRulePush,
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
mod tests {
    use super::*;

    #[test]
    fn isolate_and_unisolate_change_state() {
        let mut state = HostControlState::default();

        let iso = execute_server_command_with_state(ServerCommand::Isolate, 1, &mut state);
        assert_eq!(iso.status, "completed");
        assert!(state.isolated);

        let uniso = execute_server_command_with_state(ServerCommand::Unisolate, 2, &mut state);
        assert_eq!(uniso.status, "completed");
        assert!(!state.isolated);
    }

    #[test]
    fn unknown_command_is_failed() {
        let mut state = HostControlState::default();
        let result = execute_server_command_with_state(ServerCommand::Unknown, 3, &mut state);
        assert_eq!(result.outcome, CommandOutcome::Ignored);
        assert_eq!(result.status, "failed");
    }

    #[test]
    fn emergency_rule_push_is_recognized() {
        let cmd = parse_server_command("emergency_rule_push");
        assert_eq!(cmd, ServerCommand::EmergencyRulePush);

        let mut state = HostControlState::default();
        let result = execute_server_command_with_state(cmd, 4, &mut state);
        assert_eq!(result.outcome, CommandOutcome::Applied);
        assert_eq!(result.status, "completed");
    }
}
