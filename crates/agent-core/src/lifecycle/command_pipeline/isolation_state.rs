use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

const STATE_FILENAME: &str = "isolation-state.json";
const DEFAULT_FAILSAFE_TIMEOUT_SECS: i64 = 14400; // 4 hours

#[derive(Debug, Serialize, Deserialize)]
pub(in crate::lifecycle) struct IsolationState {
    pub isolated: bool,
    pub isolated_at_unix: i64,
    pub allowed_ips: Vec<String>,
    pub failsafe_timeout_secs: i64,
}

fn isolation_state_path() -> PathBuf {
    if let Ok(dir) = std::env::var("EGUARD_AGENT_DATA_DIR") {
        return PathBuf::from(dir).join(STATE_FILENAME);
    }
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\ProgramData\eGuard").join(STATE_FILENAME)
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/eGuard").join(STATE_FILENAME)
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        PathBuf::from("/var/lib/eguard-agent").join(STATE_FILENAME)
    }
}

fn failsafe_timeout_secs() -> i64 {
    std::env::var("EGUARD_ISOLATION_FAILSAFE_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(DEFAULT_FAILSAFE_TIMEOUT_SECS)
}

pub(in crate::lifecycle) fn save_isolation_state(allowed_ips: &[String]) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let state = IsolationState {
        isolated: true,
        isolated_at_unix: now,
        allowed_ips: allowed_ips.to_vec(),
        failsafe_timeout_secs: failsafe_timeout_secs(),
    };
    let path = isolation_state_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    match serde_json::to_string_pretty(&state) {
        Ok(json) => {
            if let Err(err) = fs::write(&path, json) {
                error!(
                    path = %path.display(),
                    error = %err,
                    "failed to persist isolation state"
                );
            } else {
                info!(path = %path.display(), "persisted isolation state");
            }
        }
        Err(err) => error!(error = %err, "failed to serialize isolation state"),
    }
}

pub(in crate::lifecycle) fn clear_isolation_state() {
    let path = isolation_state_path();
    if path.exists() {
        if let Err(err) = fs::remove_file(&path) {
            warn!(
                path = %path.display(),
                error = %err,
                "failed to remove isolation state file"
            );
        } else {
            info!(path = %path.display(), "cleared isolation state file");
        }
    }
}

pub(in crate::lifecycle) fn read_isolation_state() -> Option<IsolationState> {
    let path = isolation_state_path();
    if !path.exists() {
        return None;
    }
    match fs::read_to_string(&path) {
        Ok(contents) => match serde_json::from_str::<IsolationState>(&contents) {
            Ok(state) if state.isolated => Some(state),
            Ok(_) => None,
            Err(err) => {
                warn!(
                    path = %path.display(),
                    error = %err,
                    "failed to parse isolation state"
                );
                None
            }
        },
        Err(err) => {
            warn!(
                path = %path.display(),
                error = %err,
                "failed to read isolation state"
            );
            None
        }
    }
}

/// Returns true if the isolation failsafe timeout has expired.
pub(in crate::lifecycle) fn is_failsafe_expired(state: &IsolationState, now_unix: i64) -> bool {
    let timeout = if state.failsafe_timeout_secs > 0 {
        state.failsafe_timeout_secs
    } else {
        failsafe_timeout_secs()
    };
    now_unix - state.isolated_at_unix > timeout
}

/// Remove host isolation on the current platform. This is used by the
/// failsafe recovery path in runtime.rs and tick.rs where direct access
/// to the platform-specific removal functions is not available.
pub(in crate::lifecycle) fn force_remove_isolation() {
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = super::host_isolation_linux::remove_linux_host_isolation();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = platform_windows::response::remove_isolation();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = platform_macos::response::remove_isolation();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failsafe_expired_after_timeout() {
        let state = IsolationState {
            isolated: true,
            isolated_at_unix: 1000,
            allowed_ips: vec!["10.0.0.1".to_string()],
            failsafe_timeout_secs: 3600,
        };
        assert!(!is_failsafe_expired(&state, 2000));
        assert!(is_failsafe_expired(&state, 5000));
    }

    #[test]
    fn failsafe_not_expired_within_window() {
        let state = IsolationState {
            isolated: true,
            isolated_at_unix: 1000,
            allowed_ips: vec![],
            failsafe_timeout_secs: 14400,
        };
        assert!(!is_failsafe_expired(&state, 1000));
        assert!(!is_failsafe_expired(&state, 15399));
        assert!(is_failsafe_expired(&state, 15401));
    }
}
