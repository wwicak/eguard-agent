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

/// Persist the durable isolation recovery record. Returns `Err` if the state
/// could not be written, so callers can refuse to isolate when no recovery
/// record exists. This MUST be called before the firewall is activated: if the
/// agent crashes mid-apply, the failsafe can only tear isolation down when a
/// durable record is already on disk. A stale record with no active firewall is
/// harmless — the failsafe removal is idempotent.
pub(in crate::lifecycle) fn save_isolation_state(allowed_ips: &[String]) -> Result<(), String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    // Anchor the failsafe deadline to the FIRST isolation: if a valid record
    // already exists, preserve its isolated_at_unix so repeated isolate commands
    // cannot keep pushing the auto-recovery deadline out (indefinite lockout).
    let isolated_at_unix = read_isolation_state()
        .map(|prev| prev.isolated_at_unix)
        .unwrap_or(now);
    let state = IsolationState {
        isolated: true,
        isolated_at_unix,
        allowed_ips: allowed_ips.to_vec(),
        failsafe_timeout_secs: failsafe_timeout_secs(),
    };
    let path = isolation_state_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let json = serde_json::to_string_pretty(&state)
        .map_err(|err| format!("serialize isolation state: {err}"))?;

    // Write atomically and durably: a torn/truncated recovery record parses as
    // None and would silently disable failsafe recovery. Write a temp file,
    // fsync it, rename over the target, then fsync the directory.
    let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
    let write_tmp = || -> std::io::Result<()> {
        let mut f = fs::File::create(&tmp)?;
        std::io::Write::write_all(&mut f, json.as_bytes())?;
        f.sync_all()?;
        Ok(())
    };
    if let Err(err) = write_tmp() {
        let _ = fs::remove_file(&tmp);
        error!(path = %path.display(), error = %err, "failed to write isolation state temp file");
        return Err(format!(
            "write isolation state temp {}: {err}",
            tmp.display()
        ));
    }
    if let Err(err) = fs::rename(&tmp, &path) {
        let _ = fs::remove_file(&tmp);
        error!(path = %path.display(), error = %err, "failed to persist isolation state");
        return Err(format!("rename isolation state {}: {err}", path.display()));
    }
    // Make the rename itself durable by fsync'ing the parent directory. On
    // Unix this is required for the fail-closed durability contract, so its
    // failure is propagated. On Windows a directory handle cannot be opened via
    // std::fs and NTFS metadata journaling makes the rename durable, so the
    // step is Unix-only.
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            let dir = fs::File::open(parent)
                .map_err(|err| format!("open isolation state dir {}: {err}", parent.display()))?;
            dir.sync_all()
                .map_err(|err| format!("fsync isolation state dir {}: {err}", parent.display()))?;
        }
    }
    info!(path = %path.display(), "persisted isolation state");
    Ok(())
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
///
/// Returns `true` only if the platform reported the firewall rules were
/// successfully removed. Callers MUST NOT clear the durable isolation state or
/// mark the host unisolated when this returns `false`: doing so would erase the
/// recovery record while the host is still cut off, stranding it permanently.
/// Leaving the state intact lets the periodic failsafe retry the removal.
#[must_use]
pub(in crate::lifecycle) fn force_remove_isolation() -> bool {
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        super::host_isolation_linux::remove_linux_host_isolation().is_ok()
    }
    #[cfg(target_os = "windows")]
    {
        platform_windows::response::remove_isolation().is_ok()
    }
    #[cfg(target_os = "macos")]
    {
        platform_macos::response::remove_isolation().is_ok()
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
    fn save_persists_recovery_record_before_read_and_clear_removes_it() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let dir = std::env::temp_dir().join(format!(
            "eguard-iso-state-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = fs::create_dir_all(&dir);
        std::env::set_var("EGUARD_AGENT_DATA_DIR", &dir);

        // Persisting succeeds and produces a durable, readable recovery record
        // (this is what the failsafe relies on and must exist BEFORE the
        // firewall is applied).
        assert!(save_isolation_state(&["10.0.0.5".to_string()]).is_ok());
        let state = read_isolation_state().expect("state must be readable after save");
        assert!(state.isolated);
        assert_eq!(state.allowed_ips, vec!["10.0.0.5".to_string()]);

        // Rollback (used when firewall apply fails) removes the record so a
        // failed isolate does not leave a phantom "isolated" state behind.
        clear_isolation_state();
        assert!(read_isolation_state().is_none());

        std::env::remove_var("EGUARD_AGENT_DATA_DIR");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_preserves_original_isolated_at_unix_across_reisolate() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let dir = std::env::temp_dir().join(format!(
            "eguard-iso-ts-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = fs::create_dir_all(&dir);
        std::env::set_var("EGUARD_AGENT_DATA_DIR", &dir);

        // Seed a record with an OLD isolation timestamp, as if the host had been
        // isolated a while ago.
        let old = IsolationState {
            isolated: true,
            isolated_at_unix: 1_000,
            allowed_ips: vec!["10.0.0.5".to_string()],
            failsafe_timeout_secs: 14400,
        };
        fs::write(
            isolation_state_path(),
            serde_json::to_string_pretty(&old).unwrap(),
        )
        .unwrap();

        // A repeated isolate (new allowlist) must NOT reset the failsafe clock.
        assert!(save_isolation_state(&["10.0.0.6".to_string()]).is_ok());
        let state = read_isolation_state().expect("state");
        assert_eq!(
            state.isolated_at_unix, 1_000,
            "re-isolate must preserve the original deadline anchor"
        );
        assert_eq!(state.allowed_ips, vec!["10.0.0.6".to_string()]);

        std::env::remove_var("EGUARD_AGENT_DATA_DIR");
        let _ = fs::remove_dir_all(&dir);
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
