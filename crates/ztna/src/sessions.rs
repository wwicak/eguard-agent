use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use crate::types::{ActiveSessionRecord, SessionState};

pub fn read_session_state(path: &Path) -> Result<SessionState> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed reading session state {}", path.display()))?;
    let state = serde_json::from_str::<SessionState>(&raw)
        .with_context(|| format!("failed parsing session state {}", path.display()))?;
    Ok(state)
}

pub fn write_session_state(path: &Path, state: &SessionState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed creating session state dir {}", parent.display()))?;
    }
    let body = serde_json::to_string_pretty(state)?;
    fs::write(path, body)
        .with_context(|| format!("failed writing session state {}", path.display()))?;
    Ok(())
}

pub fn default_session_state_path() -> PathBuf {
    if let Ok(raw) = std::env::var("EGUARD_ZTNA_SESSION_STATE") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    #[cfg(target_os = "linux")]
    {
        return PathBuf::from("/var/lib/eguard-agent/ztna-sessions.json");
    }
    #[cfg(target_os = "macos")]
    {
        return PathBuf::from("/Library/Application Support/eGuard/ztna-sessions.json");
    }
    #[cfg(target_os = "windows")]
    {
        return PathBuf::from(r"C:\ProgramData\eGuard\ztna-sessions.json");
    }
    #[allow(unreachable_code)]
    PathBuf::from("ztna-sessions.json")
}

pub fn empty_session_state() -> SessionState {
    SessionState {
        updated_at_unix: now_unix(),
        ..SessionState::default()
    }
}

pub fn session_by_id<'a>(
    state: &'a SessionState,
    session_id: &str,
) -> Option<&'a ActiveSessionRecord> {
    state
        .sessions
        .iter()
        .find(|session| session.session_id == session_id)
}

pub fn upsert_session(state: &mut SessionState, session: ActiveSessionRecord) {
    if let Some(slot) = state
        .sessions
        .iter_mut()
        .find(|existing| existing.session_id == session.session_id)
    {
        *slot = session;
    } else {
        state.sessions.push(session);
    }
    state.updated_at_unix = now_unix();
}

pub fn remove_session(state: &mut SessionState, session_id: &str) -> bool {
    let before = state.sessions.len();
    state
        .sessions
        .retain(|session| session.session_id != session_id);
    let changed = before != state.sessions.len();
    if changed {
        state.updated_at_unix = now_unix();
    }
    changed
}

pub fn clear_sessions(state: &mut SessionState) -> usize {
    let count = state.sessions.len();
    state.sessions.clear();
    state.updated_at_unix = now_unix();
    count
}

pub fn set_transport_disabled(state: &mut SessionState, disabled: bool, reason: impl Into<String>) {
    state.transport_disabled = disabled;
    state.transport_disable_reason = reason.into();
    state.updated_at_unix = now_unix();
}

pub fn next_session_id(app_id: &str) -> String {
    format!("tray-{}-{}", sanitize(app_id), now_unix())
}

fn sanitize(value: &str) -> String {
    let filtered = value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>();
    filtered.trim_matches('-').to_string()
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{
        clear_sessions, empty_session_state, next_session_id, remove_session, upsert_session,
    };
    use crate::types::ActiveSessionRecord;

    #[test]
    fn session_state_helpers_work() {
        let mut state = empty_session_state();
        let session_id = next_session_id("app-1");
        upsert_session(
            &mut state,
            ActiveSessionRecord {
                session_id: session_id.clone(),
                app_id: "app-1".to_string(),
                ..ActiveSessionRecord::default()
            },
        );
        assert_eq!(state.sessions.len(), 1);
        assert!(remove_session(&mut state, &session_id));
        assert_eq!(state.sessions.len(), 0);
        upsert_session(
            &mut state,
            ActiveSessionRecord {
                session_id,
                app_id: "app-1".to_string(),
                ..ActiveSessionRecord::default()
            },
        );
        assert_eq!(clear_sessions(&mut state), 1);
    }
}
