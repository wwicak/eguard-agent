use anyhow::Result;
use grpc_client::ZtnaSessionEnvelope;
use ztna::{
    default_session_state_path, empty_session_state, read_session_state, remove_session,
    write_session_state, ActiveSessionRecord, SessionState,
};

use super::AgentRuntime;

impl AgentRuntime {
    pub(super) fn current_ztna_sessions(&self) -> Vec<ZtnaSessionEnvelope> {
        let path = default_session_state_path();
        let state = read_session_state(&path).unwrap_or_else(|_| empty_session_state());
        state
            .sessions
            .into_iter()
            .filter(|session| session.status.trim().eq_ignore_ascii_case("active"))
            .map(|session| ZtnaSessionEnvelope {
                session_id: session.session_id,
                app_id: session.app_id,
                tunnel_ip: String::new(),
                transport: session.transport,
                bytes_tx: 0,
                bytes_rx: 0,
                active_connections: 0,
                tunnel_latency_ms: 0,
                started_at_unix: session.started_at_unix,
            })
            .collect()
    }

    pub(super) fn current_ztna_bookmark_version(&self) -> String {
        self.client
            .latest_ztna_bookmarks()
            .map(|bookmarks| bookmarks.version)
            .unwrap_or_default()
    }

    pub(super) fn sync_ztna_sessions(&self) -> Result<()> {
        let path = default_session_state_path();
        let mut state = read_session_state(&path).unwrap_or_else(|_| empty_session_state());
        let current = self.current_ztna_sessions();
        state.sessions = current
            .into_iter()
            .map(|session| ActiveSessionRecord {
                session_id: session.session_id,
                app_id: session.app_id.clone(),
                name: session.app_id,
                app_type: String::new(),
                launch_uri: String::new(),
                transport: session.transport,
                started_at_unix: session.started_at_unix,
                last_activity_at_unix: session.started_at_unix,
                status: "active".to_string(),
            })
            .collect();
        self.apply_ztna_revocations(&mut state);
        write_session_state(&path, &state)
    }

    fn apply_ztna_revocations(&self, state: &mut SessionState) {
        for revoke in self.client.latest_ztna_revocations() {
            let _ = remove_session(state, &revoke.session_id);
        }
    }
}
