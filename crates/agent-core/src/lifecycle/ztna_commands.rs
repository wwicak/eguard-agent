use anyhow::Result;
use ztna::{
    clear_sessions, default_command_queue_dir, default_session_state_path, drain_commands,
    empty_session_state, read_session_state, remove_session, set_transport_disabled,
    write_session_state, TrayCommandKind, TrayCommandResult,
};

use super::AgentRuntime;

impl AgentRuntime {
    pub(super) async fn process_ztna_commands(&mut self) -> Result<()> {
        let commands = drain_commands(&default_command_queue_dir())?;
        if commands.is_empty() {
            return Ok(());
        }
        let path = default_session_state_path();
        let mut state = read_session_state(&path).unwrap_or_else(|_| empty_session_state());
        for command in commands {
            let result = match command.kind {
                TrayCommandKind::DisconnectSession { session_id } => {
                    let released = self
                        .client
                        .release_ztna_tunnel(&session_id, "user_disconnect", "tray_disconnect")
                        .await
                        .unwrap_or(false);
                    if released {
                        let _ = remove_session(&mut state, &session_id);
                        TrayCommandResult {
                            command_id: command.command_id.clone(),
                            created_at_unix: command.created_at_unix,
                            success: true,
                            message: format!("Disconnected session {}", session_id),
                        }
                    } else {
                        TrayCommandResult {
                            command_id: command.command_id.clone(),
                            created_at_unix: command.created_at_unix,
                            success: false,
                            message: format!("Failed to disconnect session {}", session_id),
                        }
                    }
                }
                TrayCommandKind::DisconnectAll => {
                    let session_ids = state
                        .sessions
                        .iter()
                        .map(|session| session.session_id.clone())
                        .collect::<Vec<_>>();
                    let mut failed = Vec::new();
                    for session_id in session_ids {
                        let released = self
                            .client
                            .release_ztna_tunnel(
                                &session_id,
                                "user_disconnect",
                                "tray_disconnect_all",
                            )
                            .await
                            .unwrap_or(false);
                        if released {
                            let _ = remove_session(&mut state, &session_id);
                        } else {
                            failed.push(session_id);
                        }
                    }
                    TrayCommandResult {
                        command_id: command.command_id.clone(),
                        created_at_unix: command.created_at_unix,
                        success: failed.is_empty(),
                        message: if failed.is_empty() {
                            "Disconnected all sessions".to_string()
                        } else {
                            format!("Failed to disconnect sessions: {}", failed.join(", "))
                        },
                    }
                }
                TrayCommandKind::DisableTransport => {
                    let session_ids = state
                        .sessions
                        .iter()
                        .map(|session| session.session_id.clone())
                        .collect::<Vec<_>>();
                    let mut failed = Vec::new();
                    for session_id in session_ids {
                        let released = self
                            .client
                            .release_ztna_tunnel(
                                &session_id,
                                "user_disconnect",
                                "tray_managed_transport_disable",
                            )
                            .await
                            .unwrap_or(false);
                        if released {
                            let _ = remove_session(&mut state, &session_id);
                        } else {
                            failed.push(session_id);
                        }
                    }
                    if failed.is_empty() {
                        set_transport_disabled(&mut state, true, "managed_transport_disable");
                    }
                    TrayCommandResult {
                        command_id: command.command_id.clone(),
                        created_at_unix: command.created_at_unix,
                        success: failed.is_empty(),
                        message: if failed.is_empty() {
                            "ZTNA transport disabled after successful session drain".to_string()
                        } else {
                            format!(
                                "Transport disable blocked; failed to drain sessions: {}",
                                failed.join(", ")
                            )
                        },
                    }
                }
                TrayCommandKind::EnableTransport => {
                    set_transport_disabled(&mut state, false, String::new());
                    TrayCommandResult {
                        command_id: command.command_id.clone(),
                        created_at_unix: command.created_at_unix,
                        success: true,
                        message: "ZTNA transport enabled".to_string(),
                    }
                }
            };
            state.command_results.insert(0, result);
            if state.command_results.len() > 20 {
                state.command_results.truncate(20);
            }
        }
        write_session_state(&path, &state)
    }
}
