use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use grpc_client::ZtnaBookmarkListEnvelope;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use super::AgentRuntime;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TrayCommandQueue {
    #[serde(default)]
    commands: Vec<QueuedTrayCommand>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct QueuedTrayCommand {
    id: String,
    created_at_unix: i64,
    command: TrayCommand,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum TrayCommand {
    Disconnect { session_id: String },
    DisconnectAll,
    DisableTransport,
    EnableTransport,
    Refresh,
    OpenApp { app_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct BookmarkState {
    #[serde(default)]
    version: String,
    #[serde(default)]
    bookmarks: Vec<BookmarkEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BookmarkEntry {
    app_id: String,
    name: String,
    #[serde(default)]
    icon: Option<String>,
    app_type: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default = "default_health")]
    health_status: String,
    launch_uri: String,
    #[serde(default)]
    launcher_supported: bool,
    #[serde(default)]
    target_host: Option<String>,
    #[serde(default)]
    target_port: Option<u32>,
    #[serde(default)]
    display_hint: Option<String>,
    #[serde(default)]
    user_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SessionState {
    #[serde(default)]
    sessions: Vec<SessionEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionEntry {
    session_id: String,
    app_id: String,
    #[serde(default)]
    app_name: String,
    #[serde(default)]
    transport: String,
    #[serde(default = "default_status")]
    status: String,
    #[serde(default)]
    started_at: Option<i64>,
    #[serde(default)]
    last_activity_at: Option<i64>,
    #[serde(default)]
    last_outcome: Option<String>,
}

impl AgentRuntime {
    pub(super) async fn sync_tray_state(&mut self, now_unix: i64) -> Result<()> {
        self.apply_tray_commands().await?;
        self.write_tray_bookmark_state().await?;
        self.write_tray_session_state(now_unix)?;
        Ok(())
    }

    async fn apply_tray_commands(&mut self) -> Result<()> {
        let path = command_queue_path()?;
        let mut queue = read_json_or_default::<TrayCommandQueue>(&path)?;
        if queue.commands.is_empty() {
            return Ok(());
        }

        let mut pending = Vec::new();
        for queued in queue.commands.drain(..) {
            if let Err(err) = self.apply_tray_command(&queued.command).await {
                warn!(command_id = %queued.id, error = %err, "failed to apply tray command");
                pending.push(queued);
            }
        }

        queue.commands = pending;
        write_json(&path, &queue)?;
        Ok(())
    }

    async fn write_tray_bookmark_state(&self) -> Result<()> {
        let payload = self.client.fetch_ztna_bookmarks().await?;
        let state = payload
            .as_ref()
            .map(bookmark_state_from_envelope)
            .unwrap_or_default();
        write_json(&bookmark_state_path()?, &state)
    }

    async fn apply_tray_command(&mut self, command: &TrayCommand) -> Result<()> {
        match command {
            TrayCommand::Disconnect { session_id } => {
                if self.ztna_last_session_id.as_deref() == Some(session_id.as_str()) {
                    self.stop_ztna_session(Some("disconnected from tray request"))
                        .await;
                } else {
                    info!(requested_session_id = %session_id, active_session_id = ?self.ztna_last_session_id, "ignoring tray disconnect for inactive session");
                }
            }
            TrayCommand::DisconnectAll => {
                self.stop_ztna_session(Some("all sessions disconnected from tray request"))
                    .await;
            }
            TrayCommand::DisableTransport => {
                self.config.transport_mode = "http".to_string();
                self.stop_ztna_session(Some("transport disabled from tray request"))
                    .await;
                info!(transport = %self.config.transport_mode, "applied tray transport disable");
            }
            TrayCommand::EnableTransport => {
                self.config.transport_mode = "grpc".to_string();
                info!(transport = %self.config.transport_mode, "applied tray transport enable");
            }
            TrayCommand::Refresh => {
                info!("received tray refresh request");
            }
            TrayCommand::OpenApp { app_id } => {
                let app_id = app_id.trim();
                if !app_id.is_empty() {
                    self.config.ztna_app_id = Some(app_id.to_string());
                    self.stop_ztna_session(Some("switching app from tray request"))
                        .await;
                    info!(app_id, "queued tray open app request into runtime");
                }
            }
        }
        Ok(())
    }

    fn write_tray_session_state(&self, now_unix: i64) -> Result<()> {
        let mut sessions = Vec::new();
        if self.ztna_forward.is_some() {
            let app_id = self
                .config
                .ztna_app_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("ztna-app")
                .to_string();
            let session_id = self
                .ztna_last_session_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("pending")
                .to_string();
            sessions.push(SessionEntry {
                session_id,
                app_id: app_id.clone(),
                app_name: app_id,
                transport: "wireguard".to_string(),
                status: "active".to_string(),
                started_at: self.ztna_last_request_unix,
                last_activity_at: Some(
                    self.ztna_forward
                        .as_ref()
                        .map(|forward| forward.last_activity_unix())
                        .filter(|value| *value > 0)
                        .unwrap_or(now_unix),
                ),
                last_outcome: self.ztna_last_outcome.clone(),
            });
        }

        write_json(
            &session_state_path()?,
            &SessionState { sessions },
        )
    }

    pub(super) async fn stop_ztna_session(&mut self, reason: Option<&str>) {
        if let Some(handle) = self.ztna_forward.take() {
            handle.stop().await;
        }
        self.release_ztna_session(reason.unwrap_or("session stopped")).await;
        self.ztna_last_session_id = None;
        if let Some(reason) = reason {
            info!(reason, "ztna session stopped");
        }
    }
}

fn session_state_path() -> Result<PathBuf> {
    Ok(tray_data_root()?.join("ztna-sessions.json"))
}

fn bookmark_state_path() -> Result<PathBuf> {
    Ok(tray_data_root()?.join("ztna-bookmarks.json"))
}

fn command_queue_path() -> Result<PathBuf> {
    Ok(tray_data_root()?.join("ztna-tray-commands.json"))
}

fn tray_data_root() -> Result<PathBuf> {
    if let Ok(raw) = std::env::var("EGUARD_TRAY_DATA_DIR") {
        if !raw.trim().is_empty() {
            let path = PathBuf::from(raw.trim());
            fs::create_dir_all(&path)
                .with_context(|| format!("create tray data dir {}", path.display()))?;
            return Ok(path);
        }
    }

    #[cfg(target_os = "windows")]
    {
        let path = PathBuf::from(r"C:\ProgramData\eGuard\tray");
        fs::create_dir_all(&path).with_context(|| format!("create tray data dir {}", path.display()))?;
        return Ok(path);
    }

    let base = dirs::data_local_dir().ok_or_else(|| anyhow::anyhow!("resolve local data dir"))?;
    let path = base.join("eGuard").join("tray");
    fs::create_dir_all(&path).with_context(|| format!("create tray data dir {}", path.display()))?;
    Ok(path)
}

fn read_json_or_default<T>(path: &PathBuf) -> Result<T>
where
    T: serde::de::DeserializeOwned + Default,
{
    if !path.exists() {
        return Ok(T::default());
    }
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
}

fn write_json<T>(path: &PathBuf, value: &T) -> Result<()>
where
    T: Serialize,
{
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let raw = serde_json::to_string_pretty(value)?;
    fs::write(path, raw).with_context(|| format!("write {}", path.display()))
}

fn default_status() -> String {
    "active".to_string()
}

fn default_health() -> String {
    "unknown".to_string()
}

fn bookmark_state_from_envelope(payload: &ZtnaBookmarkListEnvelope) -> BookmarkState {
    BookmarkState {
        version: payload.version.clone(),
        bookmarks: payload
            .bookmarks
            .iter()
            .map(|bookmark| BookmarkEntry {
                app_id: bookmark.app_id.clone(),
                name: bookmark.name.clone(),
                icon: if bookmark.icon.trim().is_empty() {
                    None
                } else {
                    Some(bookmark.icon.clone())
                },
                app_type: bookmark.app_type.clone(),
                description: if bookmark.description.trim().is_empty() {
                    None
                } else {
                    Some(bookmark.description.clone())
                },
                health_status: if bookmark.health_status.trim().is_empty() {
                    default_health()
                } else {
                    bookmark.health_status.clone()
                },
                launch_uri: bookmark.launch_uri.clone(),
                launcher_supported: bookmark.launcher_supported,
                target_host: if bookmark.target_host.trim().is_empty() {
                    None
                } else {
                    Some(bookmark.target_host.clone())
                },
                target_port: if bookmark.target_port == 0 {
                    None
                } else {
                    Some(bookmark.target_port)
                },
                display_hint: if bookmark.display_hint.trim().is_empty() {
                    None
                } else {
                    Some(bookmark.display_hint.clone())
                },
                user_hint: if bookmark.user_hint.trim().is_empty() {
                    None
                } else {
                    Some(bookmark.user_hint.clone())
                },
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{bookmark_state_path, command_queue_path, session_state_path, read_json_or_default, BookmarkState, SessionState, TrayCommand, TrayCommandQueue};
    use crate::config::AgentConfig;
    use crate::lifecycle::{shared_env_var_lock, AgentRuntime};
    use grpc_client::{ZtnaBookmarkEnvelope, ZtnaBookmarkListEnvelope};
    use ztna::LocalForwardManager;

    #[tokio::test]
    async fn sync_tray_state_writes_active_session_cache() {
        let _guard = shared_env_var_lock().lock().expect("env lock");
        let tray_dir = std::env::temp_dir().join("eguard-agent-tray-sync-session");
        let _ = fs::remove_dir_all(&tray_dir);
        std::env::set_var("EGUARD_TRAY_DATA_DIR", &tray_dir);

        let mut cfg = AgentConfig::default();
        cfg.ztna_enabled = true;
        cfg.ztna_app_id = Some("rdp-prod".to_string());
        let mut runtime = AgentRuntime::new(cfg).expect("runtime");
        runtime.ztna_last_request_unix = Some(1_700_000_000);
        runtime.ztna_last_session_id = Some("session-123".to_string());
        runtime.ztna_forward = Some(start_test_forward().await);

        runtime.sync_tray_state(1_700_000_100).await.expect("sync tray state");

        let state: SessionState =
            read_json_or_default(&session_state_path().expect("session path")).expect("read session state");
        assert_eq!(state.sessions.len(), 1);
        assert_eq!(state.sessions[0].session_id, "session-123");
        assert_eq!(state.sessions[0].app_id, "rdp-prod");
    }

    #[tokio::test]
    async fn sync_tray_state_writes_bookmark_cache() {
        let _guard = shared_env_var_lock().lock().expect("env lock");
        let tray_dir = std::env::temp_dir().join("eguard-agent-tray-sync-bookmarks");
        let _ = fs::remove_dir_all(&tray_dir);
        std::env::set_var("EGUARD_TRAY_DATA_DIR", &tray_dir);

        let cfg = AgentConfig::default();
        let mut runtime = AgentRuntime::new(cfg).expect("runtime");
        runtime.client.set_cached_ztna_bookmarks(Some(ZtnaBookmarkListEnvelope {
            version: "v1".to_string(),
            generated_at_unix: 1_700_000_000,
            bookmarks: vec![ZtnaBookmarkEnvelope {
                app_id: "app-1".to_string(),
                name: "Prod SSH".to_string(),
                icon: "terminal".to_string(),
                app_type: "ssh".to_string(),
                description: "Production jump host".to_string(),
                health_status: "healthy".to_string(),
                launch_uri: "eguard-ztna://launch?app_id=app-1&app_type=ssh&target=host".to_string(),
                launcher_supported: true,
                target_host: "host".to_string(),
                target_port: 22,
                display_hint: String::new(),
                user_hint: "admin".to_string(),
            }],
        }));

        runtime.sync_tray_state(1_700_000_100).await.expect("sync tray state");

        let state: BookmarkState =
            read_json_or_default(&bookmark_state_path().expect("bookmark path")).expect("read bookmark state");
        assert_eq!(state.version, "v1");
        assert_eq!(state.bookmarks.len(), 1);
        assert_eq!(state.bookmarks[0].app_id, "app-1");
        assert_eq!(state.bookmarks[0].app_type, "ssh");
    }

    #[tokio::test]
    async fn sync_tray_state_drains_disconnect_all_command() {
        let _guard = shared_env_var_lock().lock().expect("env lock");
        let tray_dir = std::env::temp_dir().join("eguard-agent-tray-sync-disconnect");
        let _ = fs::remove_dir_all(&tray_dir);
        std::env::set_var("EGUARD_TRAY_DATA_DIR", &tray_dir);

        let mut cfg = AgentConfig::default();
        cfg.ztna_enabled = true;
        cfg.ztna_app_id = Some("ssh-prod".to_string());
        let mut runtime = AgentRuntime::new(cfg).expect("runtime");
        runtime.ztna_last_session_id = Some("session-456".to_string());
        runtime.ztna_forward = Some(start_test_forward().await);

        let queue = TrayCommandQueue {
            commands: vec![super::QueuedTrayCommand {
                id: "cmd-1".to_string(),
                created_at_unix: 1,
                command: TrayCommand::DisconnectAll,
            }],
        };
        super::write_json(&command_queue_path().expect("queue path"), &queue).expect("write queue");

        runtime.sync_tray_state(1_700_000_200).await.expect("sync tray state");

        let queue: TrayCommandQueue =
            read_json_or_default(&command_queue_path().expect("queue path")).expect("read queue");
        let state: SessionState =
            read_json_or_default(&session_state_path().expect("session path")).expect("read session state");
        assert!(queue.commands.is_empty());
        assert!(state.sessions.is_empty());
        assert!(runtime.ztna_forward.is_none());
        assert!(runtime.ztna_last_session_id.is_none());
    }

    async fn start_test_forward() -> ztna::LocalForwardHandle {
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream listener");
        let upstream_addr = upstream.local_addr().expect("upstream local addr");
        let _upstream_task = tokio::spawn(async move {
            let _listener = upstream;
            std::future::pending::<()>().await;
        });

        LocalForwardManager
            .start(
                "127.0.0.1:0".parse().expect("listen addr"),
                upstream_addr.to_string(),
            )
            .await
            .expect("start local forward")
    }
}
