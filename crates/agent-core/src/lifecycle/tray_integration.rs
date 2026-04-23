use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use grpc_client::ZtnaBookmarkListEnvelope;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use tokio::time::{timeout, Duration};
use tracing::{info, warn};
use ztna::TunnelClientConfig;

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
    Disconnect {
        session_id: String,
    },
    DisconnectAll,
    DisableTransport,
    EnableTransport,
    Refresh,
    OpenApp {
        app_id: String,
        #[serde(default)]
        forward_host: Option<String>,
        #[serde(default)]
        forward_port: Option<u16>,
    },
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
    #[serde(default)]
    local_url: Option<String>,
    #[serde(default)]
    bytes_tx: Option<i64>,
    #[serde(default)]
    bytes_rx: Option<i64>,
    #[serde(default)]
    active_connections: Option<i32>,
    #[serde(default)]
    tunnel_latency_ms: Option<i32>,
}

impl AgentRuntime {
    pub(super) async fn apply_pending_tray_commands(&mut self) -> Result<()> {
        self.apply_tray_commands().await
    }

    pub(super) async fn sync_tray_state(&mut self, now_unix: i64) -> Result<()> {
        self.apply_tray_commands().await?;
        self.write_tray_bookmark_state().await?;
        self.write_tray_session_state(now_unix).await?;
        Ok(())
    }

    async fn apply_tray_commands(&mut self) -> Result<()> {
        let path = command_queue_path()?;
        if std::env::var("EGUARD_DEBUG_TICK_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some()
        {
            info!(path = %path.display(), "tray command queue load start");
        }
        let mut queue = read_json_or_default::<TrayCommandQueue>(&path)?;
        if std::env::var("EGUARD_DEBUG_TICK_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some()
        {
            info!(path = %path.display(), command_count = queue.commands.len(), "tray command queue load complete");
        }
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
        if std::env::var("EGUARD_DEBUG_TICK_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some()
        {
            info!(path = %path.display(), pending_count = queue.commands.len(), "tray command queue write start");
        }
        write_json(&path, &queue)?;
        if std::env::var("EGUARD_DEBUG_TICK_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some()
        {
            info!(path = %path.display(), pending_count = queue.commands.len(), "tray command queue write complete");
        }
        Ok(())
    }

    async fn write_tray_bookmark_state(&mut self) -> Result<()> {
        let path = bookmark_state_path()?;
        let payload = match timeout(Duration::from_secs(3), self.client.fetch_ztna_bookmarks()).await {
            Ok(Ok(payload)) => payload,
            Ok(Err(err)) => {
                warn!(error = %err, "failed to fetch ztna bookmarks for tray cache");
                if path.exists() && !self.tray_bookmark_refresh_pending {
                    return Ok(());
                }
                None
            }
            Err(_) => {
                warn!("timed out fetching ztna bookmarks for tray cache");
                if path.exists() && !self.tray_bookmark_refresh_pending {
                    return Ok(());
                }
                None
            }
        };
        let Some(payload) = payload else {
            if path.exists() && !self.tray_bookmark_refresh_pending {
                return Ok(());
            }
            return write_json(&path, &BookmarkState::default());
        };
        let state = bookmark_state_from_envelope(&payload);
        self.tray_bookmark_refresh_pending = false;
        write_json(&path, &state)
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
                self.config.ztna_app_id = None;
                self.config.ztna_forward_host = None;
                self.config.ztna_forward_port = None;
                self.ztna_last_request_unix = None;
                self.stop_ztna_session(Some("all sessions disconnected from tray request"))
                    .await;
                info!("cleared active ztna target from disconnect all request");
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
                self.client.set_cached_ztna_bookmarks(None);
                self.last_heartbeat_attempt_unix = None;
                self.tray_bookmark_refresh_pending = true;
                info!("received tray refresh request and forced bookmark refresh");
            }
            TrayCommand::OpenApp {
                app_id,
                forward_host,
                forward_port,
            } => {
                let app_id = app_id.trim();
                if !app_id.is_empty() {
                    let requested_forward_host = forward_host
                        .as_deref()
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_string);
                    let requested_forward_port = *forward_port;
                    let same_app_active = self.ztna_last_session_id.is_some()
                        && self.ztna_last_app_id.as_deref().map(str::trim) == Some(app_id)
                        && self.config.ztna_forward_host == requested_forward_host
                        && self.config.ztna_forward_port == requested_forward_port;
                    if same_app_active {
                        info!(app_id, forward_host = ?requested_forward_host, forward_port = ?requested_forward_port, "ignoring duplicate tray open app request for active session");
                        return Ok(());
                    }

                    self.config.ztna_app_id = Some(app_id.to_string());
                    self.config.ztna_forward_host = requested_forward_host;
                    self.config.ztna_forward_port = requested_forward_port;
                    self.ztna_last_request_unix = None;
                    if self.ztna_forward.is_some() || self.ztna_last_session_id.is_some() {
                        self.stop_ztna_session(Some("switching app from tray request"))
                            .await;
                    }
                    info!(app_id, forward_host = ?self.config.ztna_forward_host, forward_port = ?self.config.ztna_forward_port, "queued tray open app request into runtime");
                }
            }
        }
        Ok(())
    }

    pub(super) async fn write_tray_session_state(&self, now_unix: i64) -> Result<()> {
        let sessions = self.collect_tray_sessions(now_unix).await;
        write_json(&session_state_path()?, &SessionState { sessions })
    }

    async fn collect_tray_sessions(&self, now_unix: i64) -> Vec<SessionEntry> {
        if let Some(sessions) = self.active_ztna_sessions_from_controller(now_unix).await {
            if !sessions.is_empty() {
                return sessions;
            }
        }

        let mut sessions = Vec::new();
        if self.ztna_last_session_id.is_some() || self.ztna_forward.is_some() {
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
                local_url: self
                    .ztna_forward
                    .as_ref()
                    .map(|forward| format!("http://{}", forward.listen_addr)),
                bytes_tx: None,
                bytes_rx: None,
                active_connections: None,
                tunnel_latency_ms: None,
            });
        }
        sessions
    }

    async fn active_ztna_sessions_from_controller(&self, now_unix: i64) -> Option<Vec<SessionEntry>> {
        let config = TunnelClientConfig {
            base_url: self.config.ztna_controller_base_url.clone(),
            request_timeout_secs: 5,
        };
        let client = ztna::TunnelClient::new(config).ok()?;
        let sessions = client.list_sessions().await.ok()?;
        let active = sessions
            .into_iter()
            .filter(|session| {
                session.agent_id.trim() == self.config.agent_id.trim()
                    && session.status.trim().eq_ignore_ascii_case("active")
            })
            .map(|session| SessionEntry {
                session_id: session.session_id,
                app_id: session.app_id.clone(),
                app_name: session.app_id,
                transport: session.transport,
                status: if session.status.trim().is_empty() {
                    "active".to_string()
                } else {
                    session.status
                },
                started_at: parse_unix_timestamp(&session.created_at),
                last_activity_at: Some(
                    parse_unix_timestamp(&session.last_activity_at).unwrap_or(now_unix),
                ),
                last_outcome: self.ztna_last_outcome.clone(),
                local_url: self
                    .ztna_forward
                    .as_ref()
                    .map(|forward| format!("http://{}", forward.listen_addr)),
                bytes_tx: Some(session.bytes_tx),
                bytes_rx: Some(session.bytes_rx),
                active_connections: Some(session.active_connections),
                tunnel_latency_ms: Some(session.tunnel_latency_ms),
            })
            .collect::<Vec<_>>();
        Some(active)
    }

    pub(super) async fn stop_ztna_session(&mut self, reason: Option<&str>) {
        if let Some(handle) = self.ztna_forward.take() {
            handle.stop().await;
        }
        if let Err(err) = self.remove_ztna_wireguard_tunnel() {
            warn!(error = %err, "failed removing ztna wireguard tunnel during session stop");
        }
        self.release_ztna_session(reason.unwrap_or("session stopped"))
            .await;
        self.ztna_last_session_id = None;
        self.ztna_last_app_id = None;
        if let Some(reason) = reason {
            info!(reason, "ztna session stopped");
        }
    }
}

fn parse_unix_timestamp(raw: &str) -> Option<i64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    DateTime::parse_from_rfc3339(trimmed)
        .ok()
        .map(|ts| ts.with_timezone(&Utc).timestamp())
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
        fs::create_dir_all(&path)
            .with_context(|| format!("create tray data dir {}", path.display()))?;
        return Ok(path);
    }

    let base = dirs::data_local_dir().ok_or_else(|| anyhow::anyhow!("resolve local data dir"))?;
    let path = base.join("eGuard").join("tray");
    fs::create_dir_all(&path)
        .with_context(|| format!("create tray data dir {}", path.display()))?;
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

    use super::{
        bookmark_state_path, command_queue_path, read_json_or_default, session_state_path,
        BookmarkState, SessionState, TrayCommand, TrayCommandQueue,
    };
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

        runtime
            .sync_tray_state(1_700_000_100)
            .await
            .expect("sync tray state");

        let state: SessionState =
            read_json_or_default(&session_state_path().expect("session path"))
                .expect("read session state");
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
        runtime
            .client
            .set_cached_ztna_bookmarks(Some(ZtnaBookmarkListEnvelope {
                version: "v1".to_string(),
                generated_at_unix: 1_700_000_000,
                bookmarks: vec![ZtnaBookmarkEnvelope {
                    app_id: "app-1".to_string(),
                    name: "Prod SSH".to_string(),
                    icon: "terminal".to_string(),
                    app_type: "ssh".to_string(),
                    description: "Production jump host".to_string(),
                    health_status: "healthy".to_string(),
                    launch_uri: "eguard-ztna://launch?app_id=app-1&app_type=ssh&target=host"
                        .to_string(),
                    launcher_supported: true,
                    target_host: "host".to_string(),
                    target_port: 22,
                    display_hint: String::new(),
                    user_hint: "admin".to_string(),
                }],
            }));

        runtime
            .sync_tray_state(1_700_000_100)
            .await
            .expect("sync tray state");

        let state: BookmarkState =
            read_json_or_default(&bookmark_state_path().expect("bookmark path"))
                .expect("read bookmark state");
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

        runtime
            .sync_tray_state(1_700_000_200)
            .await
            .expect("sync tray state");

        let queue: TrayCommandQueue =
            read_json_or_default(&command_queue_path().expect("queue path")).expect("read queue");
        let state: SessionState =
            read_json_or_default(&session_state_path().expect("session path"))
                .expect("read session state");
        assert!(queue.commands.is_empty());
        assert!(state.sessions.is_empty());
        assert!(runtime.ztna_forward.is_none());
        assert!(runtime.ztna_last_session_id.is_none());
    }

    #[tokio::test]
    async fn sync_tray_state_writes_empty_bookmark_cache_when_offline() {
        let _guard = shared_env_var_lock().lock().expect("env lock");
        let tray_dir = std::env::temp_dir().join("eguard-agent-tray-sync-bookmarks-offline");
        let _ = fs::remove_dir_all(&tray_dir);
        std::env::set_var("EGUARD_TRAY_DATA_DIR", &tray_dir);

        let cfg = AgentConfig::default();
        let mut runtime = AgentRuntime::new(cfg).expect("runtime");
        runtime.client.set_online(false);

        runtime
            .sync_tray_state(1_700_000_300)
            .await
            .expect("sync tray state");

        let state: BookmarkState =
            read_json_or_default(&bookmark_state_path().expect("bookmark path"))
                .expect("read bookmark state");
        assert!(state.bookmarks.is_empty());
    }

    #[tokio::test]
    async fn refresh_command_clears_cached_bookmarks_and_forces_heartbeat_due() {
        let _guard = shared_env_var_lock().lock().expect("env lock");

        let mut runtime = AgentRuntime::new(AgentConfig::default()).expect("runtime");
        runtime.last_heartbeat_attempt_unix = Some(1_700_000_000);
        runtime
            .client
            .set_cached_ztna_bookmarks(Some(ZtnaBookmarkListEnvelope {
                version: "v1".to_string(),
                generated_at_unix: 1_700_000_000,
                bookmarks: vec![ZtnaBookmarkEnvelope {
                    app_id: "app-1".to_string(),
                    name: "Prod SSH".to_string(),
                    icon: "terminal".to_string(),
                    app_type: "ssh".to_string(),
                    description: "Production jump host".to_string(),
                    health_status: "healthy".to_string(),
                    launch_uri: "eguard-ztna://launch?app_id=app-1&app_type=ssh&target=host"
                        .to_string(),
                    launcher_supported: true,
                    target_host: "host".to_string(),
                    target_port: 22,
                    display_hint: String::new(),
                    user_hint: "admin".to_string(),
                }],
            }));

        runtime
            .apply_tray_command(&TrayCommand::Refresh)
            .await
            .expect("apply refresh command");

        assert!(runtime.last_heartbeat_attempt_unix.is_none());
        assert!(runtime
            .client
            .fetch_ztna_bookmarks()
            .await
            .expect("fetch cached bookmarks")
            .is_none());
    }

    #[tokio::test]
    async fn write_tray_bookmark_state_preserves_existing_cache_when_payload_missing() {
        let _guard = shared_env_var_lock().lock().expect("env lock");
        let tray_dir = std::env::temp_dir().join("eguard-agent-tray-sync-bookmarks-preserve");
        let _ = fs::remove_dir_all(&tray_dir);
        std::env::set_var("EGUARD_TRAY_DATA_DIR", &tray_dir);

        let cfg = AgentConfig::default();
        let runtime = AgentRuntime::new(cfg).expect("runtime");
        let initial = BookmarkState {
            version: "v1".to_string(),
            bookmarks: vec![super::BookmarkEntry {
                app_id: "app-1".to_string(),
                name: "Prod SSH".to_string(),
                icon: Some("terminal".to_string()),
                app_type: "ssh".to_string(),
                description: Some("Production jump host".to_string()),
                health_status: "healthy".to_string(),
                launch_uri: "eguard-ztna://launch?app_id=app-1&app_type=ssh&target=host"
                    .to_string(),
                launcher_supported: true,
                target_host: Some("host".to_string()),
                target_port: Some(22),
                display_hint: None,
                user_hint: Some("admin".to_string()),
            }],
        };
        super::write_json(&bookmark_state_path().expect("bookmark path"), &initial)
            .expect("write initial state");

        runtime
            .write_tray_bookmark_state()
            .await
            .expect("write bookmark state");

        let state: BookmarkState =
            read_json_or_default(&bookmark_state_path().expect("bookmark path"))
                .expect("read bookmark state");
        assert_eq!(state.version, "v1");
        assert_eq!(state.bookmarks.len(), 1);
        assert_eq!(state.bookmarks[0].app_id, "app-1");
    }

    #[tokio::test]
    async fn sync_tray_state_open_app_resets_tunnel_request_backoff() {
        let _guard = shared_env_var_lock().lock().expect("env lock");
        let tray_dir = std::env::temp_dir().join("eguard-agent-tray-sync-open-app");
        let _ = fs::remove_dir_all(&tray_dir);
        std::env::set_var("EGUARD_TRAY_DATA_DIR", &tray_dir);

        let mut runtime = AgentRuntime::new(AgentConfig::default()).expect("runtime");
        runtime.ztna_last_request_unix = Some(1_700_000_100);

        let queue = TrayCommandQueue {
            commands: vec![super::QueuedTrayCommand {
                id: "cmd-open-app".to_string(),
                created_at_unix: 1,
                command: TrayCommand::OpenApp {
                    app_id: "rdp-prod".to_string(),
                },
            }],
        };
        super::write_json(&command_queue_path().expect("queue path"), &queue).expect("write queue");

        runtime
            .sync_tray_state(1_700_000_200)
            .await
            .expect("sync tray state");

        assert_eq!(runtime.config.ztna_app_id.as_deref(), Some("rdp-prod"));
        assert!(runtime.ztna_last_request_unix.is_none());
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
