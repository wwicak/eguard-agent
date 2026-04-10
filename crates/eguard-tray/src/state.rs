use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BookmarkState {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub bookmarks: Vec<BookmarkEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarkEntry {
    pub app_id: String,
    pub name: String,
    #[serde(default)]
    pub icon: Option<String>,
    pub app_type: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "default_health")]
    pub health_status: String,
    pub launch_uri: String,
    #[serde(default)]
    pub launcher_supported: bool,
    #[serde(default)]
    pub target_host: Option<String>,
    #[serde(default)]
    pub target_port: Option<u32>,
    #[serde(default)]
    pub display_hint: Option<String>,
    #[serde(default)]
    pub user_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionState {
    #[serde(default)]
    pub sessions: Vec<SessionEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEntry {
    pub session_id: String,
    pub app_id: String,
    #[serde(default)]
    pub app_name: String,
    #[serde(default)]
    pub transport: String,
    #[serde(default = "default_status")]
    pub status: String,
    #[serde(default)]
    pub started_at: Option<i64>,
    #[serde(default)]
    pub last_activity_at: Option<i64>,
    #[serde(default)]
    pub last_outcome: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrayCommandQueue {
    #[serde(default)]
    pub commands: Vec<QueuedTrayCommand>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedTrayCommand {
    pub id: String,
    pub created_at_unix: i64,
    pub command: TrayCommand,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TrayCommand {
    Disconnect { session_id: String },
    DisconnectAll,
    DisableTransport,
    EnableTransport,
    Refresh,
    OpenApp { app_id: String },
}

impl BookmarkState {
    pub fn load_default() -> Result<Self> {
        read_json_or_default(bookmark_cache_path()?)
    }
}

impl SessionState {
    pub fn load_default() -> Result<Self> {
        read_json_or_default(session_state_path()?)
    }
}

impl TrayCommandQueue {
    pub fn load_default() -> Result<Self> {
        read_json_or_default(command_queue_path()?)
    }

    pub fn save_default(&self) -> Result<()> {
        write_json(command_queue_path()?, self)
    }

    pub fn push(&mut self, command: TrayCommand) {
        self.commands.push(QueuedTrayCommand {
            id: format!("tray-{}", now_unix()),
            created_at_unix: now_unix(),
            command,
        });
    }
}

pub fn bookmark_cache_path() -> Result<PathBuf> {
    Ok(data_root()?.join("ztna-bookmarks.json"))
}

pub fn session_state_path() -> Result<PathBuf> {
    Ok(data_root()?.join("ztna-sessions.json"))
}

pub fn command_queue_path() -> Result<PathBuf> {
    Ok(data_root()?.join("ztna-tray-commands.json"))
}

fn data_root() -> Result<PathBuf> {
    if let Ok(raw) = std::env::var("EGUARD_TRAY_DATA_DIR") {
        if !raw.trim().is_empty() {
            let path = PathBuf::from(raw.trim());
            fs::create_dir_all(&path)
                .with_context(|| format!("create tray data dir {}", path.display()))?;
            return Ok(path);
        }
    }

    let base = dirs::data_local_dir().ok_or_else(|| anyhow!("resolve local data dir"))?;
    let path = base.join("eGuard").join("tray");
    fs::create_dir_all(&path)
        .with_context(|| format!("create tray data dir {}", path.display()))?;
    Ok(path)
}

fn read_json_or_default<T>(path: PathBuf) -> Result<T>
where
    T: serde::de::DeserializeOwned + Default,
{
    if !path.exists() {
        return Ok(T::default());
    }
    let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
}

fn write_json<T>(path: PathBuf, value: &T) -> Result<()>
where
    T: Serialize,
{
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let raw = serde_json::to_string_pretty(value)?;
    fs::write(&path, raw).with_context(|| format!("write {}", path.display()))
}

fn default_health() -> String {
    "unknown".to_string()
}

fn default_status() -> String {
    "active".to_string()
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::{BookmarkState, TrayCommand, TrayCommandQueue};

    #[test]
    fn bookmark_state_defaults_when_missing() {
        std::env::set_var(
            "EGUARD_TRAY_DATA_DIR",
            std::env::temp_dir().join("eguard-tray-state-test-1"),
        );
        let state = BookmarkState::load_default().expect("load bookmarks");
        assert!(state.bookmarks.is_empty());
    }

    #[test]
    fn queue_push_records_command() {
        let mut queue = TrayCommandQueue::default();
        queue.push(TrayCommand::DisconnectAll);
        assert_eq!(queue.commands.len(), 1);
    }
}
