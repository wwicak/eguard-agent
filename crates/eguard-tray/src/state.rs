use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BookmarkState {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub bookmarks: Vec<BookmarkEntry>,
}

#[derive(Debug, Clone, Default)]
pub struct BookmarkCacheSnapshot {
    pub version: String,
    pub modified_at_unix_millis: Option<u128>,
}

#[derive(Debug, Clone, Default)]
pub struct SessionCacheSnapshot {
    pub session_count: usize,
    pub modified_at_unix_millis: Option<u128>,
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
    #[serde(default)]
    pub local_url: Option<String>,
    #[serde(default)]
    pub bytes_tx: Option<i64>,
    #[serde(default)]
    pub bytes_rx: Option<i64>,
    #[serde(default)]
    pub active_connections: Option<i32>,
    #[serde(default)]
    pub tunnel_latency_ms: Option<i32>,
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
    Disconnect {
        session_id: String,
    },
    DisconnectAll,
    DisableTransport,
    EnableTransport,
    Refresh,
    OpenApp {
        app_id: String,
        forward_host: Option<String>,
        forward_port: Option<u16>,
    },
}

impl BookmarkState {
    pub fn load_default() -> Result<Self> {
        read_json_or_default(bookmark_cache_path()?)
    }
}

pub fn snapshot_bookmark_cache() -> Result<BookmarkCacheSnapshot> {
    let path = bookmark_cache_path()?;
    let state = BookmarkState::load_default()?;
    let modified_at_unix_millis = file_modified_at_unix_millis(&path)?;
    Ok(BookmarkCacheSnapshot {
        version: state.version,
        modified_at_unix_millis,
    })
}

pub fn wait_for_bookmark_cache_update(
    previous: &BookmarkCacheSnapshot,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let current = snapshot_bookmark_cache()?;
        if current.version != previous.version
            || current.modified_at_unix_millis != previous.modified_at_unix_millis
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    Ok(())
}

impl SessionState {
    pub fn load_default() -> Result<Self> {
        read_json_or_default(session_state_path()?)
    }
}

pub fn snapshot_session_cache() -> Result<SessionCacheSnapshot> {
    let path = session_state_path()?;
    let state = SessionState::load_default()?;
    let modified_at_unix_millis = file_modified_at_unix_millis(&path)?;
    Ok(SessionCacheSnapshot {
        session_count: state.sessions.len(),
        modified_at_unix_millis,
    })
}

pub fn wait_for_session_cache_update(
    previous: &SessionCacheSnapshot,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let current = snapshot_session_cache()?;
        if current.session_count != previous.session_count
            || current.modified_at_unix_millis != previous.modified_at_unix_millis
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    Ok(())
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

    #[cfg(target_os = "windows")]
    {
        let path = PathBuf::from(r"C:\ProgramData\eGuard\tray");
        fs::create_dir_all(&path)
            .with_context(|| format!("create tray data dir {}", path.display()))?;
        return Ok(path);
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

fn file_modified_at_unix_millis(path: &PathBuf) -> Result<Option<u128>> {
    if !path.exists() {
        return Ok(None);
    }
    let modified = fs::metadata(path)
        .with_context(|| format!("metadata {}", path.display()))?
        .modified()
        .with_context(|| format!("modified {}", path.display()))?
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    Ok(Some(modified))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::Duration;

    use super::{
        bookmark_cache_path, snapshot_bookmark_cache, wait_for_bookmark_cache_update, write_json,
        BookmarkEntry, BookmarkState, TrayCommand, TrayCommandQueue,
    };

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

    #[test]
    fn wait_for_bookmark_cache_update_observes_rewrite() {
        let tray_dir = std::env::temp_dir().join("eguard-tray-state-test-refresh");
        let _ = fs::remove_dir_all(&tray_dir);
        std::env::set_var("EGUARD_TRAY_DATA_DIR", &tray_dir);

        let initial = BookmarkState {
            version: "v1".to_string(),
            bookmarks: vec![BookmarkEntry {
                app_id: "app-1".to_string(),
                name: "App One".to_string(),
                icon: None,
                app_type: "http".to_string(),
                description: None,
                health_status: "healthy".to_string(),
                launch_uri: "eguard-ztna://launch?app_id=app-1".to_string(),
                launcher_supported: true,
                target_host: Some("host-1".to_string()),
                target_port: Some(80),
                display_hint: None,
                user_hint: None,
            }],
        };
        write_json(bookmark_cache_path().expect("bookmark path"), &initial)
            .expect("write initial state");
        let snapshot = snapshot_bookmark_cache().expect("initial snapshot");

        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(150));
            let updated = BookmarkState {
                version: "v2".to_string(),
                bookmarks: Vec::new(),
            };
            write_json(bookmark_cache_path().expect("bookmark path"), &updated)
                .expect("write updated state");
        });

        wait_for_bookmark_cache_update(&snapshot, Duration::from_secs(2)).expect("wait for update");
        let latest = BookmarkState::load_default().expect("load latest state");
        assert_eq!(latest.version, "v2");
    }
}
