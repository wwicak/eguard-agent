use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchTargetKind {
    Ssh,
    Rdp,
    Vnc,
    Web,
    Tcp,
}

impl LaunchTargetKind {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "ssh" => Some(Self::Ssh),
            "rdp" => Some(Self::Rdp),
            "vnc" => Some(Self::Vnc),
            "http" | "https" | "web" => Some(Self::Web),
            "tcp" => Some(Self::Tcp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchRequest {
    pub app_id: String,
    pub name: String,
    pub kind: LaunchTargetKind,
    pub host: String,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub path: Option<String>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BookmarkRecord {
    #[serde(default)]
    pub app_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub icon: String,
    #[serde(default)]
    pub app_type: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub health_status: String,
    #[serde(default)]
    pub launch_uri: String,
    #[serde(default)]
    pub launcher_supported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BookmarkState {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub bookmarks: Vec<BookmarkRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ActiveSessionRecord {
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub app_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub app_type: String,
    #[serde(default)]
    pub launch_uri: String,
    #[serde(default)]
    pub transport: String,
    #[serde(default)]
    pub started_at_unix: i64,
    #[serde(default)]
    pub last_activity_at_unix: i64,
    #[serde(default)]
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SessionState {
    #[serde(default)]
    pub transport_disabled: bool,
    #[serde(default)]
    pub transport_disable_reason: String,
    #[serde(default)]
    pub updated_at_unix: i64,
    #[serde(default)]
    pub command_results: Vec<TrayCommandResult>,
    #[serde(default)]
    pub sessions: Vec<ActiveSessionRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrayCommandKind {
    DisconnectSession { session_id: String },
    DisconnectAll,
    DisableTransport,
    EnableTransport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrayCommand {
    pub command_id: String,
    pub created_at_unix: i64,
    pub kind: TrayCommandKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TrayCommandResult {
    #[serde(default)]
    pub command_id: String,
    #[serde(default)]
    pub created_at_unix: i64,
    #[serde(default)]
    pub success: bool,
    #[serde(default)]
    pub message: String,
}
