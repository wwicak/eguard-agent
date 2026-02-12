use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentMode {
    Learning,
    Active,
    Degraded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub agent_id: String,
    pub mac: String,
    pub mode: AgentMode,
    pub transport_mode: String,
    pub server_addr: String,
    pub autonomous_response: bool,
    pub offline_buffer_backend: String,
    pub offline_buffer_path: String,
    pub offline_buffer_cap_bytes: usize,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub tls_ca_path: Option<String>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_id: default_agent_id(),
            mac: "00:00:00:00:00:00".to_string(),
            mode: AgentMode::Learning,
            transport_mode: "http".to_string(),
            server_addr: "eguard-server:50051".to_string(),
            autonomous_response: false,
            offline_buffer_backend: "sqlite".to_string(),
            offline_buffer_path: "/var/lib/eguard-agent/offline-events.db".to_string(),
            offline_buffer_cap_bytes: 100 * 1024 * 1024,
            tls_cert_path: None,
            tls_key_path: None,
            tls_ca_path: None,
        }
    }
}

impl AgentConfig {
    pub fn load() -> Result<Self> {
        let mut cfg = Self::default();
        cfg.apply_file_config()?;
        cfg.apply_env_overrides();
        Ok(cfg)
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("EGUARD_AGENT_ID") {
            if !v.trim().is_empty() {
                self.agent_id = v;
            }
        }

        if let Ok(v) = std::env::var("EGUARD_AGENT_MAC") {
            if !v.trim().is_empty() {
                self.mac = v;
            }
        }

        let server = std::env::var("EGUARD_SERVER_ADDR")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .or_else(|| std::env::var("EGUARD_SERVER").ok().filter(|v| !v.trim().is_empty()));
        if let Some(server) = server {
            self.server_addr = server;
        }

        if let Ok(mode) = std::env::var("EGUARD_AGENT_MODE") {
            self.mode = parse_mode(&mode);
        }

        if let Ok(v) = std::env::var("EGUARD_TRANSPORT_MODE") {
            if !v.trim().is_empty() {
                self.transport_mode = v;
            }
        }

        if let Ok(v) = std::env::var("EGUARD_AUTONOMOUS_RESPONSE") {
            self.autonomous_response = parse_bool(&v);
        }

        if let Ok(v) = std::env::var("EGUARD_BUFFER_BACKEND") {
            if !v.trim().is_empty() {
                self.offline_buffer_backend = v;
            }
        }

        if let Ok(v) = std::env::var("EGUARD_BUFFER_PATH") {
            if !v.trim().is_empty() {
                self.offline_buffer_path = v;
            }
        }

        if let Ok(v) = std::env::var("EGUARD_BUFFER_CAP_MB") {
            if let Some(cap) = parse_cap_mb(&v) {
                self.offline_buffer_cap_bytes = cap;
            }
        }

        if let Ok(v) = std::env::var("EGUARD_TLS_CERT") {
            self.tls_cert_path = non_empty(Some(v));
        }
        if let Ok(v) = std::env::var("EGUARD_TLS_KEY") {
            self.tls_key_path = non_empty(Some(v));
        }
        if let Ok(v) = std::env::var("EGUARD_TLS_CA") {
            self.tls_ca_path = non_empty(Some(v));
        }

        if self.agent_id.trim().is_empty() {
            self.agent_id = default_agent_id();
        }
    }

    fn apply_file_config(&mut self) -> Result<()> {
        let path = resolve_config_path()?;
        let Some(path) = path else {
            return Ok(());
        };

        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed reading config file {}", path.display()))?;
        let file_cfg: FileConfig = toml::from_str(&raw)
            .with_context(|| format!("failed parsing TOML config {}", path.display()))?;

        if let Some(agent) = file_cfg.agent {
            if let Some(v) = non_empty(agent.id) {
                self.agent_id = v;
            }
            if let Some(v) = non_empty(agent.mac) {
                self.mac = v;
            }
            if let Some(v) = non_empty(agent.server_addr).or_else(|| non_empty(agent.server)) {
                self.server_addr = v;
            }
            if let Some(v) = non_empty(agent.mode) {
                self.mode = parse_mode(&v);
            }
        }

        if let Some(transport) = file_cfg.transport {
            if let Some(v) = non_empty(transport.mode) {
                self.transport_mode = v;
            }
        }

        if let Some(response) = file_cfg.response {
            if let Some(v) = response.autonomous_response {
                self.autonomous_response = v;
            }
        }

        if let Some(storage) = file_cfg.storage {
            if let Some(v) = non_empty(storage.backend) {
                self.offline_buffer_backend = v;
            }
            if let Some(v) = non_empty(storage.path) {
                self.offline_buffer_path = v;
            }
            if let Some(v) = storage.cap_mb {
                self.offline_buffer_cap_bytes = v.saturating_mul(1024 * 1024);
            }
        }

        if let Some(tls) = file_cfg.tls {
            if let Some(v) = non_empty(tls.cert_path) {
                self.tls_cert_path = Some(v);
            }
            if let Some(v) = non_empty(tls.key_path) {
                self.tls_key_path = Some(v);
            }
            if let Some(v) = non_empty(tls.ca_path) {
                self.tls_ca_path = Some(v);
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
struct FileConfig {
    #[serde(default)]
    agent: Option<FileAgentConfig>,
    #[serde(default)]
    response: Option<FileResponseConfig>,
    #[serde(default)]
    storage: Option<FileStorageConfig>,
    #[serde(default)]
    tls: Option<FileTlsConfig>,
    #[serde(default)]
    transport: Option<FileTransportConfig>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct FileAgentConfig {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    mac: Option<String>,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    server_addr: Option<String>,
    #[serde(default)]
    server: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct FileResponseConfig {
    #[serde(default)]
    autonomous_response: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct FileStorageConfig {
    #[serde(default)]
    backend: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    cap_mb: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct FileTlsConfig {
    #[serde(default)]
    cert_path: Option<String>,
    #[serde(default)]
    key_path: Option<String>,
    #[serde(default)]
    ca_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct FileTransportConfig {
    #[serde(default)]
    mode: Option<String>,
}

fn resolve_config_path() -> Result<Option<PathBuf>> {
    if let Ok(p) = std::env::var("EGUARD_AGENT_CONFIG") {
        let p = p.trim();
        if !p.is_empty() {
            let path = PathBuf::from(p);
            if !path.exists() {
                anyhow::bail!("configured EGUARD_AGENT_CONFIG does not exist: {}", path.display());
            }
            return Ok(Some(path));
        }
    }

    for candidate in [
        "/etc/eguard-agent/agent.conf",
        "./conf/agent.conf",
        "./agent.conf",
    ] {
        let p = Path::new(candidate);
        if p.exists() {
            return Ok(Some(p.to_path_buf()));
        }
    }

    Ok(None)
}

fn non_empty(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.trim().is_empty())
}

fn default_agent_id() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "agent-dev-1".to_string())
}

fn parse_mode(raw: &str) -> AgentMode {
    match raw.trim().to_ascii_lowercase().as_str() {
        "active" => AgentMode::Active,
        "degraded" => AgentMode::Degraded,
        _ => AgentMode::Learning,
    }
}

fn parse_bool(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "enabled" | "on"
    )
}

fn parse_cap_mb(raw: &str) -> Option<usize> {
    let mb = raw.trim().parse::<usize>().ok()?;
    Some(mb.saturating_mul(1024 * 1024))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn clear_env() {
        let vars = [
            "EGUARD_AGENT_CONFIG",
            "EGUARD_AGENT_ID",
            "EGUARD_SERVER_ADDR",
            "EGUARD_SERVER",
            "EGUARD_AGENT_MODE",
            "EGUARD_TRANSPORT_MODE",
            "EGUARD_AUTONOMOUS_RESPONSE",
            "EGUARD_BUFFER_BACKEND",
            "EGUARD_BUFFER_PATH",
            "EGUARD_BUFFER_CAP_MB",
            "EGUARD_TLS_CERT",
            "EGUARD_TLS_KEY",
            "EGUARD_TLS_CA",
        ];
        for v in vars {
            std::env::remove_var(v);
        }
    }

    #[test]
    fn file_config_is_loaded() {
        clear_env();

        let path = std::env::temp_dir().join(format!(
            "eguard-agent-config-{}.toml",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));

        let mut f = std::fs::File::create(&path).expect("create file");
        writeln!(
            f,
            "[agent]\nserver_addr=\"10.0.0.1:50051\"\nmode=\"active\"\n[transport]\nmode=\"grpc\"\n[response]\nautonomous_response=true\n[storage]\nbackend=\"memory\"\ncap_mb=10"
        )
        .expect("write file");

        std::env::set_var("EGUARD_AGENT_CONFIG", &path);
        let cfg = AgentConfig::load().expect("load config");

        assert_eq!(cfg.server_addr, "10.0.0.1:50051");
        assert!(matches!(cfg.mode, AgentMode::Active));
        assert!(cfg.autonomous_response);
        assert_eq!(cfg.transport_mode, "grpc");
        assert_eq!(cfg.offline_buffer_backend, "memory");
        assert_eq!(cfg.offline_buffer_cap_bytes, 10 * 1024 * 1024);

        clear_env();
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn env_overrides_file_config() {
        clear_env();

        let path = std::env::temp_dir().join(format!(
            "eguard-agent-config-{}.toml",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));

        let mut f = std::fs::File::create(&path).expect("create file");
        writeln!(f, "[agent]\nserver_addr=\"10.0.0.1:50051\"").expect("write file");

        std::env::set_var("EGUARD_AGENT_CONFIG", &path);
        std::env::set_var("EGUARD_SERVER_ADDR", "10.9.9.9:50051");
        std::env::set_var("EGUARD_TRANSPORT_MODE", "http");
        let cfg = AgentConfig::load().expect("load config");

        assert_eq!(cfg.server_addr, "10.9.9.9:50051");
        assert_eq!(cfg.transport_mode, "http");

        clear_env();
        let _ = std::fs::remove_file(path);
    }
}
