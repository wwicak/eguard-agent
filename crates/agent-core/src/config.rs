use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use response::{ResponseConfig, ResponsePolicy};
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
    pub enrollment_token: Option<String>,
    pub tenant_id: Option<String>,
    pub response: ResponseConfig,
    pub offline_buffer_backend: String,
    pub offline_buffer_path: String,
    pub offline_buffer_cap_bytes: usize,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub tls_ca_path: Option<String>,
    #[serde(skip)]
    pub bootstrap_config_path: Option<PathBuf>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_id: default_agent_id(),
            mac: "00:00:00:00:00:00".to_string(),
            mode: AgentMode::Learning,
            transport_mode: "http".to_string(),
            server_addr: "eguard-server:50051".to_string(),
            enrollment_token: None,
            tenant_id: None,
            response: ResponseConfig::default(),
            offline_buffer_backend: "sqlite".to_string(),
            offline_buffer_path: "/var/lib/eguard-agent/offline-events.db".to_string(),
            offline_buffer_cap_bytes: 100 * 1024 * 1024,
            tls_cert_path: None,
            tls_key_path: None,
            tls_ca_path: None,
            bootstrap_config_path: None,
        }
    }
}

impl AgentConfig {
    pub fn load() -> Result<Self> {
        let mut cfg = Self::default();
        let has_agent_config = cfg.apply_file_config()?;
        if !has_agent_config {
            cfg.apply_bootstrap_config()?;
        }
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
            .or_else(|| {
                std::env::var("EGUARD_SERVER")
                    .ok()
                    .filter(|v| !v.trim().is_empty())
            });
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

        if let Ok(v) = std::env::var("EGUARD_ENROLLMENT_TOKEN") {
            self.enrollment_token = non_empty(Some(v));
        }

        if let Ok(v) = std::env::var("EGUARD_TENANT_ID") {
            self.tenant_id = non_empty(Some(v));
        }

        if let Ok(v) = std::env::var("EGUARD_AUTONOMOUS_RESPONSE") {
            self.response.autonomous_response = parse_bool(&v);
        }

        if let Ok(v) = std::env::var("EGUARD_RESPONSE_DRY_RUN") {
            self.response.dry_run = parse_bool(&v);
        }

        if let Ok(v) = std::env::var("EGUARD_RESPONSE_MAX_KILLS_PER_MINUTE") {
            if let Ok(parsed) = v.trim().parse::<usize>() {
                self.response.max_kills_per_minute = parsed;
            }
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

    fn apply_file_config(&mut self) -> Result<bool> {
        let path = resolve_config_path()?;
        let Some(path) = path else {
            return Ok(false);
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
                self.response.autonomous_response = v;
            }
            if let Some(v) = response.dry_run {
                self.response.dry_run = v;
            }
            if let Some(rate_limit) = response.rate_limit {
                if let Some(v) = rate_limit.max_kills_per_minute {
                    self.response.max_kills_per_minute = v;
                }
            }

            apply_response_policy(&mut self.response.definite, response.definite);
            apply_response_policy(&mut self.response.very_high, response.very_high);
            apply_response_policy(&mut self.response.high, response.high);
            apply_response_policy(&mut self.response.medium, response.medium);
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

        Ok(true)
    }

    fn apply_bootstrap_config(&mut self) -> Result<()> {
        let path = resolve_bootstrap_path()?;
        let Some(path) = path else {
            return Ok(());
        };

        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed reading bootstrap config {}", path.display()))?;
        let bootstrap = parse_bootstrap_config(&raw).with_context(|| {
            format!(
                "failed parsing bootstrap config {}",
                path.as_path().display()
            )
        })?;

        if let Some(address) = bootstrap.address {
            self.server_addr = format_server_addr(&address, bootstrap.grpc_port);
            self.transport_mode = "grpc".to_string();
        }
        if let Some(token) = bootstrap.enrollment_token {
            self.enrollment_token = Some(token);
        }
        if let Some(tenant_id) = bootstrap.tenant_id {
            self.tenant_id = Some(tenant_id);
        }

        self.bootstrap_config_path = Some(path);
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
    #[serde(default)]
    dry_run: Option<bool>,
    #[serde(default)]
    definite: Option<FileResponsePolicy>,
    #[serde(default)]
    very_high: Option<FileResponsePolicy>,
    #[serde(default)]
    high: Option<FileResponsePolicy>,
    #[serde(default)]
    medium: Option<FileResponsePolicy>,
    #[serde(default)]
    rate_limit: Option<FileResponseRateLimitConfig>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct FileResponsePolicy {
    #[serde(default)]
    kill: Option<bool>,
    #[serde(default)]
    quarantine: Option<bool>,
    #[serde(default)]
    capture_script: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct FileResponseRateLimitConfig {
    #[serde(default)]
    max_kills_per_minute: Option<usize>,
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

#[derive(Debug, Clone, Default)]
struct BootstrapConfig {
    address: Option<String>,
    grpc_port: Option<u16>,
    enrollment_token: Option<String>,
    tenant_id: Option<String>,
}

fn resolve_config_path() -> Result<Option<PathBuf>> {
    if let Ok(p) = std::env::var("EGUARD_AGENT_CONFIG") {
        let p = p.trim();
        if !p.is_empty() {
            let path = PathBuf::from(p);
            if !path.exists() {
                anyhow::bail!(
                    "configured EGUARD_AGENT_CONFIG does not exist: {}",
                    path.display()
                );
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

fn resolve_bootstrap_path() -> Result<Option<PathBuf>> {
    if let Ok(p) = std::env::var("EGUARD_BOOTSTRAP_CONFIG") {
        let p = p.trim();
        if !p.is_empty() {
            let path = PathBuf::from(p);
            if !path.exists() {
                anyhow::bail!(
                    "configured EGUARD_BOOTSTRAP_CONFIG does not exist: {}",
                    path.display()
                );
            }
            return Ok(Some(path));
        }
    }

    for candidate in [
        "/etc/eguard-agent/bootstrap.conf",
        "./conf/bootstrap.conf",
        "./bootstrap.conf",
    ] {
        let p = Path::new(candidate);
        if p.exists() {
            return Ok(Some(p.to_path_buf()));
        }
    }

    Ok(None)
}

fn parse_bootstrap_config(raw: &str) -> Result<BootstrapConfig> {
    let mut cfg = BootstrapConfig::default();
    let mut section = String::new();

    for line in raw.lines() {
        let mut line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if let Some(content) = line.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
            section = content.trim().to_ascii_lowercase();
            continue;
        }

        if section != "server" {
            continue;
        }

        if let Some((head, _)) = line.split_once('#') {
            line = head.trim();
        }
        if let Some((head, _)) = line.split_once(';') {
            line = head.trim();
        }
        if line.is_empty() {
            continue;
        }

        let Some((raw_key, raw_value)) = line.split_once('=') else {
            continue;
        };

        let key = raw_key.trim().to_ascii_lowercase();
        let value = raw_value.trim().trim_matches('"').trim_matches('\'').trim();
        if value.is_empty() {
            continue;
        }

        match key.as_str() {
            "address" => cfg.address = Some(value.to_string()),
            "grpc_port" => {
                if let Ok(port) = value.parse::<u16>() {
                    cfg.grpc_port = Some(port);
                }
            }
            "enrollment_token" => cfg.enrollment_token = Some(value.to_string()),
            "tenant_id" => cfg.tenant_id = Some(value.to_string()),
            _ => {}
        }
    }

    Ok(cfg)
}

fn format_server_addr(address: &str, grpc_port: Option<u16>) -> String {
    let address = address.trim();
    let Some(port) = grpc_port else {
        return address.to_string();
    };
    if has_explicit_port(address) {
        return address.to_string();
    }

    if address.contains(':') && !address.starts_with('[') {
        format!("[{}]:{}", address, port)
    } else {
        format!("{}:{}", address, port)
    }
}

fn has_explicit_port(address: &str) -> bool {
    if address.starts_with('[') {
        return address.contains("]:");
    }

    if address.matches(':').count() == 1 {
        return address
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse::<u16>().ok())
            .is_some();
    }

    false
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

fn apply_response_policy(dst: &mut ResponsePolicy, src: Option<FileResponsePolicy>) {
    let Some(src) = src else {
        return;
    };

    if let Some(v) = src.kill {
        dst.kill = v;
    }
    if let Some(v) = src.quarantine {
        dst.quarantine = v;
    }
    if let Some(v) = src.capture_script {
        dst.capture_script = v;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn clear_env() {
        let vars = [
            "EGUARD_AGENT_CONFIG",
            "EGUARD_BOOTSTRAP_CONFIG",
            "EGUARD_AGENT_ID",
            "EGUARD_SERVER_ADDR",
            "EGUARD_SERVER",
            "EGUARD_AGENT_MODE",
            "EGUARD_TRANSPORT_MODE",
            "EGUARD_ENROLLMENT_TOKEN",
            "EGUARD_TENANT_ID",
            "EGUARD_AUTONOMOUS_RESPONSE",
            "EGUARD_RESPONSE_DRY_RUN",
            "EGUARD_RESPONSE_MAX_KILLS_PER_MINUTE",
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
        let _guard = env_lock().lock().expect("env lock");
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
            "[agent]\nserver_addr=\"10.0.0.1:50051\"\nmode=\"active\"\n[transport]\nmode=\"grpc\"\n[response]\nautonomous_response=true\ndry_run=true\n[response.high]\nkill=true\nquarantine=false\ncapture_script=true\n[response.rate_limit]\nmax_kills_per_minute=21\n[storage]\nbackend=\"memory\"\ncap_mb=10"
        )
        .expect("write file");

        std::env::set_var("EGUARD_AGENT_CONFIG", &path);
        let cfg = AgentConfig::load().expect("load config");

        assert_eq!(cfg.server_addr, "10.0.0.1:50051");
        assert!(matches!(cfg.mode, AgentMode::Active));
        assert!(cfg.response.autonomous_response);
        assert!(cfg.response.dry_run);
        assert!(cfg.response.high.kill);
        assert!(!cfg.response.high.quarantine);
        assert!(cfg.response.high.capture_script);
        assert_eq!(cfg.response.max_kills_per_minute, 21);
        assert_eq!(cfg.transport_mode, "grpc");
        assert_eq!(cfg.offline_buffer_backend, "memory");
        assert_eq!(cfg.offline_buffer_cap_bytes, 10 * 1024 * 1024);

        clear_env();
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn env_overrides_file_config() {
        let _guard = env_lock().lock().expect("env lock");
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
        std::env::set_var("EGUARD_AUTONOMOUS_RESPONSE", "true");
        let cfg = AgentConfig::load().expect("load config");

        assert_eq!(cfg.server_addr, "10.9.9.9:50051");
        assert_eq!(cfg.transport_mode, "http");
        assert!(cfg.response.autonomous_response);

        clear_env();
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn bootstrap_config_is_used_when_agent_config_missing() {
        let _guard = env_lock().lock().expect("env lock");
        clear_env();

        let path = std::env::temp_dir().join(format!(
            "eguard-bootstrap-config-{}.conf",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));

        let mut f = std::fs::File::create(&path).expect("create bootstrap file");
        writeln!(
            f,
            "[server]\naddress = 10.11.12.13\ngrpc_port = 50051\nenrollment_token = abc123def456\ntenant_id = default"
        )
        .expect("write bootstrap file");

        std::env::set_var("EGUARD_BOOTSTRAP_CONFIG", &path);
        let cfg = AgentConfig::load().expect("load config");

        assert_eq!(cfg.server_addr, "10.11.12.13:50051");
        assert_eq!(cfg.transport_mode, "grpc");
        assert_eq!(cfg.enrollment_token.as_deref(), Some("abc123def456"));
        assert_eq!(cfg.tenant_id.as_deref(), Some("default"));
        assert_eq!(cfg.bootstrap_config_path.as_deref(), Some(path.as_path()));

        clear_env();
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn format_server_addr_handles_ipv6_without_port() {
        assert_eq!(
            format_server_addr("2001:db8::1", Some(50051)),
            "[2001:db8::1]:50051"
        );
        assert_eq!(
            format_server_addr("[2001:db8::1]:50051", Some(50052)),
            "[2001:db8::1]:50051"
        );
        assert_eq!(
            format_server_addr("eguard.example.com", Some(50051)),
            "eguard.example.com:50051"
        );
    }
}
