use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use response::{ResponseConfig, ResponsePolicy};
use serde::{Deserialize, Serialize};

const AGENT_CONFIG_CANDIDATES: [&str; 3] = [
    "/etc/eguard-agent/agent.conf",
    "./conf/agent.conf",
    "./agent.conf",
];

const BOOTSTRAP_CONFIG_CANDIDATES: [&str; 3] = [
    "/etc/eguard-agent/bootstrap.conf",
    "./conf/bootstrap.conf",
    "./bootstrap.conf",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentMode {
    Learning,
    Active,
    Degraded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub agent_id: String,
    pub machine_id: Option<String>,
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
    pub heartbeat_interval_secs: u64,
    pub reconnect_backoff_max_secs: u64,
    pub telemetry_process_exec: bool,
    pub telemetry_file_events: bool,
    pub telemetry_network_connections: bool,
    pub telemetry_dns_queries: bool,
    pub telemetry_module_loads: bool,
    pub telemetry_user_logins: bool,
    pub telemetry_flush_interval_ms: u64,
    pub telemetry_max_batch_size: usize,
    pub detection_sigma_rules_dir: String,
    pub detection_yara_rules_dir: String,
    pub detection_ioc_dir: String,
    pub detection_scan_on_create: bool,
    pub detection_max_file_scan_size_mb: usize,
    pub compliance_check_interval_secs: u64,
    pub compliance_auto_remediate: bool,
    pub baseline_learning_period_days: u64,
    pub baseline_refresh_interval_days: u64,
    pub baseline_stale_after_days: u64,
    pub self_protection_integrity_check_interval_secs: u64,
    pub self_protection_prevent_uninstall: bool,
    #[serde(skip)]
    pub bootstrap_config_path: Option<PathBuf>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_id: default_agent_id(),
            machine_id: None,
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
            heartbeat_interval_secs: 30,
            reconnect_backoff_max_secs: 300,
            telemetry_process_exec: true,
            telemetry_file_events: true,
            telemetry_network_connections: true,
            telemetry_dns_queries: true,
            telemetry_module_loads: true,
            telemetry_user_logins: true,
            telemetry_flush_interval_ms: 100,
            telemetry_max_batch_size: 100,
            detection_sigma_rules_dir: "/var/lib/eguard-agent/rules/sigma".to_string(),
            detection_yara_rules_dir: "/var/lib/eguard-agent/rules/yara".to_string(),
            detection_ioc_dir: "/var/lib/eguard-agent/rules/ioc".to_string(),
            detection_scan_on_create: true,
            detection_max_file_scan_size_mb: 100,
            compliance_check_interval_secs: 300,
            compliance_auto_remediate: false,
            baseline_learning_period_days: 7,
            baseline_refresh_interval_days: 7,
            baseline_stale_after_days: 30,
            self_protection_integrity_check_interval_secs: 60,
            self_protection_prevent_uninstall: true,
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
        self.apply_env_agent_identity();
        self.apply_env_server_address();
        self.apply_env_runtime_mode();
        self.apply_env_transport_mode();
        self.apply_env_enrollment();
        self.apply_env_response();
        self.apply_env_storage();
        self.apply_env_tls();
        self.ensure_valid_agent_id();
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

        self.apply_file_agent(file_cfg.agent);
        self.apply_file_server(file_cfg.server);
        self.apply_file_transport(file_cfg.transport);
        self.apply_file_response(file_cfg.response);
        self.apply_file_storage(file_cfg.storage);
        self.apply_file_tls(file_cfg.tls);
        self.apply_file_heartbeat(file_cfg.heartbeat);
        self.apply_file_telemetry(file_cfg.telemetry);
        self.apply_file_detection(file_cfg.detection);
        self.apply_file_compliance(file_cfg.compliance);
        self.apply_file_baseline(file_cfg.baseline);
        self.apply_file_self_protection(file_cfg.self_protection);

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

    fn apply_env_agent_identity(&mut self) {
        if let Some(v) = env_non_empty("EGUARD_AGENT_ID") {
            self.agent_id = v;
        }
        if let Some(v) = env_non_empty("EGUARD_AGENT_MAC") {
            self.mac = v;
        }
    }

    fn apply_env_server_address(&mut self) {
        let server = env_non_empty("EGUARD_SERVER_ADDR").or_else(|| env_non_empty("EGUARD_SERVER"));
        if let Some(server) = server {
            self.server_addr = server;
        }
    }

    fn apply_env_runtime_mode(&mut self) {
        if let Ok(mode) = std::env::var("EGUARD_AGENT_MODE") {
            self.mode = parse_mode(&mode);
        }
    }

    fn apply_env_transport_mode(&mut self) {
        if let Some(v) = env_non_empty("EGUARD_TRANSPORT_MODE") {
            self.transport_mode = v;
        }
    }

    fn apply_env_enrollment(&mut self) {
        if let Ok(v) = std::env::var("EGUARD_ENROLLMENT_TOKEN") {
            self.enrollment_token = non_empty(Some(v));
        }
        if let Ok(v) = std::env::var("EGUARD_TENANT_ID") {
            self.tenant_id = non_empty(Some(v));
        }
    }

    fn apply_env_response(&mut self) {
        if let Ok(v) = std::env::var("EGUARD_AUTONOMOUS_RESPONSE") {
            self.response.autonomous_response = parse_bool(&v);
        }
        if let Ok(v) = std::env::var("EGUARD_RESPONSE_DRY_RUN") {
            self.response.dry_run = parse_bool(&v);
        }
        if let Some(v) = env_usize("EGUARD_RESPONSE_MAX_KILLS_PER_MINUTE") {
            self.response.max_kills_per_minute = v;
        }
    }

    fn apply_env_storage(&mut self) {
        if let Some(v) = env_non_empty("EGUARD_BUFFER_BACKEND") {
            self.offline_buffer_backend = v;
        }
        if let Some(v) = env_non_empty("EGUARD_BUFFER_PATH") {
            self.offline_buffer_path = v;
        }
        if let Ok(v) = std::env::var("EGUARD_BUFFER_CAP_MB") {
            if let Some(cap) = parse_cap_mb(&v) {
                self.offline_buffer_cap_bytes = cap;
            }
        }
    }

    fn apply_env_tls(&mut self) {
        if let Ok(v) = std::env::var("EGUARD_TLS_CERT") {
            self.tls_cert_path = non_empty(Some(v));
        }
        if let Ok(v) = std::env::var("EGUARD_TLS_KEY") {
            self.tls_key_path = non_empty(Some(v));
        }
        if let Ok(v) = std::env::var("EGUARD_TLS_CA") {
            self.tls_ca_path = non_empty(Some(v));
        }
    }

    fn ensure_valid_agent_id(&mut self) {
        if self.agent_id.trim().is_empty() {
            self.agent_id = default_agent_id();
        }
    }

    fn apply_file_agent(&mut self, agent: Option<FileAgentConfig>) {
        let Some(agent) = agent else {
            return;
        };

        if let Some(v) = non_empty(agent.id) {
            self.agent_id = v;
        }
        if let Some(v) = non_empty(agent.machine_id) {
            self.machine_id = Some(v);
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

    fn apply_file_transport(&mut self, transport: Option<FileTransportConfig>) {
        let Some(transport) = transport else {
            return;
        };
        if let Some(v) = non_empty(transport.mode) {
            self.transport_mode = v;
        }
    }

    fn apply_file_response(&mut self, response: Option<FileResponseConfig>) {
        let Some(response) = response else {
            return;
        };

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

    fn apply_file_server(&mut self, server: Option<FileServerConfig>) {
        let Some(server) = server else {
            return;
        };

        if let Some(address) = non_empty(server.address) {
            self.server_addr = format_server_addr(&address, server.grpc_port);
        }
        if let Some(v) = non_empty(server.cert_file) {
            self.tls_cert_path = Some(v);
        }
        if let Some(v) = non_empty(server.key_file) {
            self.tls_key_path = Some(v);
        }
        if let Some(v) = non_empty(server.ca_file) {
            self.tls_ca_path = Some(v);
        }
    }

    fn apply_file_storage(&mut self, storage: Option<FileStorageConfig>) {
        let Some(storage) = storage else {
            return;
        };

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

    fn apply_file_tls(&mut self, tls: Option<FileTlsConfig>) {
        let Some(tls) = tls else {
            return;
        };

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

    fn apply_file_heartbeat(&mut self, heartbeat: Option<FileHeartbeatConfig>) {
        let Some(heartbeat) = heartbeat else {
            return;
        };
        if let Some(v) = heartbeat.interval_secs {
            self.heartbeat_interval_secs = v;
        }
        if let Some(v) = heartbeat.reconnect_backoff_max_secs {
            self.reconnect_backoff_max_secs = v;
        }
    }

    fn apply_file_telemetry(&mut self, telemetry: Option<FileTelemetryConfig>) {
        let Some(telemetry) = telemetry else {
            return;
        };
        if let Some(v) = telemetry.process_exec {
            self.telemetry_process_exec = v;
        }
        if let Some(v) = telemetry.file_events {
            self.telemetry_file_events = v;
        }
        if let Some(v) = telemetry.network_connections {
            self.telemetry_network_connections = v;
        }
        if let Some(v) = telemetry.dns_queries {
            self.telemetry_dns_queries = v;
        }
        if let Some(v) = telemetry.module_loads {
            self.telemetry_module_loads = v;
        }
        if let Some(v) = telemetry.user_logins {
            self.telemetry_user_logins = v;
        }
        if let Some(v) = telemetry.flush_interval_ms {
            self.telemetry_flush_interval_ms = v;
        }
        if let Some(v) = telemetry.max_batch_size {
            self.telemetry_max_batch_size = v;
        }
    }

    fn apply_file_detection(&mut self, detection: Option<FileDetectionConfig>) {
        let Some(detection) = detection else {
            return;
        };
        if let Some(v) = non_empty(detection.sigma_rules_dir) {
            self.detection_sigma_rules_dir = v;
        }
        if let Some(v) = non_empty(detection.yara_rules_dir) {
            self.detection_yara_rules_dir = v;
        }
        if let Some(v) = non_empty(detection.ioc_dir) {
            self.detection_ioc_dir = v;
        }
        if let Some(v) = detection.scan_on_create {
            self.detection_scan_on_create = v;
        }
        if let Some(v) = detection.max_file_scan_size_mb {
            self.detection_max_file_scan_size_mb = v;
        }
    }

    fn apply_file_compliance(&mut self, compliance: Option<FileComplianceConfig>) {
        let Some(compliance) = compliance else {
            return;
        };
        if let Some(v) = compliance.check_interval_secs {
            self.compliance_check_interval_secs = v;
        }
        if let Some(v) = compliance.auto_remediate {
            self.compliance_auto_remediate = v;
        }
    }

    fn apply_file_baseline(&mut self, baseline: Option<FileBaselineConfig>) {
        let Some(baseline) = baseline else {
            return;
        };
        if let Some(v) = baseline.learning_period_days {
            self.baseline_learning_period_days = v;
        }
        if let Some(v) = baseline.refresh_interval_days {
            self.baseline_refresh_interval_days = v;
        }
        if let Some(v) = baseline.stale_after_days {
            self.baseline_stale_after_days = v;
        }
    }

    fn apply_file_self_protection(&mut self, self_protection: Option<FileSelfProtectionConfig>) {
        let Some(self_protection) = self_protection else {
            return;
        };
        if let Some(v) = self_protection.integrity_check_interval_secs {
            self.self_protection_integrity_check_interval_secs = v;
        }
        if let Some(v) = self_protection.prevent_uninstall {
            self.self_protection_prevent_uninstall = v;
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
struct FileConfig {
    #[serde(default)]
    agent: Option<FileAgentConfig>,
    #[serde(default)]
    response: Option<FileResponseConfig>,
    #[serde(default)]
    server: Option<FileServerConfig>,
    #[serde(default)]
    storage: Option<FileStorageConfig>,
    #[serde(default)]
    tls: Option<FileTlsConfig>,
    #[serde(default)]
    transport: Option<FileTransportConfig>,
    #[serde(default)]
    heartbeat: Option<FileHeartbeatConfig>,
    #[serde(default)]
    telemetry: Option<FileTelemetryConfig>,
    #[serde(default)]
    detection: Option<FileDetectionConfig>,
    #[serde(default)]
    compliance: Option<FileComplianceConfig>,
    #[serde(default)]
    baseline: Option<FileBaselineConfig>,
    #[serde(default)]
    self_protection: Option<FileSelfProtectionConfig>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct FileAgentConfig {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    machine_id: Option<String>,
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
struct FileServerConfig {
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    grpc_port: Option<u16>,
    #[serde(default)]
    cert_file: Option<String>,
    #[serde(default)]
    key_file: Option<String>,
    #[serde(default)]
    ca_file: Option<String>,
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

#[derive(Debug, Clone, Deserialize, Default)]
struct FileHeartbeatConfig {
    #[serde(default)]
    interval_secs: Option<u64>,
    #[serde(default)]
    reconnect_backoff_max_secs: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct FileTelemetryConfig {
    #[serde(default)]
    process_exec: Option<bool>,
    #[serde(default)]
    file_events: Option<bool>,
    #[serde(default)]
    network_connections: Option<bool>,
    #[serde(default)]
    dns_queries: Option<bool>,
    #[serde(default)]
    module_loads: Option<bool>,
    #[serde(default)]
    user_logins: Option<bool>,
    #[serde(default)]
    flush_interval_ms: Option<u64>,
    #[serde(default)]
    max_batch_size: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct FileDetectionConfig {
    #[serde(default)]
    sigma_rules_dir: Option<String>,
    #[serde(default)]
    yara_rules_dir: Option<String>,
    #[serde(default)]
    ioc_dir: Option<String>,
    #[serde(default)]
    scan_on_create: Option<bool>,
    #[serde(default)]
    max_file_scan_size_mb: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct FileComplianceConfig {
    #[serde(default)]
    check_interval_secs: Option<u64>,
    #[serde(default)]
    auto_remediate: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct FileBaselineConfig {
    #[serde(default)]
    learning_period_days: Option<u64>,
    #[serde(default)]
    refresh_interval_days: Option<u64>,
    #[serde(default)]
    stale_after_days: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct FileSelfProtectionConfig {
    #[serde(default)]
    integrity_check_interval_secs: Option<u64>,
    #[serde(default)]
    prevent_uninstall: Option<bool>,
}

#[derive(Debug, Clone, Default)]
struct BootstrapConfig {
    address: Option<String>,
    grpc_port: Option<u16>,
    enrollment_token: Option<String>,
    tenant_id: Option<String>,
}

fn resolve_config_path() -> Result<Option<PathBuf>> {
    resolve_path_from_env_or_candidates("EGUARD_AGENT_CONFIG", &AGENT_CONFIG_CANDIDATES)
}

fn resolve_bootstrap_path() -> Result<Option<PathBuf>> {
    resolve_path_from_env_or_candidates("EGUARD_BOOTSTRAP_CONFIG", &BOOTSTRAP_CONFIG_CANDIDATES)
}

fn resolve_path_from_env_or_candidates(
    env_var: &str,
    candidates: &[&str],
) -> Result<Option<PathBuf>> {
    if let Ok(p) = std::env::var(env_var) {
        let p = p.trim();
        if !p.is_empty() {
            let path = PathBuf::from(p);
            if !path.exists() {
                anyhow::bail!("configured {} does not exist: {}", env_var, path.display());
            }
            return Ok(Some(path));
        }
    }

    for candidate in candidates {
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

    for raw_line in raw.lines() {
        let line = raw_line.trim();
        if is_bootstrap_comment_or_empty(line) {
            continue;
        }

        if let Some(parsed_section) = parse_bootstrap_section_name(line) {
            section = parsed_section;
            continue;
        }

        if section != "server" {
            continue;
        }

        let Some((key, value)) = parse_bootstrap_server_entry(line) else {
            continue;
        };
        apply_bootstrap_server_entry(&mut cfg, &key, &value);
    }

    Ok(cfg)
}

fn is_bootstrap_comment_or_empty(line: &str) -> bool {
    line.is_empty() || line.starts_with('#') || line.starts_with(';')
}

fn parse_bootstrap_section_name(line: &str) -> Option<String> {
    line.strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .map(|section| section.trim().to_ascii_lowercase())
}

fn parse_bootstrap_server_entry(line: &str) -> Option<(String, String)> {
    let line = strip_bootstrap_inline_comment(line).trim();
    if line.is_empty() {
        return None;
    }

    let (raw_key, raw_value) = line.split_once('=')?;
    let key = raw_key.trim().to_ascii_lowercase();
    let value = raw_value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim()
        .to_string();
    if value.is_empty() {
        return None;
    }

    Some((key, value))
}

fn strip_bootstrap_inline_comment(line: &str) -> &str {
    let hash_idx = line.find('#');
    let semicolon_idx = line.find(';');
    let cut_at = match (hash_idx, semicolon_idx) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    };

    cut_at.map(|idx| &line[..idx]).unwrap_or(line)
}

fn apply_bootstrap_server_entry(cfg: &mut BootstrapConfig, key: &str, value: &str) {
    match key {
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

fn env_non_empty(name: &str) -> Option<String> {
    std::env::var(name).ok().and_then(|v| non_empty(Some(v)))
}

fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
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
mod tests;
