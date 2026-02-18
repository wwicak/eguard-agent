use anyhow::{Context, Result};
use response::ResponsePolicy;
use serde::Deserialize;

use super::crypto::read_agent_config_text;
use super::paths::resolve_config_path;
use super::types::AgentConfig;
use super::util::{format_server_addr, non_empty, parse_mode};

impl AgentConfig {
    pub(super) fn apply_file_config(&mut self) -> Result<bool> {
        let path = resolve_config_path()?;
        let Some(path) = path else {
            return Ok(false);
        };

        let raw = read_agent_config_text(&path)
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
        self.apply_file_control_plane(file_cfg.control_plane);
        self.apply_file_inventory(file_cfg.inventory);
        self.apply_file_baseline(file_cfg.baseline);
        self.apply_file_self_protection(file_cfg.self_protection);

        Ok(true)
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
        if let Some(auto_isolation) = response.auto_isolation {
            if let Some(v) = auto_isolation.enabled {
                self.response.auto_isolation.enabled = v;
            }
            if let Some(v) = auto_isolation.min_incidents_in_window {
                self.response.auto_isolation.min_incidents_in_window = v;
            }
            if let Some(v) = auto_isolation.window_secs {
                self.response.auto_isolation.window_secs = v;
            }
            if let Some(v) = auto_isolation.max_isolations_per_hour {
                self.response.auto_isolation.max_isolations_per_hour = v;
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
        if let Some(v) = non_empty(tls.pinned_ca_sha256) {
            self.tls_pinned_ca_sha256 = Some(v);
        }
        if let Some(v) = non_empty(tls.ca_pin_path) {
            self.tls_ca_pin_path = Some(v);
        }
        if let Some(days) = tls.rotate_before_expiry_days {
            if days > 0 {
                self.tls_rotate_before_expiry_days = days;
            }
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
        if let Some(v) = non_empty(detection.bundle_path) {
            self.detection_bundle_path = v;
        }
        if let Some(v) = detection.scan_on_create {
            self.detection_scan_on_create = v;
        }
        if let Some(v) = detection.max_file_scan_size_mb {
            self.detection_max_file_scan_size_mb = v;
        }
        if let Some(v) = detection.memory_scan_enabled {
            self.detection_memory_scan_enabled = v;
        }
        if let Some(v) = detection.memory_scan_interval_secs {
            self.detection_memory_scan_interval_secs = v;
        }
        if let Some(v) = detection.memory_scan_mode.clone() {
            self.detection_memory_scan_mode = v;
        }
        if let Some(v) = detection.memory_scan_max_pids {
            self.detection_memory_scan_max_pids = v;
        }
        if let Some(v) = detection.kernel_integrity_enabled {
            self.detection_kernel_integrity_enabled = v;
        }
        if let Some(v) = detection.kernel_integrity_interval_secs {
            self.detection_kernel_integrity_interval_secs = v;
        }
        if let Some(v) = detection.ransomware_write_threshold {
            self.detection_ransomware_write_threshold = v;
        }
        if let Some(v) = detection.ransomware_write_window_secs {
            self.detection_ransomware_write_window_secs = v;
        }
        if let Some(v) = detection.ransomware_adaptive_delta {
            self.detection_ransomware_adaptive_delta = v;
        }
        if let Some(v) = detection.ransomware_adaptive_min_samples {
            self.detection_ransomware_adaptive_min_samples = v;
        }
        if let Some(v) = detection.ransomware_adaptive_floor {
            self.detection_ransomware_adaptive_floor = v;
        }
        if let Some(v) = detection.ransomware_learned_root_min_hits {
            self.detection_ransomware_learned_root_min_hits = v;
        }
        if let Some(v) = detection.ransomware_learned_root_max {
            self.detection_ransomware_learned_root_max = v;
        }
        if let Some(v) = detection.ransomware_user_path_prefixes {
            self.detection_ransomware_user_path_prefixes = v;
        }
        if let Some(v) = detection.ransomware_system_path_prefixes {
            self.detection_ransomware_system_path_prefixes = v;
        }
        if let Some(v) = detection.ransomware_temp_path_tokens {
            self.detection_ransomware_temp_path_tokens = v;
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

    fn apply_file_control_plane(&mut self, control_plane: Option<FileControlPlaneConfig>) {
        let Some(control_plane) = control_plane else {
            return;
        };
        if let Some(v) = control_plane.policy_refresh_interval_secs {
            self.policy_refresh_interval_secs = v;
        }
    }

    fn apply_file_inventory(&mut self, inventory: Option<FileInventoryConfig>) {
        let Some(inventory) = inventory else {
            return;
        };
        if let Some(v) = inventory.interval_secs {
            self.inventory_interval_secs = v;
        }
        if let Some(v) = inventory.ownership {
            self.device_ownership = v;
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
    control_plane: Option<FileControlPlaneConfig>,
    #[serde(default)]
    inventory: Option<FileInventoryConfig>,
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
    #[serde(default)]
    auto_isolation: Option<FileResponseAutoIsolationConfig>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct FileResponseAutoIsolationConfig {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    min_incidents_in_window: Option<usize>,
    #[serde(default)]
    window_secs: Option<u64>,
    #[serde(default)]
    max_isolations_per_hour: Option<usize>,
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
pub struct FileResponsePolicy {
    #[serde(default)]
    pub kill: Option<bool>,
    #[serde(default)]
    pub quarantine: Option<bool>,
    #[serde(default)]
    pub capture_script: Option<bool>,
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
    #[serde(default)]
    pinned_ca_sha256: Option<String>,
    #[serde(default)]
    ca_pin_path: Option<String>,
    #[serde(default)]
    rotate_before_expiry_days: Option<u64>,
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
    bundle_path: Option<String>,
    #[serde(default)]
    scan_on_create: Option<bool>,
    #[serde(default)]
    max_file_scan_size_mb: Option<usize>,
    #[serde(default)]
    memory_scan_enabled: Option<bool>,
    #[serde(default)]
    memory_scan_interval_secs: Option<u64>,
    #[serde(default)]
    memory_scan_mode: Option<String>,
    #[serde(default)]
    memory_scan_max_pids: Option<usize>,
    #[serde(default)]
    kernel_integrity_enabled: Option<bool>,
    #[serde(default)]
    kernel_integrity_interval_secs: Option<u64>,
    #[serde(default)]
    ransomware_write_threshold: Option<u32>,
    #[serde(default)]
    ransomware_write_window_secs: Option<u64>,
    #[serde(default)]
    ransomware_adaptive_delta: Option<f64>,
    #[serde(default)]
    ransomware_adaptive_min_samples: Option<usize>,
    #[serde(default)]
    ransomware_adaptive_floor: Option<u32>,
    #[serde(default)]
    ransomware_learned_root_min_hits: Option<u32>,
    #[serde(default)]
    ransomware_learned_root_max: Option<usize>,
    #[serde(default)]
    ransomware_user_path_prefixes: Option<Vec<String>>,
    #[serde(default)]
    ransomware_system_path_prefixes: Option<Vec<String>>,
    #[serde(default)]
    ransomware_temp_path_tokens: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct FileComplianceConfig {
    #[serde(default)]
    check_interval_secs: Option<u64>,
    #[serde(default)]
    auto_remediate: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct FileControlPlaneConfig {
    #[serde(default)]
    policy_refresh_interval_secs: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct FileInventoryConfig {
    #[serde(default)]
    interval_secs: Option<u64>,
    #[serde(default)]
    ownership: Option<String>,
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

pub(super) fn apply_response_policy(dst: &mut ResponsePolicy, src: Option<FileResponsePolicy>) {
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
