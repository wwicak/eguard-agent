use super::types::AgentConfig;
use super::util::{
    default_agent_id, env_non_empty, env_usize, non_empty, parse_bool, parse_cap_mb, parse_mode,
    split_csv,
};

impl AgentConfig {
    pub(super) fn apply_env_overrides(&mut self) {
        self.apply_env_agent_identity();
        self.apply_env_server_address();
        self.apply_env_runtime_mode();
        self.apply_env_transport_mode();
        self.apply_env_enrollment();
        self.apply_env_response();
        self.apply_env_storage();
        self.apply_env_tls();
        self.apply_env_detection();
        self.apply_env_compliance();
        self.apply_env_control_plane();
        self.apply_env_inventory();
        self.apply_env_self_protection();
        self.ensure_valid_agent_id();
    }

    fn apply_env_detection(&mut self) {
        if let Some(v) = env_non_empty("EGUARD_BUNDLE_PATH") {
            self.detection_bundle_path = v;
        }
        if let Some(v) = env_non_empty("EGUARD_MEMORY_SCAN_MODE") {
            self.detection_memory_scan_mode = v;
        }
        if let Some(v) = env_non_empty("EGUARD_MEMORY_SCAN_ENABLED") {
            if let Ok(parsed) = v.parse::<bool>() {
                self.detection_memory_scan_enabled = parsed;
            }
        }
        if let Some(v) = env_non_empty("EGUARD_MEMORY_SCAN_INTERVAL_SECS") {
            if let Ok(parsed) = v.parse::<u64>() {
                self.detection_memory_scan_interval_secs = parsed;
            }
        }
        if let Some(v) = env_non_empty("EGUARD_MEMORY_SCAN_MAX_PIDS") {
            if let Ok(parsed) = v.parse::<usize>() {
                self.detection_memory_scan_max_pids = parsed;
            }
        }
        if let Some(v) = env_non_empty("EGUARD_KERNEL_INTEGRITY_ENABLED") {
            if let Ok(parsed) = v.parse::<bool>() {
                self.detection_kernel_integrity_enabled = parsed;
            }
        }
        if let Some(v) = env_non_empty("EGUARD_KERNEL_INTEGRITY_INTERVAL_SECS") {
            if let Ok(parsed) = v.parse::<u64>() {
                self.detection_kernel_integrity_interval_secs = parsed;
            }
        }
        if let Some(v) = env_non_empty("EGUARD_RANSOMWARE_WRITE_THRESHOLD") {
            if let Ok(parsed) = v.parse::<u32>() {
                self.detection_ransomware_write_threshold = parsed;
            }
        }
        if let Some(v) = env_non_empty("EGUARD_RANSOMWARE_WRITE_WINDOW_SECS") {
            if let Ok(parsed) = v.parse::<u64>() {
                self.detection_ransomware_write_window_secs = parsed;
            }
        }
        if let Some(v) = env_non_empty("EGUARD_RANSOMWARE_ADAPTIVE_DELTA") {
            if let Ok(parsed) = v.parse::<f64>() {
                self.detection_ransomware_adaptive_delta = parsed;
            }
        }
        if let Some(v) = env_non_empty("EGUARD_RANSOMWARE_ADAPTIVE_MIN_SAMPLES") {
            if let Ok(parsed) = v.parse::<usize>() {
                self.detection_ransomware_adaptive_min_samples = parsed;
            }
        }
        if let Some(v) = env_non_empty("EGUARD_RANSOMWARE_ADAPTIVE_FLOOR") {
            if let Ok(parsed) = v.parse::<u32>() {
                self.detection_ransomware_adaptive_floor = parsed;
            }
        }
        if let Some(v) = env_non_empty("EGUARD_RANSOMWARE_LEARNED_ROOT_MIN_HITS") {
            if let Ok(parsed) = v.parse::<u32>() {
                self.detection_ransomware_learned_root_min_hits = parsed;
            }
        }
        if let Some(v) = env_non_empty("EGUARD_RANSOMWARE_LEARNED_ROOT_MAX") {
            if let Ok(parsed) = v.parse::<usize>() {
                self.detection_ransomware_learned_root_max = parsed;
            }
        }
        if let Some(v) = env_non_empty("EGUARD_RANSOMWARE_USER_PATH_PREFIXES") {
            self.detection_ransomware_user_path_prefixes = split_csv(&v);
        }
        if let Some(v) = env_non_empty("EGUARD_RANSOMWARE_SYSTEM_PATH_PREFIXES") {
            self.detection_ransomware_system_path_prefixes = split_csv(&v);
        }
        if let Some(v) = env_non_empty("EGUARD_RANSOMWARE_TEMP_PATH_TOKENS") {
            self.detection_ransomware_temp_path_tokens = split_csv(&v);
        }
    }

    fn apply_env_compliance(&mut self) {
        if let Some(v) = env_non_empty("EGUARD_COMPLIANCE_CHECK_INTERVAL_SECS") {
            if let Ok(parsed) = v.parse::<u64>() {
                self.compliance_check_interval_secs = parsed;
            }
        }
        if let Some(v) = env_non_empty("EGUARD_COMPLIANCE_AUTO_REMEDIATE") {
            if let Ok(parsed) = v.parse::<bool>() {
                self.compliance_auto_remediate = parsed;
            }
        }
    }

    fn apply_env_control_plane(&mut self) {
        if let Some(v) = env_non_empty("EGUARD_POLICY_REFRESH_INTERVAL_SECS") {
            if let Ok(parsed) = v.parse::<u64>() {
                self.policy_refresh_interval_secs = parsed;
            }
        }
    }

    fn apply_env_inventory(&mut self) {
        if let Some(v) = env_non_empty("EGUARD_INVENTORY_INTERVAL_SECS") {
            if let Ok(parsed) = v.parse::<u64>() {
                self.inventory_interval_secs = parsed;
            }
        }
        if let Some(v) = env_non_empty("EGUARD_DEVICE_OWNERSHIP") {
            self.device_ownership = v;
        }
    }

    fn apply_env_self_protection(&mut self) {
        if let Some(v) = env_non_empty("EGUARD_SELF_PROTECTION_INTEGRITY_CHECK_INTERVAL_SECS") {
            if let Ok(parsed) = v.parse::<u64>() {
                self.self_protection_integrity_check_interval_secs = parsed;
            }
        }
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
        let mode =
            env_non_empty("EGUARD_TRANSPORT_MODE").or_else(|| env_non_empty("EGUARD_TRANSPORT"));
        if let Some(v) = mode {
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
        if let Ok(v) = std::env::var("EGUARD_RESPONSE_AUTO_ISOLATION_ENABLED") {
            self.response.auto_isolation.enabled = parse_bool(&v);
        }
        if let Some(v) = env_usize("EGUARD_RESPONSE_AUTO_ISOLATION_MIN_INCIDENTS") {
            self.response.auto_isolation.min_incidents_in_window = v;
        }
        if let Some(v) = env_usize("EGUARD_RESPONSE_AUTO_ISOLATION_WINDOW_SECS") {
            self.response.auto_isolation.window_secs = v as u64;
        }
        if let Some(v) = env_usize("EGUARD_RESPONSE_AUTO_ISOLATION_MAX_PER_HOUR") {
            self.response.auto_isolation.max_isolations_per_hour = v;
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
        if let Ok(v) = std::env::var("EGUARD_TLS_PINNED_CA_SHA256") {
            self.tls_pinned_ca_sha256 = non_empty(Some(v));
        }
        if let Ok(v) = std::env::var("EGUARD_TLS_CA_PIN_PATH") {
            self.tls_ca_pin_path = non_empty(Some(v));
        }
        if let Ok(v) = std::env::var("EGUARD_TLS_ROTATE_BEFORE_DAYS") {
            if let Ok(days) = v.trim().parse::<u64>() {
                if days > 0 {
                    self.tls_rotate_before_expiry_days = days;
                }
            }
        }
    }

    fn ensure_valid_agent_id(&mut self) {
        if self.agent_id.trim().is_empty() {
            self.agent_id = default_agent_id();
        }
    }
}
