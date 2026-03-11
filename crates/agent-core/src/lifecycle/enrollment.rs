use std::io;
use std::path::{Path, PathBuf};

use tracing::warn;

use grpc_client::EnrollmentEnvelope;

use crate::config::AgentConfig;

use super::AgentRuntime;

#[cfg(target_os = "linux")]
const DEFAULT_AGENT_CONFIG_PATH: &str = "/etc/eguard-agent/agent.conf";

#[cfg(target_os = "windows")]
const DEFAULT_AGENT_CONFIG_PATH: &str = r"C:\ProgramData\eGuard\agent.conf";

#[cfg(target_os = "macos")]
const DEFAULT_AGENT_CONFIG_PATH: &str = "/Library/Application Support/eGuard/agent.conf";
const ENCRYPTED_CONFIG_PREFIX: &str = "eguardcfg:v1:";

impl AgentRuntime {
    pub(super) async fn ensure_enrolled(&mut self) {
        if self.enrolled {
            return;
        }

        // Exponential backoff: skip enrollment if we tried recently and failed.
        // Backoff starts at 5s, doubles each failure, caps at 5 minutes.
        let now = super::timing::now_unix();
        if let Some(last_attempt) = self.last_enrollment_attempt_unix {
            let backoff_secs = self.enrollment_backoff_secs.min(300);
            if now.saturating_sub(last_attempt) < backoff_secs {
                return;
            }
        }

        self.last_enrollment_attempt_unix = Some(now);

        let enroll = self.build_enrollment_envelope();
        match self.client.enroll_with_material(&enroll).await {
            Ok(Some(result)) => {
                if !result.agent_id.is_empty() {
                    tracing::info!(agent_id = %result.agent_id, "enrollment succeeded, updating agent_id");
                    self.config.agent_id = result.agent_id;
                }
                self.enrolled = true;
                self.enrollment_backoff_secs = 5;
                self.consume_bootstrap_config();
            }
            Ok(None) => {
                self.enrolled = true;
                self.enrollment_backoff_secs = 5;
                self.consume_bootstrap_config();
            }
            Err(err) => {
                let err_str = err.to_string().to_ascii_lowercase();
                if err_str.contains("already exists") || err_str.contains("already_enrolled") {
                    tracing::info!("agent already enrolled on server, marking as enrolled");
                    self.enrolled = true;
                    self.enrollment_backoff_secs = 5;
                    self.consume_bootstrap_config();
                } else {
                    warn!(
                        error = %err,
                        next_retry_secs = self.enrollment_backoff_secs.min(300),
                        "enrollment failed, will retry with backoff"
                    );
                    self.enrollment_backoff_secs = (self.enrollment_backoff_secs * 2).min(300);
                }
            }
        }
    }

    fn build_enrollment_envelope(&self) -> EnrollmentEnvelope {
        let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| self.config.agent_id.clone());
        EnrollmentEnvelope {
            agent_id: self.config.agent_id.clone(),
            mac: self.config.mac.clone(),
            hostname,
            enrollment_token: self.config.enrollment_token.clone(),
            tenant_id: self.config.tenant_id.clone(),
        }
    }

    fn consume_bootstrap_config(&self) {
        let Some(path) = self.config.bootstrap_config_path.as_ref() else {
            return;
        };

        match persist_runtime_config_snapshot(&self.config) {
            Ok(config_path) => {
                tracing::info!(
                    path = %config_path.display(),
                    "persisted bootstrap-derived runtime config to agent.conf"
                );
            }
            Err(err) => {
                warn!(
                    error = %err,
                    bootstrap_path = %path.display(),
                    "failed persisting bootstrap-derived runtime config; keeping bootstrap file"
                );
                return;
            }
        }

        match std::fs::remove_file(path) {
            Ok(()) => {
                tracing::info!(path = %path.display(), "consumed bootstrap config after enrollment")
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                warn!(error = %err, path = %path.display(), "failed consuming bootstrap config")
            }
        }
    }
}

fn resolve_agent_config_persist_path() -> PathBuf {
    if let Ok(raw) = std::env::var("EGUARD_AGENT_CONFIG") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }

    PathBuf::from(DEFAULT_AGENT_CONFIG_PATH)
}

pub(crate) fn persist_runtime_config_snapshot(config: &AgentConfig) -> Result<PathBuf, String> {
    let path = resolve_agent_config_persist_path();

    let existing = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == io::ErrorKind::NotFound => String::new(),
        Err(err) => {
            return Err(format!(
                "read existing agent config {}: {}",
                path.display(),
                err
            ));
        }
    };

    if existing.trim_start().starts_with(ENCRYPTED_CONFIG_PREFIX) {
        return Err(format!(
            "agent config {} is encrypted; refusing plaintext migration",
            path.display()
        ));
    }

    let mut root = if existing.trim().is_empty() {
        toml::Value::Table(toml::map::Map::new())
    } else {
        existing.parse::<toml::Value>().map_err(|err| {
            format!(
                "parse existing agent config TOML {}: {}",
                path.display(),
                err
            )
        })?
    };

    let root_table = root.as_table_mut().ok_or_else(|| {
        format!(
            "agent config {} root TOML value must be table",
            path.display()
        )
    })?;

    let agent_table = root_table
        .entry("agent")
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .ok_or_else(|| format!("agent config {} [agent] must be table", path.display()))?;

    agent_table.insert(
        "server_addr".to_string(),
        toml::Value::String(config.server_addr.clone()),
    );
    if !config.agent_id.is_empty() {
        agent_table.insert(
            "id".to_string(),
            toml::Value::String(config.agent_id.clone()),
        );
    }
    // Enrollment token is bootstrap-only credential material. Do not persist it
    // into restart config snapshots written to disk.
    agent_table.remove("enrollment_token");
    if let Some(tenant_id) = config
        .tenant_id
        .as_ref()
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
    {
        agent_table.insert(
            "tenant_id".to_string(),
            toml::Value::String(tenant_id.to_string()),
        );
    }
    agent_table.insert(
        "mode".to_string(),
        toml::Value::String(runtime_mode_label(&config.mode).to_string()),
    );

    let transport_table = root_table
        .entry("transport")
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .ok_or_else(|| format!("agent config {} [transport] must be table", path.display()))?;

    transport_table.insert(
        "mode".to_string(),
        toml::Value::String(config.transport_mode.clone()),
    );

    let response_table = ensure_table(root_table, "response", &path)?;
    response_table.insert(
        "autonomous_response".to_string(),
        toml::Value::Boolean(config.response.autonomous_response),
    );
    response_table.insert(
        "dry_run".to_string(),
        toml::Value::Boolean(config.response.dry_run),
    );

    let response_rate_limit = ensure_nested_table(response_table, "rate_limit", &path)?;
    response_rate_limit.insert(
        "max_kills_per_minute".to_string(),
        toml::Value::Integer(config.response.max_kills_per_minute as i64),
    );

    let auto_isolation = ensure_nested_table(response_table, "auto_isolation", &path)?;
    auto_isolation.insert(
        "enabled".to_string(),
        toml::Value::Boolean(config.response.auto_isolation.enabled),
    );
    auto_isolation.insert(
        "min_incidents_in_window".to_string(),
        toml::Value::Integer(config.response.auto_isolation.min_incidents_in_window as i64),
    );
    auto_isolation.insert(
        "window_secs".to_string(),
        toml::Value::Integer(config.response.auto_isolation.window_secs as i64),
    );
    auto_isolation.insert(
        "max_isolations_per_hour".to_string(),
        toml::Value::Integer(config.response.auto_isolation.max_isolations_per_hour as i64),
    );

    persist_response_policy(response_table, "definite", &config.response.definite, &path)?;
    persist_response_policy(
        response_table,
        "very_high",
        &config.response.very_high,
        &path,
    )?;
    persist_response_policy(response_table, "high", &config.response.high, &path)?;
    persist_response_policy(response_table, "medium", &config.response.medium, &path)?;

    let storage_table = ensure_table(root_table, "storage", &path)?;
    storage_table.insert(
        "backend".to_string(),
        toml::Value::String(config.offline_buffer_backend.clone()),
    );
    storage_table.insert(
        "path".to_string(),
        toml::Value::String(config.offline_buffer_path.clone()),
    );
    storage_table.insert(
        "cap_mb".to_string(),
        toml::Value::Integer((config.offline_buffer_cap_bytes / (1024 * 1024)) as i64),
    );

    let heartbeat_table = ensure_table(root_table, "heartbeat", &path)?;
    heartbeat_table.insert(
        "interval_secs".to_string(),
        toml::Value::Integer(config.heartbeat_interval_secs as i64),
    );
    heartbeat_table.insert(
        "reconnect_backoff_max_secs".to_string(),
        toml::Value::Integer(config.reconnect_backoff_max_secs as i64),
    );

    let telemetry_table = ensure_table(root_table, "telemetry", &path)?;
    telemetry_table.insert(
        "process_exec".to_string(),
        toml::Value::Boolean(config.telemetry_process_exec),
    );
    telemetry_table.insert(
        "file_events".to_string(),
        toml::Value::Boolean(config.telemetry_file_events),
    );
    telemetry_table.insert(
        "network_connections".to_string(),
        toml::Value::Boolean(config.telemetry_network_connections),
    );
    telemetry_table.insert(
        "dns_queries".to_string(),
        toml::Value::Boolean(config.telemetry_dns_queries),
    );
    telemetry_table.insert(
        "module_loads".to_string(),
        toml::Value::Boolean(config.telemetry_module_loads),
    );
    telemetry_table.insert(
        "user_logins".to_string(),
        toml::Value::Boolean(config.telemetry_user_logins),
    );
    telemetry_table.insert(
        "flush_interval_ms".to_string(),
        toml::Value::Integer(config.telemetry_flush_interval_ms as i64),
    );
    telemetry_table.insert(
        "max_batch_size".to_string(),
        toml::Value::Integer(config.telemetry_max_batch_size as i64),
    );

    let detection_table = ensure_table(root_table, "detection", &path)?;
    detection_table.insert(
        "sigma_rules_dir".to_string(),
        toml::Value::String(config.detection_sigma_rules_dir.clone()),
    );
    detection_table.insert(
        "yara_rules_dir".to_string(),
        toml::Value::String(config.detection_yara_rules_dir.clone()),
    );
    detection_table.insert(
        "ioc_dir".to_string(),
        toml::Value::String(config.detection_ioc_dir.clone()),
    );
    detection_table.insert(
        "bundle_path".to_string(),
        toml::Value::String(config.detection_bundle_path.clone()),
    );
    if let Some(value) = config
        .detection_bundle_public_key
        .as_ref()
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
    {
        detection_table.insert(
            "bundle_public_key".to_string(),
            toml::Value::String(value.to_string()),
        );
    } else {
        detection_table.remove("bundle_public_key");
    }
    detection_table.insert(
        "scan_on_create".to_string(),
        toml::Value::Boolean(config.detection_scan_on_create),
    );
    detection_table.insert(
        "max_file_scan_size_mb".to_string(),
        toml::Value::Integer(config.detection_max_file_scan_size_mb as i64),
    );
    detection_table.insert(
        "memory_scan_enabled".to_string(),
        toml::Value::Boolean(config.detection_memory_scan_enabled),
    );
    detection_table.insert(
        "memory_scan_interval_secs".to_string(),
        toml::Value::Integer(config.detection_memory_scan_interval_secs as i64),
    );
    detection_table.insert(
        "memory_scan_mode".to_string(),
        toml::Value::String(config.detection_memory_scan_mode.clone()),
    );
    detection_table.insert(
        "memory_scan_max_pids".to_string(),
        toml::Value::Integer(config.detection_memory_scan_max_pids as i64),
    );
    detection_table.insert(
        "kernel_integrity_enabled".to_string(),
        toml::Value::Boolean(config.detection_kernel_integrity_enabled),
    );
    detection_table.insert(
        "kernel_integrity_interval_secs".to_string(),
        toml::Value::Integer(config.detection_kernel_integrity_interval_secs as i64),
    );
    detection_table.insert(
        "ransomware_write_threshold".to_string(),
        toml::Value::Integer(config.detection_ransomware_write_threshold as i64),
    );
    detection_table.insert(
        "ransomware_write_window_secs".to_string(),
        toml::Value::Integer(config.detection_ransomware_write_window_secs as i64),
    );
    detection_table.insert(
        "ransomware_adaptive_delta".to_string(),
        toml::Value::Float(config.detection_ransomware_adaptive_delta),
    );
    detection_table.insert(
        "ransomware_adaptive_min_samples".to_string(),
        toml::Value::Integer(config.detection_ransomware_adaptive_min_samples as i64),
    );
    detection_table.insert(
        "ransomware_adaptive_floor".to_string(),
        toml::Value::Integer(config.detection_ransomware_adaptive_floor as i64),
    );
    detection_table.insert(
        "ransomware_learned_root_min_hits".to_string(),
        toml::Value::Integer(config.detection_ransomware_learned_root_min_hits as i64),
    );
    detection_table.insert(
        "ransomware_learned_root_max".to_string(),
        toml::Value::Integer(config.detection_ransomware_learned_root_max as i64),
    );
    detection_table.insert(
        "ransomware_user_path_prefixes".to_string(),
        toml::Value::Array(
            config
                .detection_ransomware_user_path_prefixes
                .iter()
                .cloned()
                .map(toml::Value::String)
                .collect(),
        ),
    );
    detection_table.insert(
        "ransomware_system_path_prefixes".to_string(),
        toml::Value::Array(
            config
                .detection_ransomware_system_path_prefixes
                .iter()
                .cloned()
                .map(toml::Value::String)
                .collect(),
        ),
    );
    detection_table.insert(
        "ransomware_temp_path_tokens".to_string(),
        toml::Value::Array(
            config
                .detection_ransomware_temp_path_tokens
                .iter()
                .cloned()
                .map(toml::Value::String)
                .collect(),
        ),
    );

    let compliance_table = ensure_table(root_table, "compliance", &path)?;
    compliance_table.insert(
        "check_interval_secs".to_string(),
        toml::Value::Integer(config.compliance_check_interval_secs as i64),
    );
    compliance_table.insert(
        "auto_remediate".to_string(),
        toml::Value::Boolean(config.compliance_auto_remediate),
    );

    let control_plane_table = ensure_table(root_table, "control_plane", &path)?;
    control_plane_table.insert(
        "policy_refresh_interval_secs".to_string(),
        toml::Value::Integer(config.policy_refresh_interval_secs as i64),
    );

    let inventory_table = ensure_table(root_table, "inventory", &path)?;
    inventory_table.insert(
        "interval_secs".to_string(),
        toml::Value::Integer(config.inventory_interval_secs as i64),
    );
    inventory_table.insert(
        "ownership".to_string(),
        toml::Value::String(config.device_ownership.clone()),
    );

    let baseline_table = ensure_table(root_table, "baseline", &path)?;
    baseline_table.insert(
        "learning_period_days".to_string(),
        toml::Value::Integer(config.baseline_learning_period_days as i64),
    );
    baseline_table.insert(
        "refresh_interval_days".to_string(),
        toml::Value::Integer(config.baseline_refresh_interval_days as i64),
    );
    baseline_table.insert(
        "stale_after_days".to_string(),
        toml::Value::Integer(config.baseline_stale_after_days as i64),
    );

    let self_protection_table = ensure_table(root_table, "self_protection", &path)?;
    self_protection_table.insert(
        "integrity_check_interval_secs".to_string(),
        toml::Value::Integer(config.self_protection_integrity_check_interval_secs as i64),
    );
    self_protection_table.insert(
        "prevent_uninstall".to_string(),
        toml::Value::Boolean(config.self_protection_prevent_uninstall),
    );

    let tls_table = ensure_table(root_table, "tls", &path)?;
    if let Some(value) = config.tls_cert_path.as_ref() {
        tls_table.insert("cert_path".to_string(), toml::Value::String(value.clone()));
    }
    if let Some(value) = config.tls_key_path.as_ref() {
        tls_table.insert("key_path".to_string(), toml::Value::String(value.clone()));
    }
    if let Some(value) = config.tls_ca_path.as_ref() {
        tls_table.insert("ca_path".to_string(), toml::Value::String(value.clone()));
    }
    if let Some(value) = config.tls_pinned_ca_sha256.as_ref() {
        tls_table.insert(
            "pinned_ca_sha256".to_string(),
            toml::Value::String(value.clone()),
        );
    }
    if let Some(value) = config.tls_ca_pin_path.as_ref() {
        tls_table.insert(
            "ca_pin_path".to_string(),
            toml::Value::String(value.clone()),
        );
    }
    tls_table.insert(
        "rotate_before_expiry_days".to_string(),
        toml::Value::Integer(config.tls_rotate_before_expiry_days as i64),
    );

    let serialized = toml::to_string_pretty(&root)
        .map_err(|err| format!("serialize updated agent config {}: {}", path.display(), err))?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("create config dir {}: {}", parent.display(), err))?;
    }

    let tmp_path = path.with_extension("tmp");
    write_private_config_file(&tmp_path, serialized.as_bytes())
        .map_err(|err| format!("write temp config {}: {}", tmp_path.display(), err))?;
    std::fs::rename(&tmp_path, &path).map_err(|err| {
        format!(
            "persist config {} via {}: {}",
            path.display(),
            tmp_path.display(),
            err
        )
    })?;

    Ok(path)
}

fn runtime_mode_label(mode: &crate::config::AgentMode) -> &'static str {
    match mode {
        crate::config::AgentMode::Learning => "learning",
        crate::config::AgentMode::Active => "active",
        crate::config::AgentMode::Degraded => "degraded",
    }
}

fn ensure_table<'a>(
    root_table: &'a mut toml::map::Map<String, toml::Value>,
    key: &str,
    path: &Path,
) -> Result<&'a mut toml::map::Map<String, toml::Value>, String> {
    root_table
        .entry(key.to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .ok_or_else(|| format!("agent config {} [{}] must be table", path.display(), key))
}

fn ensure_nested_table<'a>(
    parent: &'a mut toml::map::Map<String, toml::Value>,
    key: &str,
    path: &Path,
) -> Result<&'a mut toml::map::Map<String, toml::Value>, String> {
    parent
        .entry(key.to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .ok_or_else(|| {
            format!(
                "agent config {} nested table {} must be table",
                path.display(),
                key
            )
        })
}

fn persist_response_policy(
    response_table: &mut toml::map::Map<String, toml::Value>,
    key: &str,
    policy: &response::ResponsePolicy,
    path: &Path,
) -> Result<(), String> {
    let table = ensure_nested_table(response_table, key, path)?;
    table.insert("kill".to_string(), toml::Value::Boolean(policy.kill));
    table.insert(
        "quarantine".to_string(),
        toml::Value::Boolean(policy.quarantine),
    );
    table.insert(
        "capture_script".to_string(),
        toml::Value::Boolean(policy.capture_script),
    );
    Ok(())
}

fn write_private_config_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(data)?;
        file.sync_all()?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
    }
}

#[cfg(test)]
mod tests {
    use super::persist_runtime_config_snapshot;
    use crate::config::AgentConfig;

    fn env_lock() -> &'static std::sync::Mutex<()> {
        crate::test_support::env_lock()
    }

    fn clear_env() {
        std::env::remove_var("EGUARD_AGENT_CONFIG");
        std::env::remove_var("EGUARD_BOOTSTRAP_CONFIG");
        std::env::remove_var("EGUARD_SERVER_ADDR");
        std::env::remove_var("EGUARD_SERVER");
        std::env::remove_var("EGUARD_RULE_BUNDLE_PUBKEY");
    }

    #[test]
    fn persist_runtime_config_snapshot_writes_restart_safe_values() {
        let _guard = env_lock().lock().expect("env lock");
        clear_env();

        let path = std::env::temp_dir().join(format!(
            "eguard-agent-persist-runtime-{}.toml",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::env::set_var("EGUARD_AGENT_CONFIG", &path);

        std::fs::write(
            &path,
            "[agent]\nid=\"agent-a\"\n[storage]\nbackend=\"memory\"\n",
        )
        .expect("write existing config");

        let cfg = AgentConfig {
            agent_id: "agent-a".to_string(),
            server_addr: "127.0.0.1:50052".to_string(),
            transport_mode: "grpc".to_string(),
            enrollment_token: Some("tok-xyz".to_string()),
            tenant_id: Some("default".to_string()),
            mode: crate::config::AgentMode::Active,
            detection_yara_rules_dir: "/opt/eguard/rules/yara".to_string(),
            detection_ioc_dir: "/opt/eguard/rules/ioc".to_string(),
            detection_bundle_public_key: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
            response: response::ResponseConfig {
                autonomous_response: true,
                ..response::ResponseConfig::default()
            },
            offline_buffer_backend: "memory".to_string(),
            ..AgentConfig::default()
        };

        let persisted = persist_runtime_config_snapshot(&cfg).expect("persist runtime config");
        assert_eq!(persisted, path);

        let loaded = AgentConfig::load().expect("load persisted config");
        assert_eq!(loaded.server_addr, "127.0.0.1:50052");
        assert_eq!(loaded.transport_mode, "grpc");
        assert!(loaded.enrollment_token.is_none());
        assert_eq!(loaded.tenant_id.as_deref(), Some("default"));
        assert_eq!(loaded.agent_id, "agent-a");
        assert!(matches!(loaded.mode, crate::config::AgentMode::Active));
        assert!(loaded.response.autonomous_response);
        assert_eq!(loaded.detection_yara_rules_dir, "/opt/eguard/rules/yara");
        assert_eq!(loaded.detection_ioc_dir, "/opt/eguard/rules/ioc");
        assert_eq!(
            loaded.detection_bundle_public_key.as_deref(),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        assert_eq!(loaded.offline_buffer_backend, "memory");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let perms = std::fs::metadata(&path)
                .expect("config metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(perms, 0o600);
        }

        clear_env();
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn persist_runtime_config_snapshot_rejects_encrypted_config() {
        let _guard = env_lock().lock().expect("env lock");
        clear_env();

        let path = std::env::temp_dir().join(format!(
            "eguard-agent-persist-encrypted-{}.toml",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::env::set_var("EGUARD_AGENT_CONFIG", &path);

        std::fs::write(&path, "eguardcfg:v1:Zm9vYmFy").expect("write encrypted marker");

        let cfg = AgentConfig::default();
        let err = persist_runtime_config_snapshot(&cfg).expect_err("encrypted config should fail");
        assert!(err.contains("encrypted"));

        clear_env();
        let _ = std::fs::remove_file(path);
    }
}
