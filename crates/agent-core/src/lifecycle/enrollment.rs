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

        let enroll = self.build_enrollment_envelope();
        match self.client.enroll_with_material(&enroll).await {
            Ok(Some(result)) => {
                if !result.agent_id.is_empty() {
                    tracing::info!(agent_id = %result.agent_id, "enrollment succeeded, updating agent_id");
                    self.config.agent_id = result.agent_id;
                }
                self.enrolled = true;
                self.consume_bootstrap_config();
            }
            Ok(None) => {
                self.enrolled = true;
                self.consume_bootstrap_config();
            }
            Err(err) => {
                let err_str = err.to_string().to_ascii_lowercase();
                if err_str.contains("already exists") || err_str.contains("already_enrolled") {
                    tracing::info!("agent already enrolled on server, marking as enrolled");
                    self.enrolled = true;
                    self.consume_bootstrap_config();
                } else {
                    warn!(error = %err, "enrollment failed");
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

fn persist_runtime_config_snapshot(config: &AgentConfig) -> Result<PathBuf, String> {
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

    let transport_table = root_table
        .entry("transport")
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .ok_or_else(|| format!("agent config {} [transport] must be table", path.display()))?;

    transport_table.insert(
        "mode".to_string(),
        toml::Value::String(config.transport_mode.clone()),
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
        return Ok(());
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

        let mut cfg = AgentConfig::default();
        cfg.agent_id = "agent-a".to_string();
        cfg.server_addr = "157.10.161.219:50052".to_string();
        cfg.transport_mode = "grpc".to_string();
        cfg.enrollment_token = Some("tok-xyz".to_string());
        cfg.tenant_id = Some("default".to_string());

        let persisted = persist_runtime_config_snapshot(&cfg).expect("persist runtime config");
        assert_eq!(persisted, path);

        let loaded = AgentConfig::load().expect("load persisted config");
        assert_eq!(loaded.server_addr, "157.10.161.219:50052");
        assert_eq!(loaded.transport_mode, "grpc");
        assert!(loaded.enrollment_token.is_none());
        assert_eq!(loaded.tenant_id.as_deref(), Some("default"));
        assert_eq!(loaded.agent_id, "agent-a");
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
