use std::collections::VecDeque;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use response::{CommandExecution, PlannedAction};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::warn;

use super::super::AgentRuntime;
use detection::{EventClass, TelemetryEvent};

const MAX_SCAN_TARGETS: usize = 16;
const MAX_SCAN_FILES: usize = 256;
const MAX_SCAN_DEPTH: usize = 8;

#[derive(Debug, Default, Deserialize)]
struct ScanCommandPayload {
    paths: Option<Vec<String>>,
}

impl AgentRuntime {
    pub(super) async fn apply_on_demand_scan(
        &mut self,
        payload_json: &str,
        now_unix: i64,
        exec: &mut CommandExecution,
    ) {
        let payload = match serde_json::from_str::<ScanCommandPayload>(payload_json) {
            Ok(payload) => payload,
            Err(err) => {
                exec.status = "failed";
                exec.detail = format!("scan rejected: invalid payload: {err}");
                return;
            }
        };

        let targets = resolve_scan_targets(payload.paths);
        let files = collect_scan_files(&targets);

        let mut scanned_files = 0usize;
        let mut matched_files = 0usize;
        let mut quarantined_files = 0usize;
        let mut scan_errors = 0usize;
        let response_cfg = self.on_demand_scan_response_config();

        for path in files {
            scanned_files = scanned_files.saturating_add(1);
            let event = match self.build_on_demand_scan_event(&path, now_unix) {
                Ok(Some(event)) => event,
                Ok(None) => continue,
                Err(err) => {
                    scan_errors = scan_errors.saturating_add(1);
                    warn!(error = %err, path = %path.display(), "on-demand scan skipped file");
                    continue;
                }
            };

            let outcome = match self.detection_state.process_event(&event) {
                Ok(outcome) => outcome,
                Err(err) => {
                    scan_errors = scan_errors.saturating_add(1);
                    warn!(error = %err, path = %path.display(), "on-demand scan failed to evaluate file");
                    continue;
                }
            };

            if outcome.confidence <= detection::Confidence::None {
                continue;
            }

            matched_files = matched_files.saturating_add(1);
            let action =
                normalize_scan_action(response::plan_action(outcome.confidence, &response_cfg));
            let detection_layers = Self::detection_layers(&outcome);
            let rule_name =
                Self::detection_rule_name(&outcome).unwrap_or_else(|| "manual_scan".to_string());
            let threat_category = Self::detection_rule_type(&outcome);

            self.report_local_action_if_needed(
                action,
                outcome.confidence,
                &event,
                now_unix,
                (&detection_layers, &rule_name, threat_category),
            )
            .await;

            if matches!(action, PlannedAction::QuarantineOnly) && !path.exists() {
                quarantined_files = quarantined_files.saturating_add(1);
            }
        }

        exec.detail = format!(
            "quick scan completed: roots={}; scanned_files={}; matched_files={}; quarantined_files={}; errors={}",
            targets.len(),
            scanned_files,
            matched_files,
            quarantined_files,
            scan_errors
        );
    }

    fn build_on_demand_scan_event(
        &self,
        path: &Path,
        now_unix: i64,
    ) -> anyhow::Result<Option<TelemetryEvent>> {
        let metadata = fs::metadata(path)?;
        if !metadata.is_file() {
            return Ok(None);
        }

        let max_bytes =
            (self.config.detection_max_file_scan_size_mb.max(1) as u64).saturating_mul(1024 * 1024);
        if metadata.len() > max_bytes {
            return Ok(None);
        }

        let sha256 = sha256_file_hex(path)?;
        Ok(Some(TelemetryEvent {
            ts_unix: now_unix,
            event_class: EventClass::FileOpen,
            pid: 0,
            ppid: 0,
            uid: 0,
            process: "on_demand_scan".to_string(),
            parent_process: "eguard-agent".to_string(),
            session_id: std::process::id(),
            file_path: Some(path.display().to_string()),
            file_write: false,
            file_hash: Some(sha256),
            dst_port: None,
            dst_ip: None,
            dst_domain: None,
            command_line: Some("on_demand_scan".to_string()),
            event_size: Some(metadata.len()),
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        }))
    }

    fn on_demand_scan_response_config(&self) -> response::ResponseConfig {
        let mut cfg = self.config.response.clone();
        cfg.autonomous_response = true;
        cfg
    }
}

fn resolve_scan_targets(paths: Option<Vec<String>>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let candidates = paths.unwrap_or_else(default_scan_targets);
    for raw in candidates {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let candidate = PathBuf::from(trimmed);
        if !candidate.exists() || out.iter().any(|existing| existing == &candidate) {
            continue;
        }
        out.push(candidate);
        if out.len() >= MAX_SCAN_TARGETS {
            break;
        }
    }
    out
}

fn default_scan_targets() -> Vec<String> {
    let mut targets = vec![std::env::temp_dir().display().to_string()];
    for candidate in ["/tmp", "/var/tmp", "/dev/shm"] {
        targets.push(candidate.to_string());
    }
    targets
}

fn collect_scan_files(targets: &[PathBuf]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = VecDeque::new();

    for target in targets {
        pending.push_back((target.clone(), 0usize));
    }

    while let Some((path, depth)) = pending.pop_front() {
        if files.len() >= MAX_SCAN_FILES {
            break;
        }

        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };

        if metadata.file_type().is_symlink() {
            continue;
        }

        if metadata.is_file() {
            files.push(path);
            continue;
        }

        if !metadata.is_dir() || depth >= MAX_SCAN_DEPTH {
            continue;
        }

        let entries = match fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            pending.push_back((entry.path(), depth.saturating_add(1)));
        }
    }

    files
}

fn normalize_scan_action(action: PlannedAction) -> PlannedAction {
    match action {
        PlannedAction::KillOnly | PlannedAction::KillAndQuarantine => PlannedAction::QuarantineOnly,
        other => other,
    }
}

fn sha256_file_hex(path: &Path) -> anyhow::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AgentConfig;
    use crate::config::AgentMode;
    use baseline::BaselineStatus;

    #[tokio::test]
    async fn run_scan_command_quarantines_detected_file() {
        let mut cfg = AgentConfig::default();
        cfg.offline_buffer_backend = "memory".to_string();
        cfg.server_addr = "127.0.0.1:1".to_string();
        cfg.response.autonomous_response = true;

        let mut runtime = AgentRuntime::new(cfg).expect("runtime");
        runtime.client.set_online(false);
        runtime.runtime_mode = AgentMode::Active;
        runtime.baseline_store.status = BaselineStatus::Active;

        let temp_root = std::env::temp_dir().join(format!(
            "eguard-on-demand-scan-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("unix time")
                .as_nanos()
        ));
        fs::create_dir_all(&temp_root).expect("create temp root");
        let quarantine_root = temp_root.join("quarantine");
        std::env::set_var("EGUARD_TEST_QUARANTINE_DIR", &quarantine_root);
        let eicar_path = temp_root.join("eicar.com");
        fs::write(
            &eicar_path,
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        )
        .expect("write eicar");

        runtime
            .handle_command(
                grpc_client::CommandEnvelope {
                    command_id: "cmd-scan-1".to_string(),
                    command_type: "scan".to_string(),
                    payload_json: serde_json::json!({
                        "paths": [eicar_path.display().to_string()]
                    })
                    .to_string(),
                },
                1_700_000_000,
            )
            .await;

        assert_eq!(runtime.host_control.last_scan_unix, Some(1_700_000_000));
        assert!(!eicar_path.exists(), "detected file should be quarantined");
        assert_eq!(runtime.pending_response_reports.len(), 1);
        let report = &runtime.pending_response_reports[0].envelope;
        assert_eq!(report.action_type, "quarantine_file");
        assert_eq!(
            report.file_path.as_deref(),
            Some(eicar_path.to_string_lossy().as_ref())
        );

        let _ = fs::remove_dir_all(&temp_root);
        std::env::remove_var("EGUARD_TEST_QUARANTINE_DIR");
    }

    #[tokio::test]
    async fn run_scan_command_bypasses_learning_mode_response_suppression() {
        let mut cfg = AgentConfig::default();
        cfg.offline_buffer_backend = "memory".to_string();
        cfg.server_addr = "127.0.0.1:1".to_string();
        cfg.response.autonomous_response = false;

        let mut runtime = AgentRuntime::new(cfg).expect("runtime");
        runtime.client.set_online(false);
        runtime.runtime_mode = AgentMode::Learning;
        runtime.baseline_store.status = BaselineStatus::Learning;

        let temp_root = std::env::temp_dir().join(format!(
            "eguard-on-demand-learning-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("unix time")
                .as_nanos()
        ));
        fs::create_dir_all(&temp_root).expect("create temp root");
        let quarantine_root = temp_root.join("quarantine");
        std::env::set_var("EGUARD_TEST_QUARANTINE_DIR", &quarantine_root);
        let eicar_path = temp_root.join("eicar.com");
        fs::write(
            &eicar_path,
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        )
        .expect("write eicar");

        runtime
            .handle_command(
                grpc_client::CommandEnvelope {
                    command_id: "cmd-scan-learning".to_string(),
                    command_type: "scan".to_string(),
                    payload_json: serde_json::json!({
                        "paths": [eicar_path.display().to_string()]
                    })
                    .to_string(),
                },
                1_700_000_001,
            )
            .await;

        assert!(
            !eicar_path.exists(),
            "manual scan should quarantine even in learning mode"
        );
        assert_eq!(runtime.pending_response_reports.len(), 1);
        assert_eq!(
            runtime.pending_response_reports[0].envelope.action_type,
            "quarantine_file"
        );

        let _ = fs::remove_dir_all(&temp_root);
        std::env::remove_var("EGUARD_TEST_QUARANTINE_DIR");
    }
}
