use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use response::CommandExecution;
use serde::Deserialize;

use super::super::dlp_discovery::{
    run_dlp_discovery_from, DlpDiscoveryCheckpoint, DlpDiscoveryLimits, DlpDiscoveryRequest,
};
use super::super::AgentRuntime;
use super::paths::resolve_agent_data_dir;

const DEFAULT_ALLOWED_EXTENSIONS: &[&str] = &["txt", "csv", "json", "xml", "log", "md"];

#[derive(Debug, Default, Deserialize)]
struct DlpDiscoveryPayload {
    roots: Vec<String>,
    #[serde(default)]
    approved_roots: Vec<String>,
    #[serde(default)]
    excluded_roots: Vec<String>,
    #[serde(default)]
    allowed_extensions: Vec<String>,
}

impl AgentRuntime {
    pub(super) async fn apply_dlp_discovery(
        &mut self,
        payload_json: &str,
        exec: &mut CommandExecution,
    ) {
        let payload = match serde_json::from_str::<DlpDiscoveryPayload>(payload_json) {
            Ok(value) => value,
            Err(err) => {
                exec.status = "failed";
                exec.detail = format!("DLP discovery rejected: invalid payload: {err}");
                return;
            }
        };
        let approved = canonical_paths(&payload.approved_roots);
        if approved.is_empty() {
            exec.status = "failed";
            exec.detail = "DLP discovery rejected: approved_roots required".to_string();
            return;
        }

        let roots = canonical_paths(&payload.roots)
            .into_iter()
            .filter(|root| {
                approved
                    .iter()
                    .any(|allowed| root == allowed || root.starts_with(allowed))
            })
            .collect::<Vec<_>>();
        if roots.is_empty() {
            exec.status = "failed";
            exec.detail = "DLP discovery rejected: no root is within approved_roots".to_string();
            return;
        }

        let scanner = match self.dlp_scanner.as_ref() {
            Some(value) => value,
            None => {
                exec.status = "failed";
                exec.detail = "DLP discovery rejected: scanner not loaded".to_string();
                return;
            }
        };
        let allowed_extensions = if payload.allowed_extensions.is_empty() {
            DEFAULT_ALLOWED_EXTENSIONS
                .iter()
                .map(|value| value.to_string())
                .collect()
        } else {
            payload.allowed_extensions
        };
        let request = DlpDiscoveryRequest {
            roots,
            excluded_roots: canonical_paths(&payload.excluded_roots),
            allowed_extensions,
            limits: DlpDiscoveryLimits::default(),
        };
        let scope = DlpDiscoveryCheckpoint::scope_for(&request);
        let checkpoint_path = discovery_checkpoint_path();
        let cursor = read_checkpoint(&checkpoint_path)
            .filter(|checkpoint| checkpoint.scope == scope)
            .map(|checkpoint| checkpoint.last_path);
        let (summary, findings) = run_dlp_discovery_from(
            &request,
            scanner,
            cursor,
            discovery_stop_requested,
            |last_path| {
                let _ = write_checkpoint(
                    &checkpoint_path,
                    &DlpDiscoveryCheckpoint {
                        scope: scope.clone(),
                        last_path: last_path.to_path_buf(),
                    },
                );
            },
        );
        if !summary.limit_reached {
            let _ = fs::remove_file(&checkpoint_path);
        }
        let matched_rules = findings
            .iter()
            .flat_map(|finding| finding.classifier_ids.iter())
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        exec.detail = format!(
            "DLP discovery completed: files_seen={}; files_scanned={}; files_matched={}; bytes_scanned={}; rules_matched={}; errors={}; limit_reached={}",
            summary.files_seen,
            summary.files_scanned,
            summary.files_matched,
            summary.bytes_scanned,
            matched_rules.len(),
            summary.errors,
            summary.limit_reached,
        );
    }
}

fn discovery_checkpoint_path() -> PathBuf {
    resolve_agent_data_dir().join("dlp-discovery-checkpoint.json")
}

fn read_checkpoint(path: &Path) -> Option<DlpDiscoveryCheckpoint> {
    read_checkpoint_at(path, SystemTime::now())
}

fn read_checkpoint_at(path: &Path, now: SystemTime) -> Option<DlpDiscoveryCheckpoint> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    if now.duration_since(modified).ok()? > Duration::from_secs(7 * 24 * 60 * 60) {
        let _ = fs::remove_file(path);
        return None;
    }
    fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
}

fn write_checkpoint(path: &Path, checkpoint: &DlpDiscoveryCheckpoint) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("json.tmp");
    fs::write(
        &temporary,
        serde_json::to_vec(checkpoint).map_err(std::io::Error::other)?,
    )?;
    fs::rename(temporary, path)
}

fn discovery_stop_requested() -> bool {
    matches!(
        std::env::var("EGUARD_DLP_DISCOVERY_STOP").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE")
    )
}

fn canonical_paths(raw: &[String]) -> Vec<PathBuf> {
    raw.iter()
        .filter_map(|value| {
            let path = PathBuf::from(value.trim());
            if path.as_os_str().is_empty() || !path.exists() {
                return None;
            }
            fs::canonicalize(path).ok()
        })
        .filter(|path| path.is_dir())
        .collect()
}

#[allow(dead_code)]
fn is_within(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_requires_approved_root() {
        let payload =
            serde_json::from_str::<DlpDiscoveryPayload>(r#"{"roots":["/tmp"]}"#).expect("payload");
        assert!(payload.approved_roots.is_empty());
    }

    #[test]
    fn stale_checkpoint_is_ignored_and_removed() {
        let path =
            std::env::temp_dir().join(format!("eguard-dlp-checkpoint-{}.json", std::process::id()));
        let _ = fs::write(
            &path,
            serde_json::to_vec(&DlpDiscoveryCheckpoint {
                scope: "scope".to_string(),
                last_path: PathBuf::from("old.txt"),
            })
            .expect("checkpoint"),
        );
        let modified = fs::metadata(&path)
            .expect("metadata")
            .modified()
            .expect("mtime");
        assert!(
            read_checkpoint_at(&path, modified + Duration::from_secs(8 * 24 * 60 * 60),).is_none()
        );
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn discovery_command_scans_synthetic_fixture_audit_only() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let root = std::env::temp_dir().join(format!(
            "eguard-dlp-command-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("unix time")
                .as_nanos()
        ));
        let data_dir = root.join("agent-data");
        let rule_path = root.join("rules.json");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::write(
            &rule_path,
            serde_json::json!({
                "schema_version": "1",
                "pack_id": "synthetic-command-test",
                "version": "1",
                "rules": [{
                    "id": "id.nik",
                    "name": "NIK",
                    "pattern": "[0-9]{16}",
                    "context": ["nik"],
                    "validator": "context_only",
                    "severity": "high",
                    "default_action": "audit",
                    "regulations": ["UU PDP"],
                    "redaction": "partial",
                    "max_matches": 3
                }]
            })
            .to_string(),
        )
        .expect("rules");
        let fixture = root.join("fixture.txt");
        let secret = "3174123456780001";
        std::fs::write(&fixture, format!("NIK {secret}")).expect("fixture");
        std::env::set_var("EGUARD_AGENT_DATA_DIR", &data_dir);

        let mut cfg = crate::config::AgentConfig::default();
        cfg.offline_buffer_backend = "memory".to_string();
        cfg.server_addr = "127.0.0.1:1".to_string();
        cfg.self_protection_integrity_check_interval_secs = 0;
        cfg.dlp_enabled = true;
        cfg.dlp_rules_path = rule_path.to_string_lossy().into_owned();
        let mut runtime = super::super::super::AgentRuntime::new(cfg).expect("runtime");
        let exec = runtime
            .handle_command(
                grpc_client::CommandEnvelope {
                    command_id: "cmd-dlp-discovery-synthetic".to_string(),
                    command_type: "dlp_discovery".to_string(),
                    payload_json: serde_json::json!({
                        "roots": [root.to_string_lossy()],
                        "approved_roots": [root.to_string_lossy()],
                        "allowed_extensions": ["txt"]
                    })
                    .to_string(),
                },
                1_700_000_000,
            )
            .await;

        assert_eq!(exec.status, "completed", "{}", exec.detail);
        assert!(exec.detail.contains("files_matched=1"), "{}", exec.detail);
        assert!(exec.detail.contains("rules_matched=1"), "{}", exec.detail);
        assert!(
            !exec.detail.contains(secret),
            "raw match leaked: {}",
            exec.detail
        );
        assert!(
            !exec.detail.contains("quarantine"),
            "non-audit action leaked: {}",
            exec.detail
        );
        assert!(
            fixture.exists(),
            "audit-only discovery must not alter fixture"
        );

        std::env::remove_var("EGUARD_AGENT_DATA_DIR");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn kill_switch_accepts_true_values() {
        std::env::set_var("EGUARD_DLP_DISCOVERY_STOP", "1");
        assert!(discovery_stop_requested());
        std::env::remove_var("EGUARD_DLP_DISCOVERY_STOP");
    }
}

#[cfg(test)]
const _: () = {
    let _ = is_within as fn(&Path, &Path) -> bool;
};
