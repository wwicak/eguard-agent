use response::{CommandExecution, CommandOutcome};
use sha2::{Digest, Sha256};

use super::paths::resolve_agent_data_dir;
use super::payloads::ForensicsPayload;
use super::AgentRuntime;

/// An evidence file captured locally that should also be uploaded to the
/// server for tamper-resistant, isolation-proof storage. The local copy is
/// always kept (dual custody); upload is best-effort and reported in the
/// command detail.
pub(super) struct PendingForensicsArtifact {
    pub path: String,
    pub artifact_type: &'static str,
}

fn forensics_hostname() -> String {
    if let Ok(value) = std::env::var("HOSTNAME") {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }
    if let Ok(value) = std::env::var("COMPUTERNAME") {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }
    if let Ok(value) = std::fs::read_to_string("/etc/hostname") {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }
    "unknown-host".to_string()
}

pub(super) fn sha256_hex(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

/// Restrict evidence to root: 0700 on the forensics directory, 0600 on the
/// files. A full process/network/open-files listing is valuable recon for a
/// local attacker, so it must not stay world-readable.
#[cfg(unix)]
fn harden_evidence_permissions(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn harden_evidence_permissions(_path: &std::path::Path, _mode: u32) {}

impl AgentRuntime {
    pub(super) fn apply_forensics_collection(
        &self,
        payload_json: &str,
        exec: &mut CommandExecution,
    ) -> Vec<PendingForensicsArtifact> {
        let payload: ForensicsPayload = serde_json::from_str(payload_json).unwrap_or_default();
        let now = forensics_now_secs();
        let output_dir = resolve_agent_data_dir().join("forensics");

        if let Err(err) = std::fs::create_dir_all(&output_dir) {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!("forensics output directory failed: {}", err);
            return Vec::new();
        }
        harden_evidence_permissions(&output_dir, 0o700);

        let include_any_snapshot = payload.wants_snapshot();
        let include_processes = payload.process_list || !include_any_snapshot;
        let include_network = payload.network_connections || !include_any_snapshot;
        let include_open_files = payload.open_files || !include_any_snapshot;
        let include_loaded_modules = payload.loaded_modules || !include_any_snapshot;

        #[cfg(target_os = "windows")]
        {
            let collector = platform_windows::response::ForensicsCollector::new();
            let mut detail_parts: Vec<String> = Vec::new();
            let mut artifacts: Vec<PendingForensicsArtifact> = Vec::new();

            let snapshot_path = if payload.output_path.trim().is_empty() || payload.memory_dump {
                output_dir
                    .join(format!("snapshot-{}.txt", now))
                    .to_string_lossy()
                    .to_string()
            } else {
                payload.output_path.trim().to_string()
            };

            let snapshot = collector.collect_full_snapshot(
                include_processes,
                include_network,
                include_open_files,
                include_loaded_modules,
            );
            let body = format!(
                "=== processes ===\n{}\n\n=== network ===\n{}\n\n=== open_files ===\n{}\n\n=== loaded_modules ===\n{}\n",
                snapshot.processes, snapshot.network, snapshot.open_files, snapshot.loaded_modules
            );
            if let Err(err) = std::fs::write(&snapshot_path, body.as_bytes()) {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("forensics capture failed: {}", err);
                return Vec::new();
            }
            detail_parts.push(format!(
                "snapshot={} (sha256={}, {} bytes, host={})",
                snapshot_path,
                sha256_hex(body.as_bytes()),
                body.len(),
                forensics_hostname()
            ));
            artifacts.push(PendingForensicsArtifact {
                path: snapshot_path.clone(),
                artifact_type: "forensics_snapshot",
            });

            if payload.memory_dump {
                let target_pids = payload.effective_target_pids();
                if target_pids.is_empty() {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail =
                        "forensics memory_dump requested but no target pid provided".to_string();
                    return Vec::new();
                }

                let mut success_count = 0usize;
                let mut dump_errors: Vec<String> = Vec::new();
                for (idx, pid) in target_pids.iter().enumerate() {
                    let dump_path =
                        if !payload.output_path.trim().is_empty() && target_pids.len() == 1 {
                            payload.output_path.trim().to_string()
                        } else {
                            output_dir
                                .join(format!("pid-{}-{}-{}.dmp", pid, now, idx))
                                .to_string_lossy()
                                .to_string()
                        };

                    match collector.create_minidump(*pid, &dump_path) {
                        Ok(()) => {
                            success_count += 1;
                            artifacts.push(PendingForensicsArtifact {
                                path: dump_path,
                                artifact_type: "memory_dump",
                            });
                        }
                        Err(err) => {
                            dump_errors.push(format!("pid {}: {}", pid, err));
                        }
                    }
                }

                if success_count == 0 {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail =
                        format!("forensics memory dump failed: {}", dump_errors.join("; "));
                    return Vec::new();
                }

                detail_parts.push(format!(
                    "memory_dump={}/{}",
                    success_count,
                    target_pids.len()
                ));
                if !dump_errors.is_empty() {
                    detail_parts.push(format!("dump_errors={}", dump_errors.join("; ")));
                }
            }

            exec.detail = format!("forensics capture completed ({})", detail_parts.join(", "));
            return artifacts;
        }

        #[cfg(target_os = "macos")]
        {
            let output_path = if payload.output_path.trim().is_empty() || payload.memory_dump {
                output_dir
                    .join(format!("snapshot-{}.txt", now))
                    .to_string_lossy()
                    .to_string()
            } else {
                payload.output_path.trim().to_string()
            };

            let collector = platform_macos::response::ForensicsCollector::new();
            let snapshot = collector.collect_full_snapshot();

            let mut sections: Vec<String> = Vec::new();
            if include_processes {
                sections.push(format!("=== processes ===\n{}", snapshot.processes));
            }
            if include_network {
                sections.push(format!("=== network ===\n{}", snapshot.network));
            }
            if include_open_files || include_loaded_modules {
                sections.push(format!("=== launchctl ===\n{}", snapshot.launchctl));
            }
            let body = sections.join("\n\n");

            if let Err(err) = std::fs::write(&output_path, body.as_bytes()) {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("forensics capture failed: {}", err);
                return Vec::new();
            }
            harden_evidence_permissions(std::path::Path::new(&output_path), 0o600);

            let summary = format!(
                "forensics snapshot captured on {} ({}): {} (sha256={}, {} bytes)",
                forensics_hostname(),
                self.config.agent_id,
                output_path,
                sha256_hex(body.as_bytes()),
                body.len()
            );
            if payload.memory_dump {
                exec.detail = format!("{} (memory_dump unsupported on macOS)", summary);
            } else {
                exec.detail = summary;
            }
            return vec![PendingForensicsArtifact {
                path: output_path,
                artifact_type: "forensics_snapshot",
            }];
        }

        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            let collector = platform_linux::response::ForensicsCollector::new();
            let output_path = if payload.output_path.trim().is_empty() || payload.memory_dump {
                output_dir
                    .join(format!("snapshot-{}.txt", now))
                    .to_string_lossy()
                    .to_string()
            } else {
                payload.output_path.trim().to_string()
            };

            let snapshot = collector.collect_full_snapshot(
                include_processes,
                include_network,
                include_open_files,
                include_loaded_modules,
            );

            let body = format!(
                "=== processes ===\n{}\n\n=== network ===\n{}\n\n=== open_files ===\n{}\n\n=== loaded_modules ===\n{}\n",
                snapshot.processes,
                snapshot.network,
                snapshot.open_files,
                snapshot.loaded_modules
            );

            if let Err(err) = std::fs::write(&output_path, body.as_bytes()) {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("forensics capture failed: {}", err);
                return Vec::new();
            }
            harden_evidence_permissions(std::path::Path::new(&output_path), 0o600);

            let summary = format!(
                "forensics snapshot captured on {} ({}): {} (sha256={}, {} bytes)",
                forensics_hostname(),
                self.config.agent_id,
                output_path,
                sha256_hex(body.as_bytes()),
                body.len()
            );
            if payload.memory_dump {
                exec.detail = format!("{} (memory_dump unsupported on linux)", summary);
            } else {
                exec.detail = summary;
            }
            vec![PendingForensicsArtifact {
                path: output_path,
                artifact_type: "forensics_snapshot",
            }]
        }
    }
}

fn forensics_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}
