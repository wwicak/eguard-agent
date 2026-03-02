use response::{CommandExecution, CommandOutcome};

use super::paths::resolve_agent_data_dir;
use super::payloads::ForensicsPayload;
use super::AgentRuntime;

impl AgentRuntime {
    pub(super) fn apply_forensics_collection(
        &self,
        payload_json: &str,
        exec: &mut CommandExecution,
    ) {
        let payload: ForensicsPayload = serde_json::from_str(payload_json).unwrap_or_default();
        let now = forensics_now_secs();
        let output_dir = resolve_agent_data_dir().join("forensics");

        if let Err(err) = std::fs::create_dir_all(&output_dir) {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!("forensics output directory failed: {}", err);
            return;
        }

        let include_any_snapshot = payload.wants_snapshot();
        let include_processes = payload.process_list || !include_any_snapshot;
        let include_network = payload.network_connections || !include_any_snapshot;
        let include_open_files = payload.open_files || !include_any_snapshot;
        let include_loaded_modules = payload.loaded_modules || !include_any_snapshot;

        #[cfg(target_os = "windows")]
        {
            let collector = platform_windows::response::ForensicsCollector::new();
            let mut detail_parts: Vec<String> = Vec::new();

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
                return;
            }
            detail_parts.push(format!("snapshot={}", snapshot_path));

            if payload.memory_dump {
                let target_pids = payload.effective_target_pids();
                if target_pids.is_empty() {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail =
                        "forensics memory_dump requested but no target pid provided".to_string();
                    return;
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
                    return;
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
            return;
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
                return;
            }

            if payload.memory_dump {
                exec.detail = format!(
                    "forensics snapshot captured: {} (memory_dump unsupported on macOS)",
                    output_path
                );
            } else {
                exec.detail = format!("forensics snapshot captured: {}", output_path);
            }
            return;
        }

        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            let output_path = if payload.output_path.trim().is_empty() || payload.memory_dump {
                output_dir
                    .join(format!("snapshot-{}.txt", now))
                    .to_string_lossy()
                    .to_string()
            } else {
                payload.output_path.trim().to_string()
            };

            let process_text = if include_processes {
                run_forensics_command_output("ps", &["aux"])
            } else {
                String::new()
            };

            let network_text = if include_network {
                let primary = run_forensics_command_output("ss", &["-tunap"]);
                if primary.starts_with("spawn failed") {
                    run_forensics_command_output("netstat", &["-anp"])
                } else {
                    primary
                }
            } else {
                String::new()
            };

            let open_files_text = if include_open_files {
                run_forensics_command_output("lsof", &["-nP"])
            } else {
                String::new()
            };

            let loaded_modules_text = if include_loaded_modules {
                run_forensics_command_output("lsmod", &[])
            } else {
                String::new()
            };

            let body = format!(
                "=== processes ===\n{}\n\n=== network ===\n{}\n\n=== open_files ===\n{}\n\n=== loaded_modules ===\n{}\n",
                process_text, network_text, open_files_text, loaded_modules_text
            );

            if let Err(err) = std::fs::write(&output_path, body.as_bytes()) {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("forensics capture failed: {}", err);
                return;
            }

            if payload.memory_dump {
                exec.detail = format!(
                    "forensics snapshot captured: {} (memory_dump unsupported on linux)",
                    output_path
                );
            } else {
                exec.detail = format!("forensics snapshot captured: {}", output_path);
            }
        }
    }
}

fn forensics_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn run_forensics_command_output(command: &str, args: &[&str]) -> String {
    use std::process::Command;

    match Command::new(command).args(args).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            if !stdout.trim().is_empty() {
                stdout
            } else if !stderr.trim().is_empty() {
                stderr
            } else {
                format!("command `{}` returned empty output", command)
            }
        }
        Err(err) => format!("spawn failed for `{}`: {}", command, err),
    }
}
