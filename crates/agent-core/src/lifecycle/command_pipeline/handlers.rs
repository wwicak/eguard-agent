use std::time::Instant;

use response::{kill_process_tree, CommandExecution, CommandOutcome};
use tracing::{info, warn};

use super::app_management::apply_app_command;
use super::AgentRuntime;

/// Hard compiled ceiling on how many target PIDs a single server-issued
/// `kill_process` command may carry. A legitimate kill command targets a
/// handful of processes; an oversized vector is either a bug or an attempt to
/// weaponize the command channel into a host-wide mass-kill. Reject the whole
/// command (fail-closed) rather than partially executing it.
const MAX_KILL_COMMAND_TARGETS: usize = 64;

/// Hard cap on the raw `kill_process` payload size, enforced BEFORE JSON
/// deserialization so a hostile/huge payload cannot force a large allocation
/// (the transport layer does not byte-bound this). A real payload is a few
/// dozen integers; 64 KiB is generous.
const MAX_KILL_PAYLOAD_BYTES: usize = 64 * 1024;

impl AgentRuntime {
    pub(super) fn apply_app_install(&self, payload_json: &str, exec: &mut CommandExecution) {
        apply_app_command("install", payload_json, exec);
    }

    pub(super) fn apply_app_remove(&self, payload_json: &str, exec: &mut CommandExecution) {
        apply_app_command("remove", payload_json, exec);
    }

    pub(super) fn apply_app_update(&self, payload_json: &str, exec: &mut CommandExecution) {
        apply_app_command("update", payload_json, exec);
    }

    pub(super) fn apply_kill_process(&mut self, payload_json: &str, exec: &mut CommandExecution) {
        #[derive(serde::Deserialize)]
        struct KillPayload {
            #[serde(default)]
            target_pids: Vec<u32>,
            #[serde(default)]
            pid: Option<u32>,
        }

        if payload_json.len() > MAX_KILL_PAYLOAD_BYTES {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!(
                "kill_process payload too large ({} bytes, max {})",
                payload_json.len(),
                MAX_KILL_PAYLOAD_BYTES
            );
            return;
        }

        let payload: KillPayload = match serde_json::from_str(payload_json) {
            Ok(p) => p,
            Err(err) => {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("invalid kill_process payload: {}", err);
                return;
            }
        };

        let mut pids = payload.target_pids;
        if let Some(pid) = payload.pid {
            if !pids.contains(&pid) {
                pids.push(pid);
            }
        }

        if pids.is_empty() {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = "kill_process: no target_pids provided".to_string();
            return;
        }

        // Bound the blast radius of a single command up front. This is the same
        // fail-closed posture the local detection path enforces via the rate
        // limiter; here it also caps the vector length before any signal.
        if pids.len() > MAX_KILL_COMMAND_TARGETS {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!(
                "kill_process: too many targets ({}, max {})",
                pids.len(),
                MAX_KILL_COMMAND_TARGETS
            );
            return;
        }

        let self_pid = std::process::id();
        let mut killed_total = 0u32;
        let mut failed_total = 0u32;
        let mut details = Vec::new();

        for pid in &pids {
            if *pid <= 2 {
                details.push(format!("pid={}: rejected (protected system process)", pid));
                failed_total += 1;
                continue;
            }

            // Never let the command channel terminate the agent itself. The
            // kill primitive also enforces this, but reject here for a clear
            // per-PID outcome and to avoid consuming rate-limiter quota on it.
            if *pid == self_pid {
                details.push(format!("pid={}: rejected (agent self pid)", pid));
                failed_total += 1;
                continue;
            }

            // Route command kills through the SAME rolling rate limiter as local
            // detections (`execute_kill_step`) so a burst of server commands
            // cannot mass-kill the host. Consuming quota on the attempt caps the
            // blast radius under a command storm.
            if !self.limiter.allow(Instant::now()) {
                details.push(format!("pid={}: rejected (rate limited)", pid));
                failed_total += 1;
                continue;
            }

            match kill_process_tree(*pid, &self.protected) {
                Ok(report) => {
                    let count = report.killed_pids.len() as u32;
                    killed_total += count;
                    info!(
                        target_pid = pid,
                        killed_count = count,
                        "kill_process command: process tree killed"
                    );
                    details.push(format!("pid={}: killed {} processes", pid, count));
                }
                Err(err) => {
                    let err_str = format!("{}", err);
                    // Treat ESRCH (no such process) as success — goal achieved.
                    if err_str.contains("No such process") || err_str.contains("ESRCH") {
                        info!(
                            target_pid = pid,
                            "kill_process command: process already dead (ESRCH)"
                        );
                        details.push(format!("pid={}: already dead", pid));
                        killed_total += 1;
                    } else {
                        warn!(
                            target_pid = pid,
                            error = %err,
                            "kill_process command: failed to kill process"
                        );
                        details.push(format!("pid={}: failed ({})", pid, err));
                        failed_total += 1;
                    }
                }
            }
        }

        if failed_total == 0 {
            exec.detail = format!("killed {} processes: {}", killed_total, details.join("; "));
        } else {
            exec.status = "partial";
            exec.detail = format!(
                "killed={} failed={}: {}",
                killed_total,
                failed_total,
                details.join("; ")
            );
        }
    }
}
