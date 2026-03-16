use response::{kill_process_tree, CommandExecution, CommandOutcome};
use tracing::{info, warn};

use super::app_management::apply_app_command;
use super::AgentRuntime;

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

        let mut killed_total = 0u32;
        let mut failed_total = 0u32;
        let mut details = Vec::new();

        for pid in &pids {
            if *pid <= 2 {
                details.push(format!("pid={}: rejected (protected system process)", pid));
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
