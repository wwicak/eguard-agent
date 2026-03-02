#[cfg(not(any(target_os = "windows", target_os = "macos")))]
use std::path::Path;

use response::{CommandExecution, CommandOutcome};

use super::command_utils::resolve_allowed_server_ips;
use super::payloads::RestoreQuarantinePayload;
use super::AgentRuntime;

impl AgentRuntime {
    pub(super) fn apply_host_isolate(&self, payload_json: &str, exec: &mut CommandExecution) {
        #[derive(Debug, serde::Deserialize, Default)]
        struct IsolatePayload {
            #[serde(default)]
            allow_server_ips: Vec<String>,
        }

        let payload: IsolatePayload = serde_json::from_str(payload_json).unwrap_or_default();
        let allowed =
            resolve_allowed_server_ips(&self.config.server_addr, &payload.allow_server_ips);

        #[cfg(target_os = "windows")]
        {
            if allowed.is_empty() {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = "isolation rejected: no routable server IPs provided".to_string();
                return;
            }

            let refs: Vec<&str> = allowed.iter().map(|value| value.as_str()).collect();
            match platform_windows::response::isolate_host(&refs) {
                Ok(()) => {
                    exec.detail = format!(
                        "host isolation enforced via Windows Firewall (allowing: {})",
                        allowed.join(",")
                    );
                }
                Err(err) => {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("host isolation failed: {}", err);
                }
            }
            return;
        }

        #[cfg(target_os = "macos")]
        {
            if allowed.is_empty() {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = "isolation rejected: no routable server IPs provided".to_string();
                return;
            }

            let refs: Vec<&str> = allowed.iter().map(|value| value.as_str()).collect();
            match platform_macos::response::isolate_host(&refs) {
                Ok(()) => {
                    exec.detail = format!(
                        "host isolation enforced via pf (allowing: {})",
                        allowed.join(",")
                    );
                }
                Err(err) => {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("host isolation failed: {}", err);
                }
            }
            return;
        }

        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            let _ = (allowed, exec);
        }
    }

    pub(super) fn apply_host_unisolate(&self, exec: &mut CommandExecution) {
        #[cfg(target_os = "windows")]
        {
            match platform_windows::response::remove_isolation() {
                Ok(()) => {
                    exec.detail = "host isolation removed via Windows Firewall".to_string();
                }
                Err(err) => {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("failed removing host isolation: {}", err);
                }
            }
            return;
        }

        #[cfg(target_os = "macos")]
        {
            match platform_macos::response::remove_isolation() {
                Ok(()) => {
                    exec.detail = "host isolation removed via pf".to_string();
                }
                Err(err) => {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("failed removing host isolation: {}", err);
                }
            }
            return;
        }

        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            let _ = exec;
        }
    }

    pub(super) fn apply_quarantine_restore(&self, payload_json: &str, exec: &mut CommandExecution) {
        let payload: RestoreQuarantinePayload = match serde_json::from_str(payload_json) {
            Ok(payload) => payload,
            Err(err) => {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("invalid restore_quarantine payload: {}", err);
                return;
            }
        };

        if payload.quarantine_path.trim().is_empty() || payload.original_path.trim().is_empty() {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail =
                "invalid restore_quarantine payload: quarantine_path and original_path are required"
                    .to_string();
            return;
        }

        #[cfg(target_os = "windows")]
        {
            match platform_windows::response::quarantine::restore_file(
                payload.quarantine_path.trim(),
                payload.original_path.trim(),
            ) {
                Ok(()) => {
                    exec.detail = format!(
                        "quarantine restored: {} -> {}",
                        payload.quarantine_path.trim(),
                        payload.original_path.trim()
                    );
                }
                Err(err) => {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("restore_quarantine failed: {}", err);
                }
            }
            return;
        }

        #[cfg(target_os = "macos")]
        {
            match platform_macos::response::restore_file(
                payload.quarantine_path.trim(),
                payload.original_path.trim(),
            ) {
                Ok(()) => {
                    exec.detail = format!(
                        "quarantine restored: {} -> {}",
                        payload.quarantine_path.trim(),
                        payload.original_path.trim()
                    );
                }
                Err(err) => {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("restore_quarantine failed: {}", err);
                }
            }
            return;
        }

        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            match response::restore_quarantined(
                Path::new(payload.quarantine_path.trim()),
                Path::new(payload.original_path.trim()),
                0o600,
            ) {
                Ok(report) => {
                    exec.detail =
                        format!("quarantine restored: {}", report.restored_path.display());
                }
                Err(err) => {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("restore_quarantine failed: {}", err);
                }
            }
        }
    }
}
