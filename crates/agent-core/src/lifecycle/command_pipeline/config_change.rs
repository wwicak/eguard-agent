#[cfg(not(any(target_os = "windows", target_os = "macos")))]
use nac::apply_network_profile_config_change;
use response::{CommandExecution, CommandOutcome};

use super::paths::resolve_network_profile_dir;
#[cfg(target_os = "windows")]
use super::windows_network_profile::apply_windows_network_profile_config_change;
use super::AgentRuntime;

impl AgentRuntime {
    pub(super) fn apply_config_change(&self, payload_json: &str, exec: &mut CommandExecution) {
        let profile_dir = resolve_network_profile_dir();

        #[cfg(target_os = "windows")]
        {
            match apply_windows_network_profile_config_change(payload_json, &profile_dir) {
                Ok(Some(path)) => {
                    exec.detail = format!("network profile applied ({})", path.display());
                }
                Ok(None) => {
                    // Non-network config payloads remain backward-compatible no-ops.
                }
                Err(err) => {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("config_change rejected: {}", err);
                }
            }
            return;
        }

        #[cfg(target_os = "macos")]
        {
            match platform_macos::response::apply_network_profile_config_change(
                payload_json,
                &profile_dir,
            ) {
                Ok(Some(report)) => {
                    exec.detail = format!(
                        "network profile applied: {} ({})",
                        report.profile_id,
                        report.profile_path.display()
                    );
                }
                Ok(None) => {
                    // Non-network config payloads remain backward-compatible no-ops.
                }
                Err(err) => {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("config_change rejected: {}", err);
                }
            }
            return;
        }

        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            match apply_network_profile_config_change(payload_json, &profile_dir) {
                Ok(Some(report)) => {
                    exec.detail = format!(
                        "network profile applied: {} ({})",
                        report.profile_id,
                        report.connection_path.display()
                    );
                }
                Ok(None) => {
                    // Non-network config payloads remain backward-compatible no-ops.
                }
                Err(err) => {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("config_change rejected: {}", err);
                }
            }
        }
    }
}
