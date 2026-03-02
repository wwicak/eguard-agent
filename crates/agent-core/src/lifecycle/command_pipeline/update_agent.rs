use std::fs;
use std::path::Path;

use response::{CommandExecution, CommandOutcome};

use super::paths::resolve_agent_data_dir;
use super::payloads::parse_update_payload;
use super::AgentRuntime;

use self::request::{normalize_update_request, NormalizedUpdateRequest};

mod request;
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
mod worker_linux;
#[cfg(target_os = "macos")]
mod worker_macos;
#[cfg(target_os = "windows")]
mod worker_windows;

impl AgentRuntime {
    pub(super) fn apply_agent_update(&self, payload_json: &str, exec: &mut CommandExecution) {
        let payload = parse_update_payload(payload_json);
        let request = match normalize_update_request(payload, &self.config.server_addr) {
            Ok(request) => request,
            Err(err) => {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("invalid update payload: {}", err);
                return;
            }
        };

        let update_dir = resolve_agent_data_dir().join("update");
        if let Err(err) = fs::create_dir_all(&update_dir) {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!("update staging dir failed: {}", err);
            return;
        }

        match spawn_update_worker(&request, &update_dir) {
            Ok(detail) => {
                exec.detail = detail;
            }
            Err(err) => {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("agent update launch failed: {}", err);
            }
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn spawn_update_worker(
    request: &NormalizedUpdateRequest,
    update_dir: &Path,
) -> Result<String, String> {
    worker_linux::spawn_update_worker(request, update_dir)
}

#[cfg(target_os = "windows")]
fn spawn_update_worker(
    request: &NormalizedUpdateRequest,
    update_dir: &Path,
) -> Result<String, String> {
    worker_windows::spawn_update_worker(request, update_dir)
}

#[cfg(target_os = "macos")]
fn spawn_update_worker(
    request: &NormalizedUpdateRequest,
    update_dir: &Path,
) -> Result<String, String> {
    worker_macos::spawn_update_worker(request, update_dir)
}
