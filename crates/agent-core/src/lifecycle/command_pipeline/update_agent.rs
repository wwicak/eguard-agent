use std::fs;
use std::path::Path;

use response::{CommandExecution, CommandOutcome};
use tracing::warn;

use super::paths::resolve_agent_data_dir;
use super::payloads::parse_update_payload;
use super::AgentRuntime;

use self::outcome::load_update_outcome_reports;
use self::request::{normalize_update_request, NormalizedUpdateRequest};

mod outcome;
mod request;
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
mod worker_linux;
#[cfg(target_os = "macos")]
mod worker_macos;
#[cfg(target_os = "windows")]
mod worker_windows;

impl AgentRuntime {
    pub(crate) async fn flush_update_outcome_reports(&self) {
        let update_dir = resolve_agent_data_dir().join("update");
        let reports = match load_update_outcome_reports(&update_dir) {
            Ok(reports) => reports,
            Err(err) => {
                warn!(error = %err, dir = %update_dir.display(), "failed to load update outcome reports");
                return;
            }
        };

        for (path, report) in reports {
            let result_json = serde_json::json!({ "detail": report.detail }).to_string();
            match self
                .client
                .ack_command_with_result(
                    &self.config.agent_id,
                    &report.command_id,
                    &report.status,
                    Some(&result_json),
                )
                .await
            {
                Ok(()) => {
                    if let Err(err) = std::fs::remove_file(&path) {
                        warn!(error = %err, path = %path.display(), "failed to remove applied update outcome report");
                    }
                }
                Err(err) => {
                    warn!(
                        error = %err,
                        command_id = %report.command_id,
                        path = %path.display(),
                        "failed to flush update outcome report"
                    );
                }
            }
        }
    }

    pub(super) fn apply_agent_update(
        &self,
        command_id: &str,
        payload_json: &str,
        exec: &mut CommandExecution,
    ) {
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

        match spawn_update_worker(command_id, &request, &update_dir) {
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
    command_id: &str,
    request: &NormalizedUpdateRequest,
    update_dir: &Path,
) -> Result<String, String> {
    worker_linux::spawn_update_worker(command_id, request, update_dir)
}

#[cfg(target_os = "windows")]
fn spawn_update_worker(
    command_id: &str,
    request: &NormalizedUpdateRequest,
    update_dir: &Path,
) -> Result<String, String> {
    worker_windows::spawn_update_worker(command_id, request, update_dir)
}

#[cfg(target_os = "macos")]
fn spawn_update_worker(
    command_id: &str,
    request: &NormalizedUpdateRequest,
    update_dir: &Path,
) -> Result<String, String> {
    worker_macos::spawn_update_worker(command_id, request, update_dir)
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::outcome::{load_update_outcome_reports, write_update_outcome_report};
    use super::AgentRuntime;
    use crate::config::AgentConfig;

    fn unique_temp_dir(label: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "eguard-update-outcome-flush-{}-{}-{}",
            label,
            std::process::id(),
            nanos
        ))
    }

    #[tokio::test]
    async fn flush_update_outcome_reports_acks_and_removes_file() {
        let _guard = crate::test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let data_dir = unique_temp_dir("ack");
        let update_dir = data_dir.join("update");
        std::env::set_var("EGUARD_AGENT_DATA_DIR", &data_dir);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock ack server");
        let addr = listener.local_addr().expect("mock server addr");
        let seen_request = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let seen_request_clone = seen_request.clone();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let mut request_buf = vec![0u8; 64 * 1024];
            let read_len = stream.read(&mut request_buf).await.expect("read request");
            let request = std::str::from_utf8(&request_buf[..read_len]).expect("request utf8");
            if let Ok(mut guard) = seen_request_clone.lock() {
                *guard = request.to_string();
            }
            let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 20\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}";
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        });

        write_update_outcome_report(
            &update_dir,
            "cmd-update-outcome-1",
            "failed",
            "package checksum verification failed",
        )
        .expect("write outcome report");

        let cfg = AgentConfig {
            transport_mode: "http".to_string(),
            server_addr: addr.to_string(),
            agent_id: "agent-test-outcome".to_string(),
            ..AgentConfig::default()
        };
        let runtime = AgentRuntime::new(cfg).expect("runtime");
        runtime.flush_update_outcome_reports().await;

        let request = seen_request
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default();
        assert!(request.starts_with("POST /api/v1/endpoint/command/ack "));
        assert!(request.contains("cmd-update-outcome-1"));
        assert!(request.contains("\"status\":\"failed\""));
        assert!(request.contains("package checksum verification failed"));
        assert!(load_update_outcome_reports(&update_dir)
            .expect("reload reports")
            .is_empty());

        server.await.expect("mock server join");
        std::env::remove_var("EGUARD_AGENT_DATA_DIR");
        let _ = std::fs::remove_dir_all(&data_dir);
    }
}
