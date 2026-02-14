use super::*;

use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct EnvGuard {
    name: String,
    previous: Option<String>,
}

impl EnvGuard {
    fn set(name: &str, value: &str) -> Self {
        let previous = std::env::var(name).ok();
        std::env::set_var(name, value);
        Self {
            name: name.to_string(),
            previous,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.as_ref() {
            std::env::set_var(&self.name, previous);
        } else {
            std::env::remove_var(&self.name);
        }
    }
}

fn temp_dir(prefix: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("{}-{}-{}", prefix, std::process::id(), ts));
    fs::create_dir_all(&path).expect("create temp dir");
    path
}

#[tokio::test]
// AC-NAC-PROFILE-004 AC-NAC-PROFILE-005
async fn config_change_network_profile_command_writes_nmconnection_file() {
    let _env_guard = env_lock().lock().expect("env lock");
    let root = temp_dir("agent-network-profile");
    let _profile_dir = EnvGuard::set("EGUARD_NETWORK_PROFILE_DIR", &root.to_string_lossy());

    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.client.set_online(false);

    let payload = serde_json::json!({
        "config_json": {
            "config_type": "network_profile",
            "profile": {
                "profile_id": "corp-main",
                "ssid": "CorpWiFi",
                "security": "wpa2_psk",
                "psk": "Sup3rSecret!",
                "priority": 25,
                "auto_connect": true
            }
        }
    })
    .to_string();

    runtime
        .handle_command(
            grpc_client::CommandEnvelope {
                command_id: "cmd-network-profile-1".to_string(),
                command_type: "config_change".to_string(),
                payload_json: payload,
            },
            100,
        )
        .await;

    let connection_path = root.join("corp-main.nmconnection");
    assert!(
        connection_path.exists(),
        "expected {}",
        connection_path.display()
    );

    let content = fs::read_to_string(&connection_path).expect("read nmconnection file");
    assert!(content.contains("id=corp-main"));
    assert!(content.contains("ssid=CorpWiFi"));
    assert!(content.contains("key-mgmt=wpa-psk"));
    assert!(content.contains("psk=Sup3rSecret!"));

    assert_eq!(
        runtime.completed_command_cursor(),
        vec!["cmd-network-profile-1".to_string()]
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
// AC-NAC-PROFILE-005
fn config_change_network_profile_rejection_marks_command_failed() {
    let _env_guard = env_lock().lock().expect("env lock");

    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();

    let runtime = AgentRuntime::new(cfg).expect("runtime");
    let mut state = response::HostControlState::default();
    let mut exec = response::execute_server_command_with_state(
        response::parse_server_command("config_change"),
        123,
        &mut state,
    );

    let invalid_payload = serde_json::json!({
        "config_json": {
            "config_type": "network_profile",
            "profile": {
                "profile_id": "corp-invalid",
                "ssid": "CorpWiFi",
                "security": "wpa2_psk",
                "psk": "short"
            }
        }
    })
    .to_string();

    runtime.apply_config_change(&invalid_payload, &mut exec);

    assert_eq!(exec.outcome, response::CommandOutcome::Ignored);
    assert_eq!(exec.status, "failed");
    assert!(exec.detail.starts_with("config_change rejected:"));
}

#[test]
// AC-NAC-PROFILE-006
fn config_change_non_network_payload_keeps_backward_compatible_noop() {
    let _env_guard = env_lock().lock().expect("env lock");

    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();

    let runtime = AgentRuntime::new(cfg).expect("runtime");
    let mut state = response::HostControlState::default();
    let mut exec = response::execute_server_command_with_state(
        response::parse_server_command("config_change"),
        124,
        &mut state,
    );

    let payload = serde_json::json!({
        "config_json": {
            "config_type": "response_policy",
            "response": { "autonomous": true }
        }
    })
    .to_string();

    runtime.apply_config_change(&payload, &mut exec);

    assert_eq!(exec.outcome, response::CommandOutcome::Applied);
    assert_eq!(exec.status, "completed");
    assert_eq!(exec.detail, "configuration change accepted");
}
