use super::*;
use detection::DetectionEngine;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn script_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn non_comment_lines(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect()
}

fn has_line(lines: &[String], expected: &str) -> bool {
    lines.iter().any(|line| line == expected)
}

#[derive(Debug, PartialEq, Eq)]
struct CommandReportProjection {
    action_type: String,
    success: bool,
    error_message: String,
}

fn project_command_report_fields(
    command_type: &str,
    status: &str,
    detail: &str,
) -> CommandReportProjection {
    CommandReportProjection {
        action_type: format!("command:{}", command_type),
        success: status == "completed",
        error_message: if status == "completed" {
            String::new()
        } else {
            detail.to_string()
        },
    }
}

#[test]
// AC-DET-151
fn reload_detection_state_records_reload_report_fields() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    let mut runtime = AgentRuntime::new(cfg).expect("runtime");

    runtime
        .reload_detection_state("v-next", "")
        .expect("reload state");

    let report = runtime
        .last_reload_report
        .clone()
        .expect("reload report should be recorded");
    assert_eq!(report.new_version, "v-next");
    assert_eq!(report.sigma_rules, 0);
    assert_eq!(report.yara_rules, 0);
    assert!(report.ioc_entries <= 1_000_000);
}

#[test]
// AC-DET-152
fn heartbeat_config_version_prefers_latest_threat_version_then_detection_state() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    let mut runtime = AgentRuntime::new(cfg).expect("runtime");

    runtime
        .detection_state
        .swap_engine("v-det".to_string(), DetectionEngine::default_with_rules())
        .expect("set detection state version");
    assert_eq!(runtime.heartbeat_config_version(), "v-det");

    runtime.latest_threat_version = Some("v-server".to_string());
    assert_eq!(runtime.heartbeat_config_version(), "v-server");
}

#[tokio::test]
// AC-DET-166
async fn command_pipeline_executes_offline_and_caps_completed_cursor() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.client.set_online(false);

    runtime
        .handle_command(
            grpc_client::CommandEnvelope {
                command_id: "cmd-isolate-1".to_string(),
                command_type: "isolate".to_string(),
                payload_json: "{}".to_string(),
            },
            10,
        )
        .await;
    assert!(runtime.host_control.isolated);

    runtime
        .handle_command(
            grpc_client::CommandEnvelope {
                command_id: "cmd-unknown-2".to_string(),
                command_type: "not_supported_command".to_string(),
                payload_json: "{}".to_string(),
            },
            11,
        )
        .await;
    assert_eq!(
        runtime.completed_command_cursor(),
        vec!["cmd-isolate-1".to_string(), "cmd-unknown-2".to_string()]
    );

    for i in 0..300 {
        runtime
            .handle_command(
                grpc_client::CommandEnvelope {
                    command_id: format!("cmd-{i}"),
                    command_type: "scan".to_string(),
                    payload_json: "{}".to_string(),
                },
                i as i64,
            )
            .await;
    }

    let cursor = runtime.completed_command_cursor();
    assert_eq!(cursor.len(), 256);
    assert_eq!(cursor.first().map(String::as_str), Some("cmd-44"));
    assert_eq!(cursor.last().map(String::as_str), Some("cmd-299"));
    assert_eq!(runtime.host_control.last_scan_unix, Some(299));
    assert!(runtime.host_control.isolated);
    assert!(runtime.host_control.last_update_unix.is_none());
    assert!(!runtime.host_control.uninstall_requested);
}

#[test]
// AC-DET-166
fn command_pipeline_maps_command_outcomes_to_reporting_fields() {
    let mut state = response::HostControlState::default();
    let isolate_exec = response::execute_server_command_with_state(
        response::parse_server_command("isolate"),
        170,
        &mut state,
    );
    assert_eq!(isolate_exec.outcome, response::CommandOutcome::Applied);
    assert_eq!(isolate_exec.status, "completed");
    assert_eq!(isolate_exec.detail, "host switched to isolated mode");
    assert!(state.isolated);

    let isolate_report =
        project_command_report_fields("isolate", isolate_exec.status, &isolate_exec.detail);
    assert_eq!(
        isolate_report,
        CommandReportProjection {
            action_type: "command:isolate".to_string(),
            success: true,
            error_message: String::new(),
        }
    );

    let unknown_exec = response::execute_server_command_with_state(
        response::parse_server_command("not_supported_command"),
        171,
        &mut state,
    );
    assert_eq!(unknown_exec.outcome, response::CommandOutcome::Ignored);
    assert_eq!(unknown_exec.status, "failed");
    assert_eq!(unknown_exec.detail, "unknown command type");
    assert!(state.isolated);

    let unknown_report = project_command_report_fields(
        "not_supported_command",
        unknown_exec.status,
        &unknown_exec.detail,
    );
    assert_eq!(
        unknown_report,
        CommandReportProjection {
            action_type: "command:not_supported_command".to_string(),
            success: false,
            error_message: "unknown command type".to_string(),
        }
    );
}

#[test]
// AC-DET-160 AC-DET-161 AC-DET-163
fn command_pipeline_maps_emergency_rule_push_rejections_to_failed_reporting_fields() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    let runtime = AgentRuntime::new(cfg).expect("runtime");

    let mut state = response::HostControlState::default();
    let mut exec = response::execute_server_command_with_state(
        response::parse_server_command("emergency_rule_push"),
        172,
        &mut state,
    );

    let invalid_payload = serde_json::json!({
        "rule_type": "signature",
        "rule_name": "cmd-emergency-invalid",
        "rule_content": "curl|bash",
        "severity": "urgent"
    })
    .to_string();
    runtime.apply_emergency_rule_push(&invalid_payload, &mut exec);

    assert_eq!(exec.outcome, response::CommandOutcome::Ignored);
    assert_eq!(exec.status, "failed");
    assert_eq!(
        exec.detail,
        "emergency rule push rejected: unsupported emergency severity: urgent"
    );

    let report = project_command_report_fields("emergency_rule_push", exec.status, &exec.detail);
    assert_eq!(
        report,
        CommandReportProjection {
            action_type: "command:emergency_rule_push".to_string(),
            success: false,
            error_message: "emergency rule push rejected: unsupported emergency severity: urgent"
                .to_string(),
        }
    );
}

#[test]
// AC-DET-160 AC-DET-161 AC-DET-163
fn command_pipeline_maps_emergency_rule_push_success_to_completed_reporting_fields() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    let runtime = AgentRuntime::new(cfg).expect("runtime");

    let mut state = response::HostControlState::default();
    let mut exec = response::execute_server_command_with_state(
        response::parse_server_command("emergency_rule_push"),
        173,
        &mut state,
    );

    let valid_payload = serde_json::json!({
        "rule_type": "signature",
        "rule_name": "cmd-emergency-valid",
        "rule_content": "curl|bash",
        "severity": "high"
    })
    .to_string();
    runtime.apply_emergency_rule_push(&valid_payload, &mut exec);

    assert_eq!(exec.outcome, response::CommandOutcome::Applied);
    assert_eq!(exec.status, "completed");
    assert_eq!(exec.detail, "emergency rule applied: cmd-emergency-valid");

    let report = project_command_report_fields("emergency_rule_push", exec.status, &exec.detail);
    assert_eq!(
        report,
        CommandReportProjection {
            action_type: "command:emergency_rule_push".to_string(),
            success: true,
            error_message: String::new(),
        }
    );
}

#[tokio::test]
// AC-DET-160 AC-DET-161 AC-DET-163
async fn emergency_command_payload_validation_is_enforced() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let runtime = AgentRuntime::new(cfg).expect("runtime");

    let valid_payload = serde_json::json!({
        "rule_type": "signature",
        "rule_name": "emergency-signature",
        "rule_content": "curl|bash",
        "severity": "high"
    })
    .to_string();
    let valid_name = runtime
        .apply_emergency_rule_from_payload(&valid_payload)
        .expect("valid emergency payload");
    assert_eq!(valid_name, "emergency-signature");

    let invalid_severity = serde_json::json!({
        "rule_type": "signature",
        "rule_name": "invalid-severity",
        "rule_content": "curl|bash",
        "severity": "urgent"
    })
    .to_string();
    let err = runtime
        .apply_emergency_rule_from_payload(&invalid_severity)
        .expect_err("invalid severity must be rejected");
    assert_eq!(err.to_string(), "unsupported emergency severity: urgent");

    let missing_content = serde_json::json!({
        "rule_type": "signature",
        "rule_name": "missing-content",
        "rule_content": "",
        "severity": "high"
    })
    .to_string();
    let err = runtime
        .apply_emergency_rule_from_payload(&missing_content)
        .expect_err("empty rule content must be rejected");
    assert_eq!(err.to_string(), "missing emergency rule content");
}

#[test]
// AC-DET-174 AC-DET-180
fn rule_push_slo_harness_executes_and_enforces_transfer_and_rollout_budgets() {
    let _guard = script_lock().lock().unwrap_or_else(|e| e.into_inner());
    let root = workspace_root();
    let script_path = root.join("scripts/run_rule_push_slo_ci.sh");

    let success = std::process::Command::new("bash")
        .arg(&script_path)
        .current_dir(&root)
        .env("EGUARD_RULE_PUSH_LINK_MBPS", "1")
        .env("EGUARD_RULE_PUSH_BUNDLE_BYTES", "625000")
        .env("EGUARD_RULE_PUSH_AGENT_COUNT", "30000")
        .env("EGUARD_RULE_PUSH_COMMANDS_PER_SEC", "1000")
        .status()
        .expect("run SLO script");
    assert!(success.success());

    let metrics_path = root.join("artifacts/rule-push-slo/metrics.json");
    let metrics_raw = std::fs::read_to_string(&metrics_path).expect("read metrics");
    let metrics: serde_json::Value = serde_json::from_str(&metrics_raw).expect("parse metrics");
    assert_eq!(metrics["suite"], "rule_push_slo");
    assert!(
        metrics["measured"]["transfer_seconds_at_link_rate"]
            .as_f64()
            .expect("transfer seconds")
            <= 5.0
    );
    assert!(
        metrics["measured"]["fleet_rollout_seconds"]
            .as_f64()
            .expect("rollout seconds")
            <= 30.0
    );

    let failure = std::process::Command::new("bash")
        .arg(&script_path)
        .current_dir(&root)
        .env("EGUARD_RULE_PUSH_LINK_MBPS", "1")
        .env("EGUARD_RULE_PUSH_BUNDLE_BYTES", "625000")
        .env("EGUARD_RULE_PUSH_AGENT_COUNT", "30000")
        .env("EGUARD_RULE_PUSH_COMMANDS_PER_SEC", "500")
        .status()
        .expect("run SLO failure scenario");
    assert!(!failure.success());

    let workflow = std::fs::read_to_string(root.join(".github/workflows/rule-push-slo.yml"))
        .expect("read SLO workflow");
    let workflow_lines = non_comment_lines(&workflow);
    assert!(has_line(
        &workflow_lines,
        "run: ./scripts/run_rule_push_slo_ci.sh"
    ));
    assert!(has_line(&workflow_lines, "path: artifacts/rule-push-slo"));
}
