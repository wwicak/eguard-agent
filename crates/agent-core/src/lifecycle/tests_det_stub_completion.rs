use super::*;
use detection::DetectionEngine;
use std::path::{Path, PathBuf};
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

fn env_var_lock() -> &'static Mutex<()> {
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

fn unique_temp_dir(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "{prefix}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ))
}

fn write_ioc_hash_bundle(bundle_root: &Path, hash_count: usize) {
    let ioc_dir = bundle_root.join("ioc");
    std::fs::create_dir_all(&ioc_dir).expect("create ioc dir");

    let mut payload = String::new();
    for idx in 0..hash_count {
        payload.push_str(&format!("bundle-ioc-hash-{idx:04}\n"));
    }
    std::fs::write(ioc_dir.join("hashes.txt"), payload).expect("write ioc hashes");
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
        .reload_detection_state("v-next", "", None)
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
// AC-DET-006 AC-DET-151
fn reload_detection_state_rejects_corroboration_mismatch_before_swap() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    let mut runtime = AgentRuntime::new(cfg).expect("runtime");

    let before = runtime
        .detection_state
        .version()
        .expect("read version")
        .unwrap_or_default();

    let expected = grpc_client::ThreatIntelVersionEnvelope {
        version: "v-next".to_string(),
        bundle_path: "/tmp/non-existent-bundle".to_string(),
        published_at_unix: 0,
        sigma_count: 5,
        yara_count: 2,
        ioc_count: 100,
        cve_count: 10,
        custom_rule_count: 0,
        custom_rule_version_hash: String::new(),
        bundle_signature_path: String::new(),
        bundle_sha256: String::new(),
    };

    let err = runtime
        .reload_detection_state("v-next", "", Some(&expected))
        .expect_err("corroboration must reject mismatched counts");
    assert!(err.to_string().contains("corroboration"));

    let after = runtime
        .detection_state
        .version()
        .expect("read version after")
        .unwrap_or_default();
    assert_eq!(after, before);
}

#[test]
// AC-DET-006 AC-DET-151
fn reload_detection_state_corroborates_ioc_count_from_bundle_payload_not_seeded_defaults() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    let mut runtime = AgentRuntime::new(cfg).expect("runtime");

    let bundle_root = std::env::temp_dir().join(format!(
        "eguard-ioc-corroboration-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let ioc_dir = bundle_root.join("ioc");
    std::fs::create_dir_all(&ioc_dir).expect("create ioc dir");
    std::fs::write(
        ioc_dir.join("hashes.txt"),
        "bundle-ioc-hash-corroboration\n",
    )
    .expect("write ioc hashes");

    let expected = grpc_client::ThreatIntelVersionEnvelope {
        version: "v-ioc-corroborated".to_string(),
        bundle_path: bundle_root.to_string_lossy().into_owned(),
        published_at_unix: 0,
        sigma_count: 0,
        yara_count: 0,
        ioc_count: 1,
        cve_count: 0,
        custom_rule_count: 0,
        custom_rule_version_hash: String::new(),
        bundle_signature_path: String::new(),
        bundle_sha256: String::new(),
    };

    runtime
        .reload_detection_state(
            "v-ioc-corroborated",
            bundle_root.to_string_lossy().as_ref(),
            Some(&expected),
        )
        .expect("bundle IOC count corroboration should succeed");

    let report = runtime
        .last_reload_report
        .clone()
        .expect("reload report should be recorded");
    assert_eq!(report.ioc_entries, 1);

    let _ = std::fs::remove_dir_all(bundle_root);
}

#[test]
// AC-DET-006 AC-DET-145 AC-DET-184
fn reload_detection_state_rejects_signature_database_floor_violation_before_swap() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    let mut runtime = AgentRuntime::new(cfg).expect("runtime");

    let before = runtime
        .detection_state
        .version()
        .expect("read version")
        .unwrap_or_default();

    let bundle_root = std::env::temp_dir().join(format!(
        "eguard-signature-floor-violation-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(&bundle_root).expect("create bundle root");

    let err = runtime
        .reload_detection_state(
            "v-signature-floor",
            bundle_root.to_string_lossy().as_ref(),
            None,
        )
        .expect_err("signature floor violation must reject bundle swap");
    assert!(err
        .to_string()
        .contains("signature database floor violation"));

    let after = runtime
        .detection_state
        .version()
        .expect("read version after")
        .unwrap_or_default();
    assert_eq!(after, before);

    let _ = std::fs::remove_dir_all(bundle_root);
}

#[test]
// AC-DET-006 AC-DET-145 AC-DET-184
fn reload_detection_state_rejects_signature_drop_guard_regression_and_keeps_last_good_version() {
    let _guard = env_var_lock().lock().expect("lock env vars");
    std::env::set_var("EGUARD_RULE_BUNDLE_MAX_SIGNATURE_DROP_PCT", "20");

    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    let mut runtime = AgentRuntime::new(cfg).expect("runtime");

    let bundle_v1 = unique_temp_dir("eguard-signature-drop-guard-v1");
    write_ioc_hash_bundle(&bundle_v1, 10);
    runtime
        .reload_detection_state("v-drop-guard-1", bundle_v1.to_string_lossy().as_ref(), None)
        .expect("initial bundle reload should pass");

    let bundle_v2 = unique_temp_dir("eguard-signature-drop-guard-v2");
    write_ioc_hash_bundle(&bundle_v2, 1);
    let err = runtime
        .reload_detection_state("v-drop-guard-2", bundle_v2.to_string_lossy().as_ref(), None)
        .expect_err("large signature drop should be blocked by guard");
    assert!(err.to_string().contains("drop guard violation"));

    assert_eq!(
        runtime
            .detection_state
            .version()
            .expect("read version after rejected reload")
            .as_deref(),
        Some("v-drop-guard-1")
    );
    assert_eq!(
        runtime
            .last_reload_report
            .as_ref()
            .map(|report| report.new_version.as_str()),
        Some("v-drop-guard-1")
    );

    std::env::remove_var("EGUARD_RULE_BUNDLE_MAX_SIGNATURE_DROP_PCT");
    let _ = std::fs::remove_dir_all(bundle_v1);
    let _ = std::fs::remove_dir_all(bundle_v2);
}

#[test]
// AC-DET-006 AC-DET-145 AC-DET-184
fn reload_detection_state_accepts_signature_drop_within_guard_threshold() {
    let _guard = env_var_lock().lock().expect("lock env vars");
    std::env::set_var("EGUARD_RULE_BUNDLE_MAX_SIGNATURE_DROP_PCT", "20");

    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    let mut runtime = AgentRuntime::new(cfg).expect("runtime");

    let bundle_v1 = unique_temp_dir("eguard-signature-drop-guard-pass-v1");
    write_ioc_hash_bundle(&bundle_v1, 10);
    runtime
        .reload_detection_state(
            "v-drop-guard-pass-1",
            bundle_v1.to_string_lossy().as_ref(),
            None,
        )
        .expect("initial bundle reload should pass");

    let bundle_v2 = unique_temp_dir("eguard-signature-drop-guard-pass-v2");
    write_ioc_hash_bundle(&bundle_v2, 8);
    runtime
        .reload_detection_state(
            "v-drop-guard-pass-2",
            bundle_v2.to_string_lossy().as_ref(),
            None,
        )
        .expect("in-range signature drop should be accepted");

    assert_eq!(
        runtime
            .detection_state
            .version()
            .expect("read version after accepted reload")
            .as_deref(),
        Some("v-drop-guard-pass-2")
    );
    assert_eq!(
        runtime
            .last_reload_report
            .as_ref()
            .map(|report| report.ioc_entries),
        Some(8)
    );

    std::env::remove_var("EGUARD_RULE_BUNDLE_MAX_SIGNATURE_DROP_PCT");
    let _ = std::fs::remove_dir_all(bundle_v1);
    let _ = std::fs::remove_dir_all(bundle_v2);
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

#[test]
// AC-DET-006 AC-DET-151 AC-DET-184
fn runtime_bootstrap_restores_last_known_good_bundle_after_restart() {
    let _guard = env_var_lock().lock().expect("lock env vars");

    let root = std::env::temp_dir().join(format!(
        "eguard-last-good-bootstrap-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let bundle_root = root.join("bundle");
    let sigma_dir = bundle_root.join("sigma");
    let yara_dir = bundle_root.join("yara");
    std::fs::create_dir_all(&sigma_dir).expect("create sigma dir");
    std::fs::create_dir_all(&yara_dir).expect("create yara dir");

    std::fs::write(
        sigma_dir.join("rule.yml"),
        r#"
title: bootstrap_last_known_good_sigma
detection:
  sequence:
    - event_class: process_exec
      process_any_of: [bash]
      parent_any_of: [sshd]
      within_secs: 30
"#,
    )
    .expect("write sigma rule");
    std::fs::write(
        yara_dir.join("rule.yar"),
        r#"
rule bootstrap_last_known_good_yara {
  strings:
    $m = "bootstrap-last-known-good-marker"
  condition:
    $m
}
"#,
    )
    .expect("write yara rule");

    let replay_floor_path = root.join("replay-floor.json");
    let last_known_good_path = root.join("last-known-good.json");
    std::env::set_var("EGUARD_THREAT_INTEL_REPLAY_FLOOR_PATH", &replay_floor_path);
    std::env::set_var(
        "EGUARD_THREAT_INTEL_LAST_KNOWN_GOOD_PATH",
        &last_known_good_path,
    );

    let version = "rules-2026.02.14.42";
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();

    {
        let mut runtime = AgentRuntime::new(cfg.clone()).expect("runtime");
        runtime
            .reload_detection_state(version, bundle_root.to_string_lossy().as_ref(), None)
            .expect("reload with local bundle");
    }

    let runtime = AgentRuntime::new(cfg).expect("runtime after restart");
    assert_eq!(
        runtime
            .detection_state
            .version()
            .expect("read version")
            .as_deref(),
        Some(version)
    );
    assert_eq!(runtime.heartbeat_config_version(), version);

    let event = detection::TelemetryEvent {
        ts_unix: 123,
        event_class: detection::EventClass::ProcessExec,
        pid: 100,
        ppid: 1,
        uid: 1000,
        process: "bash".to_string(),
        parent_process: "sshd".to_string(),
        session_id: 1,
        file_path: None,
        file_write: false,
        file_hash: None,
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
        command_line: Some("echo bootstrap-last-known-good-marker".to_string()),
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    };
    let out = runtime
        .detection_state
        .process_event(&event)
        .expect("evaluate event");
    assert!(out
        .yara_hits
        .iter()
        .any(|hit| hit.rule_name == "bootstrap_last_known_good_yara"));

    std::env::remove_var("EGUARD_THREAT_INTEL_REPLAY_FLOOR_PATH");
    std::env::remove_var("EGUARD_THREAT_INTEL_LAST_KNOWN_GOOD_PATH");
    let _ = std::fs::remove_dir_all(root);
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
    assert!(
        metrics["measured"]["dispatch_probe_seconds"]
            .as_f64()
            .is_some(),
        "dispatch probe wall seconds must be present"
    );
    assert!(
        metrics["measured"]["effective_commands_per_sec_used_for_rollout"]
            .as_f64()
            .is_some(),
        "effective command throughput must be present"
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
