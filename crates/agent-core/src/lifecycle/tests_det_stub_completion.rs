use super::*;
use detection::DetectionEngine;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
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

#[test]
// AC-DET-166
fn command_pipeline_ack_and_result_report_paths_are_wired() {
    let source = std::fs::read_to_string(
        workspace_root().join("crates/agent-core/src/lifecycle/command_pipeline.rs"),
    )
    .expect("read command_pipeline source");

    assert!(source.contains("self.ack_command_result(&command_id, exec.status).await;"));
    assert!(source.contains("self.report_command_result(&command, exec.status, &exec.detail)"));
    assert!(source.contains("action_type: format!(\"command:{}\", command.command_type)"));
}

#[test]
// AC-DET-174 AC-DET-180
fn rule_push_slo_harness_and_workflow_define_transfer_and_rollout_budgets() {
    let root = workspace_root();
    let script = std::fs::read_to_string(root.join("scripts/run_rule_push_slo_ci.sh"))
        .expect("read SLO script");
    let workflow = std::fs::read_to_string(root.join(".github/workflows/rule-push-slo.yml"))
        .expect("read SLO workflow");

    for required in [
        "TRANSFER_SLO_SECONDS=\"5\"",
        "ROLLOUT_SLO_SECONDS=\"30\"",
        "EGUARD_RULE_PUSH_LINK_MBPS",
        "transfer_seconds_at_link_rate",
        "fleet_rollout_seconds",
        "awk \"BEGIN { if (${TRANSFER_SECONDS} > ${TRANSFER_SLO_SECONDS}) exit 1 }\"",
        "awk \"BEGIN { if (${ROLLOUT_SECONDS} > ${ROLLOUT_SLO_SECONDS}) exit 1 }\"",
    ] {
        assert!(
            script.contains(required),
            "missing SLO script contract: {required}"
        );
    }

    assert!(workflow.contains("run_rule_push_slo_ci.sh"));
    assert!(workflow.contains("artifacts/rule-push-slo"));
}
