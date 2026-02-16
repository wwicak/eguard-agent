use super::*;
use self_protect::{SelfProtectReport, SelfProtectViolation};

fn event(ts: i64) -> EventEnvelope {
    EventEnvelope {
        agent_id: "agent-test".to_string(),
        event_type: "process_exec".to_string(),
        severity: String::new(),
        rule_name: String::new(),
        payload_json: format!("{{\"ts\":{ts}}}"),
        created_at_unix: ts,
    }
}

fn detection_event(ts: i64, pid: u32) -> TelemetryEvent {
    TelemetryEvent {
        ts_unix: ts,
        event_class: EventClass::ProcessExec,
        pid,
        ppid: 1,
        uid: 1000,
        process: "bash".to_string(),
        parent_process: "systemd".to_string(),
        session_id: 1,
        file_path: None,
        file_write: false,
        file_hash: None,
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
        command_line: None,
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    }
}

fn tick_evaluation_for_confidence(confidence: Confidence, ts: i64, pid: u32) -> TickEvaluation {
    TickEvaluation {
        detection_event: detection_event(ts, pid),
        detection_outcome: detection::DetectionOutcome {
            confidence,
            signals: detection::DetectionSignals {
                z1_exact_ioc: false,
                z2_temporal: false,
                z3_anomaly_high: false,
                z3_anomaly_med: false,
                z4_kill_chain: false,
                l1_prefilter_hit: false,
                exploit_indicator: false,
            },
            temporal_hits: Vec::new(),
            kill_chain_hits: Vec::new(),
            exploit_indicators: Vec::new(),
            yara_hits: Vec::new(),
            anomaly: None,
            layer1: detection::Layer1EventHit::default(),
            ml_score: None,
            behavioral_alarms: Vec::new(),
        },
        confidence,
        action: PlannedAction::AlertOnly,
        compliance: compliance::ComplianceResult {
            status: "ok".to_string(),
            detail: "ok".to_string(),
            checks: Vec::new(),
        },
        event_envelope: event(ts),
    }
}

#[test]
// AC-DET-220 AC-DET-221 AC-DET-222
fn telemetry_audit_payload_includes_rule_attribution() {
    let cfg = AgentConfig::default();
    let runtime = AgentRuntime::new(cfg).expect("runtime");

    let enriched = platform_linux::EnrichedEvent {
        event: platform_linux::RawEvent {
            event_type: platform_linux::EventType::ProcessExec,
            pid: 9001,
            uid: 0,
            ts_ns: 0,
            payload: "".to_string(),
        },
        process_exe: Some("memfd:payload (deleted)".to_string()),
        process_exe_sha256: None,
        process_cmdline: Some("python -c 'print(1)'".to_string()),
        parent_process: Some("init".to_string()),
        parent_chain: vec![1],
        file_path: Some("memfd:payload (deleted)".to_string()),
        file_path_secondary: None,
        file_write: false,
        file_sha256: None,
        event_size: None,
        dst_ip: None,
        dst_port: None,
        dst_domain: None,
        container_runtime: Some("host".to_string()),
        container_id: None,
        container_escape: false,
        container_privileged: false,
    };

    let event = detection::TelemetryEvent {
        ts_unix: 1,
        event_class: detection::EventClass::ProcessExec,
        pid: 9001,
        ppid: 1,
        uid: 0,
        process: "memfd".to_string(),
        parent_process: "init".to_string(),
        session_id: 9001,
        file_path: Some("memfd:payload (deleted)".to_string()),
        file_write: false,
        file_hash: None,
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
        command_line: Some("python -c 'print(1)'".to_string()),
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    };

    let mut layer1 = detection::Layer1EventHit::default();
    layer1.matched_fields = vec!["file_hash".to_string()];
    layer1.matched_signatures = vec!["sig".to_string()];

    let outcome = detection::DetectionOutcome {
        confidence: detection::Confidence::High,
        signals: detection::DetectionSignals {
            z1_exact_ioc: false,
            z2_temporal: false,
            z3_anomaly_high: false,
            z3_anomaly_med: false,
            z4_kill_chain: false,
            l1_prefilter_hit: false,
            exploit_indicator: true,
        },
        temporal_hits: Vec::new(),
        kill_chain_hits: Vec::new(),
        exploit_indicators: vec!["fileless_memfd".to_string()],
        yara_hits: Vec::new(),
        anomaly: None,
        layer1,
        ml_score: None,
        behavioral_alarms: Vec::new(),
    };

    let payload = runtime.telemetry_payload_json(&enriched, &event, &outcome, detection::Confidence::High, 10);
    let value: serde_json::Value = serde_json::from_str(&payload).expect("valid json");

    let audit = &value["audit"];
    assert_eq!(audit["primary_rule_name"], "exploit:fileless_memfd");
    assert_eq!(audit["rule_type"], "exploit");
    assert!(audit["matched_fields"].as_array().unwrap().iter().any(|v| v == "file_hash"));
    assert!(audit["matched_signatures"].as_array().unwrap().iter().any(|v| v == "sig"));
    assert!(audit["exploit_indicators"].as_array().unwrap().iter().any(|v| v == "fileless_memfd"));
}

#[tokio::test]
// AC-OBS-001 AC-OBS-003 AC-OBS-005
async fn observability_snapshot_tracks_send_failure_degraded_transition_and_queue_depth() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();
    cfg.self_protection_integrity_check_interval_secs = 0;

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.runtime_mode = AgentMode::Active;
    runtime.baseline_store.status = baseline::BaselineStatus::Active;
    runtime.client.set_online(false);
    runtime.runtime_mode = AgentMode::Active;

    runtime
        .send_event_batch(event(1))
        .await
        .expect("send batch 1");
    runtime
        .send_event_batch(event(2))
        .await
        .expect("send batch 2");
    runtime
        .send_event_batch(event(3))
        .await
        .expect("send batch 3");

    let snapshot = runtime.observability_snapshot();
    assert_eq!(snapshot.runtime_mode, "degraded");
    assert_eq!(snapshot.consecutive_send_failures, 3);
    assert_eq!(snapshot.pending_event_count, 3);
    assert_eq!(snapshot.degraded_due_to_send_failures, 1);
    assert_eq!(snapshot.degraded_due_to_self_protection, 0);
    assert_eq!(
        snapshot.last_degraded_cause.as_deref(),
        Some("send_failures")
    );
    assert!(snapshot.last_send_event_batch_micros > 0);
}

#[tokio::test]
// AC-OBS-002 AC-OBS-003
async fn observability_snapshot_tracks_self_protect_degraded_transition_once() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();
    cfg.self_protection_integrity_check_interval_secs = 0;

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.runtime_mode = AgentMode::Active;
    runtime.baseline_store.status = baseline::BaselineStatus::Active;
    runtime.client.set_online(false);
    runtime.runtime_mode = AgentMode::Active;

    let mut report = SelfProtectReport::default();
    report
        .violations
        .push(SelfProtectViolation::IntegrityProbeFailed {
            detail: "simulated tamper".to_string(),
        });

    runtime
        .handle_self_protection_violation(1_700_000_010, &report)
        .await
        .expect("first self-protect violation");
    runtime
        .handle_self_protection_violation(1_700_000_011, &report)
        .await
        .expect("second self-protect violation");

    let snapshot = runtime.observability_snapshot();
    assert_eq!(snapshot.runtime_mode, "degraded");
    assert_eq!(snapshot.degraded_due_to_send_failures, 0);
    assert_eq!(snapshot.degraded_due_to_self_protection, 1);
    assert_eq!(
        snapshot.last_degraded_cause.as_deref(),
        Some("self_protection")
    );
    assert!(snapshot.pending_event_count >= 1);
}

#[tokio::test]
// AC-OBS-001 AC-OBS-004 AC-OPT-005
async fn degraded_tick_updates_stage_timing_snapshot() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();
    cfg.self_protection_integrity_check_interval_secs = 0;

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.client.set_online(false);
    runtime.runtime_mode = AgentMode::Degraded;
    runtime.last_recovery_probe_unix = Some(1_700_000_000);
    runtime.ebpf_engine = platform_linux::EbpfEngine::disabled();

    runtime.tick(1_700_000_000).await.expect("tick");

    let snapshot = runtime.observability_snapshot();
    assert_eq!(snapshot.tick_count, 1);
    assert!(snapshot.last_tick_total_micros > 0);
    assert!(snapshot.max_tick_total_micros >= snapshot.last_tick_total_micros);
    assert!(snapshot.last_evaluate_micros > 0);
    assert!(snapshot.last_degraded_tick_micros > 0);
    assert_eq!(snapshot.last_connected_tick_micros, 0);
    assert_eq!(snapshot.last_send_event_batch_micros, 0);
    assert_eq!(snapshot.last_command_sync_micros, 0);
    assert_eq!(snapshot.last_control_plane_sync_micros, 0);
    assert_eq!(snapshot.pending_event_count, 0);
    assert_eq!(
        snapshot.ebpf_attach_degraded,
        snapshot.ebpf_failed_probe_count > 0
    );
}

#[tokio::test]
// AC-OBS-001 AC-DET-166
async fn observability_snapshot_reports_bounded_command_backlog_progress() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();
    cfg.self_protection_integrity_check_interval_secs = 0;

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.runtime_mode = AgentMode::Active;
    runtime.ebpf_engine = platform_linux::EbpfEngine::disabled();
    runtime.enrolled = true;
    runtime.last_heartbeat_attempt_unix = Some(1_700_000_200);
    runtime.last_compliance_attempt_unix = Some(1_700_000_200);
    runtime.last_threat_intel_refresh_unix = Some(1_700_000_200);

    for i in 0..9 {
        runtime
            .client
            .enqueue_mock_command(grpc_client::CommandEnvelope {
                command_id: format!("queued-cmd-{i}"),
                command_type: "scan".to_string(),
                payload_json: "{}".to_string(),
            });
    }

    runtime.tick(1_700_000_200).await.expect("tick 1");
    let first = runtime.observability_snapshot();
    assert_eq!(first.last_command_fetch_count, 10);
    assert_eq!(
        first.last_command_execute_count,
        COMMAND_EXECUTION_BUDGET_PER_TICK
    );
    assert_eq!(first.pending_command_count, 6);
    assert_eq!(first.last_command_backlog_depth, 6);
    assert!(first.max_command_backlog_depth >= 6);
    assert_eq!(first.last_command_backlog_oldest_age_secs, 0);
    assert_eq!(first.last_control_plane_execute_count, 1);
    assert_eq!(first.pending_control_plane_task_count, 0);
    assert_eq!(first.last_control_plane_queue_depth, 0);
    assert_eq!(first.last_control_plane_oldest_age_secs, 0);

    runtime.tick(1_700_000_205).await.expect("tick 2");
    let second = runtime.observability_snapshot();
    assert_eq!(second.last_command_fetch_count, 0);
    assert_eq!(
        second.last_command_execute_count,
        COMMAND_EXECUTION_BUDGET_PER_TICK
    );
    assert_eq!(second.pending_command_count, 2);
    assert_eq!(second.last_command_backlog_depth, 2);
    assert!(second.last_command_backlog_oldest_age_secs >= 5);
    assert!(
        second.max_command_backlog_oldest_age_secs >= second.last_command_backlog_oldest_age_secs
    );
    assert_eq!(second.last_control_plane_execute_count, 1);
    assert_eq!(second.pending_control_plane_task_count, 0);
    assert_eq!(second.pending_response_count, 0);
    assert_eq!(runtime.completed_command_cursor().len(), 8);
}

#[tokio::test]
// AC-OBS-001 AC-RSP-014
async fn observability_snapshot_reports_bounded_response_queue_progress() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();
    cfg.self_protection_integrity_check_interval_secs = 0;

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.client.set_online(false);

    for i in 0..10 {
        runtime
            .pending_response_actions
            .push_back(PendingResponseAction {
                action: PlannedAction::CaptureScript,
                confidence: Confidence::High,
                event: detection_event(1_700_000_300 + i as i64, 10_000 + i as u32),
                enqueued_at_unix: 1_700_000_300,
            });
    }

    runtime
        .run_connected_response_stage(1_700_000_310, None)
        .await;
    let snapshot = runtime.observability_snapshot();

    assert_eq!(
        snapshot.last_response_execute_count,
        RESPONSE_EXECUTION_BUDGET_PER_TICK
    );
    assert_eq!(snapshot.pending_response_count, 6);
    assert_eq!(snapshot.last_response_queue_depth, 6);
    assert!(snapshot.max_response_queue_depth >= 6);
    assert!(snapshot.last_response_oldest_age_secs >= 10);
    assert!(snapshot.max_response_oldest_age_secs >= snapshot.last_response_oldest_age_secs);
}

#[tokio::test]
// AC-RSP-124 AC-RSP-125 AC-RSP-126
async fn auto_isolation_policy_updates_host_state_and_emits_response_report() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();
    cfg.self_protection_integrity_check_interval_secs = 0;
    cfg.response.autonomous_response = true;
    cfg.response.auto_isolation.enabled = true;
    cfg.response.auto_isolation.min_incidents_in_window = 2;
    cfg.response.auto_isolation.window_secs = 120;
    cfg.response.auto_isolation.max_isolations_per_hour = 1;

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.runtime_mode = AgentMode::Active;
    runtime.baseline_store.status = baseline::BaselineStatus::Active;

    let eval1 = tick_evaluation_for_confidence(Confidence::VeryHigh, 1_700_010_000, 41_001);
    runtime.maybe_apply_auto_isolation(1_700_010_000, Some(&eval1));
    assert!(!runtime.host_control.isolated);
    assert!(runtime.pending_response_reports.is_empty());

    let eval2 = tick_evaluation_for_confidence(Confidence::Definite, 1_700_010_030, 41_002);
    runtime.maybe_apply_auto_isolation(1_700_010_030, Some(&eval2));

    assert!(runtime.host_control.isolated);
    assert_eq!(runtime.pending_response_reports.len(), 1);
    let report = runtime
        .pending_response_reports
        .front()
        .expect("auto-isolation report queued");
    assert_eq!(report.envelope.action_type, "auto_isolate");
    assert_eq!(report.envelope.confidence, "definite");
    assert!(report.envelope.success);
}

#[tokio::test]
// AC-RSP-124 AC-RSP-125
async fn auto_isolation_policy_ignores_high_confidence_and_hourly_cap() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();
    cfg.self_protection_integrity_check_interval_secs = 0;
    cfg.response.autonomous_response = true;
    cfg.response.auto_isolation.enabled = true;
    cfg.response.auto_isolation.min_incidents_in_window = 2;
    cfg.response.auto_isolation.window_secs = 60;
    cfg.response.auto_isolation.max_isolations_per_hour = 1;

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.runtime_mode = AgentMode::Active;
    runtime.baseline_store.status = baseline::BaselineStatus::Active;

    let high = tick_evaluation_for_confidence(Confidence::High, 1_700_020_000, 42_001);
    runtime.maybe_apply_auto_isolation(1_700_020_000, Some(&high));
    runtime.maybe_apply_auto_isolation(1_700_020_010, Some(&high));
    assert!(!runtime.host_control.isolated);

    let very_high = tick_evaluation_for_confidence(Confidence::VeryHigh, 1_700_020_020, 42_002);
    runtime.maybe_apply_auto_isolation(1_700_020_020, Some(&very_high));
    runtime.maybe_apply_auto_isolation(1_700_020_030, Some(&very_high));
    assert!(runtime.host_control.isolated);

    runtime.host_control.isolated = false;
    runtime.maybe_apply_auto_isolation(1_700_020_040, Some(&very_high));
    runtime.maybe_apply_auto_isolation(1_700_020_050, Some(&very_high));
    assert!(!runtime.host_control.isolated);
}

#[tokio::test]
// AC-OBS-006 AC-OPT-006
async fn async_worker_queue_dispatches_control_plane_sends() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();
    cfg.self_protection_integrity_check_interval_secs = 0;

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.client.set_online(false);

    let now = 1_700_000_800;
    runtime.last_threat_intel_refresh_unix = Some(now);
    runtime.last_command_fetch_attempt_unix = Some(now);
    runtime
        .run_connected_control_plane_stage(now, None)
        .await
        .expect("run control-plane stage");

    assert_eq!(runtime.pending_control_plane_sends.len(), 2);
    assert_eq!(runtime.control_plane_send_tasks.len(), 0);

    runtime.drive_async_workers();
    assert_eq!(runtime.pending_control_plane_sends.len(), 0);
    assert!(runtime.control_plane_send_tasks.len() <= CONTROL_PLANE_SEND_CONCURRENCY);

    tokio::task::yield_now().await;
    runtime.drive_async_workers();
}

#[tokio::test]
// AC-OBS-006 AC-RSP-014
async fn async_worker_queue_dispatches_response_reports() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();
    cfg.self_protection_integrity_check_interval_secs = 0;

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.client.set_online(false);

    runtime.enqueue_response_report(ResponseEnvelope {
        agent_id: "agent-test".to_string(),
        action_type: "capture_script".to_string(),
        confidence: "high".to_string(),
        success: false,
        error_message: "capture_failed:test".to_string(),
    });

    assert_eq!(runtime.pending_response_reports.len(), 1);
    assert_eq!(runtime.response_report_tasks.len(), 0);

    runtime.drive_async_workers();
    assert_eq!(runtime.pending_response_reports.len(), 0);
    assert!(runtime.response_report_tasks.len() <= RESPONSE_REPORT_CONCURRENCY);

    tokio::task::yield_now().await;
    runtime.drive_async_workers();
}

#[tokio::test]
// AC-OPT-006 AC-OBS-001
async fn runtime_tick_p99_and_degraded_churn_stay_within_guardrails() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();
    cfg.self_protection_integrity_check_interval_secs = 0;

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.runtime_mode = AgentMode::Active;
    runtime.ebpf_engine = platform_linux::EbpfEngine::disabled();
    runtime.enrolled = true;
    runtime.last_heartbeat_attempt_unix = Some(1_700_000_500);
    runtime.last_compliance_attempt_unix = Some(1_700_000_500);
    runtime.last_threat_intel_refresh_unix = Some(1_700_000_500);
    runtime.last_command_fetch_attempt_unix = Some(1_700_000_500);

    let mut tick_micros = Vec::new();
    for _ in 0..128 {
        let now = 1_700_000_500;
        runtime.tick(now).await.expect("tick");
        tick_micros.push(runtime.observability_snapshot().last_tick_total_micros);
    }

    tick_micros.sort_unstable();
    let idx = ((tick_micros.len() as f64) * 0.99).ceil() as usize;
    let p99 = tick_micros[idx.saturating_sub(1).min(tick_micros.len() - 1)];

    let snapshot = runtime.observability_snapshot();
    assert!(p99 <= 5_000, "tick p99 too high: {p99}us");
    assert!(
        snapshot.degraded_due_to_send_failures <= 1,
        "degraded churn too high: {}",
        snapshot.degraded_due_to_send_failures
    );
}
