use super::*;
use crate::config::{AgentConfig, AgentMode};

fn runtime() -> AgentRuntime {
    let cfg = AgentConfig {
        offline_buffer_backend: "memory".to_string(),
        server_addr: "127.0.0.1:1".to_string(),
        self_protection_integrity_check_interval_secs: 0,
        ..AgentConfig::default()
    };
    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.ebpf_engine = platform_linux::EbpfEngine::disabled();
    runtime.runtime_mode = AgentMode::Active;
    runtime.client.set_online(false);
    runtime.enrolled = true;
    runtime.deferred_bundle_bootstrap_pending = false;
    runtime
}

struct FilterBudgetFixture(std::path::PathBuf);

impl FilterBudgetFixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "eguard-filter-budget-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("exec"), b"synthetic executable").unwrap();
        Self(path)
    }

    fn queue(&self, runtime: &mut AgentRuntime, pid: u32) {
        runtime
            .raw_event_backlog
            .push_back(platform_linux::RawEvent {
                event_type: platform_linux::EventType::ProcessExec,
                pid,
                uid: 0,
                ts_ns: 1,
                payload: format!(
                    "path={};cmdline=fixture;ppid=1;comm=fixture;parent_comm=init",
                    self.0.join("exec").display()
                ),
            });
    }
}

impl Drop for FilterBudgetFixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

// Keep maintenance that writes host paths out of these synthetic ticks.
fn prepare_filter_budget_tick(runtime: &mut AgentRuntime, now: i64) {
    runtime.runtime_mode = AgentMode::Degraded;
    runtime.last_self_protect_check_unix = Some(now);
    runtime.last_config_permission_check_unix = Some(now);
    runtime.last_storage_hygiene_unix = Some(now);
    runtime.last_isolation_failsafe_check_unix = Some(now);
    runtime.last_kernel_integrity_scan_unix = Some(now);
    runtime.telemetry_eval_budget_override = Some(std::time::Duration::from_secs(3600));
}

#[tokio::test]
async fn filtered_raw_candidate_budget_bounds_tick_and_preserves_tail() {
    let mut runtime = runtime();
    let now = 1_700_000_000;
    prepare_filter_budget_tick(&mut runtime, now);
    let fixture = FilterBudgetFixture::new();
    for _ in 0..10_000 {
        fixture.queue(&mut runtime, std::process::id());
    }
    fixture.queue(&mut runtime, 424242);
    runtime.tick(now).await.unwrap();
    assert_eq!(
        runtime.raw_event_backlog.len(),
        10_001 - 256,
        "one tick must not consume more than the filtered-candidate budget"
    );
    assert_eq!(
        runtime.last_recovery_probe_unix,
        Some(now),
        "control-plane recovery must run even when the first dequeue exhausts its budget"
    );
    assert_eq!(runtime.metrics.telemetry_event_txn_total, 0);
    for _ in 0..40 {
        runtime.tick(now).await.unwrap();
        if runtime.raw_event_backlog.is_empty() {
            break;
        }
    }
    assert!(runtime.raw_event_backlog.is_empty());
    assert_eq!(
        runtime.metrics.telemetry_event_txn_total, 1,
        "the ProcessExec behind filtered candidates must survive for a later tick"
    );
}

#[tokio::test]
async fn filtered_raw_candidate_budget_stops_additional_drain() {
    let mut runtime = runtime();
    let now = 1_700_000_000;
    prepare_filter_budget_tick(&mut runtime, now);
    let fixture = FilterBudgetFixture::new();
    for _ in 0..10_000 {
        fixture.queue(&mut runtime, std::process::id());
    }
    fixture.queue(&mut runtime, 424242);
    runtime
        .run_additional_telemetry_evaluations(now, std::time::Instant::now())
        .await
        .unwrap();
    assert_eq!(runtime.raw_event_backlog.len(), 10_001 - 256);
}

#[tokio::test]
async fn filtered_raw_candidate_budget_short_backlog_unchanged() {
    let mut runtime = runtime();
    let now = 1_700_000_000;
    prepare_filter_budget_tick(&mut runtime, now);
    let fixture = FilterBudgetFixture::new();
    for _ in 0..3 {
        fixture.queue(&mut runtime, std::process::id());
    }
    fixture.queue(&mut runtime, 424242);
    runtime.tick(now).await.unwrap();
    assert!(runtime.raw_event_backlog.is_empty());
    assert_eq!(runtime.metrics.telemetry_event_txn_total, 1);
    assert_eq!(runtime.last_recovery_probe_unix, Some(now));
}

fn event(ts: i64) -> EventEnvelope {
    EventEnvelope {
        agent_id: "reviewfix".into(),
        event_type: "process_exec".into(),
        severity: String::new(),
        rule_name: String::new(),
        payload_json: "{}".into(),
        created_at_unix: ts,
    }
}

fn queue_event(runtime: &mut AgentRuntime) {
    runtime
        .raw_event_backlog
        .push_back(platform_linux::RawEvent {
            event_type: platform_linux::EventType::ProcessExec,
            pid: 424242,
            uid: 0,
            ts_ns: 1,
            payload: "path=/usr/bin/true;cmdline=true;ppid=1;comm=true;parent_comm=init".into(),
        });
}

#[tokio::test]
async fn fanout_playbook_reports_preserve_half_full_queue() {
    let mut runtime = runtime();
    let now = 1_700_000_000;
    runtime
        .playbook_engine
        .load_from_policy(&serde_json::json!({
            "response_playbooks": [{"name":"fanout", "enabled":true, "priority":1,
                "conditions":{"require_signals":[]}, "actions":[{"action":"alert"}]}]
        }));
    queue_event(&mut runtime);
    let evaluation = runtime.evaluate_tick(now).unwrap().unwrap();
    runtime
        .run_connected_response_stage(now, Some(&evaluation))
        .await;
    let mut sentinel = runtime.pending_response_reports.pop_front().unwrap();
    sentinel.envelope.action_type = "old-report-sentinel".into();
    for _ in 0..127 {
        runtime.pending_response_reports.push_back(sentinel.clone());
    }
    runtime
        .playbook_engine
        .load_from_policy(&serde_json::json!({
            "response_playbooks": [{"name":"fanout", "enabled":true, "priority":1,
                "conditions":{"require_signals":[]},
                "actions": vec![serde_json::json!({"action":"alert"}); 130]}]
        }));
    runtime
        .run_connected_response_stage(now, Some(&evaluation))
        .await;
    // One evaluation must not consume the drain's entire half-capacity headroom.
    assert_eq!(
        runtime
            .pending_response_reports
            .iter()
            .filter(|r| r.envelope.action_type == "old-report-sentinel")
            .count(),
        127
    );
    assert_eq!(runtime.pending_response_reports.len(), 127 + 16);
}

#[test]
fn fanout_ioc_signals_preserve_half_full_queue_and_all_detection_signatures() {
    let mut runtime = runtime();
    let now = 1_700_000_000;
    let signatures: Vec<String> = (0..514).map(|i| format!("signature-{i:04}")).collect();
    let mut engine = detection::DetectionEngine::default_with_rules();
    engine.layer1.load_string_signatures(signatures.clone());
    engine.layer1.load_ips(vec!["192.0.2.123".to_string()]);
    runtime.detection_state = crate::detection_state::SharedDetectionState::new(engine, None);
    for i in 0..511 {
        runtime.buffer_ioc_signal(format!("old-ioc-{i}"), "domain".into(), "high", now);
    }
    queue_event(&mut runtime);
    runtime.raw_event_backlog.back_mut().unwrap().payload = format!(
        "path=/synthetic/fanout;cmdline={};ppid=1;comm=fanout;parent_comm=init;dst_ip=192.0.2.123",
        signatures.join(" ")
    );
    let evaluation = runtime.evaluate_tick(now).unwrap().unwrap();
    assert!(evaluation.detection_outcome.signals.z1_exact_ioc);
    assert_eq!(
        evaluation.detection_outcome.layer1.matched_signatures,
        signatures
    );
    // The full detection remains intact; only the campaign upload side queue is bounded.
    assert_eq!(
        runtime
            .ioc_signal_buffer
            .iter()
            .filter(|s| s.ioc_value.starts_with("old-ioc-"))
            .count(),
        511
    );
    assert_eq!(runtime.ioc_signal_buffer.len(), 511 + 32);
    for signature in signatures {
        assert!(evaluation.event_envelope.payload_json.contains(&signature));
    }
}

fn prepare_tick(runtime: &mut AgentRuntime, now: i64) {
    runtime.last_heartbeat_attempt_unix = Some(now);
    runtime.last_compliance_attempt_unix = Some(now);
    runtime.last_inventory_attempt_unix = Some(now);
    runtime.last_baseline_save_unix = Some(now);
    runtime.last_baseline_upload_unix = Some(now);
    runtime.last_fleet_baseline_fetch_unix = Some(now);
    runtime.last_memory_scan_unix = Some(now);
    runtime.last_ioc_signal_upload_unix = Some(now);
    runtime.last_campaign_fetch_unix = Some(now);
    runtime.last_kernel_integrity_scan_unix = Some(now);
    runtime.last_command_fetch_attempt_unix = Some(now);
    let compliance = runtime.evaluate_compliance();
    runtime.collect_compliance_alerts(&compliance, now);
}

#[tokio::test]
async fn degraded_drain_preserves_oldest_buffered_sentinels() {
    let mut runtime = runtime();
    let now = 1_700_000_000;
    prepare_tick(&mut runtime, now);
    runtime.config.mode = AgentMode::Degraded;
    runtime.runtime_mode = AgentMode::Degraded;

    // Size the cap for twenty real evaluations, then fill 85% with sentinels.
    queue_event(&mut runtime);
    let sample = runtime.evaluate_tick(now).unwrap().unwrap().event_envelope;
    let event_bytes = grpc_client::estimate_event_size(&sample);
    let cap = event_bytes * 20;
    runtime.config.offline_buffer_cap_bytes = cap;
    runtime.buffer = grpc_client::EventBuffer::memory(cap);
    for timestamp in 0..17 {
        let mut sentinel = sample.clone();
        sentinel.created_at_unix = timestamp;
        runtime.buffer.enqueue(sentinel).unwrap();
    }
    assert_eq!(runtime.buffer.pending_bytes(), cap * 85 / 100);
    for _ in 0..100 {
        queue_event(&mut runtime);
    }

    runtime.tick(now).await.unwrap();

    let retained = runtime.buffer.drain_batch(100).unwrap();
    assert_eq!(
        retained
            .iter()
            .take(17)
            .map(|e| e.created_at_unix)
            .collect::<Vec<_>>(),
        (0..17).collect::<Vec<_>>(),
        "additional degraded evaluations must not evict the oldest telemetry"
    );
    assert!(
        !runtime.raw_event_backlog.is_empty(),
        "drain must stop early"
    );
}

#[tokio::test]
async fn first_send_outcome_controls_same_tick_maintenance() {
    let mut runtime = runtime();
    let now = 1_700_000_000;
    prepare_tick(&mut runtime, now);
    for i in 0..EVENT_BATCH_SIZE {
        runtime.buffer.enqueue(event(i as i64)).unwrap();
    }
    queue_event(&mut runtime);
    runtime.tick(now).await.unwrap();
    assert_eq!(runtime.consecutive_send_failures, 1);
    assert_eq!(runtime.buffer.pending_count(), EVENT_BATCH_SIZE + 1);
    assert_eq!(runtime.telemetry_send_batches, vec![EVENT_BATCH_SIZE + 1]);
    assert_eq!(runtime.last_policy_fetch_unix, None);
    assert_eq!(runtime.last_threat_intel_refresh_unix, None);
    let retained = runtime.buffer.drain_batch(EVENT_BATCH_SIZE + 1).unwrap();
    assert_eq!(
        retained
            .iter()
            .map(|event| event.created_at_unix)
            .collect::<Vec<_>>(),
        (0..EVENT_BATCH_SIZE as i64)
            .chain(std::iter::once(now))
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn successful_first_send_recovers_same_tick_maintenance() {
    let mut runtime = runtime();
    let now = 1_700_000_000;
    prepare_tick(&mut runtime, now);
    runtime.consecutive_send_failures = 1;
    for i in 0..EVENT_BATCH_SIZE {
        runtime.buffer.enqueue(event(i as i64)).unwrap();
    }
    runtime.telemetry_send_success = true;
    queue_event(&mut runtime);
    runtime.tick(now + 1).await.unwrap();
    assert_eq!(runtime.consecutive_send_failures, 0);
    assert_eq!(runtime.buffer.pending_count(), 0);
    assert_eq!(runtime.telemetry_send_batches, vec![EVENT_BATCH_SIZE + 1]);
    assert_eq!(runtime.last_policy_fetch_unix, Some(now + 1));
    assert_eq!(runtime.last_threat_intel_refresh_unix, Some(now + 1));
}

#[tokio::test]
async fn terminal_command_observes_failed_first_send() {
    check_terminal_command_order(false).await;
}

#[tokio::test]
async fn terminal_command_observes_first_send_without_spooling_full_buffer() {
    check_terminal_command_order(true).await;
}

async fn check_terminal_command_order(success: bool) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static RESTARTED: [AtomicBool; 2] = [AtomicBool::new(false), AtomicBool::new(false)];
    let mut runtime = runtime();
    let now = 1_700_000_000;
    prepare_tick(&mut runtime, now);
    runtime.telemetry_send_success = success;
    runtime.buffer.enqueue(event(1)).unwrap();
    if success {
        let capacity = runtime.buffer.pending_bytes();
        runtime.buffer = grpc_client::EventBuffer::memory(capacity);
        runtime.buffer.enqueue(event(1)).unwrap();
        // A full buffer must be sent before commands, never enqueued into first.
        runtime.buffer_enqueue_failure_at = Some(0);
    }
    RESTARTED[usize::from(success)].store(false, Ordering::SeqCst);
    runtime.device_restart_hook = Some(|runtime| {
        RESTARTED[usize::from(runtime.telemetry_send_success)].store(true, Ordering::SeqCst);
        assert!(runtime.tick_telemetry.as_ref().unwrap().is_empty());
        assert_eq!(runtime.host_control.last_restart_unix, Some(1_700_000_000));
        if runtime.telemetry_send_success {
            assert_eq!(runtime.pipeline_events_sent, 2);
            assert_eq!(runtime.buffer.pending_count(), 0);
            assert_eq!(runtime.buffer_enqueue_failure_at, Some(0));
        } else {
            assert_eq!(runtime.consecutive_send_failures, 1);
            assert_eq!(runtime.buffer.pending_count(), 2);
        }
    });
    runtime.pending_commands.push_back(PendingCommand {
        envelope: grpc_client::CommandEnvelope {
            command_id: "terminal-restart".into(),
            command_type: "restart_device".into(),
            payload_json: "{}".into(),
        },
        enqueued_at_unix: now,
    });
    queue_event(&mut runtime);
    runtime.tick(now).await.unwrap();
    assert!(
        RESTARTED[usize::from(success)].load(Ordering::SeqCst),
        "restart handler must execute"
    );
    assert_eq!(runtime.host_control.last_restart_unix, Some(now));
    assert!(runtime
        .completed_command_cursor()
        .contains(&"terminal-restart".to_string()));
}

#[test]
fn sqlite_fallback_is_heartbeat_visible() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "sqlite".to_string();
    // Both the invalid database directory and its parent belong to this test.
    let fixture = reviewfix_sqlite_dir();
    let invalid_db = fixture.join("invalid.db");
    std::fs::create_dir(&invalid_db).unwrap();
    cfg.offline_buffer_path = invalid_db.to_string_lossy().into_owned();
    let mut runtime = AgentRuntime::new(cfg).unwrap();
    assert!(matches!(
        runtime.buffer,
        grpc_client::EventBuffer::Memory(_)
    ));
    assert!(runtime
        .build_heartbeat_runtime_payload("active")
        .status
        .last_detection
        .contains("offline_buffer_volatile_fallback=true"));
    runtime.config.offline_buffer_backend = "memory".to_string();
    assert!(runtime
        .build_heartbeat_runtime_payload("active")
        .status
        .last_detection
        .contains("offline_buffer_volatile_fallback=false"));
    drop(runtime);
    std::fs::remove_dir_all(fixture).unwrap();
}

fn reviewfix_sqlite_dir() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "eguard-reviewfix-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&path).unwrap();
    path
}

#[tokio::test]
async fn sqlite_failed_send_preserves_old_tail_before_new_tick_overflow() {
    let mut runtime = runtime();
    let fixture = reviewfix_sqlite_dir();
    let path = fixture.join("offline.db");
    runtime.buffer =
        grpc_client::EventBuffer::sqlite(path.to_str().unwrap(), 16 * 1024 * 1024).unwrap();
    // More than a batch exposes destructive drain/requeue's old-tail inversion.
    for i in 0..EVENT_BATCH_SIZE + 2 {
        runtime.buffer.enqueue(event(i as i64)).unwrap();
    }
    runtime
        .flush_event_batch(
            (EVENT_BATCH_SIZE + 2..EVENT_BATCH_SIZE + 5)
                .map(|i| event(i as i64))
                .collect(),
        )
        .await
        .unwrap();
    assert_eq!(runtime.consecutive_send_failures, 1);
    let events = runtime.buffer.drain_batch(EVENT_BATCH_SIZE + 5).unwrap();
    assert_eq!(
        events.iter().map(|e| e.created_at_unix).collect::<Vec<_>>(),
        (0..EVENT_BATCH_SIZE as i64 + 5).collect::<Vec<_>>()
    );
    drop(runtime);
    std::fs::remove_dir_all(fixture).unwrap();
}

#[tokio::test]
async fn failed_send_attempts_all_current_enqueues_and_counts_failure_before_recovery() {
    let mut runtime = runtime();
    runtime.consecutive_send_failures = DEGRADE_AFTER_SEND_FAILURES - 1;
    runtime.buffer_enqueue_failure_at = Some(1);
    let err = runtime
        .flush_event_batch(vec![event(1), event(2), event(3)])
        .await
        .unwrap_err();
    assert!(err.to_string().contains("1 telemetry enqueues failed"));
    assert_eq!(
        runtime.consecutive_send_failures,
        DEGRADE_AFTER_SEND_FAILURES
    );
    assert!(matches!(runtime.runtime_mode, AgentMode::Degraded));
    let retained = runtime.buffer.drain_batch(10).unwrap();
    assert_eq!(
        retained
            .iter()
            .map(|e| e.created_at_unix)
            .collect::<Vec<_>>(),
        vec![1, 3]
    );

    // Overflow failure must not drop later overflow or the in-flight batch.
    runtime.buffer_enqueue_failure_at = Some(EVENT_BATCH_SIZE + 1);
    assert!(runtime
        .flush_event_batch((0..EVENT_BATCH_SIZE + 3).map(|i| event(i as i64)).collect())
        .await
        .is_err());
    assert_eq!(runtime.buffer.pending_count(), EVENT_BATCH_SIZE + 2);
    assert_eq!(
        runtime.consecutive_send_failures,
        DEGRADE_AFTER_SEND_FAILURES + 1
    );
}

#[tokio::test]
async fn tick_error_recovery_attempts_all_enqueues_and_preserves_original_error() {
    let mut runtime = runtime();
    runtime.tick_telemetry = Some(vec![event(1), event(2), event(3)]);
    runtime.buffer_enqueue_failure_at = Some(1);
    let err = runtime
        .finish_tick_telemetry(Err(anyhow::anyhow!("original tick failure")))
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "original tick failure");
    assert_eq!(runtime.buffer.pending_count(), 2);
    runtime.runtime_mode = AgentMode::Degraded;
    runtime.tick_telemetry = Some(vec![event(4), event(5), event(6)]);
    runtime.buffer_enqueue_failure_at = Some(1);
    let err = runtime.finish_tick_telemetry(Ok(())).await.unwrap_err();
    assert!(err.to_string().contains("1 telemetry enqueues failed"));
    assert_eq!(runtime.buffer.pending_count(), 4);
}

#[tokio::test]
async fn drain_stops_at_half_response_capacity_without_dropping_actions() {
    let mut runtime = runtime();
    let now = 1_700_000_000;
    prepare_tick(&mut runtime, now);
    runtime.runtime_mode = AgentMode::Degraded;
    runtime.response_execution_remaining = 0;
    runtime.response_action_dedupe_window_secs = 0;
    runtime
        .playbook_engine
        .load_from_policy(&serde_json::json!({
            "response_playbooks": [{"name":"capture every evaluation", "enabled":true, "priority":1,
                "conditions":{"require_signals":[]}, "actions":[{"action":"capture"}]}]
        }));
    queue_event(&mut runtime);
    runtime.evaluate_tick(now).unwrap();
    runtime.metrics.telemetry_event_txn_total = 0;
    for _ in 0..300 {
        queue_event(&mut runtime);
    }
    // Renew only the time budget: a slow test host must still reach the capacity
    // guard, rather than passing just because one 40ms window expired.
    for _ in 0..300 {
        runtime
            .run_additional_telemetry_evaluations(now, std::time::Instant::now())
            .await
            .unwrap();
        if runtime.pending_response_actions.len() >= RESPONSE_QUEUE_CAPACITY / 2 {
            break;
        }
    }
    assert_eq!(
        runtime.pending_response_actions.len(),
        RESPONSE_QUEUE_CAPACITY / 2
    );
    assert_eq!(
        runtime.metrics.telemetry_event_txn_total as usize,
        RESPONSE_QUEUE_CAPACITY / 2
    );
    assert_eq!(
        runtime.raw_event_backlog.len(),
        300 - RESPONSE_QUEUE_CAPACITY / 2
    );
    runtime
        .run_additional_telemetry_evaluations(now, std::time::Instant::now())
        .await
        .unwrap();
    assert_eq!(
        runtime.metrics.telemetry_event_txn_total as usize,
        RESPONSE_QUEUE_CAPACITY / 2
    );
}

#[tokio::test]
async fn response_budget_is_shared_by_all_evaluations_in_a_tick() {
    let mut runtime = runtime();
    runtime.telemetry_send_success = true;
    let now = 1_700_000_000;
    runtime.last_heartbeat_attempt_unix = Some(now);
    runtime.last_compliance_attempt_unix = Some(now);
    runtime.last_inventory_attempt_unix = Some(now);
    runtime.last_baseline_save_unix = Some(now);
    runtime.last_baseline_upload_unix = Some(now);
    runtime.last_fleet_baseline_fetch_unix = Some(now);
    runtime.last_memory_scan_unix = Some(now);
    runtime.last_ioc_signal_upload_unix = Some(now);
    runtime.last_campaign_fetch_unix = Some(now);
    runtime.last_kernel_integrity_scan_unix = Some(now);
    runtime.last_command_fetch_attempt_unix = Some(now);
    runtime.last_policy_fetch_unix = Some(now);
    runtime.last_threat_intel_refresh_unix = Some(now);
    runtime.response_action_dedupe_window_secs = 0;
    runtime
        .playbook_engine
        .load_from_policy(&serde_json::json!({
            "response_playbooks": [{"name":"capture every evaluation", "enabled":true, "priority":1,
                "conditions":{"require_signals":[]}, "actions":[{"action":"capture"}]}]
        }));
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 424242,
        uid: 0,
        ts_ns: 1,
        payload: "path=/usr/bin/true;cmdline=true;ppid=1;cgroup_id=0;comm=true;parent_comm=init"
            .into(),
    };
    runtime.raw_event_backlog.push_back(raw.clone());
    runtime.evaluate_tick(now).expect("warm compliance");
    runtime.metrics.telemetry_event_txn_total = 0;
    for i in 0..12 {
        runtime
            .raw_event_backlog
            .push_back(platform_linux::RawEvent {
                pid: 424242 + i,
                ..raw.clone()
            });
    }
    runtime.tick(now).await.expect("tick");
    let evaluated = runtime.metrics.telemetry_event_txn_total as usize;
    assert!(evaluated > RESPONSE_EXECUTION_BUDGET_PER_TICK);
    assert_eq!(
        runtime.metrics.last_response_execute_count,
        RESPONSE_EXECUTION_BUDGET_PER_TICK
    );
    assert_eq!(
        runtime.pending_response_actions.len(),
        evaluated - RESPONSE_EXECUTION_BUDGET_PER_TICK
    );
    runtime.tick(now).await.expect("next tick");
    assert_eq!(
        runtime.metrics.last_response_execute_count,
        RESPONSE_EXECUTION_BUDGET_PER_TICK
    );
}

#[tokio::test]
async fn fresh_compliance_alert_drains_remaining_old_rows_before_scheduling() {
    let mut runtime = runtime();
    let now = 1_700_000_000;
    prepare_tick(&mut runtime, now);
    runtime.last_compliance_result = Some(
        serde_json::from_value(serde_json::json!({
            "status": "non_compliant", "detail": "fixture", "checks": [{
                "check_id": "fresh-reviewfix", "check_type": "fixture",
                "status": "non_compliant", "detail": "fresh alert"
            }]
        }))
        .unwrap(),
    );
    runtime.telemetry_send_success = true;
    for i in 0..EVENT_BATCH_SIZE + 1 {
        runtime.buffer.enqueue(event(i as i64)).unwrap();
    }
    queue_event(&mut runtime);
    runtime.tick(now).await.unwrap();
    assert_eq!(
        runtime.telemetry_send_batches,
        vec![EVENT_BATCH_SIZE + 1, 2]
    );
    assert_eq!(runtime.buffer.pending_count(), 0);
    assert_eq!(runtime.last_policy_fetch_unix, Some(now));
    assert_eq!(runtime.last_threat_intel_refresh_unix, Some(now));
}

#[tokio::test]
async fn drain_stops_at_half_report_capacity_without_evicting_reports() {
    let mut runtime = runtime();
    let now = 1_700_000_000;
    prepare_tick(&mut runtime, now);
    runtime.runtime_mode = AgentMode::Degraded;
    runtime
        .playbook_engine
        .load_from_policy(&serde_json::json!({
            "response_playbooks": [{"name":"report each evaluation", "enabled":true, "priority":1,
                "conditions":{"require_signals":[]}, "actions":[{"action":"alert"}]}]
        }));
    queue_event(&mut runtime);
    let evaluation = runtime.evaluate_tick(now).unwrap().unwrap();
    runtime
        .run_connected_response_stage(now, Some(&evaluation))
        .await;
    let mut report = runtime.pending_response_reports.front().unwrap().clone();
    report.envelope.action_type = "old-report-sentinel".into();
    runtime.pending_response_reports.clear();
    for _ in 0..RESPONSE_REPORT_QUEUE_CAPACITY / 2 - 1 {
        runtime.pending_response_reports.push_back(report.clone());
    }
    runtime.metrics.telemetry_event_txn_total = 0;
    for _ in 0..300 {
        queue_event(&mut runtime);
    }
    for _ in 0..300 {
        runtime
            .run_additional_telemetry_evaluations(now, std::time::Instant::now())
            .await
            .unwrap();
    }
    assert_eq!(
        runtime.pending_response_reports.len(),
        RESPONSE_REPORT_QUEUE_CAPACITY / 2
    );
    assert_eq!(runtime.metrics.telemetry_event_txn_total, 1);
    assert_eq!(runtime.raw_event_backlog.len(), 299);
    assert_eq!(
        runtime
            .pending_response_reports
            .front()
            .unwrap()
            .envelope
            .action_type,
        report.envelope.action_type
    );
}

#[tokio::test]
async fn drain_stops_at_half_ioc_capacity() {
    let mut runtime = runtime();
    let now = 1_700_000_000;
    for i in 0..IOC_SIGNAL_BUFFER_CAP / 2 {
        runtime.buffer_ioc_signal(format!("ioc-{i}"), "domain".into(), "high", now);
    }
    queue_event(&mut runtime);
    runtime
        .run_additional_telemetry_evaluations(now, std::time::Instant::now())
        .await
        .unwrap();
    assert_eq!(runtime.raw_event_backlog.len(), 1);
    assert_eq!(runtime.ioc_signal_buffer.len(), IOC_SIGNAL_BUFFER_CAP / 2);
    assert_eq!(runtime.ioc_signal_buffer[0].ioc_value, "ioc-0");
}

#[tokio::test]
async fn connected_failed_send_preserves_oldest_buffered_sentinels() {
    let mut runtime = runtime();
    let now = 1_700_000_000;
    prepare_tick(&mut runtime, now);
    runtime.consecutive_send_failures = 1;
    runtime.client.set_online(true);

    // Size the cap for ten real evaluations, then fill 90% with sentinels.
    queue_event(&mut runtime);
    let sample = runtime.evaluate_tick(now).unwrap().unwrap().event_envelope;
    let event_bytes = grpc_client::estimate_event_size(&sample);
    let cap = event_bytes * 10;
    runtime.config.offline_buffer_cap_bytes = cap;
    runtime.buffer = grpc_client::EventBuffer::memory(cap);
    for timestamp in 0..9 {
        let mut sentinel = sample.clone();
        sentinel.created_at_unix = timestamp;
        runtime.buffer.enqueue(sentinel).unwrap();
    }
    assert_eq!(runtime.buffer.pending_bytes(), cap * 90 / 100);
    for _ in 0..100 {
        queue_event(&mut runtime);
    }

    // The first evaluation fits; even one additional envelope evicts a sentinel.
    // Real refused sends must not consume the drain's test budget.
    runtime.telemetry_eval_budget_override = Some(std::time::Duration::from_secs(3600));
    runtime.tick(now).await.unwrap();

    let retained = runtime.buffer.drain_batch(100).unwrap();
    assert_eq!(
        retained
            .iter()
            .take(9)
            .map(|e| e.created_at_unix)
            .collect::<Vec<_>>(),
        (0..9).collect::<Vec<_>>(),
        "additional degraded evaluations must not evict the oldest telemetry"
    );
    assert!(
        !runtime.raw_event_backlog.is_empty(),
        "drain must stop early"
    );
}

#[test]
fn oversized_compliance_policy_keeps_dedupe_across_evaluations() {
    for count in [
        COMPLIANCE_ALERT_STATE_LIMIT * 2 + 10,
        COMPLIANCE_ALERT_STATE_LIMIT + 10,
    ] {
        let mut runtime = runtime();
        let result = ComplianceResult {
            status: "non_compliant".into(),
            detail: String::new(),
            checks: (0..count)
                .map(|i| {
                    serde_json::from_value(serde_json::json!({
                        "check_id": format!("check-{i}"), "check_type": "package",
                        "status": "non_compliant", "detail": "missing"
                    }))
                    .unwrap()
                })
                .collect(),
        };
        let mut ids = std::collections::HashSet::new();
        for _ in 0..4 {
            let alerts = runtime.collect_compliance_alerts(&result, 123);
            assert!(alerts.len() <= COMPLIANCE_ALERT_STATE_LIMIT);
            for alert in alerts {
                let payload: serde_json::Value = serde_json::from_str(&alert.payload_json).unwrap();
                assert!(
                    ids.insert(payload["mdm"]["check_id"].as_str().unwrap().to_owned()),
                    "persistent failures must be emitted exactly once, not regenerated"
                );
            }
        }
        assert_eq!(ids.len(), count, "overflow must be deferred, never lost");
    }
}

#[tokio::test]
async fn telemetry_queue_push_does_not_change_send_work_metric() {
    let mut runtime = runtime();
    prepare_tick(&mut runtime, 123);
    queue_event(&mut runtime);
    let evaluation = runtime.evaluate_tick(123).unwrap().unwrap();
    runtime.tick_telemetry = Some(Vec::new());
    runtime.metrics.last_send_event_batch_micros = u64::MAX;
    runtime
        .queue_connected_telemetry(Some(&evaluation))
        .await
        .unwrap();
    assert_eq!(
        runtime.metrics.last_send_event_batch_micros,
        u64::MAX,
        "queueing is not transport work"
    );
}

#[tokio::test]
async fn connected_failed_send_drain_stage_preserves_sentinels() {
    let mut runtime = runtime();
    let now = 1_700_000_000;
    prepare_tick(&mut runtime, now);
    runtime.consecutive_send_failures = 1;
    runtime.client.set_online(true);

    // Size the cap for twenty real evaluations, then fill 85% with sentinels.
    queue_event(&mut runtime);
    let sample = runtime.evaluate_tick(now).unwrap().unwrap().event_envelope;
    let event_bytes = grpc_client::estimate_event_size(&sample);
    let cap = event_bytes * 20;
    runtime.config.offline_buffer_cap_bytes = cap;
    runtime.buffer = grpc_client::EventBuffer::memory(cap);
    for timestamp in 0..17 {
        let mut sentinel = sample.clone();
        sentinel.created_at_unix = timestamp;
        runtime.buffer.enqueue(sentinel).unwrap();
    }
    assert_eq!(runtime.buffer.pending_bytes(), cap * 85 / 100);
    for _ in 0..100 {
        queue_event(&mut runtime);
    }

    // Isolate the additional-evaluation phase from unrelated control-plane latency.
    runtime.tick_telemetry = Some(Vec::new());
    runtime
        .run_additional_telemetry_evaluations(now, std::time::Instant::now())
        .await
        .unwrap();
    let batch = runtime.tick_telemetry.take().unwrap();
    runtime.flush_event_batch(batch).await.unwrap();

    let retained = runtime.buffer.drain_batch(100).unwrap();
    assert_eq!(
        retained
            .iter()
            .take(17)
            .map(|e| e.created_at_unix)
            .collect::<Vec<_>>(),
        (0..17).collect::<Vec<_>>(),
        "additional degraded evaluations must not evict the oldest telemetry"
    );
    assert!(
        !runtime.raw_event_backlog.is_empty(),
        "drain must stop early"
    );
}

#[test]
fn compliance_policy_transition_prunes_full_old_context() {
    let mut runtime = runtime();
    let result = ComplianceResult {
        status: "non_compliant".into(),
        detail: String::new(),
        checks: (0..COMPLIANCE_ALERT_STATE_LIMIT)
            .map(|i| {
                serde_json::from_value(serde_json::json!({
                    "check_id": format!("check-{i}"), "check_type": "package",
                    "status": "non_compliant", "detail": "missing"
                }))
                .unwrap()
            })
            .collect(),
    };
    assert_eq!(
        runtime.collect_compliance_alerts(&result, 123).len(),
        COMPLIANCE_ALERT_STATE_LIMIT
    );
    runtime.compliance_policy_id = "replacement".into();
    runtime.compliance_policy_version = "replacement-version".into();
    runtime.compliance_policy_hash = "replacement-hash".into();
    assert_eq!(
        runtime.collect_compliance_alerts(&result, 123).len(),
        COMPLIANCE_ALERT_STATE_LIMIT,
        "a full previous policy must not suppress new policy failures"
    );
    assert_eq!(
        runtime.compliance_alert_state.len(),
        COMPLIANCE_ALERT_STATE_LIMIT,
        "obsolete policy dedupe entries must be pruned"
    );
    assert!(runtime.collect_compliance_alerts(&result, 123).is_empty());
}
