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
async fn first_send_outcome_controls_same_tick_maintenance() {
    let mut runtime = runtime();
    let now = 1_700_000_000;
    prepare_tick(&mut runtime, now);
    queue_event(&mut runtime);
    runtime.tick(now).await.unwrap();
    assert_eq!(runtime.consecutive_send_failures, 1);
    assert_eq!(runtime.buffer.pending_count(), 1);
    assert_eq!(runtime.last_policy_fetch_unix, None);
    assert_eq!(runtime.last_threat_intel_refresh_unix, None);
}

#[tokio::test]
async fn successful_first_send_recovers_same_tick_maintenance() {
    let mut runtime = runtime();
    let now = 1_700_000_000;
    prepare_tick(&mut runtime, now);
    runtime.consecutive_send_failures = 1;
    runtime.buffer.enqueue(event(1)).unwrap();
    runtime.telemetry_send_success = true;
    queue_event(&mut runtime);
    runtime.tick(now + 1).await.unwrap();
    assert_eq!(runtime.consecutive_send_failures, 0);
    assert_eq!(runtime.buffer.pending_count(), 0);
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

#[tokio::test]
async fn sqlite_failed_send_requeues_old_batch_before_new_tick_overflow() {
    let mut runtime = runtime();
    let path = std::env::temp_dir().join(format!(
        "eguard-reviewfix-fifo-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    runtime.buffer =
        grpc_client::EventBuffer::sqlite(path.to_str().unwrap(), 16 * 1024 * 1024).unwrap();
    for i in 0..EVENT_BATCH_SIZE {
        runtime.buffer.enqueue(event(i as i64)).unwrap();
    }
    runtime
        .flush_event_batch(
            (EVENT_BATCH_SIZE..EVENT_BATCH_SIZE + 3)
                .map(|i| event(i as i64))
                .collect(),
        )
        .await
        .unwrap();
    assert_eq!(runtime.consecutive_send_failures, 1);
    let events = runtime.buffer.drain_batch(EVENT_BATCH_SIZE + 3).unwrap();
    assert_eq!(
        events.iter().map(|e| e.created_at_unix).collect::<Vec<_>>(),
        (0..EVENT_BATCH_SIZE as i64 + 3).collect::<Vec<_>>()
    );
    drop(runtime);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn failed_send_attempts_all_requeues_and_counts_failure_before_recovery() {
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
