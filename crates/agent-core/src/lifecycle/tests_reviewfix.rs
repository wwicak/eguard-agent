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

#[tokio::test]
async fn event_bearing_control_plane_keeps_maintenance_due() {
    let mut runtime = runtime();
    let now = 1_700_000_000;
    runtime
        .raw_event_backlog
        .push_back(platform_linux::RawEvent {
            event_type: platform_linux::EventType::ProcessExec,
            pid: 424242,
            uid: 0,
            ts_ns: 1,
            payload:
                "path=/usr/bin/true;cmdline=true;ppid=1;cgroup_id=0;comm=true;parent_comm=init"
                    .into(),
        });
    let evaluation = runtime
        .evaluate_tick(now)
        .expect("evaluate event")
        .expect("one evaluated event");
    runtime.tick_telemetry = Some(vec![evaluation.event_envelope.clone()]);
    runtime.buffer_enqueue_failure_at = Some(0);
    runtime
        .run_connected_control_plane_stage(now, Some(&evaluation))
        .await
        .unwrap();
    assert_eq!(runtime.buffer.pending_count(), 0);
    assert_eq!(runtime.tick_telemetry.as_ref().unwrap().len(), 1);
    assert_eq!(runtime.last_policy_fetch_unix, Some(now));
    assert_eq!(runtime.last_threat_intel_refresh_unix, Some(now));
    assert_eq!(
        runtime.buffer_enqueue_failure_at,
        Some(0),
        "ordinary control-plane work must not spool"
    );
}

#[tokio::test]
async fn terminal_commands_spool_before_side_effect_and_fail_closed() {
    for (kind, payload) in [
        ("restart_device", "{}"),
        ("update", "{}"),
        ("uninstall", "{}"),
        (
            "config_change",
            r#"{"config_json":{"config_type":"agent_control","restart_service":true}}"#,
        ),
    ] {
        let mut runtime = runtime();
        runtime.tick_telemetry = Some(vec![event(1), event(2)]);
        runtime.terminal_command_hook = Some(|runtime| {
            assert!(runtime.tick_telemetry.as_ref().unwrap().is_empty());
            let events = runtime.buffer.drain_batch(10).unwrap();
            assert_eq!(
                events.iter().map(|e| e.created_at_unix).collect::<Vec<_>>(),
                vec![1, 2]
            );
            runtime.metrics.last_control_plane_execute_count = 99;
        });
        let command = grpc_client::CommandEnvelope {
            command_id: format!("terminal-{kind}"),
            command_type: kind.into(),
            payload_json: payload.into(),
        };
        runtime.handle_command(command.clone(), 1_700_000_000).await;
        assert_eq!(
            runtime.metrics.last_control_plane_execute_count, 99,
            "{kind}"
        );
        runtime.metrics.last_control_plane_execute_count = 0;
        runtime.tick_telemetry = Some(vec![event(3), event(4), event(5)]);
        runtime.buffer_enqueue_failure_at = Some(1);
        let exec = runtime.handle_command(command, 1_700_000_001).await;
        assert_eq!(exec.status, "failed", "{kind}");
        assert!(exec.detail.contains("telemetry spool failed"));
        assert_eq!(runtime.metrics.last_control_plane_execute_count, 0);
        assert_eq!(runtime.buffer.pending_count(), 2);
    }
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
async fn response_budget_is_shared_by_all_evaluations_in_a_tick() {
    let mut runtime = runtime();
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
