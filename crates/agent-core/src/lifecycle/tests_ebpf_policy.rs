use super::*;
use crate::config::{AgentConfig, AgentMode};
use response::plan_action;
use std::path::PathBuf;
use std::sync::Mutex;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn script_lock() -> &'static Mutex<()> {
    super::shared_env_var_lock()
}

fn write_executable(path: &std::path::Path, body: &str) {
    std::fs::write(path, body).expect("write script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path).expect("stat script").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).expect("chmod script");
    }
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

#[test]
// AC-EBP-035
fn tick_pipeline_produces_detection_compliance_envelope_and_baseline_learning() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();
    cfg.self_protection_integrity_check_interval_secs = 0;

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    let before_samples: u64 = runtime
        .baseline_store
        .baselines
        .values()
        .map(|profile| profile.sample_count)
        .sum();

    let now = 1_700_000_000i64;
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: std::process::id(),
        uid: 0,
        ts_ns: (now as u64) * 1_000_000_000,
        payload: "cmdline=/usr/bin/bash -lc whoami".to_string(),
    };
    let enriched = platform_linux::enrich_event_with_cache(raw, &mut runtime.enrichment_cache);
    let detection_event = to_detection_event(&enriched, now);
    runtime.observe_baseline(&detection_event, now);

    let detection_outcome = runtime
        .detection_state
        .process_event(&detection_event)
        .expect("detect event");
    let confidence = detection_outcome.confidence;
    let action = plan_action(confidence, &runtime.effective_response_config());
    let compliance = runtime.evaluate_compliance();
    let event_envelope = runtime.build_event_envelope(
        &enriched,
        &detection_event,
        &detection_outcome,
        confidence,
        now,
    );

    let after_samples: u64 = runtime
        .baseline_store
        .baselines
        .values()
        .map(|profile| profile.sample_count)
        .sum();

    assert_eq!(after_samples, before_samples.saturating_add(1));
    assert_eq!(detection_event.ts_unix, now);
    assert_eq!(event_envelope.event_type, "process_exec");
    assert_eq!(event_envelope.created_at_unix, now);
    let payload: serde_json::Value =
        serde_json::from_str(&event_envelope.payload_json).expect("parse payload");
    assert!(payload.get("event").is_some());
    assert!(payload.get("detection").is_some());
    assert!(!compliance.status.trim().is_empty());
    assert!(matches!(
        action,
        response::PlannedAction::AlertOnly
            | response::PlannedAction::CaptureScript
            | response::PlannedAction::KillOnly
            | response::PlannedAction::QuarantineOnly
            | response::PlannedAction::KillAndQuarantine
            | response::PlannedAction::None
    ));
}

#[test]
// AC-DET-223
fn module_load_payload_maps_to_detection_file_path() {
    let now = 1_700_000_100i64;
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ModuleLoad,
        pid: std::process::id(),
        uid: 0,
        ts_ns: (now as u64) * 1_000_000_000,
        payload: "module=fake_rootkit".to_string(),
    };

    let mut cache = platform_linux::EnrichmentCache::default();
    let enriched = platform_linux::enrich_event_with_cache(raw, &mut cache);
    let detection_event = to_detection_event(&enriched, now);

    assert_eq!(detection_event.event_class, EventClass::ModuleLoad);
    assert_eq!(detection_event.file_path.as_deref(), Some("fake_rootkit"));
}

#[tokio::test]
// AC-EBP-042
async fn send_event_batch_attempts_delivery_on_each_call_without_flush_gates() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();
    cfg.self_protection_integrity_check_interval_secs = 0;

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.client.set_online(false);
    runtime.tick_count = 10_000;
    runtime.runtime_mode = AgentMode::Active;

    runtime
        .send_event_batch(EventEnvelope {
            agent_id: "agent-test".to_string(),
            event_type: "process_exec".to_string(),
            severity: String::new(),
            rule_name: String::new(),
            payload_json: "{\"tick\":1}".to_string(),
            created_at_unix: 1_700_000_001,
        })
        .await
        .expect("send batch 1");
    assert_eq!(runtime.buffer.pending_count(), 1);
    assert_eq!(runtime.consecutive_send_failures, 1);
    assert!(matches!(runtime.runtime_mode, AgentMode::Active));

    runtime
        .send_event_batch(EventEnvelope {
            agent_id: "agent-test".to_string(),
            event_type: "process_exec".to_string(),
            severity: String::new(),
            rule_name: String::new(),
            payload_json: "{\"tick\":2}".to_string(),
            created_at_unix: 1_700_000_002,
        })
        .await
        .expect("send batch 2");
    assert_eq!(runtime.buffer.pending_count(), 2);
    assert_eq!(runtime.consecutive_send_failures, 2);
    assert!(matches!(runtime.runtime_mode, AgentMode::Active));

    runtime
        .send_event_batch(EventEnvelope {
            agent_id: "agent-test".to_string(),
            event_type: "process_exec".to_string(),
            severity: String::new(),
            rule_name: String::new(),
            payload_json: "{\"tick\":3}".to_string(),
            created_at_unix: 1_700_000_003,
        })
        .await
        .expect("send batch 3");
    assert_eq!(runtime.buffer.pending_count(), 3);
    assert_eq!(runtime.consecutive_send_failures, 3);
    assert!(matches!(runtime.runtime_mode, AgentMode::Degraded));
}

#[test]
// AC-EBP-080 AC-EBP-081 AC-EBP-082 AC-EBP-083 AC-EBP-084 AC-EBP-086 AC-EBP-087 AC-EBP-088 AC-EBP-090 AC-RES-001 AC-RES-002 AC-RES-003 AC-RES-004 AC-RES-005 AC-RES-006 AC-RES-007
fn ebpf_resource_budget_harness_executes_and_writes_limits_metrics_and_command_manifest() {
    let _guard = script_lock().lock().unwrap_or_else(|e| e.into_inner());
    let root = workspace_root();

    let temp = std::env::temp_dir().join(format!(
        "eguard-ebpf-budget-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let bin_dir = temp.join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create bin dir");
    let command_log = temp.join("command.log");

    write_executable(
        &bin_dir.join("cargo"),
        r#"#!/usr/bin/env bash
echo "cargo $*" >> "${EGUARD_TEST_COMMAND_LOG}"
exit 0
"#,
    );

    let agent_bin = root.join("target/release/agent-core");
    let previous_agent_bin = std::fs::read(&agent_bin).ok();
    if let Some(parent) = agent_bin.parent() {
        std::fs::create_dir_all(parent).expect("create target/release");
    }
    let fake_bin = vec![0u8; 1_572_864];
    std::fs::write(&agent_bin, &fake_bin).expect("seed fake release binary");

    let path_env = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let status = std::process::Command::new("bash")
        .arg(root.join("scripts/run_ebpf_resource_budget_ci.sh"))
        .current_dir(&root)
        .env("PATH", path_env)
        .env("EGUARD_TEST_COMMAND_LOG", &command_log)
        .status()
        .expect("run resource budget harness");
    assert!(status.success());

    let metrics_raw =
        std::fs::read_to_string(root.join("artifacts/ebpf-resource-budget/metrics.json"))
            .expect("read metrics");
    let metrics: serde_json::Value = serde_json::from_str(&metrics_raw).expect("parse metrics");
    assert_eq!(metrics["suite"], "ebpf_resource_budget");
    assert_eq!(metrics["limits"]["idle_cpu_pct"], 0.05);
    assert_eq!(metrics["limits"]["active_cpu_pct"], 0.5);
    assert_eq!(metrics["limits"]["peak_cpu_pct"], 3);
    assert_eq!(metrics["limits"]["memory_rss_mb"], 25);
    assert!(metrics["limits"]["binary_size_mb"].is_null());
    assert_eq!(metrics["limits"]["binary_size_enforced"], false);
    assert_eq!(
        metrics["measured"]["binary_size_bytes"].as_u64(),
        Some(fake_bin.len() as u64)
    );
    assert_eq!(
        metrics["measurement_commands"]["idle_cpu"],
        "pidstat -p $(pidof agent-core) 60"
    );
    assert_eq!(
        metrics["measurement_commands"]["memory_rss"],
        "ps -o rss= -p $(pidof agent-core)"
    );
    assert_eq!(
        metrics["measurement_commands"]["detection_latency"],
        "cargo test -p detection tests::detection_latency_p99_stays_within_budget_for_reference_workload -- --exact"
    );
    assert_eq!(
        metrics["measurement_commands"]["lsm_block_latency"],
        "cargo test -p platform-linux ebpf::tests::parses_structured_lsm_block_payload -- --exact"
    );
    assert!(
        metrics["measured"]["detection_latency_probe_wall_ms"]
            .as_u64()
            .is_some(),
        "detection latency probe wall time must be emitted"
    );
    assert!(
        metrics["measured"]["lsm_block_probe_wall_ms"]
            .as_u64()
            .is_some(),
        "lsm block probe wall time must be emitted"
    );
    assert_eq!(
        metrics["probe_status"]["detection_latency"],
        serde_json::Value::from(0)
    );
    assert_eq!(
        metrics["probe_status"]["lsm_block_latency"],
        serde_json::Value::from(0)
    );

    let command_log_raw = std::fs::read_to_string(&command_log).expect("read command log");
    let command_log_lines = non_comment_lines(&command_log_raw);
    assert!(has_line(
        &command_log_lines,
        "cargo build --release -p agent-core"
    ));

    if let Some(bytes) = previous_agent_bin {
        std::fs::write(&agent_bin, bytes).expect("restore previous release binary");
    } else {
        let _ = std::fs::remove_file(&agent_bin);
    }

    let _ = std::fs::remove_dir_all(root.join("artifacts/ebpf-resource-budget"));
    let _ = std::fs::remove_dir_all(temp);
}

#[test]
// AC-EBP-080 AC-EBP-081 AC-EBP-082 AC-EBP-083 AC-EBP-084 AC-EBP-086 AC-EBP-087 AC-EBP-088 AC-EBP-090 AC-RES-001 AC-RES-003 AC-RES-004 AC-RES-005 AC-RES-006 AC-RES-007
fn ebpf_resource_budget_workflow_runs_harness_and_publishes_artifacts() {
    let workflow = std::fs::read_to_string(
        workspace_root().join(".github/workflows/ebpf-resource-budget.yml"),
    )
    .expect("read eBPF budget workflow");
    let workflow_lines = non_comment_lines(&workflow);

    for required in [
        "name: ebpf-resource-budget",
        "run: ./scripts/run_ebpf_resource_budget_ci.sh",
        "uses: actions/upload-artifact@v4",
        "name: ebpf-resource-budget",
        "path: artifacts/ebpf-resource-budget",
    ] {
        assert!(
            has_line(&workflow_lines, required),
            "missing workflow contract: {required}"
        );
    }
}

#[test]
// AC-EBP-055 AC-RES-021
fn sampling_stride_scales_with_backlog_and_drop_backpressure() {
    assert_eq!(compute_sampling_stride(0, 0), 1);
    assert_eq!(compute_sampling_stride(1_500, 0), 2);
    assert_eq!(compute_sampling_stride(9_000, 0), 8);
    assert_eq!(compute_sampling_stride(1_500, 1), 2);
    assert_eq!(compute_sampling_stride(5_000, 7), 4);
    assert_eq!(compute_sampling_stride(9_000, 3), 8);
}

#[test]
// AC-EBP-035 AC-OPT-005
fn evaluate_tick_returns_none_when_no_ebpf_events_are_available() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.ebpf_engine = platform_linux::EbpfEngine::disabled();

    let now = 1_700_000_000i64;
    let evaluation = runtime.evaluate_tick(now).expect("evaluate tick");
    assert!(evaluation.is_none());
}

#[test]
// AC-11
fn evaluate_tick_drains_polled_replay_events_across_multiple_ticks() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let replay_path = std::env::temp_dir().join(format!(
        "eguard-agent-replay-batch-{}.ndjson",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let replay = [
        r#"{"event_type":"process_exec","pid":4101,"uid":0,"ts_ns":1700000000000000000,"comm":"bash","path":"/usr/bin/bash","cmdline":"bash -lc echo 1"}"#,
        r#"{"event_type":"process_exec","pid":4102,"uid":0,"ts_ns":1700000001000000000,"comm":"bash","path":"/usr/bin/bash","cmdline":"bash -lc echo 2"}"#,
        r#"{"event_type":"process_exec","pid":4103,"uid":0,"ts_ns":1700000002000000000,"comm":"bash","path":"/usr/bin/bash","cmdline":"bash -lc echo 3"}"#,
    ]
    .join("\n");
    std::fs::write(&replay_path, replay).expect("write replay file");

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.ebpf_engine =
        platform_linux::EbpfEngine::from_replay(&replay_path).expect("replay backend");

    let now = 1_700_000_000i64;
    let first = runtime.evaluate_tick(now).expect("evaluate tick 1");
    let second = runtime.evaluate_tick(now + 1).expect("evaluate tick 2");
    let third = runtime.evaluate_tick(now + 2).expect("evaluate tick 3");
    let fourth = runtime.evaluate_tick(now + 3).expect("evaluate tick 4");

    assert!(first.is_some());
    assert!(second.is_some());
    assert!(third.is_some());
    assert!(fourth.is_none());

    let _ = std::fs::remove_file(replay_path);
}

#[test]
fn file_event_burst_coalescing_drops_repeated_writes_within_short_window() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let replay_path = std::env::temp_dir().join(format!(
        "eguard-agent-replay-coalesce-{}.ndjson",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let file_path = "/tmp/eguard-coalesce-target.bin";
    let replay = [
        format!(r#"{{"event_type":"file_write","pid":9101,"uid":0,"ts_ns":1700000000000000000,"file_path":"{}","size":64}}"#, file_path),
        format!(r#"{{"event_type":"file_write","pid":9101,"uid":0,"ts_ns":1700000000000100000,"file_path":"{}","size":64}}"#, file_path),
        format!(r#"{{"event_type":"file_write","pid":9101,"uid":0,"ts_ns":1700000000000200000,"file_path":"{}","size":64}}"#, file_path),
    ]
    .join("\n");
    std::fs::write(&replay_path, replay).expect("write replay file");

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.ebpf_engine =
        platform_linux::EbpfEngine::from_replay(&replay_path).expect("replay backend");
    runtime.file_event_coalesce_window_ns = 5_000_000_000; // 5s

    let first = runtime.evaluate_tick(1_700_000_000).expect("tick 1");
    let second = runtime.evaluate_tick(1_700_000_001).expect("tick 2");
    let third = runtime.evaluate_tick(1_700_000_002).expect("tick 3");

    assert!(first.is_some());
    assert!(second.is_none());
    assert!(third.is_none());

    let snapshot = runtime.observability_snapshot();
    assert!(snapshot.telemetry_coalesced_events_total >= 2);

    let _ = std::fs::remove_file(replay_path);
}

#[test]
fn file_event_burst_coalescing_normalizes_path_case() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let replay_path = std::env::temp_dir().join(format!(
        "eguard-agent-replay-coalesce-case-{}.ndjson",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let replay = [
        r#"{"event_type":"file_write","pid":9301,"uid":0,"ts_ns":1700000000000000000,"file_path":"C:\\TEMP\\CASE.TMP","size":64}"#,
        r#"{"event_type":"file_write","pid":9301,"uid":0,"ts_ns":1700000000000100000,"file_path":"c:\\temp\\case.tmp","size":64}"#,
    ]
    .join("\n");
    std::fs::write(&replay_path, replay).expect("write replay file");

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.ebpf_engine =
        platform_linux::EbpfEngine::from_replay(&replay_path).expect("replay backend");
    runtime.file_event_coalesce_window_ns = 5_000_000_000;

    let first = runtime.evaluate_tick(1_700_000_000).expect("tick 1");
    let second = runtime.evaluate_tick(1_700_000_001).expect("tick 2");

    assert!(first.is_some());
    assert!(second.is_none());
    assert!(
        runtime
            .observability_snapshot()
            .telemetry_coalesced_events_total
            >= 1
    );

    let _ = std::fs::remove_file(replay_path);
}

#[test]
fn strict_budget_mode_skips_expensive_file_hashing_when_backlog_is_high() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let replay_path = std::env::temp_dir().join(format!(
        "eguard-agent-replay-strict-budget-{}.ndjson",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let target_file = std::env::temp_dir().join(format!(
        "eguard-strict-budget-target-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::write(&target_file, b"payload").expect("write target file");

    let replay = format!(
        r#"{{"event_type":"file_write","pid":9201,"uid":0,"ts_ns":1700000005000000000,"file_path":"{}","size":64}}"#,
        target_file.to_string_lossy()
    );
    std::fs::write(&replay_path, replay).expect("write replay file");

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.ebpf_engine =
        platform_linux::EbpfEngine::from_replay(&replay_path).expect("replay backend");
    runtime.strict_budget_pending_threshold = 1;
    runtime
        .buffer
        .enqueue(EventEnvelope {
            agent_id: "agent-backlog".to_string(),
            event_type: "telemetry".to_string(),
            severity: String::new(),
            rule_name: String::new(),
            payload_json: "{}".to_string(),
            created_at_unix: 1,
        })
        .expect("enqueue backlog marker");

    let eval = runtime
        .evaluate_tick(1_700_000_005)
        .expect("evaluate tick")
        .expect("tick should produce event");

    assert!(runtime.strict_budget_mode);
    assert!(eval.detection_event.file_hash.is_none());

    let _ = runtime
        .buffer
        .drain_batch(10)
        .expect("drain backlog marker");
    let _ = runtime
        .evaluate_tick(1_700_000_006)
        .expect("evaluate tick 2");
    let snapshot = runtime.observability_snapshot();
    assert!(!snapshot.strict_budget_mode);
    assert!(snapshot.strict_budget_mode_transition_total >= 2);

    let _ = std::fs::remove_file(replay_path);
    let _ = std::fs::remove_file(target_file);
}

#[tokio::test]
// AC-EBP-042
async fn send_event_batch_failures_rebuffer_events_and_trigger_degraded_mode() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.client.set_online(false);
    runtime.runtime_mode = AgentMode::Active;

    let event = |ts| EventEnvelope {
        agent_id: "agent-test".to_string(),
        event_type: "process_exec".to_string(),
        severity: String::new(),
        rule_name: String::new(),
        payload_json: format!("{{\"ts\":{ts}}}"),
        created_at_unix: ts,
    };

    runtime
        .send_event_batch(event(1))
        .await
        .expect("send attempt 1");
    assert_eq!(runtime.buffer.pending_count(), 1);
    assert_eq!(runtime.consecutive_send_failures, 1);
    assert!(matches!(runtime.runtime_mode, AgentMode::Active));

    runtime
        .send_event_batch(event(2))
        .await
        .expect("send attempt 2");
    assert_eq!(runtime.buffer.pending_count(), 2);
    assert_eq!(runtime.consecutive_send_failures, 2);
    assert!(matches!(runtime.runtime_mode, AgentMode::Active));

    runtime
        .send_event_batch(event(3))
        .await
        .expect("send attempt 3");
    assert_eq!(runtime.buffer.pending_count(), 3);
    assert_eq!(runtime.consecutive_send_failures, 3);
    assert!(matches!(runtime.runtime_mode, AgentMode::Degraded));
}
