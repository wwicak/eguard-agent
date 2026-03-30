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
    let event_txn = EventTxn::from_enriched(&enriched, &detection_event, now);
    let event_envelope = runtime.build_event_envelope(
        &enriched,
        &detection_event,
        &detection_outcome,
        &event_txn,
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
    assert!(payload.get("event_txn").is_some());
    assert_eq!(
        payload["event_txn"]["operation"],
        serde_json::Value::from("process_exec")
    );
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
    assert_eq!(compute_sampling_stride(300, 0), 2);
    assert_eq!(compute_sampling_stride(1_500, 0), 4);
    assert_eq!(compute_sampling_stride(9_000, 0), 8);
    assert_eq!(compute_sampling_stride(1_500, 1), 4);
    assert_eq!(compute_sampling_stride(5_000, 7), 8);
    assert_eq!(compute_sampling_stride(9_000, 3), 8);
}

#[test]
fn additional_telemetry_eval_budget_scales_with_backlog_pressure() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();
    cfg.self_protection_integrity_check_interval_secs = 0;

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 4242,
        uid: 0,
        ts_ns: 1,
        payload: "path=/usr/bin/cmd.exe;cmdline=cmd.exe /c whoami;ppid=1;cgroup_id=0;comm=cmd.exe;parent_comm=powershell.exe".to_string(),
    };

    assert_eq!(runtime.additional_telemetry_eval_budget(), 0);

    runtime.strict_budget_mode = true;
    runtime.raw_event_backlog = std::collections::VecDeque::from(vec![raw.clone(); 1024]);
    assert_eq!(runtime.additional_telemetry_eval_budget(), 1);

    runtime.raw_event_backlog = std::collections::VecDeque::from(vec![raw.clone(); 2048]);
    assert_eq!(runtime.additional_telemetry_eval_budget(), 3);

    runtime.raw_event_backlog = std::collections::VecDeque::from(vec![raw; 4096]);
    assert_eq!(
        runtime.additional_telemetry_eval_budget(),
        AgentRuntime::MAX_EXTRA_TELEMETRY_EVALS_PER_TICK
    );
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
fn ingest_polled_events_caps_per_poll_burst_and_backlog_growth() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.raw_event_ingest_cap = 4;
    runtime.raw_event_backlog_cap = 4;

    let burst = (0..12)
        .map(|idx| platform_linux::RawEvent {
            event_type: platform_linux::EventType::ProcessExec,
            pid: 5100 + idx,
            uid: 0,
            ts_ns: 1_700_000_000_000_000_000 + idx as u64,
            payload: format!(
                "path=/usr/bin/bash;comm=bash;cmdline=bash -lc echo {};ppid=1",
                idx
            ),
        })
        .collect::<Vec<_>>();

    let retained = runtime.limit_raw_event_ingress(burst);
    runtime.enqueue_raw_events_with_priority(retained);
    runtime.enforce_raw_event_backlog_cap();

    assert!(runtime.raw_event_backlog.len() <= 4);
    assert!(
        runtime
            .observability_snapshot()
            .telemetry_raw_backlog_dropped_total
            >= 8
    );
}

#[test]
fn sensitive_windows_credential_path_exec_survives_process_burst_ingress_cap() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.raw_event_ingest_cap = 4;

    let mut burst = (0..6)
        .map(|idx| platform_linux::RawEvent {
            event_type: platform_linux::EventType::ProcessExec,
            pid: 6100 + idx,
            uid: 0,
            ts_ns: 1_700_000_000_000_000_000 + idx as u64,
            payload: format!(
                "path=C:\\Windows\\system32\\cmd.exe;comm=cmd.exe;cmdline=cmd.exe /c echo benign-{};ppid=1",
                idx
            ),
        })
        .collect::<Vec<_>>();
    burst.push(platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 6200,
        uid: 0,
        ts_ns: 1_700_000_000_100_000_000,
        payload: "path=C:\\Windows\\system32\\cmd.exe;comm=cmd.exe;cmdline=cmd.exe /c dir %APPDATA%\\Microsoft\\Protect & dir %APPDATA%\\Microsoft\\Credentials;ppid=1".to_string(),
    });

    let retained = runtime.limit_raw_event_ingress(burst);

    assert_eq!(retained.len(), 4);
    assert!(retained.iter().any(|event| {
        event.payload.contains("Microsoft\\Protect")
            && event.payload.contains("Microsoft\\Credentials")
    }));
}

#[test]
fn backlog_cap_preserves_frontloaded_high_value_file_open_events() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.raw_event_backlog_cap = 2;

    runtime.enqueue_raw_events_with_priority(vec![
        platform_linux::RawEvent {
            event_type: platform_linux::EventType::FileOpen,
            pid: 6101,
            uid: 0,
            ts_ns: 1_700_000_000_000_000_000,
            payload: "path=/var/log/messages;flags=0;mode=0;ppid=1;cgroup_id=30;comm=cat;parent_comm=bash".to_string(),
        },
        platform_linux::RawEvent {
            event_type: platform_linux::EventType::FileOpen,
            pid: 6102,
            uid: 0,
            ts_ns: 1_700_000_000_100_000_000,
            payload: "path=/tmp/eguard-preserve-ioc.bin;flags=0;mode=0;ppid=1;cgroup_id=30;comm=cat;parent_comm=bash".to_string(),
        },
        platform_linux::RawEvent {
            event_type: platform_linux::EventType::FileOpen,
            pid: 6103,
            uid: 0,
            ts_ns: 1_700_000_000_200_000_000,
            payload: "path=/var/log/secure;flags=0;mode=0;ppid=1;cgroup_id=30;comm=cat;parent_comm=bash".to_string(),
        },
    ]);

    runtime.enforce_raw_event_backlog_cap();

    assert_eq!(runtime.raw_event_backlog.len(), 2);
    assert!(runtime
        .raw_event_backlog
        .iter()
        .any(|event| { event.payload.contains("/tmp/eguard-preserve-ioc.bin") }));
}

#[test]
fn evaluate_tick_suppresses_known_windows_powershell_sensor_child() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.ebpf_engine = platform_linux::EbpfEngine::disabled();
    runtime.raw_event_backlog.push_back(platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 4701,
        uid: 0,
        ts_ns: 1_700_000_100_000_000_000,
        payload: format!(
            r#"path=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe;ppid={};parent_process=C:\Program Files\eGuard\eguard-agent.exe;cmdline=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -Command Get-MpComputerStatus"#,
            std::process::id()
        ),
    });

    let evaluation = runtime
        .evaluate_tick(1_700_000_100)
        .expect("evaluate tick for self-noise powershell");
    assert!(evaluation.is_none());
}

#[test]
fn windows_sensor_child_pid_suppression_clears_on_process_exit() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.ebpf_engine = platform_linux::EbpfEngine::disabled();
    let sensor_pid = 4702u32;
    runtime.raw_event_backlog.push_back(platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: sensor_pid,
        uid: 0,
        ts_ns: 1_700_000_200_000_000_000,
        payload: format!(
            r#"path=C:\Windows\System32\reg.exe;ppid={};parent_process=C:\Program Files\eGuard\eguard-agent.exe;cmdline=C:\Windows\System32\reg.exe query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion /v ProductName"#,
            std::process::id()
        ),
    });

    assert!(runtime
        .evaluate_tick(1_700_000_200)
        .expect("sensor process exec tick")
        .is_none());

    runtime
        .raw_event_backlog
        .push_back(platform_linux::RawEvent {
            event_type: platform_linux::EventType::FileOpen,
            pid: sensor_pid,
            uid: 0,
            ts_ns: 1_700_000_200_100_000_000,
            payload: r#"path=C:\Windows\System32\drivers\etc\hosts"#.to_string(),
        });
    assert!(runtime
        .evaluate_tick(1_700_000_201)
        .expect("sensor child file tick")
        .is_none());

    runtime
        .raw_event_backlog
        .push_back(platform_linux::RawEvent {
            event_type: platform_linux::EventType::ProcessExit,
            pid: sensor_pid,
            uid: 0,
            ts_ns: 1_700_000_200_200_000_000,
            payload: "exit_code=0".to_string(),
        });
    assert!(runtime
        .evaluate_tick(1_700_000_202)
        .expect("sensor process exit tick")
        .is_none());

    runtime
        .raw_event_backlog
        .push_back(platform_linux::RawEvent {
            event_type: platform_linux::EventType::ProcessExec,
            pid: sensor_pid,
            uid: 0,
            ts_ns: 1_700_000_200_300_000_000,
            payload: "cmdline=/usr/bin/bash -lc whoami".to_string(),
        });
    let evaluation = runtime
        .evaluate_tick(1_700_000_203)
        .expect("post-exit reused pid tick")
        .expect("reused pid should no longer be suppressed");
    assert_eq!(evaluation.detection_event.pid, sensor_pid);
}

#[test]
fn evaluate_tick_suppresses_linux_internal_child_process_exec() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.ebpf_engine = platform_linux::EbpfEngine::disabled();
    runtime
        .raw_event_backlog
        .push_back(platform_linux::RawEvent {
            event_type: platform_linux::EventType::ProcessExec,
            pid: 5701,
            uid: 0,
            ts_ns: 1_700_000_300_000_000_000,
            payload: format!(
            "path=/usr/bin/ps;cmdline=ps aux;ppid={};cgroup_id=30;comm=ps;parent_comm=eguard-agent",
            std::process::id()
        ),
        });

    let evaluation = runtime
        .evaluate_tick(1_700_000_300)
        .expect("evaluate tick for linux helper process exec");
    assert!(evaluation.is_none());
}

#[test]
fn linux_agent_helper_pid_suppression_clears_on_process_exit() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.ebpf_engine = platform_linux::EbpfEngine::disabled();
    let helper_pid = 5702u32;
    runtime
        .raw_event_backlog
        .push_back(platform_linux::RawEvent {
            event_type: platform_linux::EventType::ProcessExec,
            pid: helper_pid,
            uid: 0,
            ts_ns: 1_700_000_400_000_000_000,
            payload: format!(
            "path=/usr/bin/ps;cmdline=ps aux;ppid={};cgroup_id=30;comm=ps;parent_comm=eguard-agent",
            std::process::id()
        ),
        });

    assert!(runtime
        .evaluate_tick(1_700_000_400)
        .expect("helper process exec tick")
        .is_none());

    runtime
        .raw_event_backlog
        .push_back(platform_linux::RawEvent {
            event_type: platform_linux::EventType::FileOpen,
            pid: helper_pid,
            uid: 0,
            ts_ns: 1_700_000_400_100_000_000,
            payload: "path=/proc/1469/status;flags=0;mode=0;ppid=2095;cgroup_id=30;comm=ps;parent_comm=eguard-agent".to_string(),
        });
    assert!(runtime
        .evaluate_tick(1_700_000_401)
        .expect("helper child procfs tick")
        .is_none());

    runtime
        .raw_event_backlog
        .push_back(platform_linux::RawEvent {
            event_type: platform_linux::EventType::ProcessExit,
            pid: helper_pid,
            uid: 0,
            ts_ns: 1_700_000_400_200_000_000,
            payload: "exit_code=0".to_string(),
        });
    assert!(runtime
        .evaluate_tick(1_700_000_402)
        .expect("helper process exit tick")
        .is_none());

    runtime
        .raw_event_backlog
        .push_back(platform_linux::RawEvent {
            event_type: platform_linux::EventType::ProcessExec,
            pid: helper_pid,
            uid: 0,
            ts_ns: 1_700_000_400_300_000_000,
            payload: "path=/usr/bin/bash;cmdline=/usr/bin/bash -lc whoami;ppid=6999;cgroup_id=30;comm=bash;parent_comm=bash".to_string(),
        });
    let evaluation = runtime
        .evaluate_tick(1_700_000_403)
        .expect("post-exit reused pid tick")
        .expect("reused pid should no longer be suppressed");
    assert_eq!(evaluation.detection_event.pid, helper_pid);
}

#[test]
fn linux_internal_descendant_process_is_suppressed_transitively() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.ebpf_engine = platform_linux::EbpfEngine::disabled();
    let bridge_pid = 5703u32;
    let descendant_pid = 5704u32;

    runtime.raw_event_backlog.push_back(platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: bridge_pid,
        uid: 0,
        ts_ns: 1_700_000_450_000_000_000,
        payload: format!(
            "path=/usr/bin/systemd-run;cmdline=systemd-run --collect /bin/sh -lc true;ppid={};cgroup_id=30;comm=systemd-run;parent_comm=eguard-agent",
            std::process::id()
        ),
    });
    assert!(runtime
        .evaluate_tick(1_700_000_450)
        .expect("bridge process exec tick")
        .is_none());

    runtime.raw_event_backlog.push_back(platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: descendant_pid,
        uid: 0,
        ts_ns: 1_700_000_450_100_000_000,
        payload: format!(
            "path=/usr/bin/bash;cmdline=/usr/bin/bash -lc true;ppid={bridge_pid};cgroup_id=30;comm=bash;parent_comm=systemd-run"
        ),
    });
    assert!(runtime
        .evaluate_tick(1_700_000_451)
        .expect("descendant process exec tick")
        .is_none());
}

#[test]
fn linux_internal_direct_child_file_open_is_suppressed_without_exec_tracking() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.ebpf_engine = platform_linux::EbpfEngine::disabled();
    runtime.raw_event_backlog.push_back(platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 5705,
        uid: 0,
        ts_ns: 1_700_000_460_000_000_000,
        payload: format!(
            "path=/proc/1469/status;flags=0;mode=0;ppid={};cgroup_id=30;comm=ps;parent_comm=eguard-agent",
            std::process::id()
        ),
    });

    assert!(runtime
        .evaluate_tick(1_700_000_460)
        .expect("direct child file open tick")
        .is_none());
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
fn high_value_linux_file_open_events_bypass_pre_detection_coalescing() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let replay_path = std::env::temp_dir().join(format!(
        "eguard-agent-replay-high-value-open-{}.ndjson",
        nonce
    ));
    let target_file = std::env::temp_dir().join(format!("eguard-high-value-open-{}.bin", nonce));
    let target_path = target_file.to_string_lossy().to_string();
    std::fs::write(&target_file, b"payload").expect("write target file");

    let replay = [
        format!(
            r#"{{"event_type":"file_open","pid":9305,"uid":0,"ts_ns":1700000000000000000,"file_path":"{}","flags":0,"mode":0}}"#,
            target_path
        ),
        format!(
            r#"{{"event_type":"file_open","pid":9305,"uid":0,"ts_ns":1700000000000100000,"file_path":"{}","flags":0,"mode":0}}"#,
            target_path
        ),
    ]
    .join("\n");
    std::fs::write(&replay_path, replay).expect("write replay file");

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.ebpf_engine =
        platform_linux::EbpfEngine::from_replay(&replay_path).expect("replay backend");
    runtime.file_event_coalesce_window_ns = 5_000_000_000;
    runtime.event_txn_coalesce_window_ns = 5_000_000_000;

    let first = runtime.evaluate_tick(1_700_000_000).expect("tick 1");
    let second = runtime.evaluate_tick(1_700_000_001).expect("tick 2");

    assert!(first.is_some());
    assert!(second.is_some());
    assert_eq!(
        runtime
            .observability_snapshot()
            .telemetry_coalesced_events_total,
        0
    );

    let _ = std::fs::remove_file(replay_path);
    let _ = std::fs::remove_file(target_file);
}

#[test]
fn event_txn_coalescing_drops_duplicate_dns_queries_within_window() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let replay_path = std::env::temp_dir().join(format!(
        "eguard-agent-replay-txn-coalesce-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let replay = [
        r#"{"event_type":"dns_query","pid":9401,"uid":0,"ts_ns":1700000000000000000,"domain":"dup.example"}"#,
        r#"{"event_type":"dns_query","pid":9401,"uid":0,"ts_ns":1700000000000100000,"domain":"dup.example"}"#,
    ]
    .join("\n");
    std::fs::write(&replay_path, replay).expect("write replay file");

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.ebpf_engine =
        platform_linux::EbpfEngine::from_replay(&replay_path).expect("replay backend");
    runtime.event_txn_coalesce_window_ns = 5_000_000_000;

    let first = runtime.evaluate_tick(1_700_000_000).expect("tick 1");
    let second = runtime.evaluate_tick(1_700_000_001).expect("tick 2");

    assert!(first.is_some());
    assert!(second.is_none());
    assert!(
        runtime
            .observability_snapshot()
            .telemetry_event_txn_coalesced_total
            >= 1
    );

    let _ = std::fs::remove_file(replay_path);
}

#[test]
fn file_open_coalescing_preserves_follow_up_read_after_write_for_exact_ioc_hashing() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let replay_path = std::env::temp_dir().join(format!(
        "eguard-agent-replay-file-open-access-{}.ndjson",
        nonce
    ));
    let target_file = std::env::temp_dir().join(format!("eguard-eicar-follow-up-{}.com", nonce));
    let target_path = target_file.to_string_lossy().to_string();

    let replay = [
        format!(
            r#"{{"event_type":"file_open","pid":9501,"uid":0,"ts_ns":1700000000000000000,"file_path":"{}","flags":577,"mode":420}}"#,
            target_path
        ),
        format!(
            r#"{{"event_type":"file_open","pid":9501,"uid":0,"ts_ns":1700000000000100000,"file_path":"{}","flags":0,"mode":0}}"#,
            target_path
        ),
    ]
    .join("\n");
    std::fs::write(&replay_path, replay).expect("write replay file");

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.ebpf_engine =
        platform_linux::EbpfEngine::from_replay(&replay_path).expect("replay backend");
    runtime.file_event_coalesce_window_ns = 5_000_000_000;
    runtime.event_txn_coalesce_window_ns = 5_000_000_000;

    let first = runtime
        .evaluate_tick(1_700_000_000)
        .expect("tick 1")
        .expect("write-open event");
    assert_eq!(
        first.detection_event.file_path.as_deref(),
        Some(target_path.as_str())
    );
    assert!(first.detection_event.file_hash.is_none());

    std::fs::write(
        &target_file,
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    )
    .expect("write eicar payload");

    let second = runtime
        .evaluate_tick(1_700_000_001)
        .expect("tick 2")
        .expect("read-open event preserved");

    assert_eq!(
        second.detection_event.file_path.as_deref(),
        Some(target_path.as_str())
    );
    assert_eq!(
        second.detection_event.file_hash.as_deref(),
        Some("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    );
    assert!(second.detection_outcome.signals.z1_exact_ioc);

    let _ = std::fs::remove_file(target_file);
    let _ = std::fs::remove_file(replay_path);
}

#[test]
fn same_session_eicar_exact_ioc_file_open_survives_process_exec_burst_ingress_cap() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let target_file = std::env::temp_dir().join(format!("eguard-eicar-same-session-{}.com", nonce));
    let target_path = target_file.to_string_lossy().to_string();
    std::fs::write(
        &target_file,
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    )
    .expect("write eicar payload");

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.ebpf_engine = platform_linux::EbpfEngine::disabled();
    runtime.raw_event_ingest_cap = 6;
    runtime.raw_event_backlog_cap = 6;

    let mut engine = detection::DetectionEngine::default_with_rules();
    engine.layer1.load_hashes([
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
    ]);
    runtime
        .detection_state
        .swap_engine("test-same-session-eicar".to_string(), engine)
        .expect("swap detection engine");

    let mut burst = vec![
        platform_linux::RawEvent {
            event_type: platform_linux::EventType::ProcessExec,
            pid: 9601,
            uid: 1000,
            ts_ns: 1,
            payload: "path=/usr/bin/systemctl;cmdline=systemctl --user show-environment;ppid=9500;cgroup_id=30;comm=systemctl;parent_comm=bash".to_string(),
        },
        platform_linux::RawEvent {
            event_type: platform_linux::EventType::ProcessExec,
            pid: 9602,
            uid: 1000,
            ts_ns: 2,
            payload: "path=/usr/bin/readlink;cmdline=readlink /usr/bin/bash;ppid=9500;cgroup_id=30;comm=readlink;parent_comm=bash".to_string(),
        },
        platform_linux::RawEvent {
            event_type: platform_linux::EventType::ProcessExec,
            pid: 9603,
            uid: 1000,
            ts_ns: 3,
            payload: "path=/usr/bin/basename;cmdline=basename /usr/bin/bash;ppid=9500;cgroup_id=30;comm=basename;parent_comm=bash".to_string(),
        },
        platform_linux::RawEvent {
            event_type: platform_linux::EventType::ProcessExec,
            pid: 9604,
            uid: 1000,
            ts_ns: 4,
            payload: "path=/usr/bin/locale;cmdline=locale;ppid=9500;cgroup_id=30;comm=locale;parent_comm=bash".to_string(),
        },
        platform_linux::RawEvent {
            event_type: platform_linux::EventType::ProcessExec,
            pid: 9605,
            uid: 1000,
            ts_ns: 5,
            payload: "path=/usr/bin/sed;cmdline=sed -n 1p /etc/profile;ppid=9500;cgroup_id=30;comm=sed;parent_comm=bash".to_string(),
        },
        platform_linux::RawEvent {
            event_type: platform_linux::EventType::ProcessExec,
            pid: 9606,
            uid: 1000,
            ts_ns: 6,
            payload: format!(
                "path=/usr/bin/cat;cmdline=cat {} >/dev/null;ppid=9500;cgroup_id=30;comm=cat;parent_comm=bash",
                target_path
            ),
        },
        platform_linux::RawEvent {
            event_type: platform_linux::EventType::FileOpen,
            pid: 9606,
            uid: 1000,
            ts_ns: 7,
            payload: format!(
                "path={};flags=0;mode=0;ppid=9500;cgroup_id=30;comm=cat;parent_comm=bash",
                target_path
            ),
        },
    ];
    burst.sort_by_key(AgentRuntime::raw_event_priority);
    let retained = runtime.limit_raw_event_ingress(burst);
    runtime.enqueue_raw_events_with_priority(retained);
    runtime.enforce_raw_event_backlog_cap();

    assert!(
        runtime
            .observability_snapshot()
            .telemetry_raw_backlog_dropped_total
            >= 1,
        "test must exercise the ingress cap path"
    );

    let mut exact_ioc_eval = None;
    for tick in 0..8 {
        let evaluation = runtime
            .evaluate_tick(1_700_000_100 + tick)
            .expect("evaluate tick");
        let Some(evaluation) = evaluation else {
            continue;
        };
        if evaluation.detection_event.file_path.as_deref() == Some(target_path.as_str()) {
            exact_ioc_eval = Some(evaluation);
            break;
        }
    }

    let evaluation = exact_ioc_eval.expect(
        "same-session /tmp EICAR file open should survive the benign process burst ingress cap",
    );
    assert_eq!(
        evaluation.detection_event.file_hash.as_deref(),
        Some("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    );
    assert!(evaluation.detection_outcome.signals.z1_exact_ioc);

    let _ = std::fs::remove_file(target_file);
}

#[test]
fn same_session_eicar_exact_ioc_file_open_survives_high_value_home_burst_ingress_cap() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let target_file = std::env::temp_dir().join(format!("eguard-eicar-home-burst-{}.com", nonce));
    let target_path = target_file.to_string_lossy().to_string();
    std::fs::write(
        &target_file,
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    )
    .expect("write eicar payload");

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.ebpf_engine = platform_linux::EbpfEngine::disabled();
    runtime.raw_event_ingest_cap = 3;
    runtime.raw_event_backlog_cap = 3;

    let mut engine = detection::DetectionEngine::default_with_rules();
    engine.layer1.load_hashes([
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
    ]);
    runtime
        .detection_state
        .swap_engine("test-home-burst-eicar".to_string(), engine)
        .expect("swap detection engine");

    let mut burst = vec![
        platform_linux::RawEvent {
            event_type: platform_linux::EventType::FileOpen,
            pid: 9701,
            uid: 1000,
            ts_ns: 1,
            payload: "path=/home/agent/.ssh/known_hosts;flags=0;mode=0;ppid=9500;cgroup_id=30;comm=bash;parent_comm=sshd-session".to_string(),
        },
        platform_linux::RawEvent {
            event_type: platform_linux::EventType::FileOpen,
            pid: 9701,
            uid: 1000,
            ts_ns: 2,
            payload: "path=/home/agent/.local/share/direnv/allow/1234;flags=0;mode=0;ppid=9500;cgroup_id=30;comm=bash;parent_comm=sshd-session".to_string(),
        },
        platform_linux::RawEvent {
            event_type: platform_linux::EventType::FileOpen,
            pid: 9701,
            uid: 1000,
            ts_ns: 3,
            payload: "path=/home/agent/projects/demo/.envrc;flags=0;mode=0;ppid=9500;cgroup_id=30;comm=bash;parent_comm=sshd-session".to_string(),
        },
        platform_linux::RawEvent {
            event_type: platform_linux::EventType::FileOpen,
            pid: 9702,
            uid: 1000,
            ts_ns: 4,
            payload: format!(
                "path={};flags=0;mode=0;ppid=9500;cgroup_id=30;comm=cat;parent_comm=bash",
                target_path
            ),
        },
    ];
    burst.sort_by_key(AgentRuntime::raw_event_priority);
    let retained = runtime.limit_raw_event_ingress(burst);
    runtime.enqueue_raw_events_with_priority(retained);
    runtime.enforce_raw_event_backlog_cap();

    assert!(
        runtime
            .observability_snapshot()
            .telemetry_raw_backlog_dropped_total
            >= 1,
        "test must exercise the ingress cap path"
    );

    let mut exact_ioc_eval = None;
    for tick in 0..6 {
        let evaluation = runtime
            .evaluate_tick(1_700_000_200 + tick)
            .expect("evaluate tick");
        let Some(evaluation) = evaluation else {
            continue;
        };
        if evaluation.detection_event.file_path.as_deref() == Some(target_path.as_str()) {
            exact_ioc_eval = Some(evaluation);
            break;
        }
    }

    let evaluation = exact_ioc_eval.expect(
        "same-session /tmp EICAR file open should survive even when several earlier /home file opens are also high-priority",
    );
    assert_eq!(
        evaluation.detection_event.file_hash.as_deref(),
        Some("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    );
    assert!(evaluation.detection_outcome.signals.z1_exact_ioc);

    let _ = std::fs::remove_file(target_file);
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

#[tokio::test]
async fn send_event_batch_timeout_rebuffers_and_returns_promptly() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock telemetry server");
    let addr = listener.local_addr().expect("mock telemetry addr");

    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.expect("accept telemetry client");
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    });

    let mut cfg = AgentConfig::default();
    cfg.transport_mode = "http".to_string();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = addr.to_string();
    cfg.self_protection_integrity_check_interval_secs = 0;

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.runtime_mode = AgentMode::Active;

    let started = std::time::Instant::now();
    runtime
        .send_event_batch(EventEnvelope {
            agent_id: "agent-test".to_string(),
            event_type: "process_exec".to_string(),
            severity: String::new(),
            rule_name: String::new(),
            payload_json: "{\"ts\":1}".to_string(),
            created_at_unix: 1,
        })
        .await
        .expect("timeout send attempt");
    let elapsed = started.elapsed();

    assert_eq!(runtime.buffer.pending_count(), 1);
    assert_eq!(runtime.consecutive_send_failures, 1);
    assert!(matches!(runtime.runtime_mode, AgentMode::Active));
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "telemetry timeout should bound stalled sends, elapsed={elapsed:?}"
    );

    server.abort();
}

#[test]
fn low_value_linux_systemd_cgroup_chatter_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 1,
        uid: 0,
        ts_ns: 1,
        payload: "path=/sys/fs/cgroup/user.slice/memory.events;flags=0;mode=0;ppid=0;cgroup_id=30;comm=systemd;parent_comm=swapper/0".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn systemd_spawned_loader_library_chatter_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 4997,
        uid: 0,
        ts_ns: 1,
        payload: "path=/usr/lib64/systemd/libpam.so.0;flags=524288;mode=0;ppid=1;cgroup_id=30;comm=16;parent_comm=systemd".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn systemd_runtime_loader_cache_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 117008,
        uid: 0,
        ts_ns: 1,
        payload: "path=/etc/ld.so.cache;flags=0;mode=0;ppid=641;cgroup_id=30;comm=systemd-nsresou;parent_comm=systemd-nsresou".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn systemd_user_worker_library_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 117021,
        uid: 0,
        ts_ns: 1,
        payload: "path=/usr/lib64/libnss_systemd.so.2;flags=0;mode=0;ppid=117020;cgroup_id=30;comm=systemd-userwor;parent_comm=systemd-userdbd".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn systemd_selinux_runtime_chatter_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 1,
        uid: 0,
        ts_ns: 1,
        payload: "path=/sys/fs/selinux/class/process/perms/execheap;flags=0;mode=0;ppid=0;cgroup_id=30;comm=systemd;parent_comm=swapper/0".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn systemd_selinux_policy_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 2975,
        uid: 0,
        ts_ns: 1,
        payload: "path=/etc/selinux/targeted/contexts/default_contexts;flags=0;mode=0;ppid=1;cgroup_id=30;comm=(systemd);parent_comm=systemd".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn systemd_pam_policy_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 2975,
        uid: 0,
        ts_ns: 1,
        payload: "path=/etc/pam.d/other;flags=0;mode=0;ppid=1;cgroup_id=30;comm=(systemd);parent_comm=systemd".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn systemd_user_hidden_config_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 3149,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/home/agent/.config/systemd/user.conf;flags=0;mode=0;ppid=1;cgroup_id=30;comm=systemd;parent_comm=systemd".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn systemd_journald_log_file_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 607,
        uid: 0,
        ts_ns: 1,
        payload: "path=/var/log/journal/5d3dc8654c993f8c581dbff93588b35f/system.journal;flags=0;mode=0;ppid=1;cgroup_id=30;comm=systemd-journald;parent_comm=systemd".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn systemd_journald_proc_scrape_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 607,
        uid: 0,
        ts_ns: 1,
        payload: "path=/proc/113282/status;flags=0;mode=0;ppid=1;cgroup_id=30;comm=systemd-journald;parent_comm=systemd".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn systemd_cleanup_relative_path_chatter_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 113065,
        uid: 0,
        ts_ns: 1,
        payload: "path=var;flags=0;mode=0;ppid=1;cgroup_id=30;comm=(sd-rmrf);parent_comm=systemd"
            .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn agent_spawned_systemctl_loader_chatter_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 114337,
        uid: 0,
        ts_ns: 1,
        payload: "path=/usr/lib/locale/locale-archive;flags=0;mode=0;ppid=114329;cgroup_id=30;comm=systemctl;parent_comm=eguard-agent".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn agent_spawned_systemctl_procfs_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 117027,
        uid: 0,
        ts_ns: 1,
        payload: "path=/proc/sys/kernel/ngroups_max;flags=0;mode=0;ppid=117020;cgroup_id=30;comm=systemctl;parent_comm=eguard-agent".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn agent_spawned_rpm_metadata_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 114339,
        uid: 0,
        ts_ns: 1,
        payload: "path=/usr/lib/rpm/macros;flags=0;mode=0;ppid=114329;cgroup_id=30;comm=rpm;parent_comm=agent-core".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn sshd_session_pam_stack_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 114522,
        uid: 0,
        ts_ns: 1,
        payload: "path=/usr/lib64/security/pam_unix.so;flags=0;mode=0;ppid=1;cgroup_id=30;comm=sshd-session;parent_comm=sshd".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn sshd_session_auth_config_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 114522,
        uid: 0,
        ts_ns: 1,
        payload: "path=/etc/pam.d/sshd;flags=0;mode=0;ppid=1;cgroup_id=30;comm=sshd-session;parent_comm=sshd".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn sshd_session_bootstrap_proc_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 114522,
        uid: 0,
        ts_ns: 1,
        payload: "path=/proc/self/loginuid;flags=0;mode=0;ppid=1;cgroup_id=30;comm=sshd-session;parent_comm=sshd".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn sshd_session_crypto_policy_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 114522,
        uid: 0,
        ts_ns: 1,
        payload: "path=/etc/crypto-policies/back-ends/opensslcnf.config;flags=0;mode=0;ppid=1;cgroup_id=30;comm=sshd-session;parent_comm=sshd".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn sshd_session_selinux_runtime_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 114522,
        uid: 0,
        ts_ns: 1,
        payload: "path=/sys/fs/selinux/status;flags=0;mode=0;ppid=1;cgroup_id=30;comm=sshd-session;parent_comm=sshd".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn sshd_session_environment_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 114522,
        uid: 0,
        ts_ns: 1,
        payload: "path=/etc//environment;flags=0;mode=0;ppid=1;cgroup_id=30;comm=sshd-session;parent_comm=sshd".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn sshd_session_nologin_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 114522,
        uid: 0,
        ts_ns: 1,
        payload: "path=/var/run/nologin;flags=0;mode=0;ppid=1;cgroup_id=30;comm=sshd-session;parent_comm=sshd".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn sshd_session_security_policy_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 114522,
        uid: 0,
        ts_ns: 1,
        payload: "path=/etc/security/namespace.d;flags=0;mode=0;ppid=1;cgroup_id=30;comm=sshd-session;parent_comm=sshd".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn ssh_login_shell_dotfile_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 114526,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/home/agent/.bashrc;flags=0;mode=0;ppid=114522;cgroup_id=30;comm=bash;parent_comm=sshd-session".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn ssh_login_shell_profile_d_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 114526,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/etc/profile.d/bash_completion.sh;flags=0;mode=0;ppid=114522;cgroup_id=30;comm=bash;parent_comm=sshd-session".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn sshd_session_authorized_keys_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 114522,
        uid: 0,
        ts_ns: 1,
        payload: "path=/home/agent/.ssh/authorized_keys;flags=0;mode=0;ppid=1;cgroup_id=30;comm=sshd-session;parent_comm=sshd".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn unix_chkpwd_bootstrap_localtime_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 114524,
        uid: 0,
        ts_ns: 1,
        payload: "path=/etc/localtime;flags=0;mode=0;ppid=114522;cgroup_id=30;comm=unix_chkpwd;parent_comm=sshd-session".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn agent_spawned_systemctl_unit_reads_remain_visible() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 114337,
        uid: 0,
        ts_ns: 1,
        payload: "path=/usr/lib/systemd/system/eguard-agent.service;flags=0;mode=0;ppid=114329;cgroup_id=30;comm=systemctl;parent_comm=eguard-agent".to_string(),
    };

    assert!(!AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn user_spawned_rpm_metadata_reads_remain_visible() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 114339,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/usr/lib/rpm/macros;flags=0;mode=0;ppid=6999;cgroup_id=30;comm=rpm;parent_comm=bash".to_string(),
    };

    assert!(!AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn sudo_auth_stack_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 7001,
        uid: 1000,
        ts_ns: 1,
        payload:
            "path=/etc/sudoers;flags=0;mode=0;ppid=6999;cgroup_id=30;comm=sudo;parent_comm=bash"
                .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn sudo_pam_library_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 7002,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/usr/lib64/security/pam_unix.so;flags=0;mode=0;ppid=6999;cgroup_id=30;comm=sudo;parent_comm=bash".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn unix_chkpwd_shadow_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 7003,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/etc/shadow;flags=0;mode=0;ppid=7002;cgroup_id=30;comm=unix_chkpwd;parent_comm=sudo".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn unix_chkpwd_passwd_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 7003,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/etc/passwd;flags=0;mode=0;ppid=7002;cgroup_id=30;comm=unix_chkpwd;parent_comm=sshd-session".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn unix_chkpwd_nsswitch_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 7003,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/etc/nsswitch.conf;flags=0;mode=0;ppid=7002;cgroup_id=30;comm=unix_chkpwd;parent_comm=sshd-session".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn sudo_security_policy_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 7004,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/etc/security/limits.conf;flags=0;mode=0;ppid=6999;cgroup_id=30;comm=sudo;parent_comm=bash".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn systemd_userwork_shadow_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 7005,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/etc/shadow;flags=0;mode=0;ppid=1;cgroup_id=30;comm=systemd-userwork;parent_comm=systemd".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn benign_procfd_exec_runtime_artifacts_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 7006,
        uid: 0,
        ts_ns: 1,
        payload: "path=/proc/self/fd/16;cmdline=16;ppid=1;cgroup_id=30;comm=16;parent_comm=systemd"
            .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn sshd_session_exec_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 14424,
        uid: 0,
        ts_ns: 1,
        payload: "path=/usr/libexec/openssh/sshd-session;cmdline=sshd-session: [accepted];ppid=1086;cgroup_id=30;comm=sshd-session;parent_comm=sshd"
            .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn unix_chkpwd_ssh_auth_exec_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 14425,
        uid: 0,
        ts_ns: 1,
        payload: "path=/usr/sbin/unix_chkpwd;cmdline=unix_chkpwd;ppid=14424;cgroup_id=30;comm=unix_chkpwd;parent_comm=sshd-session"
            .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn systemd_user_manager_exec_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 3149,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/usr/lib/systemd/systemd;cmdline=/usr/lib/systemd/systemd --user;ppid=1;cgroup_id=30;comm=systemd;parent_comm=systemd".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn systemd_user_generator_exec_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 3156,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/usr/lib/systemd/user-generators/systemd-xdg-autostart-generator;cmdline=systemd-xdg-autostart-generator;ppid=3154;cgroup_id=30;comm=systemd-xdg-autostart-generator;parent_comm=(sd-exec-strv)".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn systemd_user_environment_generator_exec_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 3157,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/usr/lib/systemd/user-environment-generators/30-systemd-environment-d-generator;cmdline=30-systemd-environment-d-generator;ppid=3154;cgroup_id=30;comm=30-systemd-environment-d-generator;parent_comm=(sd-exec-strv)".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn systemd_user_environment_generator_exec_noise_without_path_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 3160,
        uid: 1000,
        ts_ns: 1,
        payload: "cmdline=30-systemd-environment-d-generator;ppid=3154;cgroup_id=30;comm=30-systemd-environment-d-generator;parent_comm=(sd-exec-strv)".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn systemd_user_generator_exec_noise_without_path_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 3161,
        uid: 1000,
        ts_ns: 1,
        payload: "cmdline=systemd-xdg-autostart-generator;ppid=3154;cgroup_id=30;comm=systemd-xdg-autostart-generator;parent_comm=(sd-exec-strv)".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn systemd_tmpfiles_exec_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 3158,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/usr/bin/systemd-tmpfiles;cmdline=systemd-tmpfiles --user --create --remove --boot --prefix=/run/user/1000/systemd/user;ppid=1;cgroup_id=30;comm=systemd-tmpfiles;parent_comm=systemd".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn systemd_tmpfiles_exec_noise_without_path_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 3162,
        uid: 1000,
        ts_ns: 1,
        payload:
            "cmdline=systemd-tmpfiles;ppid=1;cgroup_id=30;comm=systemd-tmpfiles;parent_comm=systemd"
                .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn bash_systemctl_show_environment_exec_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 3159,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/usr/bin/systemctl;cmdline=systemctl --user show-environment;ppid=114526;cgroup_id=30;comm=systemctl;parent_comm=bash".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn systemd_user_runtime_dir_exec_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 3150,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/usr/lib/systemd/systemd-user-runtime-dir;cmdline=systemd-user-runtime-dir;ppid=1;cgroup_id=30;comm=systemd-user-runtime-dir;parent_comm=systemd".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn systemd_user_runtime_dir_exec_noise_without_path_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 3163,
        uid: 1000,
        ts_ns: 1,
        payload: "cmdline=systemd-user-runtime-dir;ppid=1;cgroup_id=30;comm=systemd-user-runtime-dir;parent_comm=systemd".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn systemd_user_manager_exec_noise_without_path_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 3164,
        uid: 1000,
        ts_ns: 1,
        payload: "cmdline=systemd;ppid=1;cgroup_id=30;comm=systemd;parent_comm=systemd".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn systemd_systemctl_exec_noise_without_path_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 3165,
        uid: 1000,
        ts_ns: 1,
        payload: "cmdline=systemctl;ppid=1;cgroup_id=30;comm=systemctl;parent_comm=systemd"
            .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn unix_chkpwd_systemd_exec_noise_without_path_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 3166,
        uid: 0,
        ts_ns: 1,
        payload: "cmdline=unix_chkpwd;ppid=1;cgroup_id=30;comm=unix_chkpwd;parent_comm=(systemd)"
            .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn bash_profile_helper_exec_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 3151,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/usr/libexec/grepconf.sh;cmdline=grepconf.sh;ppid=114526;cgroup_id=30;comm=grepconf.sh;parent_comm=bash".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn systemd_started_bash_login_shell_exec_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 45876,
        uid: 1000,
        ts_ns: 1,
        payload:
            "path=/usr/bin/bash;cmdline=bash;ppid=1;cgroup_id=30;comm=bash;parent_comm=systemd"
                .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn sshd_session_started_bash_login_shell_exec_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 45877,
        uid: 1000,
        ts_ns: 1,
        payload:
            "path=/bin/bash;cmdline=bash;ppid=924;cgroup_id=30;comm=bash;parent_comm=sshd-session"
                .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn sshd_session_started_pathless_bash_login_shell_exec_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 45878,
        uid: 1000,
        ts_ns: 1,
        payload: "cmdline=bash;ppid=924;cgroup_id=30;comm=bash;parent_comm=sshd-session"
            .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn bash_nohup_startup_exec_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 45889,
        uid: 1000,
        ts_ns: 1,
        payload:
            "path=/usr/bin/nohup;cmdline=nohup;ppid=45876;cgroup_id=30;comm=nohup;parent_comm=bash"
                .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn bash_basename_startup_exec_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 45890,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/usr/bin/basename;cmdline=basename;ppid=45876;cgroup_id=30;comm=basename;parent_comm=bash"
            .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn bash_cat_startup_exec_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 45891,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/usr/bin/cat;cmdline=cat;ppid=45876;cgroup_id=30;comm=cat;parent_comm=bash"
            .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn bash_readlink_startup_exec_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 45892,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/usr/bin/readlink;cmdline=readlink;ppid=45876;cgroup_id=30;comm=readlink;parent_comm=bash"
            .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn bash_locale_startup_exec_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 45893,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/usr/bin/locale;cmdline=locale;ppid=45876;cgroup_id=30;comm=locale;parent_comm=bash"
            .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn bash_tr_startup_exec_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 45894,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/usr/bin/tr;cmdline=tr;ppid=45876;cgroup_id=30;comm=tr;parent_comm=bash"
            .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn bash_tty_startup_exec_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 45891,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/usr/bin/tty;cmdline=tty;ppid=45876;cgroup_id=30;comm=tty;parent_comm=bash"
            .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn bash_sed_startup_exec_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::ProcessExec,
        pid: 45892,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/usr/bin/sed;cmdline=sed;ppid=45876;cgroup_id=30;comm=sed;parent_comm=bash"
            .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn bash_bashrc_read_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 45876,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/home/agent/.bashrc;flags=0;mode=0;ppid=1;cgroup_id=30;comm=bash;parent_comm=systemd"
            .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn bash_curlrc_read_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 45893,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/home/agent/.curlrc;flags=0;mode=0;ppid=45876;cgroup_id=30;comm=curl;parent_comm=bash"
            .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn sshd_session_motd_read_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 5900,
        uid: 1000,
        ts_ns: 1,
        payload:
            "path=/etc/motd;flags=0;mode=0;ppid=924;cgroup_id=30;comm=sshd-session;parent_comm=sshd"
                .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn sshd_session_nologin_read_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 5901,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/etc/nologin;flags=0;mode=0;ppid=924;cgroup_id=30;comm=sshd-session;parent_comm=sshd"
            .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn sshd_session_boot_id_read_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 5902,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/proc/sys/kernel/random/boot_id;flags=0;mode=0;ppid=924;cgroup_id=30;comm=sshd-session;parent_comm=sshd"
            .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn sshd_session_userdb_runtime_read_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 5903,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/run/systemd/userdb/;flags=0;mode=0;ppid=924;cgroup_id=30;comm=sshd-session;parent_comm=sshd"
            .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn sshd_session_unix_chkpwd_loader_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 5904,
        uid: 0,
        ts_ns: 1,
        payload: "path=/lib64/libaudit.so.1;flags=0;mode=0;ppid=5900;cgroup_id=30;comm=unix_chkpwd;parent_comm=sshd-session"
            .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn systemd_userwork_root_probe_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 5905,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/;flags=0;mode=0;ppid=781;cgroup_id=30;comm=systemd-userwork;parent_comm=systemd-userdbd"
            .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn sshd_session_bash_locale_file_read_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 5906,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/usr/lib/locale/en_US.UTF-8/LC_CTYPE;flags=0;mode=0;ppid=924;cgroup_id=30;comm=bash;parent_comm=sshd-session"
            .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn sshd_session_bash_gconv_cache_read_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 5907,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/usr/lib64/gconv/gconv-modules.cache;flags=0;mode=0;ppid=924;cgroup_id=30;comm=bash;parent_comm=sshd-session"
            .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn sshd_session_oom_score_adj_read_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 5908,
        uid: 1000,
        ts_ns: 1,
        payload: "path=/proc/self/oom_score_adj;flags=0;mode=0;ppid=924;cgroup_id=30;comm=sshd-session;parent_comm=sshd"
            .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn bash_basename_pathless_file_open_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 5909,
        uid: 1000,
        ts_ns: 1,
        payload:
            "flags=0;mode=0;ppid=45876;cgroup_id=30;comm=basename;parent_comm=bash;cmdline=basename"
                .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn bash_readlink_pathless_file_open_noise_is_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 5910,
        uid: 1000,
        ts_ns: 1,
        payload:
            "flags=0;mode=0;ppid=45876;cgroup_id=30;comm=readlink;parent_comm=bash;cmdline=readlink"
                .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn linux_console_device_reads_are_filtered_before_backloging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 7006,
        uid: 1000,
        ts_ns: 1,
        payload:
            "path=/dev/console;flags=0;mode=0;ppid=6999;cgroup_id=30;comm=bash;parent_comm=sshd"
                .to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn pathless_linux_file_write_events_are_filtered_before_backlogging() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileWrite,
        pid: 7007,
        uid: 1000,
        ts_ns: 1,
        payload: "fd=3;size=68".to_string(),
    };

    assert!(AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn suspicious_linux_tmp_file_open_is_not_filtered() {
    let raw = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 5986,
        uid: 0,
        ts_ns: 1,
        payload: "path=/tmp/eguard-dump-proof.bin;flags=0;mode=0;ppid=5980;cgroup_id=23998;comm=cat;parent_comm=bash".to_string(),
    };

    assert!(!AgentRuntime::should_drop_low_value_linux_raw_event(&raw));
}

#[test]
fn suspicious_linux_tmp_file_open_is_prioritized_ahead_of_systemd_chatter() {
    let noisy = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 1,
        uid: 0,
        ts_ns: 1,
        payload: "path=/sys/fs/cgroup/user.slice/memory.events;flags=0;mode=0;ppid=0;cgroup_id=30;comm=systemd;parent_comm=swapper/0".to_string(),
    };
    let suspicious = platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 5986,
        uid: 0,
        ts_ns: 2,
        payload: "path=/tmp/eguard-dump-proof.bin;flags=0;mode=0;ppid=5980;cgroup_id=23998;comm=cat;parent_comm=bash".to_string(),
    };

    assert!(
        AgentRuntime::raw_event_priority(&suspicious) < AgentRuntime::raw_event_priority(&noisy)
    );
}

#[test]
fn frontloaded_high_priority_linux_event_is_dequeued_before_existing_low_value_backlog() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.raw_event_backlog.push_back(platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 1,
        uid: 0,
        ts_ns: 1,
        payload: "path=/sys/fs/cgroup/user.slice/memory.events;flags=0;mode=0;ppid=0;cgroup_id=30;comm=systemd;parent_comm=swapper/0".to_string(),
    });

    runtime.enqueue_raw_events_with_priority(vec![platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 5986,
        uid: 0,
        ts_ns: 2,
        payload: "path=/tmp/eguard-dump-proof.bin;flags=0;mode=0;ppid=5980;cgroup_id=23998;comm=cat;parent_comm=bash".to_string(),
    }]);

    let first = runtime
        .raw_event_backlog
        .pop_front()
        .expect("frontloaded event");
    assert!(first.payload.contains("/tmp/eguard-dump-proof.bin"));
}

#[test]
fn sampling_preserves_frontloaded_high_value_linux_file_open() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.enqueue_raw_events_with_priority(vec![
        platform_linux::RawEvent {
            event_type: platform_linux::EventType::ProcessExec,
            pid: 7001,
            uid: 1000,
            ts_ns: 1,
            payload: "path=/usr/bin/cat;cmdline=cat /home/agent/eicar_exact_proof.com >/dev/null;ppid=6999;cgroup_id=30;comm=cat;parent_comm=bash".to_string(),
        },
        platform_linux::RawEvent {
            event_type: platform_linux::EventType::FileOpen,
            pid: 7001,
            uid: 1000,
            ts_ns: 2,
            payload: "path=/home/agent/eicar_exact_proof.com;flags=0;mode=0;ppid=6999;cgroup_id=30;comm=cat;parent_comm=bash".to_string(),
        },
        platform_linux::RawEvent {
            event_type: platform_linux::EventType::FileOpen,
            pid: 7001,
            uid: 1000,
            ts_ns: 3,
            payload: "path=/var/log/messages;flags=0;mode=0;ppid=6999;cgroup_id=30;comm=cat;parent_comm=bash".to_string(),
        },
    ]);

    let first = runtime
        .dequeue_sampled_raw_event(2)
        .expect("first sampled event");
    assert!(matches!(
        first.event_type,
        platform_linux::EventType::ProcessExec
    ));

    let second = runtime
        .dequeue_sampled_raw_event(1)
        .expect("high-value file open preserved");
    assert!(second.payload.contains("/home/agent/eicar_exact_proof.com"));
    assert!(runtime.raw_event_backlog.is_empty());
}

#[test]
fn next_raw_event_continues_polling_kernel_when_backlog_is_non_empty() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let replay_path = std::env::temp_dir().join(format!(
        "eguard-agent-next-raw-event-replay-{}.ndjson",
        nonce
    ));
    let replay = r#"{"event_type":"file_open","pid":9901,"uid":1000,"ts_ns":1700000000000000000,"file_path":"/tmp/eicar_poll_while_backlogged.com","flags":0,"mode":0}"#;
    std::fs::write(&replay_path, replay).expect("write replay file");

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.ebpf_engine =
        platform_linux::EbpfEngine::from_replay(&replay_path).expect("replay backend");
    runtime.raw_event_backlog.push_back(platform_linux::RawEvent {
        event_type: platform_linux::EventType::FileOpen,
        pid: 1,
        uid: 0,
        ts_ns: 1,
        payload: "path=/sys/fs/cgroup/user.slice/memory.events;flags=0;mode=0;ppid=0;cgroup_id=30;comm=systemd;parent_comm=swapper/0".to_string(),
    });

    let next = runtime.next_raw_event().expect("next raw event");
    assert!(next
        .payload
        .contains("/tmp/eicar_poll_while_backlogged.com"));
    assert_eq!(runtime.raw_event_backlog.len(), 1);
    assert!(runtime
        .raw_event_backlog
        .front()
        .expect("remaining backlog event")
        .payload
        .contains("/sys/fs/cgroup/user.slice/memory.events"));

    let _ = std::fs::remove_file(replay_path);
}
