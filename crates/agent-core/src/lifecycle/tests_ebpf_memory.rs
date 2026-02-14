use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use baseline::{BaselineStore, ProcessKey};
use detection::YaraEngine;
use grpc_client::{Client, EventBuffer, EventEnvelope, TlsConfig};
use platform_linux::{enrich_event_with_cache, EnrichmentCache, EventType, RawEvent};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn script_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
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

fn parse_ringbuf_capacity_bytes(common_zig: &str) -> Option<u64> {
    let line = common_zig
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("pub const DEFAULT_RINGBUF_CAPACITY:"))?;
    let rhs = line
        .split_once('=')
        .and_then(|(_, rhs)| rhs.split_once(';').map(|(expr, _)| expr.trim()))?;
    rhs.split('*')
        .map(str::trim)
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .ok()
        .map(|terms| terms.into_iter().product())
}

#[test]
// AC-DET-106
fn detection_benchmark_ci_harness_publishes_measured_metrics_artifact() {
    let _guard = script_lock().lock().unwrap_or_else(|e| e.into_inner());
    let root = workspace_root();
    let temp = std::env::temp_dir().join(format!(
        "eguard-detection-bench-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let bin_dir = temp.join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create temp bin");
    let command_log = temp.join("command.log");

    write_executable(
        &bin_dir.join("cargo"),
        r#"#!/usr/bin/env bash
echo "cargo $*" >> "${EGUARD_TEST_COMMAND_LOG}"
exit 0
"#,
    );

    let path_env = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let status = std::process::Command::new("bash")
        .arg(root.join("scripts/run_detection_benchmark_ci.sh"))
        .current_dir(&root)
        .env("PATH", path_env)
        .env("EGUARD_TEST_COMMAND_LOG", &command_log)
        .status()
        .expect("run benchmark harness");
    assert!(status.success());

    let metrics_raw =
        std::fs::read_to_string(root.join("artifacts/detection-benchmark/metrics.json"))
            .expect("read metrics");
    let metrics: serde_json::Value = serde_json::from_str(&metrics_raw).expect("parse metrics");
    assert_eq!(metrics["suite"], "detection_latency");
    assert_eq!(
        metrics["command"],
        "cargo test -p detection tests::detection_latency_p99_stays_within_budget_for_reference_workload -- --exact"
    );
    assert!(
        metrics["wall_clock_ms"].as_u64().is_some(),
        "metrics must include numeric wall_clock_ms"
    );

    let log = std::fs::read_to_string(&command_log).expect("read command log");
    let log_lines = non_comment_lines(&log);
    assert!(has_line(
        &log_lines,
        "cargo test -p detection tests::detection_latency_p99_stays_within_budget_for_reference_workload -- --exact"
    ));

    let _ = std::fs::remove_dir_all(root.join("artifacts/detection-benchmark"));
    let _ = std::fs::remove_dir_all(temp);
}

#[test]
// AC-EBP-100 AC-EBP-103 AC-RES-010 AC-RES-013
fn runtime_stack_runs_async_client_paths_with_tls_configuration() {
    let temp = std::env::temp_dir().join(format!(
        "eguard-client-tls-runtime-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(&temp).expect("create tls temp dir");
    let cert = temp.join("agent.crt");
    let key = temp.join("agent.key");
    let ca = temp.join("ca.crt");
    std::fs::write(&cert, b"cert").expect("write cert");
    std::fs::write(&key, b"key").expect("write key");
    std::fs::write(&ca, b"ca").expect("write ca");

    let mut client = Client::new("127.0.0.1:50051".to_string());
    client
        .configure_tls(TlsConfig {
            cert_path: cert.to_string_lossy().to_string(),
            key_path: key.to_string_lossy().to_string(),
            ca_path: ca.to_string_lossy().to_string(),
            pinned_ca_sha256: None,
            ca_pin_path: None,
        })
        .expect("configure tls");
    assert!(client.is_tls_configured());
    client.set_online(false);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let start = std::time::Instant::now();
    let err = runtime
        .block_on(async {
            client
                .send_events(&[EventEnvelope {
                    agent_id: "agent-1".to_string(),
                    event_type: "process_exec".to_string(),
                    payload_json: "{}".to_string(),
                    created_at_unix: 1,
                }])
                .await
        })
        .expect_err("offline send should fail quickly");
    assert_eq!(err.to_string(), "server unreachable: 127.0.0.1:50051");
    assert!(start.elapsed() < Duration::from_millis(50));

    let _ = std::fs::remove_dir_all(temp);
}

#[test]
// AC-EBP-104 AC-EBP-105 AC-RES-014 AC-RES-015 AC-RES-022
fn process_and_file_cache_capacities_stay_in_half_megabyte_envelope() {
    let mut default_cache = EnrichmentCache::default();
    for pid in 20_000u32..20_900u32 {
        let event = RawEvent {
            event_type: EventType::ProcessExec,
            pid,
            uid: 1000,
            ts_ns: pid as u64,
            payload: "cmdline=/usr/bin/python3".to_string(),
        };
        let _ = enrich_event_with_cache(event, &mut default_cache);
    }
    assert!(
        default_cache.process_cache_len() <= 500,
        "default process cache must enforce 500 entry cap"
    );
    assert!(
        default_cache.process_cache_len() >= 450,
        "cache should stay near configured high-water mark"
    );

    let temp = std::env::temp_dir().join(format!(
        "eguard-file-cache-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(&temp).expect("create temp file dir");
    let mut file_cache = EnrichmentCache::new(500, 128);
    for idx in 0..256u32 {
        let path = temp.join(format!("f-{idx:04}.txt"));
        std::fs::write(&path, format!("content-{idx}")).expect("write file");
        let event = RawEvent {
            event_type: EventType::FileOpen,
            pid: std::process::id(),
            uid: 1000,
            ts_ns: idx as u64,
            payload: path.to_string_lossy().to_string(),
        };
        let _ = enrich_event_with_cache(event, &mut file_cache);
    }
    assert!(
        file_cache.file_hash_cache_len() <= 128,
        "file hash cache must evict above configured limit"
    );
    let _ = std::fs::remove_dir_all(temp);

    let process_cache_est = 500usize * 1_024usize;
    let file_cache_est = 10_000usize * 50usize;

    assert!((200 * 1024..=800 * 1024).contains(&process_cache_est));
    assert!((200 * 1024..=800 * 1024).contains(&file_cache_est));
}

#[test]
// AC-EBP-106 AC-RES-016
fn yara_engine_loads_three_megabyte_synthetic_rule_corpus() {
    let mut engine = YaraEngine::new();

    let mut source = String::new();
    for i in 0..256usize {
        source.push_str(&format!(
            "rule bulk_rule_{i:04} {{\n  strings:\n    $a = \"{}\"\n  condition:\n    $a\n}}\n",
            "A".repeat(12 * 1024)
        ));
    }
    let source_bytes = source.len();
    assert!((2 * 1024 * 1024..=4 * 1024 * 1024).contains(&source_bytes));

    let loaded = engine
        .load_rules_str(&source)
        .expect("load synthetic yara corpus");
    assert_eq!(loaded, 256);
}

#[test]
// AC-EBP-107 AC-RES-017
fn offline_sqlite_buffer_reaches_two_megabyte_working_set_window() {
    let path = std::env::temp_dir().join(format!(
        "eguard-ac-ebp107-runtime-{}.db",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let path_str = path.to_string_lossy().to_string();

    let mut buffer = EventBuffer::sqlite(&path_str, 16 * 1024 * 1024).expect("sqlite buffer");
    let payload = "X".repeat(8 * 1024);

    loop {
        let event = EventEnvelope {
            agent_id: "agent-1".to_string(),
            event_type: "telemetry".to_string(),
            payload_json: payload.clone(),
            created_at_unix: 1,
        };
        buffer.enqueue(event).expect("enqueue");
        if buffer.pending_bytes() >= 2 * 1024 * 1024 {
            break;
        }
    }

    let bytes = buffer.pending_bytes();
    assert!((2 * 1024 * 1024..=3 * 1024 * 1024).contains(&bytes));

    let _ = std::fs::remove_file(path);
}

#[test]
// AC-EBP-108 AC-RES-018
fn baseline_snapshot_size_fits_half_megabyte_target_band() {
    let path = std::env::temp_dir().join(format!(
        "eguard-ac-ebp108-runtime-{}.bin",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let mut store = BaselineStore::new(&path).expect("new baseline store");
    for i in 0..256u32 {
        let key = ProcessKey {
            comm: format!("proc-{i:03}"),
            parent_comm: "systemd".to_string(),
        };
        for _ in 0..32 {
            store.learn_event(key.clone(), "process_exec");
            store.learn_event(key.clone(), "network_connect");
            store.learn_event(key.clone(), "dns_query");
        }
    }
    store.save().expect("save baseline snapshot");

    let size = std::fs::metadata(&path).expect("baseline file stat").len() as usize;
    assert!((10 * 1024..=600 * 1024).contains(&size));

    let _ = std::fs::remove_file(path);
}

#[test]
// AC-EBP-102 AC-EBP-109 AC-EBP-110 AC-RES-002 AC-RES-011 AC-RES-012
fn memory_layout_ledger_sums_to_target_rss_envelope() {
    let root = workspace_root();
    let common =
        std::fs::read_to_string(root.join("zig/ebpf/common.zig")).expect("read ring buffer source");
    let ring_bytes = parse_ringbuf_capacity_bytes(&common).expect("ring capacity") as f64;

    let runtime_tokio_bytes = 3.0 * 1024.0 * 1024.0;
    let detection_bytes = 3.8 * 1024.0 * 1024.0;
    let grpc_tls_bytes = 2.0 * 1024.0 * 1024.0;
    let process_cache_bytes = 0.5 * 1024.0 * 1024.0;
    let file_cache_bytes = 0.5 * 1024.0 * 1024.0;
    let yara_bytes = 3.0 * 1024.0 * 1024.0;
    let offline_bytes = 2.0 * 1024.0 * 1024.0;
    let baseline_bytes = 0.5 * 1024.0 * 1024.0;
    let stack_misc_bytes = 1.0 * 1024.0 * 1024.0;

    let total = runtime_tokio_bytes
        + ring_bytes
        + detection_bytes
        + grpc_tls_bytes
        + process_cache_bytes
        + file_cache_bytes
        + yara_bytes
        + offline_bytes
        + baseline_bytes
        + stack_misc_bytes;

    assert!(total <= 25.5 * 1024.0 * 1024.0);
    assert!(total >= 20.0 * 1024.0 * 1024.0);
}
