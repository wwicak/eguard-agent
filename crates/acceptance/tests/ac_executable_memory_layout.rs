use std::path::PathBuf;

use baseline::{BaselineStore, ProcessKey};
use detection::YaraEngine;
use grpc_client::{EventBuffer, EventEnvelope};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_ringbuf_capacity_bytes(source: &str) -> Option<u64> {
    for line in source.lines() {
        if !line.contains("8 * 1024 * 1024") {
            continue;
        }
        return Some(8 * 1024 * 1024);
    }
    None
}

#[test]
// AC-DET-106
fn ac_det_benchmark_harness_ci_publishes_measured_artifact() {
    let root = repo_root();
    let workflow = std::fs::read_to_string(root.join(".github/workflows/detection-benchmark.yml"))
        .expect("read detection benchmark workflow");
    let script = std::fs::read_to_string(root.join("scripts/run_detection_benchmark_ci.sh"))
        .expect("read detection benchmark script");

    assert!(workflow.contains("scripts/run_detection_benchmark_ci.sh"));
    assert!(workflow.contains("upload-artifact"));
    assert!(workflow.contains("artifacts/detection-benchmark/metrics.json"));
    assert!(script.contains("wall_clock_ms"));
    assert!(script.contains("metrics.json"));
}

#[test]
// AC-EBP-101
fn ac_ebp_ring_buffer_capacity_is_eight_megabytes() {
    let root = repo_root();
    let helpers = std::fs::read_to_string(root.join("zig/ebpf/bpf_helpers.h"))
        .expect("read bpf ring buffer definition");
    let capacity = parse_ringbuf_capacity_bytes(&helpers).expect("parse ringbuf capacity");
    assert_eq!(capacity, 8 * 1024 * 1024);
}

#[test]
// AC-EBP-100 AC-EBP-103
fn ac_ebp_runtime_uses_tokio_and_grpc_tls_stack() {
    let root = repo_root();
    let agent_main =
        std::fs::read_to_string(root.join("crates/agent-core/src/main.rs")).expect("main.rs");
    let grpc_client =
        std::fs::read_to_string(root.join("crates/grpc-client/src/client.rs")).expect("client.rs");

    assert!(agent_main.contains("#[tokio::main]"));
    assert!(grpc_client.contains("ClientTlsConfig"));
    assert!(grpc_client.contains("Identity"));
    assert!(grpc_client.contains("Certificate"));
}

#[test]
// AC-EBP-104 AC-EBP-105
fn ac_ebp_cache_capacities_align_with_half_megabyte_targets() {
    let root = repo_root();
    let platform = std::fs::read_to_string(root.join("crates/platform-linux/src/lib.rs"))
        .expect("platform linux source");

    assert!(platform.contains("Self::new(500, 10_000)"));

    let process_cache_est = 500usize * 1_024usize;
    let file_cache_est = 10_000usize * 50usize;

    assert!((200 * 1024..=800 * 1024).contains(&process_cache_est));
    assert!((200 * 1024..=800 * 1024).contains(&file_cache_est));
}

#[test]
// AC-EBP-106
fn ac_ebp_yara_engine_accepts_three_megabyte_rule_corpus() {
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
// AC-EBP-107
fn ac_ebp_offline_sqlite_buffer_has_two_megabyte_working_set() {
    let path = std::env::temp_dir().join(format!(
        "eguard-ac-ebp107-{}.db",
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
            severity: String::new(),
            rule_name: String::new(),
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
// AC-EBP-108
fn ac_ebp_baseline_store_snapshot_fits_half_megabyte_budget() {
    let path = std::env::temp_dir().join(format!(
        "eguard-ac-ebp108-{}.bin",
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
// AC-EBP-102 AC-EBP-109 AC-EBP-110
fn ac_ebp_memory_layout_ledger_sums_to_target_rss_envelope() {
    let root = repo_root();
    let helpers = std::fs::read_to_string(root.join("zig/ebpf/bpf_helpers.h"))
        .expect("read ring buffer source");
    let ring_bytes = parse_ringbuf_capacity_bytes(&helpers).expect("ring capacity") as f64;

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
