use super::*;
use ::baseline::{BaselineStore, ProcessKey, ProcessProfile};
use grpc_client::FleetBaselineEnvelope;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn env_lock() -> &'static std::sync::Mutex<()> {
    crate::test_support::env_lock()
}

fn unique_baseline_path(prefix: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "{prefix}-{}.bin",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ))
}

#[test]
fn baseline_store_loading_seeds_defaults_for_fresh_deployments_and_persists_them() {
    let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
    let path = unique_baseline_path("eguard-baseline-seed");
    let _ = std::fs::remove_file(&path);

    std::env::set_var("EGUARD_BASELINE_PATH", &path);
    let store = load_baseline_store().expect("load baseline store");
    std::env::remove_var("EGUARD_BASELINE_PATH");

    assert_eq!(store.path(), path.as_path());
    assert!(
        store.baselines.len() >= 5,
        "expected built-in seed profiles"
    );
    assert!(path.exists(), "seeded baseline store should be persisted");

    let reloaded = BaselineStore::load(&path).expect("reload seeded baseline store");
    assert_eq!(reloaded.baselines.len(), store.baselines.len());
    assert!(reloaded.baselines.contains_key(&ProcessKey {
        comm: "bash".to_string(),
        parent_comm: "sshd".to_string(),
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn baseline_store_loading_preserves_existing_profiles_without_reseeding_defaults() {
    let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
    let path = unique_baseline_path("eguard-baseline-existing");
    let _ = std::fs::remove_file(&path);

    let mut existing = BaselineStore::new(path.clone()).expect("create baseline store");
    existing.learn_event(
        ProcessKey {
            comm: "custom-proc".to_string(),
            parent_comm: "custom-parent".to_string(),
        },
        "process_exec",
    );
    existing.save().expect("save existing baseline store");

    std::env::set_var("EGUARD_BASELINE_PATH", &path);
    let loaded = load_baseline_store().expect("load existing baseline store");
    std::env::remove_var("EGUARD_BASELINE_PATH");

    assert_eq!(
        loaded.baselines.len(),
        1,
        "existing store must not be reseeded"
    );
    assert!(loaded.baselines.contains_key(&ProcessKey {
        comm: "custom-proc".to_string(),
        parent_comm: "custom-parent".to_string(),
    }));
    assert!(!loaded.baselines.contains_key(&ProcessKey {
        comm: "bash".to_string(),
        parent_comm: "sshd".to_string(),
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn apply_fleet_baseline_seeds_adds_missing_profiles_and_strengthens_weak_locals() {
    let path = unique_baseline_path("eguard-fleet-seed-apply");
    let _ = std::fs::remove_file(&path);

    let mut store = BaselineStore::new(path.clone()).expect("create baseline store");
    store.learn_event(
        ProcessKey {
            comm: "bash".to_string(),
            parent_comm: "sshd".to_string(),
        },
        "process_exec",
    );

    let mut distribution = std::collections::HashMap::new();
    distribution.insert("process_exec".to_string(), 0.7);
    distribution.insert("dns_query".to_string(), 0.3);

    let seeded = apply_fleet_baseline_seeds(
        &mut store,
        &[
            FleetBaselineEnvelope {
                process_key: "bash:sshd".to_string(),
                median_distribution: distribution.clone(),
                agent_count: 9,
                stddev_kl: 0.2,
                source: "fleet_aggregated".to_string(),
            },
            FleetBaselineEnvelope {
                process_key: "nginx:systemd".to_string(),
                median_distribution: distribution,
                agent_count: 12,
                stddev_kl: 0.1,
                source: "fleet_aggregated".to_string(),
            },
        ],
    );

    assert_eq!(seeded, 2, "weak local + missing profile should be seeded");
    assert!(store.baselines.contains_key(&ProcessKey {
        comm: "nginx".to_string(),
        parent_comm: "systemd".to_string(),
    }));

    let strengthened = store
        .baselines
        .get(&ProcessKey {
            comm: "bash".to_string(),
            parent_comm: "sshd".to_string(),
        })
        .expect("strengthened local profile");
    assert!(strengthened.sample_count >= 1000);
    assert!(strengthened.event_distribution.contains_key("dns_query"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn apply_fleet_baseline_seeds_keeps_mature_local_profiles() {
    let path = unique_baseline_path("eguard-fleet-seed-mature");
    let _ = std::fs::remove_file(&path);

    let mut store = BaselineStore::new(path.clone()).expect("create baseline store");
    let key = ProcessKey {
        comm: "bash".to_string(),
        parent_comm: "sshd".to_string(),
    };
    for _ in 0..1200 {
        store.learn_event(key.clone(), "process_exec");
    }
    store.force_active(store.learning_started_unix + (8 * 24 * 3600));

    let mut distribution = std::collections::HashMap::new();
    distribution.insert("process_exec".to_string(), 0.6);
    distribution.insert("dns_query".to_string(), 0.4);

    let seeded = apply_fleet_baseline_seeds(
        &mut store,
        &[FleetBaselineEnvelope {
            process_key: "bash:sshd".to_string(),
            median_distribution: distribution,
            agent_count: 9,
            stddev_kl: 0.2,
            source: "fleet_aggregated".to_string(),
        }],
    );

    assert_eq!(seeded, 0, "mature local profile must not be overwritten");
    let profile = store.baselines.get(&key).expect("mature profile exists");
    assert!(!profile.event_distribution.contains_key("dns_query"));

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn baseline_upload_dirty_trigger_runs_without_waiting_interval() {
    let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("EGUARD_BASELINE_UPLOAD_MAX_BYTES", "1");

    let cfg = crate::config::AgentConfig {
        transport_mode: "http".to_string(),
        server_addr: "http://127.0.0.1:65535".to_string(),
        ..crate::config::AgentConfig::default()
    };

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.baseline_upload_enabled = true;

    let now = 1_700_123_456i64;
    runtime.last_baseline_upload_unix = Some(now);

    for i in 0..BASELINE_UPLOAD_BATCH_SIZE {
        let key = ProcessKey {
            comm: format!("trigger-proc-{i}"),
            parent_comm: "trigger-parent".to_string(),
        };
        runtime.baseline_store.baselines.insert(
            key.clone(),
            ProcessProfile {
                event_distribution: [("process_exec".to_string(), 1u64)].into_iter().collect(),
                sample_count: 1,
                entropy_threshold: 0.0,
            },
        );
        runtime
            .dirty_baseline_keys
            .insert(format!("{}:{}", key.comm, key.parent_comm));
    }

    runtime
        .upload_baseline_profiles_if_due(now)
        .await
        .expect("dirty-trigger upload path should execute");

    assert_eq!(runtime.metrics.baseline_upload_payload_reject_total, 1);

    std::env::remove_var("EGUARD_BASELINE_UPLOAD_MAX_BYTES");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn baseline_upload_canary_zero_disables_upload_path() {
    let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("EGUARD_BASELINE_UPLOAD_CANARY_PERCENT", "0");

    let cfg = crate::config::AgentConfig {
        transport_mode: "http".to_string(),
        server_addr: "http://127.0.0.1:65535".to_string(),
        ..crate::config::AgentConfig::default()
    };

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.baseline_upload_enabled = true;

    let key = ProcessKey {
        comm: "canary-off".to_string(),
        parent_comm: "systemd".to_string(),
    };
    runtime.baseline_store.baselines.insert(
        key.clone(),
        ProcessProfile {
            event_distribution: [("process_exec".to_string(), 1u64)]
                .into_iter()
                .collect(),
            sample_count: 1,
            entropy_threshold: 0.0,
        },
    );
    runtime
        .dirty_baseline_keys
        .insert(format!("{}:{}", key.comm, key.parent_comm));

    runtime
        .upload_baseline_profiles_if_due(1_700_200_000)
        .await
        .expect("upload path with canary 0 should no-op");

    assert_eq!(runtime.metrics.baseline_rows_uploaded_total, 0);
    assert!(runtime.last_baseline_upload_unix.is_none());

    std::env::remove_var("EGUARD_BASELINE_UPLOAD_CANARY_PERCENT");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn fleet_seed_canary_zero_disables_fetch_path() {
    let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("EGUARD_FLEET_SEED_CANARY_PERCENT", "0");

    let cfg = crate::config::AgentConfig {
        transport_mode: "http".to_string(),
        server_addr: "http://127.0.0.1:65535".to_string(),
        ..crate::config::AgentConfig::default()
    };

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.fleet_seed_enabled = true;
    runtime.baseline_store.status = ::baseline::BaselineStatus::Learning;

    runtime
        .fetch_and_apply_fleet_baselines_if_due(1_700_200_100)
        .await
        .expect("fleet fetch path with canary 0 should no-op");

    assert_eq!(runtime.metrics.baseline_seed_rows_applied_total, 0);
    assert!(runtime.last_fleet_baseline_fetch_unix.is_none());

    std::env::remove_var("EGUARD_FLEET_SEED_CANARY_PERCENT");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn baseline_upload_rejects_oversized_payload_and_tracks_metric() {
    let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("EGUARD_BASELINE_UPLOAD_MAX_BYTES", "128");

    let cfg = crate::config::AgentConfig {
        transport_mode: "http".to_string(),
        server_addr: "http://127.0.0.1:65535".to_string(),
        ..crate::config::AgentConfig::default()
    };

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.baseline_upload_enabled = true;

    let key = ProcessKey {
        comm: "oversized-proc".to_string(),
        parent_comm: "oversized-parent".to_string(),
    };
    let mut distribution = std::collections::HashMap::new();
    for i in 0..200usize {
        distribution.insert(format!("event_{i}"), 1u64);
    }

    runtime.baseline_store.baselines.insert(
        key.clone(),
        ProcessProfile {
            event_distribution: distribution,
            sample_count: 200,
            entropy_threshold: 2.5,
        },
    );
    let key_str = format!("{}:{}", key.comm, key.parent_comm);
    runtime.dirty_baseline_keys.insert(key_str.clone());

    runtime
        .upload_baseline_profiles_if_due(1_700_000_000)
        .await
        .expect("oversized payload path should not fail runtime");

    assert_eq!(runtime.metrics.baseline_upload_payload_reject_total, 1);
    assert!(runtime.dirty_baseline_keys.contains(&key_str));

    std::env::remove_var("EGUARD_BASELINE_UPLOAD_MAX_BYTES");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn baseline_e2e_upload_fetch_seed_flow_works() {
    let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
    let baseline_path = unique_baseline_path("eguard-baseline-e2e-loop");
    let _ = std::fs::remove_file(&baseline_path);
    std::env::set_var("EGUARD_BASELINE_PATH", &baseline_path);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock baseline server");
    let addr = listener.local_addr().expect("mock server addr");
    let request_flags = std::sync::Arc::new(std::sync::Mutex::new((false, false)));
    let request_flags_clone = request_flags.clone();

    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let mut request_buf = vec![0u8; 64 * 1024];
            let read_len = stream.read(&mut request_buf).await.expect("read request");
            let request = std::str::from_utf8(&request_buf[..read_len]).expect("request utf8");
            let request_line = request.lines().next().unwrap_or_default();

            if request_line.starts_with("POST /api/v1/endpoint/baseline/batch ") {
                if let Ok(mut guard) = request_flags_clone.lock() {
                    guard.0 = true;
                }
                let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write upload response");
            } else if request_line.starts_with("GET /api/v1/endpoint/baseline/fleet") {
                if let Ok(mut guard) = request_flags_clone.lock() {
                    guard.1 = true;
                }
                let body = r#"{
  "status":"ok",
  "seeded":false,
  "fleet_baselines":[
    {
      "process_key":"customapp:systemd",
      "median_distribution":{
        "process_exec":0.6,
        "dns_query":0.4
      },
      "agent_count":7,
      "stddev_kl":0.08,
      "source":"fleet_aggregated"
    }
  ]
}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body,
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write fleet response");
            } else {
                let response =
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write 404 response");
            }
        }
    });

    let cfg = crate::config::AgentConfig {
        transport_mode: "http".to_string(),
        server_addr: addr.to_string(),
        ..crate::config::AgentConfig::default()
    };

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.baseline_upload_enabled = true;
    runtime.fleet_seed_enabled = true;
    runtime.baseline_store.status = ::baseline::BaselineStatus::Learning;

    let local_key = ProcessKey {
        comm: "bash".to_string(),
        parent_comm: "sshd".to_string(),
    };
    runtime.baseline_store.baselines.insert(
        local_key.clone(),
        ProcessProfile {
            event_distribution: [("process_exec".to_string(), 10u64)].into_iter().collect(),
            sample_count: 10,
            entropy_threshold: 0.0,
        },
    );
    runtime
        .dirty_baseline_keys
        .insert(format!("{}:{}", local_key.comm, local_key.parent_comm));

    let now = 1_700_100_000i64;
    runtime
        .upload_baseline_profiles_if_due(now)
        .await
        .expect("upload baseline batch");
    runtime
        .fetch_and_apply_fleet_baselines_if_due(now + 1)
        .await
        .expect("fetch and apply fleet seed");

    let (upload_seen, fetch_seen) = *request_flags.lock().expect("request flags lock");
    assert!(upload_seen, "baseline upload endpoint should be hit");
    assert!(fetch_seen, "fleet baseline fetch endpoint should be hit");

    assert!(runtime.baseline_store.baselines.contains_key(&ProcessKey {
        comm: "customapp".to_string(),
        parent_comm: "systemd".to_string(),
    }));
    assert!(runtime.metrics.baseline_rows_uploaded_total >= 1);
    assert!(runtime.metrics.baseline_seed_rows_applied_total >= 1);

    std::env::remove_var("EGUARD_BASELINE_PATH");
    let _ = std::fs::remove_file(&baseline_path);
    let mut journal = baseline_path.clone();
    journal.set_extension("journal");
    let _ = std::fs::remove_file(&journal);
    let mut meta = baseline_path.clone();
    meta.set_extension("journal.meta");
    let _ = std::fs::remove_file(meta);

    server.await.expect("mock server join");
}
