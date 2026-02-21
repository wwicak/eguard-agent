use super::*;
use ::baseline::{BaselineStore, ProcessKey};
use grpc_client::FleetBaselineEnvelope;

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
fn apply_fleet_baseline_seeds_adds_missing_learning_profiles() {
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

    assert_eq!(seeded, 1, "existing local key must not be overwritten");
    assert!(store.baselines.contains_key(&ProcessKey {
        comm: "nginx".to_string(),
        parent_comm: "systemd".to_string(),
    }));

    let _ = std::fs::remove_file(path);
}
