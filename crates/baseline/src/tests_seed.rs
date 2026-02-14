use super::*;
use std::collections::HashMap;

#[test]
fn seed_defaults_populate_profiles_when_store_is_empty() {
    let path = std::env::temp_dir().join(format!(
        "eguard-baseline-seed-{}.bin",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let mut store = BaselineStore::new(&path).expect("create store");
    assert!(store.baselines.is_empty());

    let seeded = store.seed_with_defaults_if_empty();
    assert!(seeded >= 5);
    assert_eq!(seeded, store.baselines.len());

    let key = ProcessKey {
        comm: "bash".to_string(),
        parent_comm: "sshd".to_string(),
    };
    let profile = store.baselines.get(&key).expect("seed profile exists");
    assert!(profile.sample_count > 0);
    assert!(profile.entropy_threshold > 1.0);
}

#[test]
fn seed_defaults_do_not_override_existing_baselines() {
    let path = std::env::temp_dir().join(format!(
        "eguard-baseline-seed-existing-{}.bin",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let mut store = BaselineStore::new(&path).expect("create store");
    let key = ProcessKey {
        comm: "custom".to_string(),
        parent_comm: "launcher".to_string(),
    };
    store.learn_event(key.clone(), "process_exec");

    let seeded = store.seed_with_defaults_if_empty();
    assert_eq!(seeded, 0);
    assert_eq!(store.baselines.len(), 1);
    assert!(store.baselines.contains_key(&key));
}

#[test]
fn fleet_seed_populates_missing_profiles_without_overwriting_existing_local_learning() {
    let path = std::env::temp_dir().join(format!(
        "eguard-baseline-fleet-seed-{}.bin",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let mut store = BaselineStore::new(&path).expect("create store");
    store.learn_event(
        ProcessKey {
            comm: "bash".to_string(),
            parent_comm: "sshd".to_string(),
        },
        "process_exec",
    );

    let mut dist = HashMap::new();
    dist.insert("process_exec".to_string(), 0.6);
    dist.insert("dns_query".to_string(), 0.4);

    let seeded_existing = store.seed_from_fleet_baseline("bash:sshd", &dist, 1200);
    assert!(
        !seeded_existing,
        "existing local profile must win over fleet seed"
    );

    let seeded_new = store.seed_from_fleet_baseline("nginx:systemd", &dist, 1200);
    assert!(seeded_new, "new fleet profile should be seeded");

    let nginx = store
        .baselines
        .get(&ProcessKey {
            comm: "nginx".to_string(),
            parent_comm: "systemd".to_string(),
        })
        .expect("seeded nginx profile");
    assert!(nginx.sample_count >= 1000);
    assert!(nginx.event_distribution.contains_key("process_exec"));
    assert!(nginx.event_distribution.contains_key("dns_query"));
    assert!(nginx.entropy_threshold > 1.0);
}

#[test]
fn fleet_seed_normalizes_path_like_process_keys_to_fleet_parent() {
    let path = std::env::temp_dir().join(format!(
        "eguard-baseline-fleet-path-key-{}.bin",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let mut store = BaselineStore::new(&path).expect("create store");
    let mut dist = HashMap::new();
    dist.insert("process_exec".to_string(), 0.5);
    dist.insert("network_connect".to_string(), 0.5);

    let seeded = store.seed_from_fleet_baseline("/usr/bin/systemd", &dist, 500);
    assert!(seeded, "path-like keys should still seed a usable baseline");

    assert!(store.baselines.contains_key(&ProcessKey {
        comm: "systemd".to_string(),
        parent_comm: "fleet".to_string(),
    }));
}
