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
    let local_key = ProcessKey {
        comm: "bash".to_string(),
        parent_comm: "sshd".to_string(),
    };
    for _ in 0..1200 {
        store.learn_event(local_key.clone(), "process_exec");
    }
    store.force_active(store.learning_started_unix + LEARNING_WINDOW_SECS + 1);

    let mut dist = HashMap::new();
    dist.insert("process_exec".to_string(), 0.6);
    dist.insert("dns_query".to_string(), 0.4);

    let seeded_existing = store.seed_from_fleet_baseline("bash:sshd", &dist, 1200);
    assert!(
        !seeded_existing,
        "matured local profile must win over fleet seed"
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
fn fleet_seed_can_strengthen_weak_local_profile() {
    let path = std::env::temp_dir().join(format!(
        "eguard-baseline-fleet-weak-local-{}.bin",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let mut store = BaselineStore::new(&path).expect("create store");
    store.learn_event(
        ProcessKey {
            comm: "python3".to_string(),
            parent_comm: "bash".to_string(),
        },
        "process_exec",
    );

    let mut dist = HashMap::new();
    dist.insert("process_exec".to_string(), 0.5);
    dist.insert("dns_query".to_string(), 0.5);

    let seeded = store.seed_from_fleet_baseline("python3:bash", &dist, 1200);
    assert!(
        seeded,
        "weak local profile should be strengthened by fleet seed"
    );

    let profile = store
        .baselines
        .get(&ProcessKey {
            comm: "python3".to_string(),
            parent_comm: "bash".to_string(),
        })
        .expect("strengthened profile");
    assert!(profile.sample_count >= 1000);
    assert!(profile.event_distribution.contains_key("dns_query"));
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

// --- Bayesian Dirichlet prior tests ---

fn make_temp_store(label: &str) -> BaselineStore {
    let path = std::env::temp_dir().join(format!(
        "eguard-baseline-{}-{}.bin",
        label,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    BaselineStore::new(&path).expect("create store")
}

#[test]
fn bayesian_zero_local_samples_fleet_fully_dominates() {
    let mut store = make_temp_store("bayes-zero-local");

    let mut dist = HashMap::new();
    dist.insert("process_exec".to_string(), 0.7);
    dist.insert("dns_query".to_string(), 0.3);

    let seeded = store.seed_from_fleet_baseline("curl:bash", &dist, 1000);
    assert!(seeded);

    let profile = store
        .baselines
        .get(&ProcessKey {
            comm: "curl".to_string(),
            parent_comm: "bash".to_string(),
        })
        .expect("profile");

    // decay_factor = 1.0 (no local data), concentration = 1000
    // alpha(process_exec) = 0.7 * 1000 = 700, alpha(dns_query) = 0.3 * 1000 = 300
    let exec_count = profile.event_distribution["process_exec"];
    let dns_count = profile.event_distribution["dns_query"];
    assert_eq!(exec_count, 700);
    assert_eq!(dns_count, 300);
    assert_eq!(profile.sample_count, 1000);
}

#[test]
fn bayesian_half_local_samples_fleet_influence_halved() {
    let mut store = make_temp_store("bayes-half-local");

    let key = ProcessKey {
        comm: "node".to_string(),
        parent_comm: "bash".to_string(),
    };
    // Build 500 local observations: all process_exec.
    for _ in 0..500 {
        store.learn_event(key.clone(), "process_exec");
    }

    let mut dist = HashMap::new();
    dist.insert("process_exec".to_string(), 0.5);
    dist.insert("network_connect".to_string(), 0.5);

    let seeded = store.seed_from_fleet_baseline("node:bash", &dist, 1000);
    assert!(seeded);

    let profile = store.baselines.get(&key).expect("profile");

    // decay_factor = max(0.01, 1.0 - 500/1000) = 0.5
    // concentration = 1000 * 0.5 = 500
    // alpha(process_exec) = 0.5 * 500 = 250, alpha(network_connect) = 0.5 * 500 = 250
    // posterior(process_exec) = 250 + 500 = 750
    // posterior(network_connect) = 250 + 0 = 250
    // total = 1000
    let exec_count = profile.event_distribution["process_exec"];
    let net_count = profile.event_distribution["network_connect"];
    assert_eq!(exec_count, 750);
    assert_eq!(net_count, 250);
    assert_eq!(profile.sample_count, 1000);
}

#[test]
fn bayesian_near_mature_local_dominates_over_fleet() {
    let mut store = make_temp_store("bayes-near-mature");

    let key = ProcessKey {
        comm: "redis".to_string(),
        parent_comm: "systemd".to_string(),
    };
    // 999 local samples: 800 process_exec, 199 file_open.
    for _ in 0..800 {
        store.learn_event(key.clone(), "process_exec");
    }
    for _ in 0..199 {
        store.learn_event(key.clone(), "file_open");
    }

    // Fleet says 100% dns_query — should barely affect the posterior.
    let mut dist = HashMap::new();
    dist.insert("dns_query".to_string(), 1.0);

    let seeded = store.seed_from_fleet_baseline("redis:systemd", &dist, 1000);
    assert!(seeded);

    let profile = store.baselines.get(&key).expect("profile");

    // decay_factor = max(0.01, 1.0 - 999/1000) = max(0.01, 0.001) = 0.01
    // concentration = 1000 * 0.01 = 10
    // alpha(dns_query) = 1.0 * 10 = 10
    // posterior(process_exec) = 0 + 800 = 800
    // posterior(file_open) = 0 + 199 = 199
    // posterior(dns_query) = 10 + 0 = 10
    // total = 1009
    let exec_count = profile.event_distribution["process_exec"];
    let file_count = profile.event_distribution["file_open"];
    let dns_count = profile.event_distribution["dns_query"];
    assert_eq!(exec_count, 800);
    assert_eq!(file_count, 199);
    assert_eq!(dns_count, 10);

    // Local dominates: process_exec is ~79% of posterior, fleet's dns_query is ~1%.
    let total = profile.sample_count as f64;
    assert!(exec_count as f64 / total > 0.78);
    assert!(dns_count as f64 / total < 0.02);
}

#[test]
fn bayesian_all_zero_fleet_distribution_returns_false() {
    let mut store = make_temp_store("bayes-all-zero");

    let mut dist = HashMap::new();
    dist.insert("process_exec".to_string(), 0.0);
    dist.insert("dns_query".to_string(), -1.0);
    dist.insert("file_open".to_string(), f64::NAN);

    let seeded = store.seed_from_fleet_baseline("bad:fleet", &dist, 1000);
    assert!(
        !seeded,
        "all-zero/invalid fleet distribution must be rejected"
    );
}

#[test]
fn bayesian_single_event_fleet_works() {
    let mut store = make_temp_store("bayes-single-event");

    let mut dist = HashMap::new();
    dist.insert("network_connect".to_string(), 1.0);

    let seeded = store.seed_from_fleet_baseline("wget:bash", &dist, 2000);
    assert!(seeded);

    let profile = store
        .baselines
        .get(&ProcessKey {
            comm: "wget".to_string(),
            parent_comm: "bash".to_string(),
        })
        .expect("profile");

    // concentration = 2000 * 1.0 = 2000, single event gets all of it.
    assert_eq!(profile.event_distribution.len(), 1);
    assert_eq!(profile.event_distribution["network_connect"], 2000);
    assert_eq!(profile.sample_count, 2000);
}
