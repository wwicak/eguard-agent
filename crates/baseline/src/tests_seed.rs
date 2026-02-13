use super::*;

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
