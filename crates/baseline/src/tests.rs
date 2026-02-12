use super::*;

#[test]
fn baseline_store_roundtrip_persists() {
    let path = std::env::temp_dir().join(format!(
        "eguard-baseline-{}.bin",
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
    store.save().expect("save store");

    let loaded = BaselineStore::load(&path).expect("load store");
    assert_eq!(loaded.baselines.len(), 1);

    let _ = std::fs::remove_file(path);
}

#[test]
// AC-BSL-004 AC-BSL-005
fn transitions_learning_to_active() {
    let path = std::env::temp_dir().join(format!(
        "eguard-baseline-{}.bin",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let mut store = BaselineStore::new(&path).expect("create store");
    let now = store.learning_started_unix + LEARNING_WINDOW_SECS + 1;
    let transition = store.check_transition_with_now(now);
    assert_eq!(transition, Some(BaselineTransition::LearningComplete));
    assert_eq!(store.status, BaselineStatus::Active);
}

#[test]
// AC-BSL-039
fn transitions_active_to_stale() {
    let path = std::env::temp_dir().join(format!(
        "eguard-baseline-{}.bin",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let mut store = BaselineStore::new(&path).expect("create store");
    store.status = BaselineStatus::Active;
    store.last_refresh_unix = 0;

    let transition = store.check_transition_with_now(STALE_WINDOW_SECS + 1);
    assert_eq!(transition, Some(BaselineTransition::BecameStale));
    assert_eq!(store.status, BaselineStatus::Stale);
}

#[test]
// AC-BSL-004
fn learning_does_not_transition_before_window() {
    let path = std::env::temp_dir().join(format!(
        "eguard-baseline-{}.bin",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let mut store = BaselineStore::new(&path).expect("create store");
    let now = store.learning_started_unix + LEARNING_WINDOW_SECS - 1;
    let transition = store.check_transition_with_now(now);
    assert_eq!(transition, None);
    assert_eq!(store.status, BaselineStatus::Learning);
}

#[test]
fn active_does_not_become_stale_before_window() {
    let path = std::env::temp_dir().join(format!(
        "eguard-baseline-{}.bin",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let mut store = BaselineStore::new(&path).expect("create store");
    store.status = BaselineStatus::Active;
    store.last_refresh_unix = 500;

    let transition = store.check_transition_with_now(500 + STALE_WINDOW_SECS - 1);
    assert_eq!(transition, None);
    assert_eq!(store.status, BaselineStatus::Active);
}

#[test]
fn learn_event_updates_distribution_and_sample_count() {
    let path = std::env::temp_dir().join(format!(
        "eguard-baseline-{}.bin",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let mut store = BaselineStore::new(&path).expect("create store");
    let key = ProcessKey {
        comm: "bash".to_string(),
        parent_comm: "sshd".to_string(),
    };

    store.learn_event(key.clone(), "process_exec");
    store.learn_event(key.clone(), "process_exec");
    store.learn_event(key.clone(), "network_connect");

    let profile = store.baselines.get(&key).expect("profile created");
    assert_eq!(profile.sample_count, 3);
    assert_eq!(profile.event_distribution.get("process_exec"), Some(&2));
    assert_eq!(profile.event_distribution.get("network_connect"), Some(&1));
}

#[test]
fn init_entropy_baselines_normalizes_distribution() {
    let path = std::env::temp_dir().join(format!(
        "eguard-baseline-{}.bin",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let mut store = BaselineStore::new(&path).expect("create store");
    let key = ProcessKey {
        comm: "python".to_string(),
        parent_comm: "bash".to_string(),
    };
    store.learn_event(key, "process_exec");
    store.learn_event(
        ProcessKey {
            comm: "python".to_string(),
            parent_comm: "bash".to_string(),
        },
        "process_exec",
    );
    store.learn_event(
        ProcessKey {
            comm: "python".to_string(),
            parent_comm: "bash".to_string(),
        },
        "dns_query",
    );

    let out = store.init_entropy_baselines();
    let dist = out
        .get(&("python".to_string(), "bash".to_string()))
        .expect("baseline distribution");
    let total = dist.values().sum::<f64>();
    assert!((total - 1.0).abs() < 1e-9);
    assert!((dist.get("process_exec").copied().unwrap_or_default() - (2.0 / 3.0)).abs() < 1e-9);
    assert!((dist.get("dns_query").copied().unwrap_or_default() - (1.0 / 3.0)).abs() < 1e-9);
}

#[test]
fn load_or_new_creates_then_loads_existing_store() {
    let path = std::env::temp_dir().join(format!(
        "eguard-baseline-{}.bin",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let mut first = BaselineStore::load_or_new(&path).expect("load or new first");
    first.learn_event(
        ProcessKey {
            comm: "bash".to_string(),
            parent_comm: "sshd".to_string(),
        },
        "process_exec",
    );
    first.save().expect("save first");

    let second = BaselineStore::load_or_new(&path).expect("load or new second");
    assert_eq!(second.baselines.len(), 1);

    let _ = std::fs::remove_file(path);
}

#[test]
fn learning_completion_derives_entropy_thresholds() {
    let path = std::env::temp_dir().join(format!(
        "eguard-baseline-{}.bin",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let mut store = BaselineStore::new(&path).expect("create store");
    let key = ProcessKey {
        comm: "node".to_string(),
        parent_comm: "systemd".to_string(),
    };
    for _ in 0..100 {
        store.learn_event(key.clone(), "process_exec");
    }

    let now = store.learning_started_unix + LEARNING_WINDOW_SECS + 1;
    let transition = store.check_transition_with_now(now);
    assert_eq!(transition, Some(BaselineTransition::LearningComplete));

    let profile = store.baselines.get(&key).expect("profile exists");
    assert!((profile.entropy_threshold - derive_entropy_threshold(100)).abs() < 1e-9);
}

#[test]
fn process_baseline_observe_updates_counts_and_sample_total() {
    let mut baseline = ProcessBaseline::new("bash:sshd".to_string());
    baseline.observe("process_exec");
    baseline.observe("process_exec");
    baseline.observe("network_connect");

    assert_eq!(baseline.sample_count(), 3);
    assert_eq!(baseline.counts.get("process_exec"), Some(&2));
    assert_eq!(baseline.counts.get("network_connect"), Some(&1));
}

#[test]
fn learning_completion_updates_last_refresh_timestamp() {
    let path = std::env::temp_dir().join(format!(
        "eguard-baseline-{}.bin",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let mut store = BaselineStore::new(&path).expect("create store");
    let before = store.last_refresh_unix;
    let now = store.learning_started_unix + LEARNING_WINDOW_SECS + 1;

    let transition = store.check_transition_with_now(now);
    assert_eq!(transition, Some(BaselineTransition::LearningComplete));
    assert!(store.last_refresh_unix >= before);
    assert_eq!(store.last_refresh_unix, now);
}
