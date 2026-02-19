use std::cmp::Ordering;
use std::path::PathBuf;

use super::bundle_guard::{
    compute_file_sha256_hex, enforce_bundle_signature_database_floor, enforce_signature_drop_guard,
    ensure_shard_bundle_summary_matches, signature_database_total, verify_bundle_sha256_if_present,
};
use super::download::resolve_signature_reference;
use super::state::{
    load_threat_intel_last_known_good_state, load_threat_intel_replay_floor_state,
    persist_threat_intel_last_known_good_state, persist_threat_intel_replay_floor_state,
    resolve_threat_intel_last_known_good_path, resolve_threat_intel_replay_floor_path,
};
use super::version::{
    compare_version_natural, ensure_publish_timestamp_floor, ensure_version_monotonicity,
};
use super::{
    RULE_BUNDLE_MAX_SIGNATURE_DROP_PCT_ENV, RULE_BUNDLE_MIN_SIGNATURE_TOTAL_ENV,
    THREAT_INTEL_LAST_KNOWN_GOOD_PATH_ENV, THREAT_INTEL_REPLAY_FLOOR_PATH_ENV,
};

#[test]
fn resolve_signature_reference_prefers_explicit_value() {
    let signature = resolve_signature_reference(
        "/api/v1/endpoint/threat-intel/bundle/rules-2026.02.14",
        "/api/v1/endpoint/threat-intel/bundle/rules-2026.02.14.sig",
    );
    assert_eq!(
        signature,
        "/api/v1/endpoint/threat-intel/bundle/rules-2026.02.14.sig"
    );
}

#[test]
fn resolve_signature_reference_falls_back_to_bundle_sidecar() {
    let signature =
        resolve_signature_reference("/api/v1/endpoint/threat-intel/bundle/rules-2026.02.14", "");
    assert_eq!(
        signature,
        "/api/v1/endpoint/threat-intel/bundle/rules-2026.02.14.sig"
    );
}

#[test]
fn verify_bundle_sha256_if_present_accepts_matching_digest() {
    let bundle_path = write_temp_bundle_file("sha256-accept", b"bundle-payload");
    let expected = compute_file_sha256_hex(&bundle_path).expect("compute bundle sha256");

    verify_bundle_sha256_if_present(&bundle_path, &format!("sha256:{}", expected))
        .expect("sha256 should match");

    let _ = std::fs::remove_file(bundle_path);
}

#[test]
fn verify_bundle_sha256_if_present_rejects_mismatch() {
    let bundle_path = write_temp_bundle_file("sha256-reject", b"bundle-payload");
    let err = verify_bundle_sha256_if_present(
        &bundle_path,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    )
    .expect_err("mismatch should be rejected");
    assert!(err.to_string().contains("sha256 mismatch"));

    let _ = std::fs::remove_file(bundle_path);
}

#[test]
fn compare_version_natural_handles_numeric_tokens() {
    assert_eq!(
        compare_version_natural("rules-2026.02.14.2", "rules-2026.02.14.10"),
        Ordering::Less
    );
    assert_eq!(
        compare_version_natural("rules-2026.02.14.10", "rules-2026.02.14.2"),
        Ordering::Greater
    );
}

#[test]
fn ensure_version_monotonicity_rejects_replay_or_downgrade() {
    let err = ensure_version_monotonicity(Some("rules-2026.02.14.10"), "rules-2026.02.14.2")
        .expect_err("downgrade should be rejected");
    assert!(err.to_string().contains("version replay detected"));
}

#[test]
fn ensure_version_monotonicity_accepts_cross_family_migration() {
    ensure_version_monotonicity(Some("v2"), "rules-2026.02.14.1")
        .expect("cross-family migration should not be rejected");
}

#[test]
fn ensure_publish_timestamp_floor_rejects_older_timestamp() {
    let err = ensure_publish_timestamp_floor(Some(1_700_000_100), 1_700_000_050)
        .expect_err("older timestamp should be rejected");
    assert!(err.to_string().contains("timestamp replay detected"));
}

#[test]
fn threat_intel_replay_floor_state_roundtrip_persists_and_loads() {
    let _guard = env_lock().lock().expect("lock env vars");
    let path = write_temp_replay_floor_path("roundtrip");
    std::env::set_var(THREAT_INTEL_REPLAY_FLOOR_PATH_ENV, &path);

    persist_threat_intel_replay_floor_state("rules-2026.02.14.10", 1_700_000_100)
        .expect("persist replay floor state");
    let resolved = resolve_threat_intel_replay_floor_path();
    assert_eq!(resolved, path);

    let loaded = load_threat_intel_replay_floor_state().expect("load replay floor state");
    assert_eq!(loaded.version_floor, "rules-2026.02.14.10");
    assert_eq!(loaded.published_at_unix_floor, 1_700_000_100);

    std::env::remove_var(THREAT_INTEL_REPLAY_FLOOR_PATH_ENV);
    let _ = std::fs::remove_file(path);
}

#[test]
fn threat_intel_replay_floor_state_rejects_signature_mismatch() {
    let _guard = env_lock().lock().expect("lock env vars");
    let path = write_temp_replay_floor_path("tampered");
    std::env::set_var(THREAT_INTEL_REPLAY_FLOOR_PATH_ENV, &path);

    persist_threat_intel_replay_floor_state("rules-2026.02.14.10", 1_700_000_100)
        .expect("persist replay floor state");

    let mut payload: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&path).expect("read replay floor state file"),
    )
    .expect("parse replay floor state file");
    payload["version_floor"] = serde_json::Value::String("rules-2026.02.14.09".to_string());
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&payload).expect("encode tampered replay floor payload"),
    )
    .expect("write tampered replay floor payload");

    assert!(
        load_threat_intel_replay_floor_state().is_none(),
        "tampered replay floor state should be ignored"
    );

    std::env::remove_var(THREAT_INTEL_REPLAY_FLOOR_PATH_ENV);
    let _ = std::fs::remove_file(path);
}

#[test]
fn threat_intel_last_known_good_state_roundtrip_persists_and_loads() {
    let _guard = env_lock().lock().expect("lock env vars");
    let bundle_path = write_temp_bundle_file("last-good-roundtrip", b"bundle-payload");
    let state_path = write_temp_last_known_good_path("roundtrip");
    std::env::set_var(THREAT_INTEL_LAST_KNOWN_GOOD_PATH_ENV, &state_path);

    persist_threat_intel_last_known_good_state(
        "rules-2026.02.14.12",
        bundle_path.to_string_lossy().as_ref(),
    )
    .expect("persist last-known-good state");

    let resolved = resolve_threat_intel_last_known_good_path();
    assert_eq!(resolved, state_path);

    let loaded = load_threat_intel_last_known_good_state().expect("load last-known-good state");
    assert_eq!(loaded.version, "rules-2026.02.14.12");
    assert!(loaded.bundle_path.ends_with(".bundle.tar.zst"));

    std::env::remove_var(THREAT_INTEL_LAST_KNOWN_GOOD_PATH_ENV);
    let _ = std::fs::remove_file(state_path);
    let _ = std::fs::remove_file(bundle_path);
}

#[test]
fn threat_intel_last_known_good_state_rejects_signature_mismatch() {
    let _guard = env_lock().lock().expect("lock env vars");
    let bundle_path = write_temp_bundle_file("last-good-tampered", b"bundle-payload");
    let state_path = write_temp_last_known_good_path("tampered");
    std::env::set_var(THREAT_INTEL_LAST_KNOWN_GOOD_PATH_ENV, &state_path);

    persist_threat_intel_last_known_good_state(
        "rules-2026.02.14.12",
        bundle_path.to_string_lossy().as_ref(),
    )
    .expect("persist last-known-good state");

    let mut payload: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&state_path).expect("read last-known-good state file"),
    )
    .expect("parse last-known-good state file");
    payload["bundle_path"] = serde_json::Value::String("/tmp/fake.bundle.tar.zst".to_string());
    std::fs::write(
        &state_path,
        serde_json::to_vec_pretty(&payload).expect("encode tampered last-known-good payload"),
    )
    .expect("write tampered last-known-good payload");

    assert!(
        load_threat_intel_last_known_good_state().is_none(),
        "tampered last-known-good state should be ignored"
    );

    std::env::remove_var(THREAT_INTEL_LAST_KNOWN_GOOD_PATH_ENV);
    let _ = std::fs::remove_file(state_path);
    let _ = std::fs::remove_file(bundle_path);
}

#[test]
fn signature_database_floor_rejects_bundle_without_signature_material() {
    let _guard = env_lock().lock().expect("lock env vars");
    std::env::set_var(RULE_BUNDLE_MIN_SIGNATURE_TOTAL_ENV, "2");

    let summary = bundle_summary([0, 0, 1, 0, 0, 3, 10, 5]);
    let err = enforce_bundle_signature_database_floor("/tmp/bundle-empty-signatures", &summary)
        .expect_err("bundle should violate signature database floor");
    assert!(err
        .to_string()
        .contains("signature database floor violation"));

    std::env::remove_var(RULE_BUNDLE_MIN_SIGNATURE_TOTAL_ENV);
}

#[test]
fn signature_database_floor_accepts_bundle_with_sufficient_signature_material() {
    let _guard = env_lock().lock().expect("lock env vars");
    std::env::set_var(RULE_BUNDLE_MIN_SIGNATURE_TOTAL_ENV, "5");

    let summary = bundle_summary([2, 2, 1, 0, 0, 3, 10, 5]);
    enforce_bundle_signature_database_floor("/tmp/bundle-good-signatures", &summary)
        .expect("bundle should satisfy signature database floor");
    assert_eq!(signature_database_total(&summary), 5);

    std::env::remove_var(RULE_BUNDLE_MIN_SIGNATURE_TOTAL_ENV);
}

#[test]
fn signature_drop_guard_rejects_large_regression_when_enabled() {
    let _guard = env_lock().lock().expect("lock env vars");
    std::env::set_var(RULE_BUNDLE_MAX_SIGNATURE_DROP_PCT_ENV, "20");

    let err = enforce_signature_drop_guard("/tmp/bundle-drop-guard", Some(100), 60)
        .expect_err("large signature_total drop should be rejected");
    assert!(err.to_string().contains("drop guard violation"));

    std::env::remove_var(RULE_BUNDLE_MAX_SIGNATURE_DROP_PCT_ENV);
}

#[test]
fn signature_drop_guard_accepts_in_range_regression_when_enabled() {
    let _guard = env_lock().lock().expect("lock env vars");
    std::env::set_var(RULE_BUNDLE_MAX_SIGNATURE_DROP_PCT_ENV, "20");

    enforce_signature_drop_guard("/tmp/bundle-drop-guard", Some(100), 80)
        .expect("in-range signature_total drop should pass");
    enforce_signature_drop_guard("/tmp/bundle-drop-guard", None, 80)
        .expect("first observed bundle should bypass drop guard");

    std::env::remove_var(RULE_BUNDLE_MAX_SIGNATURE_DROP_PCT_ENV);
}

#[test]
fn signature_drop_guard_is_disabled_when_env_not_set() {
    let _guard = env_lock().lock().expect("lock env vars");
    std::env::remove_var(RULE_BUNDLE_MAX_SIGNATURE_DROP_PCT_ENV);

    enforce_signature_drop_guard("/tmp/bundle-drop-guard", Some(100), 1)
        .expect("drop guard should be disabled when env is unset");
}

#[test]
fn shard_bundle_summary_mismatch_is_rejected() {
    let primary = bundle_summary([2, 2, 1, 0, 0, 3, 10, 5]);
    let shard = bundle_summary([2, 1, 1, 0, 0, 3, 10, 5]);
    let err = ensure_shard_bundle_summary_matches(3, &primary, &shard)
        .expect_err("shard summary mismatch should be rejected");
    assert!(err.to_string().contains("shard 3 load diverged"));
}

#[test]
fn shard_bundle_summary_match_is_accepted() {
    let primary = bundle_summary([2, 2, 1, 0, 0, 3, 10, 5]);
    let shard = bundle_summary([2, 2, 1, 0, 0, 3, 10, 5]);
    ensure_shard_bundle_summary_matches(1, &primary, &shard)
        .expect("identical shard summary should pass");
}

fn bundle_summary(counts: [usize; 8]) -> super::super::rule_bundle_loader::BundleLoadSummary {
    super::super::rule_bundle_loader::BundleLoadSummary {
        sigma_loaded: counts[0],
        yara_loaded: counts[1],
        ioc_hashes: counts[2],
        ioc_domains: counts[3],
        ioc_ips: counts[4],
        suricata_rules: counts[5],
        elastic_rules: counts[6],
        cve_entries: counts[7],
    }
}

fn write_temp_bundle_file(name: &str, payload: &[u8]) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock monotonic")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "eguard-agent-{}-{}-{}.bundle.tar.zst",
        name,
        std::process::id(),
        nonce
    ));
    std::fs::write(&path, payload).expect("write temp bundle");
    path
}

fn write_temp_replay_floor_path(name: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock monotonic")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "eguard-agent-{}-{}-{}.replay-floor.json",
        name,
        std::process::id(),
        nonce
    ))
}

fn write_temp_last_known_good_path(name: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock monotonic")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "eguard-agent-{}-{}-{}.last-known-good.json",
        name,
        std::process::id(),
        nonce
    ))
}

fn env_lock() -> &'static std::sync::Mutex<()> {
    static ENV_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    ENV_LOCK.get_or_init(|| std::sync::Mutex::new(()))
}
