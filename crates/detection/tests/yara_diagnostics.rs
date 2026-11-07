#![cfg(feature = "yara-x")]
use detection::YaraEngine;
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn saturation_never_turns_truncated_counts_into_a_match_and_dedups_by_pack() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut engine = YaraEngine::new();
    engine
        .load_rules_str("rule counts { meta: score = 90 strings: $a = \"x\" condition: #a == 128 }")
        .unwrap();
    let bytes = vec![b'x'; 129];
    assert!(engine.scan_bytes("synthetic/path", &bytes).is_empty());
    let first = engine.take_incomplete();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].reason, "match_limit");
    assert_eq!(first[0].path, "synthetic/path");
    assert_eq!(first[0].sha256.len(), 64);
    assert_eq!(first[0].pack_hash.len(), 64);
    assert!(engine.scan_bytes("other/path", &bytes).is_empty());
    assert!(engine.take_incomplete().is_empty());
    engine
        .load_rules_str("rule new_pack { condition: false }")
        .unwrap();
    assert!(engine.scan_bytes("synthetic/path", &bytes).is_empty());
    let second = engine.take_incomplete();
    assert_eq!(second.len(), 1);
    assert_ne!(second[0].pack_hash, first[0].pack_hash);
}
#[test]
fn saturation_of_private_nonmatching_patterns_invalidates_the_entire_scan() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut engine = YaraEngine::new();
    engine.load_rules_str("private rule hidden { strings: $_a = \"x\" condition: #_a == 127 } rule public_rule { meta: score = 90 condition: true }").unwrap();
    assert!(engine
        .scan_bytes("synthetic/private", &vec![b'x'; 129])
        .is_empty());
    assert_eq!(engine.take_incomplete()[0].reason, "match_limit");
}
#[test]
fn compile_failure_is_loud_and_retains_previous_real_pack() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut engine = YaraEngine::new();
    engine
        .load_rules_str("rule prior { meta: score = 75 condition: uint16(0) == 0x5A4D }")
        .unwrap();
    let before = engine.status_handle().health();
    assert!(engine
        .load_rules_str("rule invalid { condition: undefined_fixture }")
        .is_err());
    assert_eq!(engine.backend_name(), "yara-x");
    assert!(engine
        .status_handle()
        .health()
        .contains("yara_compile_errors=1"));
    assert_eq!(engine.scan_bytes("x", b"MZ").len(), 1);
    assert!(before.contains("yara_compile_errors=0"));
}
#[test]
fn executable_and_other_size_skips_are_separate_and_no_prefix_is_scanned() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut engine = YaraEngine::new();
    engine
        .load_rules_str("rule any_data { meta: score = 75 condition: filesize > 0 }")
        .unwrap();
    let mut boundary = vec![0; 4 * 1024 * 1024];
    boundary[..2].copy_from_slice(b"MZ");
    assert_eq!(engine.scan_bytes("boundary_exec", &boundary).len(), 1);
    let mut executable = vec![0; 4 * 1024 * 1024 + 1];
    executable[..2].copy_from_slice(b"MZ");
    assert!(engine.scan_bytes("large_exec", &executable).is_empty());
    let other = vec![0; 1024 * 1024 + 1];
    assert!(engine.scan_bytes("large_other", &other).is_empty());
    let health = engine.status_handle().health();
    assert!(health.contains("yara_size_exec_skips=1"));
    assert!(health.contains("yara_size_other_skips=1"));
    assert!(engine.take_incomplete().is_empty());
}
