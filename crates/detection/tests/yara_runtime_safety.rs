#![cfg(any(feature = "yara-rust", feature = "yara-x"))]
use detection::{Confidence, DetectionEngine, EventClass, TelemetryEvent, YaraEngine};
fn event(path: &std::path::Path) -> TelemetryEvent {
    serde_json::from_value(serde_json::json!({"ts_unix":1,"event_class":"FileOpen","pid":42,"ppid":1,"uid":1000,"process":"synthetic","parent_process":"test","session_id":42,"file_path":path.to_str(),"file_write":true,"container_escape":false,"container_privileged":false})).unwrap()
}
fn source(score: i64) -> String {
    format!(
        r#"rule bounded_fixture {{ meta: score = {score} strings: $a = "family_payload_7f9c" condition: $a }}"#
    )
}
#[test]
fn ordinary_raw_inputs_are_capped_without_truncation() {
    let mut engine = YaraEngine::new();
    engine.load_rules_str(&source(75)).unwrap();
    let mut bytes = b"family_payload_7f9c".to_vec();
    bytes.resize(1024 * 1024 + 1, 0);
    assert!(engine.scan_bytes("ordinary", &bytes).is_empty());
}
#[test]
fn complete_executables_above_one_mib_are_scanned() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image");
    let mut bytes = vec![0; 2 * 1024 * 1024];
    bytes[..2].copy_from_slice(b"MZ");
    let end = bytes.len();
    bytes[end - 19..].copy_from_slice(b"family_payload_7f9c");
    std::fs::write(&path, &bytes).unwrap();
    let mut engine = YaraEngine::new();
    engine.load_rules_str(&source(75)).unwrap();
    assert_eq!(engine.scan_event(&event(&path)).len(), 1);
}
#[test]
#[cfg(unix)]
fn symlinks_are_not_scanned() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("target");
    let link = dir.path().join("link");
    std::fs::write(&path, b"family_payload_7f9c").unwrap();
    std::os::unix::fs::symlink(&path, &link).unwrap();
    let mut engine = YaraEngine::new();
    engine.load_rules_str(&source(75)).unwrap();
    assert!(engine.scan_event(&event(&link)).is_empty());
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::write(real.join("payload"), b"family_payload_7f9c").unwrap();
    let alias = dir.path().join("parent-link");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    assert!(engine.scan_event(&event(&alias.join("payload"))).is_empty());
    assert_eq!(engine.scan_event(&event(&real.join("../target"))).len(), 1);
}
#[test]
fn rule_meta_medium_does_not_become_high() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("payload");
    std::fs::write(&path, b"family_payload_7f9c").unwrap();
    let mut engine = DetectionEngine::default_with_rules();
    engine.load_yara_rules_str(&source(50)).unwrap();
    assert_eq!(
        engine.process_event(&event(&path)).confidence,
        Confidence::Medium
    );
}
#[test]
fn rule_count_cap_rejects_the_entire_addition() {
    let mut engine = YaraEngine::new();
    let src = (0..65)
        .map(|i| format!("rule r{i} {{ condition: true }}\n"))
        .collect::<String>();
    assert!(engine.load_rules_str(&src).is_err());
    assert!(engine.scan_bytes("x", b"x").is_empty());
}
#[test]
fn source_size_cap_rejects_the_entire_addition() {
    let mut engine = YaraEngine::new();
    let src = format!("/*{}*/{}", "x".repeat(512 * 1024), source(75));
    assert!(engine.load_rules_str(&src).is_err());
}
#[test]
fn pattern_cap_rejects_the_entire_addition() {
    let strings = (0..1025)
        .map(|i| format!("$a{i} = \"unique_pattern_{i}\"\n"))
        .collect::<String>();
    let mut engine = YaraEngine::new();
    assert!(engine
        .load_rules_str(&format!(
            "rule many {{ strings: {strings} condition: any of them }}"
        ))
        .is_err());
}
#[test]
fn nested_curated_rule_directories_are_loaded() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("vendor")).unwrap();
    std::fs::write(dir.path().join("vendor/rule.yar"), source(75)).unwrap();
    let mut engine = YaraEngine::new();
    assert_eq!(engine.load_rules_from_dir(dir.path()).unwrap(), 1);
    assert_eq!(engine.scan_bytes("x", b"family_payload_7f9c").len(), 1);
}
#[test]
fn cached_clean_verdict_is_invalidated_by_pack_change() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("payload");
    std::fs::write(&path, b"family_payload_7f9c").unwrap();
    let mut ev = event(&path);
    ev.event_class = EventClass::ProcessExec;
    ev.file_write = false;
    let mut engine = YaraEngine::new();
    engine
        .load_rules_str("rule clean { condition: false }")
        .unwrap();
    assert!(engine.scan_event(&ev).is_empty());
    engine.load_rules_str(&source(75)).unwrap();
    assert_eq!(engine.scan_event(&ev).len(), 1);
}

#[test]
#[cfg(windows)]
fn windows_open_shares_read_write_delete_and_rejects_junction_parents() {
    use std::{io::Write, os::windows::fs::OpenOptionsExt};
    let directory = tempfile::tempdir().unwrap();
    let real = directory.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let path = real.join("payload");
    let mut writer = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .share_mode(1 | 2 | 4)
        .open(&path)
        .unwrap();
    writer.write_all(b"family_payload_7f9c").unwrap();
    writer.flush().unwrap();
    let mut engine = YaraEngine::new();
    engine.load_rules_str(&source(75)).unwrap();
    assert_eq!(engine.scan_event(&event(&path)).len(), 1);
    let alias = directory.path().join("junction");
    let quote = |path: &std::path::Path| path.to_string_lossy().replace('\'', "''");
    let status = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!(
                "New-Item -ItemType Junction -Path '{}' -Target '{}' | Out-Null",
                quote(&alias),
                quote(&real)
            ),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(engine.scan_event(&event(&alias.join("payload"))).is_empty());
}
