#![cfg(not(feature = "yara-rust"))]

use detection::{EventClass, TelemetryEvent, YaraEngine};

const SUPPORTED: &str = r#"
rule eguard_literal_fixture {
  meta:
    version = "1.0"
    os = "windows"
  strings:
    $a = "synthetic_payload"
  condition:
    $a at 0 and filesize <= 128
}
"#;
fn event(path: &std::path::Path, class: EventClass, write: bool) -> TelemetryEvent {
    serde_json::from_value(serde_json::json!({"ts_unix":1,"event_class":class,"pid":42,"ppid":1,"uid":1000,
        "process":"synthetic","parent_process":"test","session_id":42,"file_path":path.to_str(),"file_write":write,
        "container_escape":false,"container_privileged":false})).unwrap()
}
#[test]
fn only_string_definitions_are_literals_and_condition_is_enforced() {
    let mut engine = YaraEngine::new();
    engine.load_rules_str(SUPPORTED).unwrap();
    assert!(engine
        .scan_bytes("fixture", b"version 1.0 windows")
        .is_empty());
    assert_eq!(engine.scan_bytes("fixture", b"synthetic_payload").len(), 1);
    assert!(engine
        .scan_bytes("fixture", b"prefix synthetic_payload")
        .is_empty());
    let mut oversized = b"synthetic_payload".to_vec();
    oversized.resize(129, b'x');
    assert!(engine.scan_bytes("fixture", &oversized).is_empty());
}
#[test]
fn unsupported_conditions_and_string_types_fail_closed() {
    for condition in [
        "$a",
        "all of them",
        "not $a",
        "$a or true",
        "$a at 0",
        "$a at 0 and filesize <= 128 or true",
    ] {
        let mut engine = YaraEngine::new();
        assert!(
            engine
                .load_rules_str(&SUPPORTED.replace("$a at 0 and filesize <= 128", condition))
                .is_err(),
            "accepted {condition}"
        );
        assert!(engine
            .scan_bytes("fixture", b"synthetic_payload")
            .is_empty());
    }
    for definition in [
        "$a = { 41 42 }",
        "$a = /payload/",
        "$a = \"payload\" wide nocase",
        "$a = \"payload\"\n    $b = \"other\"",
    ] {
        let mut engine = YaraEngine::new();
        assert!(engine
            .load_rules_str(&SUPPORTED.replace("$a = \"synthetic_payload\"", definition))
            .is_err());
    }
}
#[test]
fn scans_only_exec_and_write_not_exit_or_reads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic.bin");
    std::fs::write(&path, b"synthetic_payload").unwrap();
    let mut engine = YaraEngine::new();
    engine.load_rules_str(SUPPORTED).unwrap();
    for class in [
        EventClass::ProcessExit,
        EventClass::DnsQuery,
        EventClass::ModuleLoad,
        EventClass::NetworkConnect,
    ] {
        assert!(engine.scan_event(&event(&path, class, false)).is_empty());
    }
    assert!(engine
        .scan_event(&event(&path, EventClass::FileOpen, false))
        .is_empty());
    assert_eq!(
        engine
            .scan_event(&event(&path, EventClass::FileOpen, true))
            .len(),
        1
    );
    assert_eq!(
        engine
            .scan_event(&event(&path, EventClass::ProcessExec, false))
            .len(),
        1
    );
}
#[test]
fn eicar_read_is_quiet_but_write_and_exec_scan() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("eicar.com");
    std::fs::write(
        &path,
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    )
    .unwrap();
    let mut engine = YaraEngine::new();
    assert_eq!(
        engine
            .load_rules_str(include_str!("../../../rules/yara/default.yar"))
            .unwrap(),
        1
    );
    assert!(engine
        .scan_event(&event(&path, EventClass::FileOpen, false))
        .is_empty());
    assert_eq!(
        engine
            .scan_event(&event(&path, EventClass::FileOpen, true))
            .len(),
        1
    );
    assert_eq!(
        engine
            .scan_event(&event(&path, EventClass::ProcessExec, false))
            .len(),
        1
    );
}
#[test]
fn canonical_eicar_is_full_string_at_zero_and_small_file_only() {
    let mut engine = YaraEngine::new();
    engine
        .load_rules_str(include_str!("../../../rules/yara/default.yar"))
        .unwrap();
    let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    assert_eq!(eicar.len(), 68);
    let hits = engine.scan_bytes("fixture", eicar);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].rule_name, "eguard_eicar_test_file");
    assert!(engine.scan_bytes("fixture", &eicar[..28]).is_empty());
    assert!(engine
        .scan_bytes(
            "fixture",
            b"a document mentioning eguard-malware-test-marker"
        )
        .is_empty());
    assert!(engine
        .scan_bytes("fixture", &[&b"prefix"[..], eicar].concat())
        .is_empty());
}
