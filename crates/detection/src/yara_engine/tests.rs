use super::*;

#[test]
// AC-DET-145
fn parses_and_scans_rule_source() {
    let src = r#"
rule test_rule {
  strings:
    $a = "evil_payload"
  condition:
    $a
}
"#;

    let mut engine = YaraEngine::new();
    let loaded = engine.load_rules_str(src).expect("load rules");
    assert_eq!(loaded, 1);

    // scan_event only scans file content (not command lines).
    // Create a temp file with the marker string.
    let tmp_dir = std::env::temp_dir().join(format!(
        "eguard-yara-scan-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let marker_file = tmp_dir.join("evil.bin");
    std::fs::write(&marker_file, b"evil_payload").unwrap();

    let event = TelemetryEvent {
        ts_unix: 1,
        event_class: crate::EventClass::FileOpen,
        pid: 1,
        ppid: 0,
        uid: 0,
        process: "bash".to_string(),
        parent_process: "sshd".to_string(),
        session_id: 0,
        file_path: Some(marker_file.display().to_string()),
        file_write: false,
        file_hash: None,
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
        command_line: None,
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    };

    let hits = engine.scan_event(&event);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].rule_name, "test_rule");
    let _ = std::fs::remove_dir_all(tmp_dir);
}

#[test]
// AC-DET-145
fn loads_rules_from_directory() {
    let base = std::env::temp_dir().join(format!(
        "eguard-yara-rules-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(&base).expect("create rules dir");

    let path = base.join("sample.yar");
    std::fs::write(
        &path,
        r#"
rule sample_from_dir {
  strings:
    $x = "abc123"
  condition:
    $x
}
"#,
    )
    .expect("write rule file");

    let mut engine = YaraEngine::new();
    let loaded = engine.load_rules_from_dir(&base).expect("load rule dir");
    assert_eq!(loaded, 1);

    let event = TelemetryEvent {
        ts_unix: 1,
        event_class: crate::EventClass::FileOpen,
        pid: 1,
        ppid: 0,
        uid: 0,
        process: "cat".to_string(),
        parent_process: "bash".to_string(),
        session_id: 0,
        file_path: Some(path.to_string_lossy().into_owned()),
        file_write: false,
        file_hash: None,
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
        command_line: None,
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    };

    let sample = base.join("payload.bin");
    std::fs::write(&sample, b"xxabc123yy").expect("write payload");
    let payload_event = TelemetryEvent {
        file_path: Some(sample.to_string_lossy().into_owned()),
        ..event
    };
    let hits = engine.scan_event(&payload_event);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].rule_name, "sample_from_dir");

    let _ = std::fs::remove_file(sample);
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir(base);
}

#[cfg(feature = "yara-rust")]
#[test]
fn yara_rust_backend_compiles_and_scans() {
    let mut backend = YaraRustBackend::new().expect("init yara backend");
    let loaded = backend
        .load_rules_str(
            r#"
rule rust_backend_rule {
  strings:
    $x = "abc123xyz"
  condition:
    $x
}
"#,
        )
        .expect("load rule");
    assert_eq!(loaded, 1);

    let hits = backend.scan_bytes("memory", b"hello abc123xyz world");
    assert!(hits.iter().any(|h| h.rule_name == "rust_backend_rule"));
}
