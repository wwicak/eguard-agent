use super::*;

#[test]
// AC-DET-145
fn parses_and_scans_rule_source() {
    let src = r#"
rule test_rule {
  strings:
    $a = "evil_payload"
  condition:
    $a at 0 and filesize <= 128
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
        file_write: true,
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
    $x at 0 and filesize <= 128
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
        file_write: true,
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
    std::fs::write(&sample, b"abc123yy").expect("write payload");
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

#[test]
fn yara_scanning_skips_pseudo_and_non_regular_paths() {
    let tmp_dir = std::env::temp_dir().join(format!(
        "eguard-yara-path-safety-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(&tmp_dir).expect("create temp dir");
    let regular = tmp_dir.join("sample.bin");
    std::fs::write(&regular, b"ok").expect("write regular file");

    assert!(is_scannable_regular_file(&regular));
    assert!(!is_scannable_regular_file(Path::new("/dev/null")));
    assert!(!is_scannable_regular_file(Path::new("/proc/self/stat")));
    assert!(!is_scannable_regular_file(Path::new(
        "/sys/kernel/uevent_seqnum"
    )));

    let _ = std::fs::remove_dir_all(tmp_dir);
}

#[test]
fn yara_process_exec_skips_system_binary_paths() {
    let src = r#"
rule elf_marker {
  strings:
    $a = "ELF"
  condition:
    $a at 0 and filesize <= 128
}
"#;

    let mut engine = YaraEngine::new();
    let loaded = engine.load_rules_str(src).expect("load rules");
    assert_eq!(loaded, 1);

    let event = TelemetryEvent {
        ts_unix: 1,
        event_class: crate::EventClass::ProcessExec,
        pid: 1,
        ppid: 0,
        uid: 0,
        process: "cat".to_string(),
        parent_process: "bash".to_string(),
        session_id: 0,
        file_path: Some("/usr/bin/cat".to_string()),
        file_write: true,
        file_hash: None,
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
        command_line: Some("cat /tmp/payload".to_string()),
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    };

    let hits = engine.scan_event(&event);
    assert!(hits.is_empty());
}

#[test]
fn yara_default_exclusions_cover_runtime_cache_and_journal_paths() {
    let engine = YaraEngine::new();

    assert!(engine.is_excluded_path("/etc/ld.so.cache"));
    assert!(
        engine.is_excluded_path("/var/log/journal/5d3dc8654c993f8c581dbff93588b35f/system.journal")
    );
}

#[cfg(feature = "yara-x")]
#[test]
fn yara_rust_backend_compiles_and_scans() {
    let mut backend = real::RealYaraBackend::new(Arc::new(YaraStatus::default()));
    let loaded = backend
        .load_rules_str(
            r#"
rule rust_backend_rule {
  strings:
    $x = "abc123xyz"
  condition:
    $x at 0 and filesize <= 128
}
"#,
        )
        .expect("load rule");
    assert_eq!(loaded, 1);

    let hits = backend.scan_bytes("memory", b"abc123xyz world");
    assert!(hits.iter().any(|h| h.rule_name == "rust_backend_rule"));
}

#[test]
fn cache_reuses_verdict_and_invalidates_content_and_rule_changes() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct CountingBackend(Arc<AtomicUsize>);
    impl YaraBackend for CountingBackend {
        fn load_rules_str(&mut self, _: &str) -> Result<usize> {
            Ok(1)
        }
        fn scan_bytes(&self, _: &str, _: &[u8]) -> Vec<YaraHit> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Vec::new()
        }
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let mut engine = YaraEngine::new();
    engine.backend = Box::new(CountingBackend(Arc::clone(&calls)));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("payload");
    fs::write(&path, b"one").unwrap();
    let event: TelemetryEvent = serde_json::from_value(serde_json::json!({"ts_unix":1,"event_class":"ProcessExec","pid":42,"ppid":1,"uid":1000,"process":"synthetic","parent_process":"test","session_id":42,"file_path":path.to_str(),"file_write":false,"container_escape":false,"container_privileged":false})).unwrap();
    engine.scan_event(&event);
    engine.scan_event(&event);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    let mut write = event.clone();
    write.event_class = EventClass::FileOpen;
    write.file_write = true;
    engine.scan_event(&write);
    assert_eq!(
        calls.load(Ordering::Relaxed),
        2,
        "writes must bypass possibly restored metadata"
    );
    engine.scan_event(&event);
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    fs::write(&path, b"two_changed").unwrap();
    engine.scan_event(&event);
    assert_eq!(calls.load(Ordering::Relaxed), 3);
    engine.load_rules_str("new rules").unwrap();
    engine.scan_event(&event);
    assert_eq!(calls.load(Ordering::Relaxed), 4);
}

#[test]
fn compiled_fallback_rules_are_shared_across_shards() {
    let source = r#"
rule eguard_shared_fixture {
  strings:
    $x = "synthetic"
  condition:
    $x at 0 and filesize <= 128
}
"#;
    let mut first = SubstringYaraBackend::default();
    let mut second = SubstringYaraBackend::default();
    first.load_rules_str(source).unwrap();
    second.load_rules_str(source).unwrap();
    assert!(Arc::ptr_eq(&first.rules[0], &second.rules[0]));
}

#[test]
fn system_root_exclusions_cover_windows_and_macos_with_boundaries() {
    for p in [
        r"C:\Windows\System32\notepad.exe",
        r"d:\WINDOWS\SysWOW64\cmd.exe",
        "/System/Library/test",
    ] {
        assert!(is_excluded_process_exec_path(p), "{p}");
    }
    for p in [
        r"C:\WindowsBackup\payload.exe",
        r"C:\Windows\Temp\payload.exe",
        r"D:\Windows\Tasks\payload.exe",
        "/System/Volumes/Data/Users/synthetic/payload",
        "/SystemBackup/payload",
        "/tmp/payload",
    ] {
        assert!(!is_excluded_process_exec_path(p), "{p}");
    }
}

#[test]
#[cfg(unix)]
fn verdict_cache_never_exceeds_entry_ceiling() {
    let engine = YaraEngine::new();
    let dir = tempfile::tempdir().unwrap();
    for i in 0..514 {
        let path = dir.path().join(format!("synthetic-{i}"));
        fs::write(&path, b"clean").unwrap();
        let event: TelemetryEvent = serde_json::from_value(serde_json::json!({"ts_unix":1,"event_class":"ProcessExec","pid":42,"ppid":1,"uid":1000,"process":"synthetic","parent_process":"test","session_id":42,"file_path":path.to_str(),"file_write":false,"container_escape":false,"container_privileged":false})).unwrap();
        assert!(engine.scan_event(&event).is_empty());
        let len = engine.verdicts.lock().unwrap().len();
        assert!(len > 0 && len <= 512, "cache entries: {len}");
    }
}

#[test]
fn cache_key_pins_file_identity_content_and_active_pack() {
    let mut engine = YaraEngine::new();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("payload");
    fs::write(&path, b"synthetic").unwrap();
    let event:TelemetryEvent=serde_json::from_value(serde_json::json!({"ts_unix":1,"event_class":"ProcessExec","pid":1,"ppid":0,"uid":1000,"process":"fixture","parent_process":"fixture","session_id":1,"file_path":path,"file_write":false,"container_escape":false,"container_privileged":false})).unwrap();
    assert!(engine.scan_event(&event).is_empty());
    let old_pack = {
        let cache = engine.verdicts.lock().unwrap();
        let key = cache.keys().next().unwrap();
        let expected: [u8; 32] = Sha256::digest(b"synthetic").into();
        assert_eq!(key.1, expected);
        let file = fs::File::open(event.file_path.as_ref().unwrap()).unwrap();
        assert_eq!(
            key.0,
            FileKey::new(
                event.file_path.as_ref().unwrap(),
                &file,
                &file.metadata().unwrap()
            )
            .unwrap()
        );
        key.2
    };
    engine
        .load_rules_str(
            "rule new_pack { strings: $a = \"synthetic\" condition: $a at 0 and filesize <= 128 }",
        )
        .unwrap();
    assert_eq!(engine.scan_event(&event).len(), 1);
    let cache = engine.verdicts.lock().unwrap();
    let key = cache.keys().next().unwrap();
    assert_ne!(key.2, old_pack);
    assert_eq!(key.2, engine.backend.pack_hash());
}

#[cfg(feature = "yara-x")]
#[path = "../../tests/support/yara_fixtures.rs"]
mod curated_fixtures;

#[cfg(feature = "yara-x")]
#[test]
fn missing_score_is_one_medium_and_69_70_eicar100_preserve_policy() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("payload");
    let event:TelemetryEvent=serde_json::from_value(serde_json::json!({"ts_unix":1,"event_class":"FileOpen","pid":42,"ppid":1,"uid":1000,"process":"synthetic","parent_process":"test","session_id":42,"file_path":path,"file_write":true,"container_escape":false,"container_privileged":false})).unwrap();
    for (metadata, expected) in [
        ("", crate::Confidence::Medium),
        ("meta: score = 69", crate::Confidence::Medium),
        ("meta: score = 70", crate::Confidence::High),
    ] {
        fs::write(event.file_path.as_ref().unwrap(), b"malware-test-marker").unwrap();
        let mut engine = crate::DetectionEngine::default_with_rules();
        engine.load_yara_rules_str(&format!("rule eguard_fixture_suspicious_payload {{ {metadata} strings: $a = \"malware-test-marker\" condition: $a at 0 and filesize <= 128 }}")).unwrap();
        let outcome = engine.process_event(&event);
        assert_eq!(outcome.yara_hits.len(), 1);
        assert_eq!(outcome.yara_hits[0].severity, expected);
        assert_eq!(outcome.confidence, expected, "{metadata}");
    }
    let eicar = curated_fixtures::cases()
        .into_iter()
        .find(|case| case.0 == "eguard_eicar_test_file")
        .unwrap()
        .1;
    fs::write(event.file_path.as_ref().unwrap(), eicar).unwrap();
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/yara/default.yar"),
    )
    .unwrap();
    let mut engine = crate::DetectionEngine::default_with_rules();
    engine.load_yara_rules_str(&source).unwrap();
    let outcome = engine.process_event(&event);
    assert_eq!(outcome.yara_hits.len(), 1);
    assert_eq!(outcome.yara_hits[0].severity, crate::Confidence::High);
    assert_eq!(outcome.confidence, crate::Confidence::High);
}

#[test]
fn inline_score_metadata_keeps_the_fallback_restricted() {
    let mut backend = SubstringYaraBackend::default();
    backend.load_rules_str("rule fixture {\nmeta: score = 75\nstrings:\n$a = \"fixture\"\ncondition:\n$a at 0 and filesize <= 128\n}\n").unwrap();
    assert_eq!(backend.scan_bytes("x", b"fixture").len(), 1);
    assert!(backend.scan_bytes("x", b"prefix fixture").is_empty());
}
