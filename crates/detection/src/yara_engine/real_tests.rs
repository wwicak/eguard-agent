use super::*;

fn raw_backend(source: &str) -> RealYaraBackend {
    let mut compiler = yara_x::Compiler::new();
    compiler.add_source(source).unwrap();
    let mut backend = RealYaraBackend::new(Arc::new(YaraStatus::default()));
    backend.pack_hash = Sha256::digest(source.as_bytes()).into();
    backend.compiled = Some(Arc::new(Compiled {
        rules: compiler.build(),
        file_active: std::sync::atomic::AtomicBool::new(false),
        control: Mutex::new(ScanControl {
            updated: Instant::now(),
            available_us: SCAN_BUDGET_US,
        }),
    }));
    backend
}
#[test]
fn timeout_produces_one_incomplete_finding_within_deadline() {
    // Bypass the load-time slow-loop rejection to qualify the SDK's last-resort deadline.
    let backend = raw_backend(
        "rule pathological { condition: for all i in (0..1000000000): (uint8(i % filesize) == 0) }",
    );
    let started = Instant::now();
    assert!(backend
        .scan_bytes("synthetic/timeout", &[0; 128])
        .is_empty());
    assert!(started.elapsed() < Duration::from_secs(4));
    let pending = backend.status.pending.lock().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].reason, "timeout");
}
#[test]
fn budget_skips_are_counted_separately_and_never_cached_clean() {
    let backend = raw_backend("rule image { meta: score = 75 condition: uint16(0) == 0x5A4D }");
    let compiled = Arc::clone(backend.compiled.as_ref().unwrap());
    let status = Arc::clone(&backend.status);
    let mut engine = YaraEngine::new();
    engine.backend = Box::new(backend);
    engine.status = status;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("image");
    fs::write(&path, b"MZ").unwrap();
    let event:TelemetryEvent=serde_json::from_value(serde_json::json!({"ts_unix":1,"event_class":"ProcessExec","pid":1,"ppid":0,"uid":1000,"process":"fixture","parent_process":"fixture","session_id":1,"file_path":path,"file_write":false,"container_escape":false,"container_privileged":false})).unwrap();
    {
        let mut control = compiled.control.lock().unwrap();
        control.available_us = -1_000_000;
        control.updated = Instant::now();
    }
    assert!(engine.scan_event(&event).is_empty());
    assert!(engine.verdicts.lock().unwrap().is_empty());
    assert!(engine.status.health().contains("yara_budget_exec_skips=1"));
    {
        let mut control = compiled.control.lock().unwrap();
        control.available_us = SCAN_BUDGET_US;
    }
    assert_eq!(engine.scan_event(&event).len(), 1);
}
#[test]
fn file_permit_serializes_io_and_charges_read_hash_and_scan_wall_time() {
    let backend = raw_backend("rule a { condition: false }");
    let compiled = backend.compiled.as_ref().unwrap();
    let permit = backend.begin_file_scan(b"MZ").unwrap();
    assert!(backend.begin_file_scan(b"MZ").is_none());
    std::thread::sleep(Duration::from_millis(60));
    drop(permit);
    assert!(compiled.control.lock().unwrap().available_us < 0);
    assert!(!compiled
        .file_active
        .load(std::sync::atomic::Ordering::Acquire));
}

#[test]
fn exhausted_wall_budget_denies_full_file_read_permit() {
    let backend = raw_backend("rule no_match { condition: false }");
    {
        let mut control = backend.compiled.as_ref().unwrap().control.lock().unwrap();
        control.available_us = -1_000_000;
        control.updated = Instant::now();
    }
    assert!(
        backend.begin_file_scan(b"MZ").is_none(),
        "do not read/hash a file before rejecting exhausted wall budget"
    );
}
