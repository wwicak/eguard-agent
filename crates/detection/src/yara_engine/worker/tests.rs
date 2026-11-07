use super::*;
fn fixture() -> (
    Arc<YaraEngine>,
    tempfile::TempDir,
    TelemetryEvent,
    Arc<AtomicBool>,
) {
    static PACK_ID: AtomicU64 = AtomicU64::new(0);
    let pack_id = PACK_ID.fetch_add(1, Ordering::Relaxed);
    let mut engine = YaraEngine::new();
    // Parallel tests must not share the real backend's per-pack scan budget.
    engine.load_rules_str(&format!("rule asynchronous_fixture_{pack_id} {{\nmeta:\nscore = 75\nstrings:\n$a = \"evil\"\ncondition:\n$a at 0 and filesize <= 128\n}}\n")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sample");
    fs::write(&path, b"evil").unwrap();
    let event = serde_json::from_value(serde_json::json!({"ts_unix":123,"event_class":"ProcessExec","pid":42,"ppid":17,"uid":1000,"process":"original","parent_process":"shell","session_id":99,"file_path":path,"process_exe":"/original/image","file_write":false,"container_escape":false,"container_privileged":false})).unwrap();
    (
        Arc::new(engine),
        dir,
        event,
        Arc::new(AtomicBool::new(true)),
    )
}
fn hold(worker: &YaraWorker) -> mpsc::Sender<()> {
    let (release, rx) = mpsc::channel();
    let (entered, wait) = mpsc::channel();
    worker
        .inner
        .tx
        .as_ref()
        .unwrap()
        .send(Command::Hold(rx, entered))
        .unwrap();
    wait.recv().unwrap();
    release
}
#[test]
fn eligible_event_only_enqueues_and_result_keeps_original_context() {
    let (engine, _dir, event, active) = fixture();
    let worker = YaraWorker::new();
    let release = hold(&worker);
    worker.submit(
        engine.clone(),
        active,
        &event,
        Some("original-observation".into()),
    );
    assert_eq!(
        engine.status.file_read_count(),
        0,
        "no header/read/hash/scan inline"
    );
    release.send(()).unwrap();
    worker.drain_for_tests();
    let result = worker.take_results().pop().unwrap();
    assert_eq!(result.event.pid, 42);
    assert_eq!(result.event.ppid, 17);
    assert_eq!(result.event.session_id, 99);
    assert_eq!(result.event.ts_unix, 123);
    assert_eq!(result.event.process_exe.as_deref(), Some("/original/image"));
    assert_eq!(
        result.observation_id.as_deref(),
        Some("original-observation")
    );
    assert_eq!(result.hits[0].severity, crate::Confidence::High);
    assert_eq!(result.sha256.len(), 64);
    assert_eq!(result.pack_hash.len(), 64);
}
#[test]
fn full_queue_is_nonblocking_counted_and_cache_hits_bypass_it() {
    let (engine, _dir, event, active) = fixture();
    mature(&engine);
    engine.scan_event(&event);
    let worker = YaraWorker::new();
    let release = hold(&worker);
    let (cold, _cold_dir, cold_event, cold_active) = fixture();
    for _ in 0..QUEUE_CAPACITY + 1 {
        worker.submit(cold.clone(), cold_active.clone(), &cold_event, None);
    }
    assert_eq!(worker.inner.counters.queue_full.load(Ordering::Relaxed), 1);
    let reads = engine.status.file_read_count();
    worker.submit(engine.clone(), active, &event, None);
    assert_eq!(worker.inner.counters.hits.load(Ordering::Relaxed), 1);
    assert_eq!(worker.inner.counters.queue_full.load(Ordering::Relaxed), 1);
    assert_eq!(engine.status.file_read_count(), reads);
    assert_eq!(worker.take_results().len(), 1);
    release.send(()).unwrap();
    worker.drain_for_tests();
}
#[test]
fn pack_change_discards_queued_work_and_completed_old_results() {
    let (engine, _dir, event, active) = fixture();
    let worker = YaraWorker::new();
    let release = hold(&worker);
    worker.submit(engine.clone(), active.clone(), &event, None);
    active.store(false, Ordering::Release);
    release.send(()).unwrap();
    worker.drain_for_tests();
    assert_eq!(engine.status.file_read_count(), 0);
    assert!(worker.take_results().is_empty());
    assert_eq!(worker.inner.counters.stale.load(Ordering::Relaxed), 1);
    let live = Arc::new(AtomicBool::new(true));
    worker.submit(engine.clone(), live.clone(), &event, None);
    worker.drain_for_tests();
    live.store(false, Ordering::Release);
    assert!(worker.take_results().is_empty());
    assert_eq!(worker.inner.counters.stale.load(Ordering::Relaxed), 2);
}
#[test]
fn shutdown_cancels_pending_work_without_sleep() {
    let (engine, _dir, event, active) = fixture();
    let worker = YaraWorker::new();
    let release = hold(&worker);
    worker.submit(engine.clone(), active, &event, None);
    worker.shutdown();
    release.send(()).unwrap();
    worker.drain_for_tests();
    assert_eq!(engine.status.file_read_count(), 0);
    assert!(worker.take_results().is_empty());
}
#[test]
fn result_overflow_never_blocks_scanner() {
    let (engine, _dir, event, active) = fixture();
    mature(&engine);
    engine.scan_event(&event);
    let worker = YaraWorker::new();
    for _ in 0..QUEUE_CAPACITY + 3 {
        worker.submit(engine.clone(), active.clone(), &event, None);
    }
    assert_eq!(worker.inner.counters.overflow.load(Ordering::Relaxed), 3);
    assert_eq!(worker.take_results().len(), QUEUE_CAPACITY);
}

fn mature(engine: &YaraEngine) {
    *engine.read_clock.lock().unwrap() =
        Some(std::time::SystemTime::now() + std::time::Duration::from_secs(3));
}

#[test]
fn byte_budget_is_per_second_and_never_borrows_past_capacity() {
    let now = Instant::now();
    let mut budget = ByteBudget {
        available: BYTES_PER_SECOND,
        updated: now,
    };
    assert!(budget.take(BYTES_PER_SECOND, now));
    assert!(!budget.take(1, now));
    assert!(budget.take(
        BYTES_PER_SECOND / 2,
        now + std::time::Duration::from_millis(500)
    ));
    assert!(!budget.take(1, now + std::time::Duration::from_millis(500)));
    assert!(!budget.take(
        BYTES_PER_SECOND + 1,
        now + std::time::Duration::from_secs(100)
    ));
}

#[test]
fn trusted_metadata_result_keeps_the_warmed_digest_without_reading() {
    let (engine, _directory, event, active) = fixture();
    mature(&engine);
    assert_eq!(engine.scan_event(&event).len(), 1);
    let reads = engine.status.file_read_count();
    let worker = YaraWorker::new();
    worker.submit(engine.clone(), active, &event, None);
    let result = worker.take_results().pop().unwrap();
    assert_eq!(result.sha256, digest_hex(&Sha256::digest(b"evil").into()));
    assert_eq!(engine.status.file_read_count(), reads);
    assert_eq!(worker.inner.counters.depth.load(Ordering::Relaxed), 0);
}

#[test]
fn write_notification_invalidates_only_its_own_path() {
    let (engine, directory, first, active) = fixture();
    mature(&engine);
    let second_path = directory.path().join("second");
    fs::write(&second_path, b"evil").unwrap();
    let mut second = first.clone();
    second.file_path = Some(second_path.to_string_lossy().into());
    assert_eq!(engine.scan_event(&first).len(), 1);
    assert_eq!(engine.scan_event(&second).len(), 1);
    let first_key = FileKey::at_path(first.file_path.as_ref().unwrap()).unwrap();
    let second_key = FileKey::at_path(second.file_path.as_ref().unwrap()).unwrap();
    assert!(engine.cached_metadata(&first_key).is_some());
    assert!(engine.cached_metadata(&second_key).is_some());
    let worker = YaraWorker::new();
    let release = hold(&worker);
    let mut write = first.clone();
    write.event_class = EventClass::FileOpen;
    write.file_write = true;
    worker.submit(engine.clone(), active.clone(), &write, None);
    assert!(engine.cached_metadata(&first_key).is_none());
    assert!(
        engine.cached_metadata(&second_key).is_some(),
        "unrelated mature verdict must survive"
    );
    let reads = engine.status.file_read_count();
    worker.submit(engine.clone(), active, &second, None);
    assert_eq!(engine.status.file_read_count(), reads);
    assert_eq!(worker.inner.counters.hits.load(Ordering::Relaxed), 1);
    release.send(()).unwrap();
    worker.drain_for_tests();
}
