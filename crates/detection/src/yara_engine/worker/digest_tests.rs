use super::*;

struct ConcurrentBudgetSkip(Arc<YaraStatus>);
impl YaraBackend for ConcurrentBudgetSkip {
    fn load_rules_str(&mut self, _: &str) -> Result<usize> {
        Ok(1)
    }
    fn scan_bytes(&self, source: &str, bytes: &[u8]) -> Vec<YaraHit> {
        assert_eq!(bytes, b"evil");
        // Model a different queued event exhausting budget while this valid scan runs.
        self.0.budget_skip(true);
        vec![YaraHit {
            rule_name: "actual_scanned_bytes".into(),
            source: source.into(),
            matched_literal: "evil".into(),
            severity: crate::Confidence::High,
        }]
    }
}
fn colliding_verdict_result(rewrite: bool) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("image");
    fs::write(&path, if rewrite { b"safe" } else { b"evil" }).unwrap();
    let modified = fs::metadata(&path).unwrap().modified().unwrap();
    if rewrite {
        fs::write(&path, b"evil").unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(modified)
            .unwrap();
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), modified);
    }
    let event: TelemetryEvent = serde_json::from_value(serde_json::json!({"ts_unix":123,"event_class":"ProcessExec","pid":42,"ppid":17,"uid":1000,"process":"original","parent_process":"shell","session_id":99,"file_path":path,"file_write":false,"container_escape":false,"container_privileged":false})).unwrap();
    let mut engine = YaraEngine::new();
    engine.backend = Box::new(ConcurrentBudgetSkip(engine.status.clone()));
    let key = FileKey::at_path(event.file_path.as_ref().unwrap()).unwrap();
    // A coarse-timestamp collision has an older content digest under this SAME FileKey+pack.
    engine.verdicts.lock().unwrap().insert(
        (key, [42; 32], [0; 32]),
        super::super::CachedVerdict {
            hits: Vec::new(),
            metadata_trusted: false,
        },
    );
    let engine = Arc::new(engine);
    let worker = YaraWorker::new();
    worker.submit(
        engine.clone(),
        Arc::new(AtomicBool::new(true)),
        &event,
        None,
    );
    worker.drain_for_tests();
    assert_eq!(
        engine.verdicts.lock().unwrap().len(),
        1,
        "budget epoch prevents caching the new result"
    );
    let result = worker.take_results().pop().unwrap();
    assert_eq!(result.hits[0].rule_name, "actual_scanned_bytes");
    assert_eq!(
        result.sha256,
        digest_hex(&Sha256::digest(b"evil").into()),
        "digest must travel with the scanned buffer, never be guessed from the cache"
    );
    assert_eq!(engine.status.file_read_count(), 1);
}
#[test]
fn result_digest_stays_paired_when_an_old_colliding_verdict_is_the_only_cache_entry() {
    colliding_verdict_result(false);
}
#[test]
fn result_digest_matches_scanned_bytes_after_same_tick_same_mtime_rewrite() {
    colliding_verdict_result(true);
}
