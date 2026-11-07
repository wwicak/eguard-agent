use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
struct Counting(Arc<AtomicUsize>);
impl YaraBackend for Counting {
    fn load_rules_str(&mut self, _: &str) -> Result<usize> {
        Ok(1)
    }
    fn scan_bytes(&self, source: &str, bytes: &[u8]) -> Vec<YaraHit> {
        self.0.fetch_add(1, Ordering::Relaxed);
        if bytes.ends_with(b"evil") {
            vec![YaraHit {
                rule_name: "owned_fixture".into(),
                source: source.into(),
                matched_literal: "evil".into(),
                severity: crate::Confidence::High,
            }]
        } else {
            Vec::new()
        }
    }
}
fn fixture() -> (
    YaraEngine,
    Arc<AtomicUsize>,
    tempfile::TempDir,
    TelemetryEvent,
) {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut engine = YaraEngine::new();
    engine.backend = Box::new(Counting(Arc::clone(&calls)));
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("image");
    fs::write(&path, b"safe").unwrap();
    let event=serde_json::from_value(serde_json::json!({"ts_unix":1,"event_class":"ProcessExec","pid":42,"ppid":1,"uid":1000,"process":"synthetic","parent_process":"synthetic","session_id":42,"file_path":path,"file_write":false,"container_escape":false,"container_privileged":false})).unwrap();
    (engine, calls, directory, event)
}
#[test]
fn unrelated_write_preserves_another_content_bound_cached_verdict() {
    let (engine, calls, directory, event) = fixture();
    assert!(engine.scan_event(&event).is_empty());
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    let other = directory.path().join("other");
    fs::write(&other, b"other").unwrap();
    let mut write = event.clone();
    write.event_class = EventClass::FileOpen;
    write.file_write = true;
    write.file_path = Some(other.to_string_lossy().into());
    engine.scan_event(&write);
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    engine.scan_event(&event);
    assert_eq!(
        calls.load(Ordering::Relaxed),
        2,
        "unrelated write must not invalidate cached exec"
    );
}
#[cfg(unix)]
fn rewrite_and_restore_mtime(event: &TelemetryEvent) {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let path = Path::new(event.file_path.as_ref().unwrap());
    let metadata = fs::metadata(path).unwrap();
    fs::write(path, b"evil").unwrap();
    let times = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
        libc::timespec {
            tv_sec: metadata.mtime(),
            tv_nsec: metadata.mtime_nsec(),
        },
    ];
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: live NUL-terminated path and exactly two valid timespecs.
    assert_eq!(
        unsafe { libc::utimensat(libc::AT_FDCWD, name.as_ptr(), times.as_ptr(), 0) },
        0
    );
    let after = fs::metadata(path).unwrap();
    assert_eq!(metadata.len(), after.len());
    assert_eq!(metadata.modified().unwrap(), after.modified().unwrap());
}
#[test]
#[cfg(unix)]
fn same_size_same_mtime_rewrite_is_rescanned_and_detected() {
    let (engine, calls, _directory, event) = fixture();
    assert!(engine.scan_event(&event).is_empty());
    rewrite_and_restore_mtime(&event);
    assert_eq!(engine.scan_event(&event).len(), 1);
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}
#[test]
#[cfg(unix)]
fn sha_is_required_even_when_all_filekey_metadata_collides() {
    let (engine, calls, _directory, event) = fixture();
    assert!(engine.scan_event(&event).is_empty());
    rewrite_and_restore_mtime(&event);
    // Unix ctime cannot be restored by utimensat. Model a metadata collision explicitly:
    // Windows has changed=(0,0), and other filesystems can have coarse timestamps.
    let file = fs::File::open(event.file_path.as_ref().unwrap()).unwrap();
    let metadata = file.metadata().unwrap();
    let key = FileKey::new(event.file_path.as_ref().unwrap(), &file, &metadata).unwrap();
    let mut cache = engine.verdicts.lock().unwrap();
    let ((_, digest, pack), verdict) = cache.drain().next().unwrap();
    cache.insert((key, digest, pack), verdict);
    drop(cache);
    assert_eq!(engine.scan_event(&event).len(), 1);
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}
#[test]
#[ignore = "explicit cache-hit path RSS/performance qualification"]
fn cached_4mib_read_hash_path_p99() {
    let (engine, calls, _directory, event) = fixture();
    let mut bytes = vec![0; 4 * 1024 * 1024];
    bytes[..4].copy_from_slice(b"\x7fELF");
    fs::write(event.file_path.as_ref().unwrap(), bytes).unwrap();
    engine.scan_event(&event);
    let mut elapsed = Vec::new();
    for _ in 0..100 {
        let started = std::time::Instant::now();
        engine.scan_event(&event);
        elapsed.push(started.elapsed().as_micros());
    }
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "every measured call must be a cache hit"
    );
    elapsed.sort();
    println!(
        "YARA_CACHE_HIT {}",
        serde_json::json!({"samples":100,"file_mib":4,"p50_us":elapsed[50],"p99_us":elapsed[98],"backend_calls_total":1,"loadavg":fs::read_to_string("/proc/loadavg").ok()})
    );
}
