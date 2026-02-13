use super::*;

fn sample_event(i: i64) -> EventEnvelope {
    EventEnvelope {
        agent_id: "a1".to_string(),
        event_type: "process_exec".to_string(),
        payload_json: format!("{{\"n\":{i}}}"),
        created_at_unix: i,
    }
}

#[test]
// AC-GRP-082 AC-EBP-044 AC-CFG-020
fn memory_buffer_enforces_cap() {
    let mut b = OfflineBuffer::new(80);
    for i in 0..20 {
        b.enqueue(sample_event(i));
    }
    assert!(b.pending_count() < 20);
    assert!(b.pending_bytes() <= 80);
}

#[test]
// AC-GRP-082 AC-GRP-083
fn sqlite_buffer_roundtrip() {
    let unique = format!(
        "eguard-agent-test-{}.db",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    );
    let path = std::env::temp_dir().join(unique);
    let path_str = path.to_string_lossy().into_owned();

    let mut b = SqliteBuffer::new(&path_str, 1024).expect("sqlite open");
    b.enqueue(sample_event(1)).expect("enqueue 1");
    b.enqueue(sample_event(2)).expect("enqueue 2");

    let out = b.drain_batch(10).expect("drain");
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].created_at_unix, 1);
    assert_eq!(out[1].created_at_unix, 2);

    let _ = std::fs::remove_file(path);
}

#[test]
// AC-GRP-083 AC-RES-024
fn memory_buffer_drain_preserves_fifo_order() {
    let mut b = OfflineBuffer::new(4096);
    b.enqueue(sample_event(1));
    b.enqueue(sample_event(2));
    b.enqueue(sample_event(3));

    let out = b.drain_batch(2);
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].created_at_unix, 1);
    assert_eq!(out[1].created_at_unix, 2);
    assert_eq!(b.pending_count(), 1);
}

#[test]
// AC-GRP-082 AC-GRP-083
fn sqlite_buffer_enforces_fifo_eviction_when_full() {
    let unique = format!(
        "eguard-agent-cap-test-{}.db",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    );
    let path = std::env::temp_dir().join(unique);
    let path_str = path.to_string_lossy().into_owned();

    let sample_size = estimate_event_size(&sample_event(0));
    let mut b = SqliteBuffer::new(&path_str, sample_size * 2 + 8).expect("sqlite open");
    b.enqueue(sample_event(1)).expect("enqueue 1");
    b.enqueue(sample_event(2)).expect("enqueue 2");
    b.enqueue(sample_event(3)).expect("enqueue 3");

    let out = b.drain_batch(10).expect("drain");
    assert!(out.len() <= 2);
    assert!(out.iter().all(|ev| ev.created_at_unix >= 2));

    let _ = std::fs::remove_file(path);
}

#[test]
// AC-GRP-084
fn event_buffer_memory_variant_reports_sizes() {
    let mut b = EventBuffer::memory(1024);
    b.enqueue(sample_event(1)).expect("enqueue");
    assert_eq!(b.pending_count(), 1);
    assert!(b.pending_bytes() > 0);
}

#[test]
// AC-GRP-082 AC-EBP-044 AC-CFG-020
fn default_buffer_cap_matches_acceptance_limit() {
    assert_eq!(DEFAULT_BUFFER_CAP_BYTES, 100 * 1024 * 1024);
}

#[test]
// AC-GRP-082
fn sqlite_buffer_new_creates_parent_directories() {
    let unique = format!(
        "eguard-agent-parent-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    );
    let root = std::env::temp_dir().join(unique);
    let path = root.join("nested").join("offline.db");
    let path_str = path.to_string_lossy().into_owned();

    let _ = SqliteBuffer::new(&path_str, 1024).expect("sqlite open");
    assert!(root.join("nested").exists());

    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
// AC-GRP-083 AC-GRP-084
fn event_buffer_sqlite_variant_reports_sizes() {
    let unique = format!(
        "eguard-agent-buffer-sqlite-{}.db",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    );
    let path = std::env::temp_dir().join(unique);
    let path_str = path.to_string_lossy().into_owned();

    let mut b = EventBuffer::sqlite(&path_str, 1024).expect("sqlite");
    b.enqueue(sample_event(1)).expect("enqueue");
    assert_eq!(b.pending_count(), 1);
    assert!(b.pending_bytes() > 0);

    let drained = b.drain_batch(1).expect("drain");
    assert_eq!(drained.len(), 1);
    assert_eq!(b.pending_count(), 0);

    let _ = std::fs::remove_file(path);
}
