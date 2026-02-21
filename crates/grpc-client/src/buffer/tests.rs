use super::*;

fn sample_event(i: i64) -> EventEnvelope {
    EventEnvelope {
        agent_id: "a1".to_string(),
        event_type: "process_exec".to_string(),
        severity: String::new(),
        rule_name: String::new(),
        payload_json: format!("{{\"n\":{i}}}"),
        created_at_unix: i,
    }
}

fn large_event(i: i64, payload_bytes: usize) -> EventEnvelope {
    EventEnvelope {
        agent_id: "a1".to_string(),
        event_type: "process_exec".to_string(),
        severity: String::new(),
        rule_name: String::new(),
        payload_json: "x".repeat(payload_bytes),
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
// AC-GRP-082 AC-GRP-083 AC-TST-021 AC-VER-013
fn sqlite_buffer_cap_preserves_fifo_suffix_and_size_accounting() {
    let unique = format!(
        "eguard-agent-cap-accounting-{}.db",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    );
    let path = std::env::temp_dir().join(unique);
    let path_str = path.to_string_lossy().into_owned();

    let ev1 = sample_event(1);
    let ev2 = sample_event(2);
    let ev3 = sample_event(3);
    let ev4 = sample_event(4);
    let sample_size = estimate_event_size(&ev1);
    let cap = sample_size * 2 + 8;
    let mut b = SqliteBuffer::new(&path_str, cap).expect("sqlite open");

    b.enqueue(ev1).expect("enqueue 1");
    b.enqueue(ev2).expect("enqueue 2");
    b.enqueue(ev3).expect("enqueue 3");
    b.enqueue(ev4).expect("enqueue 4");

    let pending_count = b.pending_count().expect("pending count");
    let pending_bytes = b.pending_bytes().expect("pending bytes");
    assert!(pending_count <= 2);
    assert!(pending_bytes <= cap);

    let drained = b.drain_batch(10).expect("drain");
    assert!(!drained.is_empty());
    assert!(drained.iter().all(|ev| ev.created_at_unix >= 3));
    for pair in drained.windows(2) {
        assert!(pair[0].created_at_unix < pair[1].created_at_unix);
    }

    let drained_bytes: usize = drained.iter().map(estimate_event_size).sum();
    assert_eq!(drained_bytes, pending_bytes);

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
// AC-GRP-082 AC-GRP-083 AC-GRP-084
fn default_memory_event_buffer_never_exceeds_100mb_and_evicts_fifo() {
    let payload_bytes = 8 * 1024 * 1024;
    let event_size = estimate_event_size(&large_event(0, payload_bytes));
    assert!(event_size < DEFAULT_BUFFER_CAP_BYTES);

    let max_retained = DEFAULT_BUFFER_CAP_BYTES / event_size;
    assert!(max_retained > 0);

    let total_events = max_retained + 6;
    let mut b = EventBuffer::Memory(OfflineBuffer::default());
    for i in 0..total_events {
        b.enqueue(large_event(i as i64, payload_bytes))
            .expect("enqueue");
        assert!(
            b.pending_bytes() <= DEFAULT_BUFFER_CAP_BYTES,
            "pending bytes exceeded default cap after enqueue {i}"
        );
    }

    let drained = b.drain_batch(total_events).expect("drain");
    let expected_len = max_retained.min(total_events);
    assert_eq!(drained.len(), expected_len);

    let expected_start = (total_events - expected_len) as i64;
    for (offset, event) in drained.iter().enumerate() {
        assert_eq!(event.created_at_unix, expected_start + offset as i64);
    }

    assert_eq!(b.pending_count(), 0);
    assert_eq!(b.pending_bytes(), 0);
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

#[cfg(unix)]
#[test]
// SG-15
fn sqlite_buffer_new_sets_private_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let unique = format!(
        "eguard-agent-buffer-perm-{}.db",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    );
    let path = std::env::temp_dir().join(unique);
    let path_str = path.to_string_lossy().into_owned();

    let _ = SqliteBuffer::new(&path_str, 1024).expect("sqlite open");

    let mode = std::fs::metadata(&path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);

    let _ = std::fs::remove_file(path);
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
