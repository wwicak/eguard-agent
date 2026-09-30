use grpc_client::EventBuffer;
use tracing::{info, warn};

/// Retry at most once per minute, including failures, to avoid log/IO storms.
pub(super) fn retry_sqlite_buffer(
    buffer: &mut EventBuffer,
    path: &str,
    cap_bytes: usize,
    last_attempt: &mut Option<i64>,
    now: i64,
) {
    if !matches!(buffer, EventBuffer::Memory(_))
        || !super::timing::interval_due(*last_attempt, now, 60)
    {
        return;
    }
    *last_attempt = Some(now);
    let recovery = (|| -> anyhow::Result<()> {
        let mut sqlite = grpc_client::SqliteBuffer::new(path, cap_bytes)?;
        // Keep existing SQLite rows ahead of fallback events. Acknowledge each
        // memory row only after its durable enqueue; a failed migration can retry.
        loop {
            let batch = buffer.peek_batch(4096)?;
            if batch.is_empty() {
                break;
            }
            let (ids, events): (Vec<_>, Vec<_>) = batch.into_iter().unzip();
            sqlite.enqueue_batch(&events)?;
            buffer.ack(&ids)?;
        }
        *buffer = EventBuffer::Sqlite(sqlite);
        Ok(())
    })();
    match recovery {
        Ok(()) => info!("offline buffer recovered SQLite backend"),
        Err(err) => {
            warn!(error = %err, "offline buffer still using volatile memory; SQLite retry failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grpc_client::EventEnvelope;

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "eguard-buffer-recovery-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn event(seq: u64) -> EventEnvelope {
        EventEnvelope::info("test".into(), "test".into(), seq.to_string(), seq as i64)
    }

    #[test]
    fn fallback_recovers_fifo_and_survives_reopen() {
        let fixture = Fixture::new();
        let parent = fixture.0.join("blocked");
        std::fs::write(&parent, "not a directory").unwrap();
        let path = parent.join("buffer.db");
        let path = path.to_str().unwrap();
        assert!(EventBuffer::sqlite(path, 1_000_000).is_err());
        let mut buffer = EventBuffer::memory(1_000_000);
        for seq in 1..=3 {
            buffer.enqueue(event(seq)).unwrap();
        }
        let expected = buffer
            .peek_batch(10)
            .unwrap()
            .into_iter()
            .map(|(_, e)| (e.created_at_unix, e.payload_json))
            .collect::<Vec<_>>();
        let mut last = None;
        retry_sqlite_buffer(&mut buffer, path, 1_000_000, &mut last, 100);
        assert!(matches!(buffer, EventBuffer::Memory(_)));
        std::fs::remove_file(&parent).unwrap();
        // Existing durable backlog must remain ahead of events accumulated in memory.
        let mut existing = EventBuffer::sqlite(path, 1_000_000).unwrap();
        existing.enqueue(event(0)).unwrap();
        drop(existing);
        retry_sqlite_buffer(&mut buffer, path, 1_000_000, &mut last, 160);
        assert!(
            matches!(buffer, EventBuffer::Sqlite(_)),
            "fallback must not remain volatile forever"
        );
        drop(buffer);
        let reopened = EventBuffer::sqlite(path, 1_000_000).unwrap();
        let actual = reopened
            .peek_batch(10)
            .unwrap()
            .into_iter()
            .map(|(_, e)| (e.created_at_unix, e.payload_json))
            .collect::<Vec<_>>();
        let mut expected_with_backlog = vec![(0, "0".to_string())];
        expected_with_backlog.extend(expected);
        assert_eq!(
            actual, expected_with_backlog,
            "recovery must persist existing backlog followed by FIFO fallback events"
        );
    }

    #[test]
    fn near_capacity_recovery_leaves_watchdog_headroom() {
        let fixture = Fixture::new();
        let path = fixture.0.join("near-capacity.db");
        let cap = 100 * 1024 * 1024;
        let mut buffer = EventBuffer::memory(cap);
        for seq in 0..150_000 {
            let mut row = event(seq);
            row.payload_json = "x".repeat(512);
            buffer.enqueue(row).unwrap();
        }
        assert_eq!(buffer.pending_count(), 150_000);
        // Fill durable storage too: cap eviction must also avoid per-row commits.
        let mut existing = grpc_client::SqliteBuffer::new(path.to_str().unwrap(), cap).unwrap();
        let mut old = event(999_999);
        old.payload_json = "y".repeat(512);
        for _ in 0..40 {
            existing.enqueue_batch(&vec![old.clone(); 4096]).unwrap();
        }
        drop(existing);
        let started = std::time::Instant::now();
        retry_sqlite_buffer(&mut buffer, path.to_str().unwrap(), cap, &mut None, 100);
        assert!(
            matches!(buffer, EventBuffer::Sqlite(_)),
            "recovery must run"
        );
        // The invariant is headroom below the 60s systemd watchdog. Optimized
        // builds (what ships) must keep 4x headroom; unoptimized debug builds
        // run the same code several times slower but must still beat it.
        let budget = if cfg!(debug_assertions) { 45 } else { 15 };
        assert!(
            started.elapsed() < std::time::Duration::from_secs(budget),
            "near-capacity recovery must leave headroom below the 60s watchdog (budget {budget}s): {:?}",
            started.elapsed()
        );
        drop(buffer);
        let reopened = EventBuffer::sqlite(path.to_str().unwrap(), cap).unwrap();
        let rows = reopened.peek_batch(200_000).unwrap();
        let rows = rows
            .iter()
            .filter(|(_, row)| row.created_at_unix != 999_999)
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 150_000);
        assert!(rows
            .iter()
            .enumerate()
            .all(|(seq, (_, row))| row.created_at_unix == seq as i64));
    }

    #[test]
    fn fallback_failed_retries_preserve_events_and_are_rate_limited() {
        let fixture = Fixture::new();
        let parent = fixture.0.join("blocked");
        std::fs::write(&parent, "not a directory").unwrap();
        let path = parent.join("buffer.db");
        let mut buffer = EventBuffer::memory(1_000_000);
        buffer.enqueue(event(1)).unwrap();
        let mut last = None;
        for now in 100..220 {
            retry_sqlite_buffer(
                &mut buffer,
                path.to_str().unwrap(),
                1_000_000,
                &mut last,
                now,
            );
            assert_eq!(
                last,
                Some(if now < 160 { 100 } else { 160 }),
                "failed attempts (and warnings) must be limited to once per minute"
            );
            assert!(matches!(buffer, EventBuffer::Memory(_)));
            assert_eq!(
                buffer.pending_count(),
                1,
                "failed recovery must not acknowledge memory events"
            );
        }
    }
}
