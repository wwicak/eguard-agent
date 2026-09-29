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
        let mut sqlite = EventBuffer::sqlite(path, cap_bytes)?;
        // Keep existing SQLite rows ahead of fallback events. Acknowledge each
        // memory row only after its durable enqueue; a failed migration can retry.
        loop {
            let batch = buffer.peek_batch(128)?;
            if batch.is_empty() {
                break;
            }
            for (id, event) in batch {
                sqlite.enqueue(event)?;
                buffer.ack(&[id])?;
            }
        }
        *buffer = sqlite;
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
