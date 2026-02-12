use std::collections::VecDeque;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use tracing::warn;

use crate::types::EventEnvelope;

pub const DEFAULT_BUFFER_CAP_BYTES: usize = 100 * 1024 * 1024;

#[derive(Debug)]
pub struct OfflineBuffer {
    queue: VecDeque<EventEnvelope>,
    current_bytes: usize,
    cap_bytes: usize,
}

impl OfflineBuffer {
    pub fn new(cap_bytes: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            current_bytes: 0,
            cap_bytes,
        }
    }

    pub fn enqueue(&mut self, event: EventEnvelope) {
        let size = estimate_event_size(&event);
        while self.current_bytes.saturating_add(size) > self.cap_bytes {
            if let Some(old) = self.queue.pop_front() {
                self.current_bytes = self.current_bytes.saturating_sub(estimate_event_size(&old));
            } else {
                break;
            }
        }
        self.current_bytes = self.current_bytes.saturating_add(size);
        self.queue.push_back(event);
    }

    pub fn drain_batch(&mut self, max_items: usize) -> Vec<EventEnvelope> {
        let mut out = Vec::with_capacity(max_items);
        for _ in 0..max_items {
            if let Some(ev) = self.queue.pop_front() {
                self.current_bytes = self.current_bytes.saturating_sub(estimate_event_size(&ev));
                out.push(ev);
            } else {
                break;
            }
        }
        out
    }

    pub fn pending_count(&self) -> usize {
        self.queue.len()
    }

    pub fn pending_bytes(&self) -> usize {
        self.current_bytes
    }
}

impl Default for OfflineBuffer {
    fn default() -> Self {
        Self::new(DEFAULT_BUFFER_CAP_BYTES)
    }
}

pub fn estimate_event_size(event: &EventEnvelope) -> usize {
    event.agent_id.len() + event.event_type.len() + event.payload_json.len() + 16
}

#[derive(Debug)]
pub struct SqliteBuffer {
    conn: Connection,
    cap_bytes: usize,
}

impl SqliteBuffer {
    pub fn new(path: &str, cap_bytes: usize) -> Result<Self> {
        if let Some(parent) = Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed creating sqlite parent dir {}", parent.display()))?;
            }
        }

        let conn = Connection::open(path)
            .with_context(|| format!("failed opening sqlite buffer {}", path))?;
        conn.execute_batch(
            "
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            CREATE TABLE IF NOT EXISTS offline_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at_unix INTEGER NOT NULL,
                size_bytes INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_offline_events_id ON offline_events(id);
            ",
        )
        .context("failed initializing sqlite schema")?;

        Ok(Self { conn, cap_bytes })
    }

    pub fn enqueue(&mut self, event: EventEnvelope) -> Result<()> {
        let size = estimate_event_size(&event) as i64;
        self.conn.execute(
            "INSERT INTO offline_events(agent_id,event_type,payload_json,created_at_unix,size_bytes) VALUES(?1,?2,?3,?4,?5)",
            params![event.agent_id, event.event_type, event.payload_json, event.created_at_unix, size],
        )?;
        self.enforce_cap()
    }

    pub fn drain_batch(&mut self, max_items: usize) -> Result<Vec<EventEnvelope>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, agent_id, event_type, payload_json, created_at_unix FROM offline_events ORDER BY id ASC LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![max_items as i64], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                EventEnvelope {
                    agent_id: row.get::<_, String>(1)?,
                    event_type: row.get::<_, String>(2)?,
                    payload_json: row.get::<_, String>(3)?,
                    created_at_unix: row.get::<_, i64>(4)?,
                },
            ))
        })?;

        let mut ids = Vec::new();
        let mut out = Vec::new();
        for row in rows {
            let (id, event) = row?;
            ids.push(id);
            out.push(event);
        }
        drop(stmt);

        for id in ids {
            self.conn
                .execute("DELETE FROM offline_events WHERE id = ?1", params![id])?;
        }

        Ok(out)
    }

    pub fn pending_count(&self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM offline_events", [], |row| row.get(0))?;
        Ok(count.max(0) as usize)
    }

    pub fn pending_bytes(&self) -> Result<usize> {
        let total: Option<i64> = self
            .conn
            .query_row("SELECT SUM(size_bytes) FROM offline_events", [], |row| row.get(0))
            .optional()?
            .flatten();
        Ok(total.unwrap_or(0).max(0) as usize)
    }

    fn enforce_cap(&mut self) -> Result<()> {
        loop {
            let bytes = self.pending_bytes()?;
            if bytes <= self.cap_bytes {
                break;
            }

            let deleted = self.conn.execute(
                "DELETE FROM offline_events WHERE id = (SELECT id FROM offline_events ORDER BY id ASC LIMIT 1)",
                [],
            )?;
            if deleted == 0 {
                break;
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum EventBuffer {
    Memory(OfflineBuffer),
    Sqlite(SqliteBuffer),
}

impl EventBuffer {
    pub fn memory(cap_bytes: usize) -> Self {
        Self::Memory(OfflineBuffer::new(cap_bytes))
    }

    pub fn sqlite(path: &str, cap_bytes: usize) -> Result<Self> {
        Ok(Self::Sqlite(SqliteBuffer::new(path, cap_bytes)?))
    }

    pub fn enqueue(&mut self, event: EventEnvelope) -> Result<()> {
        match self {
            Self::Memory(buf) => {
                buf.enqueue(event);
                Ok(())
            }
            Self::Sqlite(buf) => buf.enqueue(event),
        }
    }

    pub fn drain_batch(&mut self, max_items: usize) -> Result<Vec<EventEnvelope>> {
        match self {
            Self::Memory(buf) => Ok(buf.drain_batch(max_items)),
            Self::Sqlite(buf) => buf.drain_batch(max_items),
        }
    }

    pub fn pending_count(&self) -> usize {
        match self {
            Self::Memory(buf) => buf.pending_count(),
            Self::Sqlite(buf) => match buf.pending_count() {
                Ok(v) => v,
                Err(err) => {
                    warn!(error = %err, "failed reading sqlite pending count");
                    0
                }
            },
        }
    }

    pub fn pending_bytes(&self) -> usize {
        match self {
            Self::Memory(buf) => buf.pending_bytes(),
            Self::Sqlite(buf) => match buf.pending_bytes() {
                Ok(v) => v,
                Err(err) => {
                    warn!(error = %err, "failed reading sqlite pending bytes");
                    0
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
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
    fn memory_buffer_enforces_cap() {
        let mut b = OfflineBuffer::new(80);
        for i in 0..20 {
            b.enqueue(sample_event(i));
        }
        assert!(b.pending_count() < 20);
        assert!(b.pending_bytes() <= 80);
    }

    #[test]
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
}
