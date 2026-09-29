use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use tracing::warn;

use crate::types::EventEnvelope;

pub const DEFAULT_BUFFER_CAP_BYTES: usize = 100 * 1024 * 1024;
const OFFLINE_META_ROW_ID: i64 = 1;

#[derive(Debug)]
pub struct OfflineBuffer {
    queue: VecDeque<(i64, EventEnvelope)>,
    next_id: i64,
    current_bytes: usize,
    cap_bytes: usize,
}

impl OfflineBuffer {
    pub fn new(cap_bytes: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            next_id: 1,
            current_bytes: 0,
            cap_bytes,
        }
    }

    pub fn enqueue(&mut self, event: EventEnvelope) {
        let size = estimate_event_size(&event);
        while self.current_bytes.saturating_add(size) > self.cap_bytes {
            if let Some((_, old)) = self.queue.pop_front() {
                self.current_bytes = self.current_bytes.saturating_sub(estimate_event_size(&old));
            } else {
                break;
            }
        }
        self.current_bytes = self.current_bytes.saturating_add(size);
        self.queue.push_back((self.next_id, event));
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("buffer row id exhausted");
    }

    pub fn peek_batch(&self, max_items: usize) -> Vec<(i64, EventEnvelope)> {
        self.queue.iter().take(max_items).cloned().collect()
    }

    pub fn ack(&mut self, ids: &[i64]) {
        // Normal delivery acknowledges the FIFO prefix. Do not scan or compact
        // the unsent backlog on every batch: recovery must be linear overall.
        if ids.len() <= self.queue.len()
            && ids
                .iter()
                .zip(&self.queue)
                .all(|(id, (queued_id, _))| id == queued_id)
        {
            for _ in ids {
                let (_, event) = self.queue.pop_front().expect("checked prefix length");
                self.current_bytes = self
                    .current_bytes
                    .saturating_sub(estimate_event_size(&event));
            }
            return;
        }
        let ids: std::collections::HashSet<_> = ids.iter().copied().collect();
        self.queue.retain(|(id, event)| {
            if ids.contains(id) {
                self.current_bytes = self
                    .current_bytes
                    .saturating_sub(estimate_event_size(event));
                false
            } else {
                true
            }
        });
    }

    pub fn drain_batch(&mut self, max_items: usize) -> Vec<EventEnvelope> {
        let mut events = Vec::with_capacity(max_items.min(self.queue.len()));
        for _ in 0..max_items {
            let Some((_, event)) = self.queue.pop_front() else {
                break;
            };
            self.current_bytes = self
                .current_bytes
                .saturating_sub(estimate_event_size(&event));
            events.push(event);
        }
        events
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
    path: PathBuf,
}

impl SqliteBuffer {
    pub fn new(path: &str, cap_bytes: usize) -> Result<Self> {
        if let Some(parent) = Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                // DirBuilder applies the mode only to directories it creates,
                // never to existing ancestors (including concurrent creations).
                let mut builder = fs::DirBuilder::new();
                builder.recursive(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                builder.create(parent).with_context(|| {
                    format!("failed creating sqlite parent dir {}", parent.display())
                })?;

                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    let metadata = fs::metadata(parent)?;
                    // SAFETY: geteuid has no preconditions or pointer arguments.
                    let euid = unsafe { libc::geteuid() };
                    if metadata.mode() & 0o002 != 0 || metadata.uid() != euid {
                        tracing::warn!(
                            parent = %parent.display(),
                            "sqlite parent is world-writable or owned by another user; preserving directory permissions and restricting database to 0600"
                        );
                    }
                }
            }
        }

        let conn = Connection::open(path)
            .with_context(|| format!("failed opening sqlite buffer {}", path))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
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
            CREATE TABLE IF NOT EXISTS offline_buffer_meta (
                id INTEGER PRIMARY KEY CHECK(id = 1),
                total_bytes INTEGER NOT NULL DEFAULT 0
            );
            INSERT OR IGNORE INTO offline_buffer_meta(id, total_bytes) VALUES(1, 0);
            UPDATE offline_buffer_meta
            SET total_bytes = COALESCE((SELECT SUM(size_bytes) FROM offline_events), 0)
            WHERE id = 1;
            ",
        )
        .context("failed initializing sqlite schema")?;

        Ok(Self {
            conn,
            cap_bytes,
            path: PathBuf::from(path),
        })
    }

    pub fn enqueue(&mut self, event: EventEnvelope) -> Result<()> {
        let size = estimate_event_size(&event) as i64;
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO offline_events(agent_id,event_type,payload_json,created_at_unix,size_bytes) VALUES(?1,?2,?3,?4,?5)",
            params![event.agent_id, event.event_type, event.payload_json, event.created_at_unix, size],
        )?;
        tx.execute(
            "UPDATE offline_buffer_meta SET total_bytes = total_bytes + ?1 WHERE id = ?2",
            params![size, OFFLINE_META_ROW_ID],
        )?;
        tx.commit()?;
        self.enforce_cap()
    }

    pub fn peek_batch(&self, max_items: usize) -> Result<Vec<(i64, EventEnvelope)>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, agent_id, event_type, payload_json, created_at_unix, size_bytes FROM offline_events ORDER BY id ASC LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![max_items as i64], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                EventEnvelope {
                    agent_id: row.get::<_, String>(1)?,
                    event_type: row.get::<_, String>(2)?,
                    severity: String::new(),
                    rule_name: String::new(),
                    payload_json: row.get::<_, String>(3)?,
                    created_at_unix: row.get::<_, i64>(4)?,
                },
            ))
        })?;

        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn ack(&mut self, ids: &[i64]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let tx = self.conn.transaction()?;
        for id in ids {
            // Account only rows still present: cap eviction and repeated acks are harmless.
            tx.execute(
                "UPDATE offline_buffer_meta SET total_bytes = MAX(total_bytes - COALESCE((SELECT size_bytes FROM offline_events WHERE id = ?1), 0), 0) WHERE id = ?2",
                params![id, OFFLINE_META_ROW_ID],
            )?;
            tx.execute("DELETE FROM offline_events WHERE id = ?1", params![id])?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn drain_batch(&mut self, max_items: usize) -> Result<Vec<EventEnvelope>> {
        let rows = self.peek_batch(max_items)?;
        self.ack(&rows.iter().map(|(id, _)| *id).collect::<Vec<_>>())?;
        Ok(rows.into_iter().map(|(_, event)| event).collect())
    }

    pub fn pending_count(&self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM offline_events", [], |row| row.get(0))?;
        Ok(count.max(0) as usize)
    }

    pub fn pending_bytes(&self) -> Result<usize> {
        let total = self.current_total_bytes()?;
        Ok(total.max(0) as usize)
    }

    fn current_total_bytes(&self) -> Result<i64> {
        let total: Option<i64> = self
            .conn
            .query_row(
                "SELECT total_bytes FROM offline_buffer_meta WHERE id = ?1",
                params![OFFLINE_META_ROW_ID],
                |row| row.get(0),
            )
            .optional()?;

        if let Some(total_bytes) = total {
            return Ok(total_bytes);
        }

        let fallback: Option<i64> = self
            .conn
            .query_row("SELECT SUM(size_bytes) FROM offline_events", [], |row| {
                row.get(0)
            })
            .optional()?
            .flatten();
        Ok(fallback.unwrap_or(0))
    }

    fn enforce_cap(&mut self) -> Result<()> {
        loop {
            let bytes = self.current_total_bytes()?;
            if bytes <= self.cap_bytes as i64 {
                break;
            }

            let oldest: Option<(i64, i64)> = self
                .conn
                .query_row(
                    "SELECT id, size_bytes FROM offline_events ORDER BY id ASC LIMIT 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;

            let Some((id, size_bytes)) = oldest else {
                self.conn.execute(
                    "UPDATE offline_buffer_meta SET total_bytes = 0 WHERE id = ?1",
                    params![OFFLINE_META_ROW_ID],
                )?;
                break;
            };

            let tx = self.conn.transaction()?;
            let deleted = tx.execute("DELETE FROM offline_events WHERE id = ?1", params![id])?;
            if deleted == 0 {
                break;
            }
            tx.execute(
                "UPDATE offline_buffer_meta SET total_bytes = MAX(total_bytes - ?1, 0) WHERE id = ?2",
                params![size_bytes.max(0), OFFLINE_META_ROW_ID],
            )?;
            tx.commit()?;
        }
        Ok(())
    }

    pub fn run_maintenance(&mut self) -> Result<()> {
        self.conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .context("failed checkpointing sqlite WAL")?;

        let on_disk_bytes = self.on_disk_bytes();
        let pending_bytes = self.current_total_bytes()?.max(0) as u64;
        let vacuum_threshold = (self.cap_bytes as u64).saturating_mul(2);
        let pending_threshold = (self.cap_bytes as u64) / 2;
        if on_disk_bytes > vacuum_threshold && pending_bytes < pending_threshold {
            self.conn
                .execute_batch("VACUUM;")
                .context("failed vacuuming sqlite offline buffer")?;
        }

        Ok(())
    }

    fn on_disk_bytes(&self) -> u64 {
        let base = file_len(&self.path);
        let wal = file_len(&wal_path(&self.path));
        let shm = file_len(&shm_path(&self.path));
        base.saturating_add(wal).saturating_add(shm)
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

    /// Read oldest rows without removing them. Acknowledge only after delivery.
    pub fn peek_batch(&self, max_items: usize) -> Result<Vec<(i64, EventEnvelope)>> {
        match self {
            Self::Memory(buf) => Ok(buf.peek_batch(max_items)),
            Self::Sqlite(buf) => buf.peek_batch(max_items),
        }
    }

    pub fn ack(&mut self, ids: &[i64]) -> Result<()> {
        match self {
            Self::Memory(buf) => {
                buf.ack(ids);
                Ok(())
            }
            Self::Sqlite(buf) => buf.ack(ids),
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

    pub fn run_maintenance(&mut self) -> Result<()> {
        match self {
            Self::Memory(_) => Ok(()),
            Self::Sqlite(buf) => buf.run_maintenance(),
        }
    }
}

fn wal_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}-wal", path.to_string_lossy()))
}

fn shm_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}-shm", path.to_string_lossy()))
}

fn file_len(path: &Path) -> u64 {
    fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;
