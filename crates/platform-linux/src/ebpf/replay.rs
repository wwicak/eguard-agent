use std::path::Path;
use std::time::Duration;

use super::backend::RingBufferBackend;
use super::replay_codec::encode_replay_event;
use super::types::{EbpfError, PollBatch, Result};

/// Maximum events to yield per poll call.
///
/// The agent tick loop calls `poll_once()` and then picks at most one event
/// from the returned batch.  To avoid discarding lines we yield only a small
/// batch per poll so every event gets processed across successive ticks.
const REPLAY_BATCH_LIMIT: usize = 1;

pub(super) struct ReplayBackend {
    reader: std::io::BufReader<std::fs::File>,
}

impl ReplayBackend {
    pub(super) fn open(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path).map_err(|e| {
            EbpfError::Backend(format!("open replay file '{}': {}", path.display(), e))
        })?;
        Ok(Self {
            reader: std::io::BufReader::new(file),
        })
    }
}

impl RingBufferBackend for ReplayBackend {
    fn poll_raw_events(&mut self, _timeout: Duration) -> Result<PollBatch> {
        use std::io::BufRead;

        let debug = std::env::var("EGUARD_DEBUG_REPLAY_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some();
        let mut records = Vec::new();
        while records.len() < REPLAY_BATCH_LIMIT {
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) => break, // EOF
                Ok(_) => {}
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    return Err(EbpfError::Backend(format!("replay read: {}", e)));
                }
            }
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if debug {
                eprintln!("eg-agent: replay line: {}", trimmed);
            }
            match encode_replay_event(trimmed) {
                Ok(raw) => records.push(raw),
                Err(e) => {
                    eprintln!("eg-agent: replay parse warning: {}", e);
                }
            }
        }
        if debug {
            eprintln!("eg-agent: replay batch size={}", records.len());
        }
        Ok(PollBatch {
            records,
            dropped: 0,
        })
    }
}
