//! Real-time ETW event consumer.
//!
//! Processes events from an active ETW session and converts them into
//! `RawEvent` instances via the codec module.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::RawEvent;

const ETW_REPLAY_PATH_ENV: &str = "EGUARD_ETW_REPLAY_PATH";

/// Consumes events from an ETW real-time session.
pub struct EtwConsumer {
    session_handle: u64,
    events_received: u64,
    pending_events: VecDeque<RawEvent>,
    running: bool,
}

impl EtwConsumer {
    /// Create a consumer bound to the given session handle.
    pub fn new(session_handle: u64) -> Self {
        let mut consumer = Self {
            session_handle,
            events_received: 0,
            pending_events: VecDeque::new(),
            running: false,
        };
        consumer.load_replay_from_env();
        consumer
    }

    /// Begin consuming events. Returns when the session is stopped.
    pub fn run(&mut self) -> Result<(), super::EtwError> {
        if self.session_handle == 0 {
            return Err(super::EtwError::ConsumerStart(
                "cannot run ETW consumer without an active session handle".to_string(),
            ));
        }

        self.running = true;
        Ok(())
    }

    /// Poll for the next batch of events (non-blocking).
    pub fn poll_events(&mut self, max_batch: usize) -> Vec<RawEvent> {
        if !self.running || max_batch == 0 || self.pending_events.is_empty() {
            return Vec::new();
        }

        let batch_size = max_batch.min(self.pending_events.len());
        let mut events = Vec::with_capacity(batch_size);
        for _ in 0..batch_size {
            if let Some(event) = self.pending_events.pop_front() {
                events.push(event);
            }
        }

        self.events_received = self.events_received.saturating_add(events.len() as u64);
        events
    }

    /// Number of events received so far.
    pub fn events_received(&self) -> u64 {
        self.events_received
    }

    fn load_replay_from_env(&mut self) {
        let Some(path) = std::env::var(ETW_REPLAY_PATH_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
        else {
            return;
        };

        match load_replay_events(Path::new(&path)) {
            Ok(events) => {
                if !events.is_empty() {
                    self.pending_events.extend(events);
                    tracing::info!(
                        replay_path = %path,
                        replay_events = self.pending_events.len(),
                        "loaded ETW replay events"
                    );
                }
            }
            Err(err) => {
                tracing::warn!(
                    replay_path = %path,
                    error = %err,
                    "failed loading ETW replay events"
                );
            }
        }
    }

    #[cfg(test)]
    fn inject_events(&mut self, events: Vec<RawEvent>) {
        self.pending_events.extend(events);
    }
}

fn load_replay_events(path: &Path) -> std::io::Result<Vec<RawEvent>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut out = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        match serde_json::from_str::<RawEvent>(trimmed) {
            Ok(event) => out.push(event),
            Err(err) => {
                tracing::warn!(
                    replay_path = %path.display(),
                    line = trimmed,
                    error = %err,
                    "failed parsing ETW replay line"
                );
            }
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{load_replay_events, EtwConsumer};
    use crate::{EventType, RawEvent};

    #[test]
    fn load_replay_events_parses_ndjson_lines() {
        let replay_path =
            std::env::temp_dir().join(format!("eguard-etw-replay-{}.ndjson", std::process::id()));

        let content = [
            "# comment",
            r#"{"event_type":"ProcessExec","pid":10,"uid":0,"ts_ns":1,"payload":"cmdline=powershell"}"#,
            r#"{"event_type":"TcpConnect","pid":10,"uid":0,"ts_ns":2,"payload":"dst=203.0.113.10:443"}"#,
        ]
        .join("\n");
        std::fs::write(&replay_path, content).expect("write replay file");

        let events = load_replay_events(&replay_path).expect("parse replay file");
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0].event_type, EventType::ProcessExec));
        assert!(matches!(events[1].event_type, EventType::TcpConnect));

        let _ = std::fs::remove_file(replay_path);
    }

    #[test]
    fn poll_events_respects_batch_size_and_updates_counter() {
        let mut consumer = EtwConsumer::new(1);
        consumer.inject_events(vec![
            RawEvent {
                event_type: EventType::ProcessExec,
                pid: 1,
                uid: 0,
                ts_ns: 1,
                payload: "a".to_string(),
            },
            RawEvent {
                event_type: EventType::ProcessExec,
                pid: 2,
                uid: 0,
                ts_ns: 2,
                payload: "b".to_string(),
            },
        ]);

        consumer.run().expect("consumer starts");

        let batch = consumer.poll_events(1);
        assert_eq!(batch.len(), 1);
        assert_eq!(consumer.events_received(), 1);

        let remaining = consumer.poll_events(10);
        assert_eq!(remaining.len(), 1);
        assert_eq!(consumer.events_received(), 2);
    }

    #[test]
    fn run_requires_non_zero_session_handle() {
        let mut consumer = EtwConsumer::new(0);
        assert!(consumer.run().is_err());
    }
}
