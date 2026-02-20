//! Real-time ETW event consumer.
//!
//! Processes events from an active ETW session and converts them into
//! `RawEvent` instances via the codec module.

use crate::RawEvent;

/// Consumes events from an ETW real-time session.
pub struct EtwConsumer {
    session_handle: u64,
    events_received: u64,
}

impl EtwConsumer {
    /// Create a consumer bound to the given session handle.
    pub fn new(session_handle: u64) -> Self {
        Self {
            session_handle,
            events_received: 0,
        }
    }

    /// Begin consuming events. Returns when the session is stopped.
    pub fn run(&mut self) -> Result<(), super::EtwError> {
        #[cfg(target_os = "windows")]
        {
            // TODO: call ProcessTrace with the session handle
            let _ = self.session_handle;
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            tracing::warn!(
                handle = self.session_handle,
                "EtwConsumer::run is a stub on non-Windows platforms"
            );
            Ok(())
        }
    }

    /// Poll for the next batch of events (non-blocking).
    pub fn poll_events(&mut self, _max_batch: usize) -> Vec<RawEvent> {
        tracing::warn!("EtwConsumer::poll_events not yet implemented");
        Vec::new()
    }

    /// Number of events received so far.
    pub fn events_received(&self) -> u64 {
        self.events_received
    }
}
