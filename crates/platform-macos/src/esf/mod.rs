//! ESF (Endpoint Security Framework) subsystem.
//!
//! Provides real-time kernel event collection via Apple's Endpoint Security
//! framework. This is the macOS equivalent of eBPF on Linux or ETW on Windows.

use std::fmt;

/// Core ESF telemetry engine, analogous to `EbpfEngine` on Linux.
pub struct EsfEngine {
    enabled: bool,
}

impl EsfEngine {
    /// Create a new ESF engine (not yet started).
    pub fn new() -> Self {
        Self { enabled: false }
    }

    /// Start the ESF client and subscribe to events.
    pub fn start(&mut self) -> Result<(), EsfError> {
        #[cfg(target_os = "macos")]
        {
            // Future: es_new_client() + es_subscribe() via Security.framework FFI.
            self.enabled = true;
            tracing::info!("ESF engine started (stub)");
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.enabled = true;
            Ok(())
        }
    }

    /// Stop the ESF client and release resources.
    pub fn stop(&mut self) -> Result<(), EsfError> {
        #[cfg(target_os = "macos")]
        {
            self.enabled = false;
            tracing::info!("ESF engine stopped");
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.enabled = false;
            Ok(())
        }
    }

    /// Whether the ESF client is currently active.
    pub fn is_active(&self) -> bool {
        self.enabled
    }

    /// Poll decoded ESF events.
    pub fn poll_events(&mut self, _max_batch: usize) -> Result<Vec<super::RawEvent>, EsfError> {
        Ok(Vec::new())
    }

    /// Collect current statistics.
    pub fn stats(&self) -> EsfStats {
        EsfStats::default()
    }
}

impl Default for EsfEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for the ESF subsystem.
#[derive(Debug, Clone, Default)]
pub struct EsfStats {
    pub events_received: u64,
    pub events_dropped: u64,
}

/// Errors from ESF operations.
#[derive(Debug)]
pub enum EsfError {
    NotAvailable(String),
}

impl fmt::Display for EsfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAvailable(msg) => write!(f, "ESF not available: {msg}"),
        }
    }
}

impl std::error::Error for EsfError {}

#[cfg(test)]
mod tests {
    use super::EsfEngine;

    #[test]
    fn esf_engine_stub_starts_cleanly() {
        let mut engine = EsfEngine::new();
        assert!(!engine.is_active());

        engine.start().expect("engine starts in stub mode");
        assert!(engine.is_active());

        let events = engine.poll_events(100).expect("poll succeeds");
        assert!(events.is_empty());

        let stats = engine.stats();
        assert_eq!(stats.events_received, 0);

        engine.stop().expect("engine stops cleanly");
        assert!(!engine.is_active());
    }
}
