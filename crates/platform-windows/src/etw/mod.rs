//! ETW (Event Tracing for Windows) subsystem.
//!
//! Provides real-time kernel and user-mode event collection via ETW sessions.

mod codec;
mod consumer;
mod providers;
mod session;

pub use codec::decode_etw_event;
pub use consumer::EtwConsumer;
pub use session::EtwSession;

use serde::{Deserialize, Serialize};
use std::fmt;

const DEFAULT_SESSION_NAME: &str = "eGuardEtwSession";

/// Core ETW telemetry engine, analogous to `EbpfEngine` on Linux.
pub struct EtwEngine {
    session: Option<EtwSession>,
    consumer: Option<EtwConsumer>,
    stats: EtwStats,
}

impl EtwEngine {
    /// Create a new ETW engine (not yet started).
    pub fn new() -> Self {
        Self {
            session: None,
            consumer: None,
            stats: EtwStats::default(),
        }
    }

    /// Start the ETW trace session and enable providers.
    pub fn start(&mut self) -> Result<(), EtwError> {
        if self.is_active() {
            return Ok(());
        }

        let mut session = EtwSession::new(DEFAULT_SESSION_NAME);
        session.start()?;

        let mut providers_enabled = 0u32;
        for provider in providers::DEFAULT_PROVIDER_GUIDS {
            session.enable_provider(provider)?;
            providers_enabled = providers_enabled.saturating_add(1);
        }

        let mut consumer = EtwConsumer::new(session.handle());
        consumer.run()?;

        self.consumer = Some(consumer);
        self.stats.providers_active = providers_enabled;
        self.session = Some(session);

        Ok(())
    }

    /// Stop the ETW session and clean up resources.
    pub fn stop(&mut self) -> Result<(), EtwError> {
        self.consumer = None;

        if let Some(mut session) = self.session.take() {
            session.stop()?;
        }

        self.stats.providers_active = 0;
        Ok(())
    }

    /// Whether the session is currently active.
    pub fn is_active(&self) -> bool {
        self.session
            .as_ref()
            .map(|session| session.is_active())
            .unwrap_or(false)
    }

    /// Poll decoded ETW events from the consumer.
    pub fn poll_events(&mut self, max_batch: usize) -> Result<Vec<crate::RawEvent>, EtwError> {
        let Some(consumer) = self.consumer.as_mut() else {
            return Ok(Vec::new());
        };

        let events = consumer.poll_events(max_batch);
        self.stats.events_received = self
            .stats
            .events_received
            .saturating_add(events.len() as u64);
        Ok(events)
    }

    /// Collect current statistics.
    pub fn stats(&self) -> EtwStats {
        self.stats.clone()
    }
}

impl Default for EtwEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for the ETW subsystem.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EtwStats {
    pub events_received: u64,
    pub events_lost: u64,
    pub providers_active: u32,
}

/// Errors from ETW operations.
#[derive(Debug)]
pub enum EtwError {
    SessionCreate(String),
    ProviderEnable(String),
    ConsumerStart(String),
    InvalidState(String),
}

impl fmt::Display for EtwError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionCreate(msg) => write!(f, "ETW session creation failed: {msg}"),
            Self::ProviderEnable(msg) => write!(f, "ETW provider enable failed: {msg}"),
            Self::ConsumerStart(msg) => write!(f, "ETW consumer start failed: {msg}"),
            Self::InvalidState(msg) => write!(f, "ETW invalid state: {msg}"),
        }
    }
}

impl std::error::Error for EtwError {}

#[cfg(test)]
mod tests {
    use super::EtwEngine;

    #[test]
    fn start_and_stop_updates_provider_stats() {
        let mut engine = EtwEngine::new();
        engine.start().expect("engine starts in stub mode");

        let stats = engine.stats();
        assert!(stats.providers_active >= 1);

        engine.stop().expect("engine stops cleanly");
        assert_eq!(engine.stats().providers_active, 0);
    }
}
