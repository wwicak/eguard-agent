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

/// Core ETW telemetry engine, analogous to `EbpfEngine` on Linux.
pub struct EtwEngine {
    session_active: bool,
}

impl EtwEngine {
    /// Create a new ETW engine (not yet started).
    pub fn new() -> Self {
        Self {
            session_active: false,
        }
    }

    /// Start the ETW trace session and enable providers.
    pub fn start(&mut self) -> Result<(), EtwError> {
        #[cfg(target_os = "windows")]
        {
            // TODO: call StartTrace / EnableTraceEx2
            self.session_active = true;
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            tracing::warn!("EtwEngine::start is a stub on non-Windows platforms");
            self.session_active = true;
            Ok(())
        }
    }

    /// Stop the ETW session and clean up resources.
    pub fn stop(&mut self) -> Result<(), EtwError> {
        self.session_active = false;
        Ok(())
    }

    /// Whether the session is currently active.
    pub fn is_active(&self) -> bool {
        self.session_active
    }

    /// Collect current statistics.
    pub fn stats(&self) -> EtwStats {
        EtwStats {
            events_received: 0,
            events_lost: 0,
            providers_active: 0,
        }
    }
}

impl Default for EtwEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for the ETW subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

impl fmt::Display for EtwError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionCreate(msg) => write!(f, "ETW session creation failed: {msg}"),
            Self::ProviderEnable(msg) => write!(f, "ETW provider enable failed: {msg}"),
            Self::ConsumerStart(msg) => write!(f, "ETW consumer start failed: {msg}"),
        }
    }
}

impl std::error::Error for EtwError {}
