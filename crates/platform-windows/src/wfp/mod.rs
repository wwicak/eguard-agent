//! WFP (Windows Filtering Platform) engine management.
//!
//! Provides network filtering and host isolation capabilities via WFP.

pub mod filters;
pub mod isolation;

pub use filters::WfpFilter;
pub use isolation::HostIsolation;

/// Handle to an open WFP engine session.
pub struct WfpEngine {
    handle: u64,
}

impl WfpEngine {
    /// Open a new WFP engine session.
    pub fn open() -> Result<Self, WfpError> {
        #[cfg(target_os = "windows")]
        {
            // TODO: FwpmEngineOpen0
            Ok(Self { handle: 0 })
        }
        #[cfg(not(target_os = "windows"))]
        {
            tracing::warn!("WfpEngine::open is a stub on non-Windows");
            Ok(Self { handle: 0 })
        }
    }

    /// Close the WFP engine session.
    pub fn close(&mut self) -> Result<(), WfpError> {
        #[cfg(target_os = "windows")]
        {
            // TODO: FwpmEngineClose0(self.handle)
            self.handle = 0;
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.handle = 0;
            Ok(())
        }
    }

    /// Engine session handle.
    pub fn handle(&self) -> u64 {
        self.handle
    }
}

impl Drop for WfpEngine {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Errors from WFP operations.
#[derive(Debug)]
pub enum WfpError {
    EngineOpen(String),
    FilterAdd(String),
    FilterRemove(String),
    TransactionFailed(String),
}

impl std::fmt::Display for WfpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EngineOpen(msg) => write!(f, "WFP engine open failed: {msg}"),
            Self::FilterAdd(msg) => write!(f, "WFP filter add failed: {msg}"),
            Self::FilterRemove(msg) => write!(f, "WFP filter remove failed: {msg}"),
            Self::TransactionFailed(msg) => write!(f, "WFP transaction failed: {msg}"),
        }
    }
}

impl std::error::Error for WfpError {}
