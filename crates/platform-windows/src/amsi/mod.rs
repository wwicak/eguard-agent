//! AMSI (Antimalware Scan Interface) provider integration.
//!
//! Registers as an AMSI provider to receive content scanning requests
//! from Windows applications (PowerShell, VBScript, etc.).

pub mod scanner;

pub use scanner::AmsiScanner;

/// Register as an AMSI provider with the system.
pub fn register_amsi_provider() -> Result<(), AmsiError> {
    #[cfg(target_os = "windows")]
    {
        // TODO: AmsiInitialize + register COM provider
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        tracing::warn!("AMSI provider registration is a stub on non-Windows");
        Ok(())
    }
}

/// Unregister the AMSI provider.
pub fn unregister_amsi_provider() -> Result<(), AmsiError> {
    #[cfg(target_os = "windows")]
    {
        // TODO: AmsiUninitialize
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(())
    }
}

/// Errors from AMSI operations.
#[derive(Debug)]
pub enum AmsiError {
    InitFailed(String),
    ScanFailed(String),
}

impl std::fmt::Display for AmsiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InitFailed(msg) => write!(f, "AMSI init failed: {msg}"),
            Self::ScanFailed(msg) => write!(f, "AMSI scan failed: {msg}"),
        }
    }
}

impl std::error::Error for AmsiError {}
