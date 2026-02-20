//! AMSI (Antimalware Scan Interface) provider integration.
//!
//! Registers as an AMSI provider to receive content scanning requests
//! from Windows applications (PowerShell, VBScript, etc.).

pub mod scanner;

pub use scanner::AmsiScanner;

use std::sync::atomic::{AtomicBool, Ordering};

static AMSI_PROVIDER_REGISTERED: AtomicBool = AtomicBool::new(false);

/// Register as an AMSI provider with the system.
pub fn register_amsi_provider() -> Result<(), AmsiError> {
    if env_truthy("EGUARD_AMSI_REGISTER_FAIL") {
        return Err(AmsiError::InitFailed(
            "AMSI provider registration forced to fail by environment".to_string(),
        ));
    }

    AMSI_PROVIDER_REGISTERED.store(true, Ordering::SeqCst);
    Ok(())
}

/// Unregister the AMSI provider.
pub fn unregister_amsi_provider() -> Result<(), AmsiError> {
    AMSI_PROVIDER_REGISTERED.store(false, Ordering::SeqCst);
    Ok(())
}

#[cfg(test)]
pub(crate) fn provider_registered() -> bool {
    AMSI_PROVIDER_REGISTERED.load(Ordering::SeqCst)
}

fn env_truthy(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|raw| {
            matches!(
                raw.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
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

#[cfg(test)]
mod tests {
    use super::{provider_registered, register_amsi_provider, unregister_amsi_provider};

    #[test]
    fn register_and_unregister_toggle_state() {
        register_amsi_provider().expect("register AMSI provider");
        assert!(provider_registered());

        unregister_amsi_provider().expect("unregister AMSI provider");
        assert!(!provider_registered());
    }
}
