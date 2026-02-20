//! Credential Guard status checks.

use serde::{Deserialize, Serialize};

/// Credential Guard status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialGuardStatus {
    pub configured: bool,
    pub running: bool,
}

/// Check whether Credential Guard is configured and running.
pub fn check_credential_guard() -> CredentialGuardStatus {
    #[cfg(target_os = "windows")]
    {
        // TODO: WMI Win32_DeviceGuard or registry check
        CredentialGuardStatus {
            configured: false,
            running: false,
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        tracing::warn!("check_credential_guard is a stub on non-Windows");
        CredentialGuardStatus {
            configured: false,
            running: false,
        }
    }
}
