//! UAC (User Account Control) configuration checks.

use serde::{Deserialize, Serialize};

/// UAC configuration status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UacStatus {
    pub enabled: bool,
    pub consent_prompt_behavior: u32,
    pub secure_desktop: bool,
}

/// Check UAC configuration from the registry.
pub fn check_uac() -> UacStatus {
    #[cfg(target_os = "windows")]
    {
        // TODO: read HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
        UacStatus {
            enabled: false,
            consent_prompt_behavior: 0,
            secure_desktop: false,
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        tracing::warn!("check_uac is a stub on non-Windows");
        UacStatus {
            enabled: false,
            consent_prompt_behavior: 0,
            secure_desktop: false,
        }
    }
}
