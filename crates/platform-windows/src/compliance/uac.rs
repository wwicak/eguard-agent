//! UAC (User Account Control) configuration checks.

use serde::{Deserialize, Serialize};

#[cfg(target_os = "windows")]
use super::registry::read_reg_dword;

#[cfg(target_os = "windows")]
const UAC_POLICIES_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

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
        let enable_lua = read_reg_dword("HKLM", UAC_POLICIES_KEY, "EnableLUA").unwrap_or(0);
        let consent_prompt_behavior =
            read_reg_dword("HKLM", UAC_POLICIES_KEY, "ConsentPromptBehaviorAdmin")
                .unwrap_or_default();
        let secure_desktop =
            read_reg_dword("HKLM", UAC_POLICIES_KEY, "PromptOnSecureDesktop").unwrap_or(0) == 1;

        UacStatus {
            enabled: enable_lua == 1,
            consent_prompt_behavior,
            secure_desktop,
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
