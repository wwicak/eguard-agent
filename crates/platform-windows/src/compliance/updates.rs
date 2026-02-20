//! Windows Update compliance checks.

use serde::{Deserialize, Serialize};

/// Windows Update compliance status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateStatus {
    pub pending_count: u32,
    pub last_install_date: Option<String>,
    pub reboot_required: bool,
}

/// Check Windows Update compliance.
pub fn check_updates() -> UpdateStatus {
    #[cfg(target_os = "windows")]
    {
        // TODO: IUpdateSearcher -> Search("IsInstalled=0")
        UpdateStatus {
            pending_count: 0,
            last_install_date: None,
            reboot_required: false,
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        tracing::warn!("check_updates is a stub on non-Windows");
        UpdateStatus {
            pending_count: 0,
            last_install_date: None,
            reboot_required: false,
        }
    }
}
