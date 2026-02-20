//! Windows Defender status checks.

use serde::{Deserialize, Serialize};

/// Windows Defender status summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenderStatus {
    pub enabled: bool,
    pub real_time_protection: bool,
    pub signature_version: Option<String>,
    pub last_scan_time: Option<String>,
}

/// Check Windows Defender status.
pub fn check_defender() -> DefenderStatus {
    #[cfg(target_os = "windows")]
    {
        // TODO: WMI MSFT_MpComputerStatus or Get-MpComputerStatus
        DefenderStatus {
            enabled: false,
            real_time_protection: false,
            signature_version: None,
            last_scan_time: None,
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        tracing::warn!("check_defender is a stub on non-Windows");
        DefenderStatus {
            enabled: false,
            real_time_protection: false,
            signature_version: None,
            last_scan_time: None,
        }
    }
}
