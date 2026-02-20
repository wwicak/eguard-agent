//! BitLocker / disk encryption compliance checks.

use serde::{Deserialize, Serialize};

/// BitLocker encryption status for the system drive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitLockerStatus {
    pub enabled: bool,
    pub protection_status: ProtectionStatus,
    pub encryption_method: Option<String>,
}

/// Protection state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ProtectionStatus {
    On,
    Off,
    Unknown,
}

/// Check BitLocker status on the system drive.
pub fn check_bitlocker() -> BitLockerStatus {
    #[cfg(target_os = "windows")]
    {
        // TODO: WMI query Win32_EncryptableVolume
        BitLockerStatus {
            enabled: false,
            protection_status: ProtectionStatus::Unknown,
            encryption_method: None,
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        tracing::warn!("check_bitlocker is a stub on non-Windows");
        BitLockerStatus {
            enabled: false,
            protection_status: ProtectionStatus::Unknown,
            encryption_method: None,
        }
    }
}
