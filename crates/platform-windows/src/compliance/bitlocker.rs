//! BitLocker / disk encryption compliance checks.

use serde::{Deserialize, Serialize};
#[cfg(any(test, target_os = "windows"))]
use serde_json::Value;

#[cfg(target_os = "windows")]
use super::registry::run_powershell;

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
        let cmd = "$vol = Get-BitLockerVolume -MountPoint $env:SystemDrive | Select-Object -First 1 ProtectionStatus,EncryptionMethod; if ($null -ne $vol) { $vol | ConvertTo-Json -Compress }";
        if let Some(json) = run_powershell(cmd) {
            return parse_bitlocker_status_json(&json).unwrap_or_default();
        }
        BitLockerStatus::default()
    }
    #[cfg(not(target_os = "windows"))]
    {
        tracing::warn!("check_bitlocker is a stub on non-Windows");
        BitLockerStatus::default()
    }
}

#[cfg(any(test, target_os = "windows"))]
fn parse_bitlocker_status_json(raw: &str) -> Option<BitLockerStatus> {
    let value: Value = serde_json::from_str(raw).ok()?;
    let status_code = value
        .get("ProtectionStatus")
        .and_then(Value::as_i64)
        .unwrap_or(-1);
    let protection_status = match status_code {
        0 => ProtectionStatus::Off,
        1 => ProtectionStatus::On,
        _ => ProtectionStatus::Unknown,
    };

    Some(BitLockerStatus {
        enabled: matches!(protection_status, ProtectionStatus::On),
        protection_status,
        encryption_method: value
            .get("EncryptionMethod")
            .and_then(Value::as_str)
            .map(ToString::to_string),
    })
}

impl Default for BitLockerStatus {
    fn default() -> Self {
        Self {
            enabled: false,
            protection_status: ProtectionStatus::Unknown,
            encryption_method: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_bitlocker_status_json, ProtectionStatus};

    #[test]
    fn parses_bitlocker_status_json() {
        let raw = r#"{"ProtectionStatus":1,"EncryptionMethod":"XtsAes256"}"#;
        let parsed = parse_bitlocker_status_json(raw).expect("parsed bitlocker json");

        assert!(parsed.enabled);
        assert!(matches!(parsed.protection_status, ProtectionStatus::On));
        assert_eq!(parsed.encryption_method.as_deref(), Some("XtsAes256"));
    }
}
