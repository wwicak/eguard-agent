//! Windows Defender status checks.

use serde::{Deserialize, Serialize};
#[cfg(any(test, target_os = "windows"))]
use serde_json::Value;

#[cfg(target_os = "windows")]
use super::registry::run_powershell;

/// Windows Defender status summary.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
        let cmd = "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureVersion,QuickScanEndTime | ConvertTo-Json -Compress";
        if let Some(json) = run_powershell(cmd) {
            return parse_defender_status_json(&json).unwrap_or_default();
        }
        DefenderStatus::default()
    }
    #[cfg(not(target_os = "windows"))]
    {
        tracing::warn!("check_defender is a stub on non-Windows");
        DefenderStatus::default()
    }
}

#[cfg(any(test, target_os = "windows"))]
fn parse_defender_status_json(raw: &str) -> Option<DefenderStatus> {
    let value: Value = serde_json::from_str(raw).ok()?;
    Some(DefenderStatus {
        enabled: value
            .get("AntivirusEnabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        real_time_protection: value
            .get("RealTimeProtectionEnabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        signature_version: value
            .get("AntivirusSignatureVersion")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        last_scan_time: value
            .get("QuickScanEndTime")
            .and_then(Value::as_str)
            .map(ToString::to_string),
    })
}

#[cfg(test)]
mod tests {
    use super::parse_defender_status_json;

    #[test]
    fn parses_defender_status_json() {
        let raw = r#"{"AntivirusEnabled":true,"RealTimeProtectionEnabled":true,"AntivirusSignatureVersion":"1.2.3.4","QuickScanEndTime":"2026-02-20T01:00:00"}"#;
        let parsed = parse_defender_status_json(raw).expect("parsed defender json");

        assert!(parsed.enabled);
        assert!(parsed.real_time_protection);
        assert_eq!(parsed.signature_version.as_deref(), Some("1.2.3.4"));
    }
}
