//! Windows Update compliance checks.

use serde::{Deserialize, Serialize};
#[cfg(any(test, target_os = "windows"))]
use serde_json::Value;

#[cfg(target_os = "windows")]
use super::registry::run_powershell;

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
        let cmd = "$reboot = Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired'; $last = (Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update' -ErrorAction SilentlyContinue).LastSuccessTime; [pscustomobject]@{ pending_count = 0; reboot_required = $reboot; last_install_date = $last } | ConvertTo-Json -Compress";
        if let Some(json) = run_powershell(cmd) {
            return parse_update_status_json(&json).unwrap_or_default();
        }
        UpdateStatus::default()
    }
    #[cfg(not(target_os = "windows"))]
    {
        tracing::warn!("check_updates is a stub on non-Windows");
        UpdateStatus::default()
    }
}

#[cfg(any(test, target_os = "windows"))]
fn parse_update_status_json(raw: &str) -> Option<UpdateStatus> {
    let value: Value = serde_json::from_str(raw).ok()?;

    Some(UpdateStatus {
        pending_count: value
            .get("pending_count")
            .and_then(Value::as_u64)
            .unwrap_or(0) as u32,
        last_install_date: value
            .get("last_install_date")
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .filter(|s| !s.trim().is_empty()),
        reboot_required: value
            .get("reboot_required")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

impl Default for UpdateStatus {
    fn default() -> Self {
        Self {
            pending_count: 0,
            last_install_date: None,
            reboot_required: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_update_status_json;

    #[test]
    fn parses_update_status_json() {
        let raw = r#"{"pending_count":3,"reboot_required":true,"last_install_date":"2026-02-20T01:11:12"}"#;
        let parsed = parse_update_status_json(raw).expect("parsed update status");

        assert_eq!(parsed.pending_count, 3);
        assert!(parsed.reboot_required);
    }
}
