//! Credential Guard status checks.

use serde::{Deserialize, Serialize};
#[cfg(any(test, target_os = "windows"))]
use serde_json::Value;

#[cfg(target_os = "windows")]
use super::registry::{read_reg_dword, run_powershell};

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
        let cmd = "Get-CimInstance -ClassName Win32_DeviceGuard | Select-Object -First 1 SecurityServicesConfigured,SecurityServicesRunning | ConvertTo-Json -Compress";
        if let Some(json) = run_powershell(cmd) {
            if let Some(parsed) = parse_device_guard_json(&json) {
                return parsed;
            }
        }

        // Fallback to registry-based approximation.
        let configured = read_reg_dword(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
            "EnableVirtualizationBasedSecurity",
        )
        .unwrap_or(0)
            == 1;
        let running = read_reg_dword(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "LsaCfgFlags",
        )
        .unwrap_or(0)
            > 0;

        CredentialGuardStatus {
            configured,
            running,
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

#[cfg(any(test, target_os = "windows"))]
fn parse_device_guard_json(raw: &str) -> Option<CredentialGuardStatus> {
    let value: Value = serde_json::from_str(raw).ok()?;

    let configured = value
        .get("SecurityServicesConfigured")
        .and_then(Value::as_array)
        .map(|items| items.iter().any(|v| v.as_i64() == Some(1)))
        .unwrap_or(false);

    let running = value
        .get("SecurityServicesRunning")
        .and_then(Value::as_array)
        .map(|items| items.iter().any(|v| v.as_i64() == Some(1)))
        .unwrap_or(false);

    Some(CredentialGuardStatus {
        configured,
        running,
    })
}

#[cfg(test)]
mod tests {
    use super::parse_device_guard_json;

    #[test]
    fn parses_device_guard_json() {
        let raw = r#"{"SecurityServicesConfigured":[1,2],"SecurityServicesRunning":[1]}"#;
        let parsed = parse_device_guard_json(raw).expect("parsed device guard json");

        assert!(parsed.configured);
        assert!(parsed.running);
    }
}
