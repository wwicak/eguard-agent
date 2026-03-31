//! Windows Firewall compliance checks.

use serde::{Deserialize, Serialize};
#[cfg(any(test, target_os = "windows"))]
use serde_json::Value;

#[cfg(target_os = "windows")]
use super::registry::run_powershell;

/// Windows Firewall profile status.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FirewallStatus {
    pub domain_profile_enabled: bool,
    pub private_profile_enabled: bool,
    pub public_profile_enabled: bool,
}

/// Check Windows Firewall status across all profiles.
pub fn check_firewall() -> FirewallStatus {
    #[cfg(target_os = "windows")]
    {
        let cmd = "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress";
        if let Some(json) = run_powershell(cmd) {
            return parse_firewall_profiles_json(&json).unwrap_or_default();
        }
        FirewallStatus::default()
    }
    #[cfg(not(target_os = "windows"))]
    {
        tracing::warn!("check_firewall is a stub on non-Windows");
        FirewallStatus::default()
    }
}

#[cfg(any(test, target_os = "windows"))]
fn parse_firewall_profiles_json(raw: &str) -> Option<FirewallStatus> {
    let value: Value = serde_json::from_str(raw).ok()?;
    let mut status = FirewallStatus::default();

    let records = match value {
        Value::Array(arr) => arr,
        single => vec![single],
    };

    for record in records {
        let name = record.get("Name")?.as_str()?.to_ascii_lowercase();
        let enabled = parse_enabled_value(record.get("Enabled")?);

        match name.as_str() {
            "domain" => status.domain_profile_enabled = enabled,
            "private" => status.private_profile_enabled = enabled,
            "public" => status.public_profile_enabled = enabled,
            _ => {}
        }
    }

    Some(status)
}

#[cfg(any(test, target_os = "windows"))]
fn parse_enabled_value(value: &Value) -> bool {
    value
        .as_bool()
        .unwrap_or_else(|| value.as_i64().unwrap_or(0) != 0)
}

#[cfg(test)]
mod tests {
    use super::parse_firewall_profiles_json;

    #[test]
    fn parses_firewall_profiles() {
        let raw = r#"[{"Name":"Domain","Enabled":true},{"Name":"Private","Enabled":false},{"Name":"Public","Enabled":true}]"#;
        let parsed = parse_firewall_profiles_json(raw).expect("parsed firewall json");

        assert!(parsed.domain_profile_enabled);
        assert!(!parsed.private_profile_enabled);
        assert!(parsed.public_profile_enabled);
    }

    #[test]
    fn parses_firewall_profiles_with_numeric_enabled_values() {
        let raw = r#"[{"Name":"Domain","Enabled":1},{"Name":"Private","Enabled":1},{"Name":"Public","Enabled":0}]"#;
        let parsed = parse_firewall_profiles_json(raw).expect("parsed firewall json");

        assert!(parsed.domain_profile_enabled);
        assert!(parsed.private_profile_enabled);
        assert!(!parsed.public_profile_enabled);
    }
}
