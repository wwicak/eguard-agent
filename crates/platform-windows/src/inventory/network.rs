//! Network adapter inventory.

#[cfg(target_os = "windows")]
use std::process::Command;

use serde::{Deserialize, Serialize};
#[cfg(any(test, target_os = "windows"))]
use serde_json::Value;

/// A network adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAdapter {
    pub name: String,
    pub mac_address: Option<String>,
    pub ip_addresses: Vec<String>,
    pub dhcp_enabled: bool,
}

/// Collect all network adapters and their configuration.
pub fn collect_network_adapters() -> Vec<NetworkAdapter> {
    #[cfg(target_os = "windows")]
    {
        let cmd = "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter \"IPEnabled=TRUE\" | Select-Object Description,MACAddress,IPAddress,DHCPEnabled | ConvertTo-Json -Compress";
        if let Some(json) = run_powershell(cmd) {
            return parse_network_adapters_json(&json);
        }
        Vec::new()
    }
    #[cfg(not(target_os = "windows"))]
    {
        tracing::warn!("collect_network_adapters is a stub on non-Windows");
        Vec::new()
    }
}

#[cfg(target_os = "windows")]
fn run_powershell(command: &str) -> Option<String> {
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", command])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        None
    } else {
        Some(stdout)
    }
}

#[cfg(any(test, target_os = "windows"))]
fn parse_network_adapters_json(raw: &str) -> Vec<NetworkAdapter> {
    let value: Value = match serde_json::from_str(raw) {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };

    let records = match value {
        Value::Array(arr) => arr,
        single => vec![single],
    };

    records
        .into_iter()
        .filter_map(|entry| {
            let name = entry
                .get("Description")
                .and_then(Value::as_str)
                .map(ToString::to_string)?;

            let ip_addresses = entry
                .get("IPAddress")
                .and_then(Value::as_array)
                .map(|ips| {
                    ips.iter()
                        .filter_map(Value::as_str)
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            Some(NetworkAdapter {
                name,
                mac_address: entry
                    .get("MACAddress")
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
                ip_addresses,
                dhcp_enabled: entry
                    .get("DHCPEnabled")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_network_adapters_json;

    #[test]
    fn parses_network_adapters_json() {
        let raw = r#"[{"Description":"Intel NIC","MACAddress":"AA-BB-CC-DD-EE-FF","IPAddress":["10.0.0.5","fe80::1"],"DHCPEnabled":true}]"#;
        let parsed = parse_network_adapters_json(raw);

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "Intel NIC");
        assert_eq!(parsed[0].ip_addresses.len(), 2);
        assert!(parsed[0].dhcp_enabled);
    }
}
