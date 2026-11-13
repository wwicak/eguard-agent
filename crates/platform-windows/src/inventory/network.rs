//! Network adapter inventory.

#[cfg(target_os = "windows")]
use crate::windows_cmd::POWERSHELL_EXE;
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
        let cmd = "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter \"IPEnabled=TRUE\" | Select-Object Description,@{n='Name';e={(Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue).Name}},MACAddress,IPAddress,DHCPEnabled,DefaultIPGateway | ConvertTo-Json -Compress";
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
    let output = Command::new(POWERSHELL_EXE)
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

    let mut records = records;
    records.sort_by_key(|e| !has_gateway(e));
    let mut seen = std::collections::HashSet::new();
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

            let mac = adapter_filter::normalize_mac(
                entry
                    .get("MACAddress")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            )?;
            if adapter_filter::virtual_name_for_os(
                "windows",
                entry.get("Name").and_then(Value::as_str).unwrap_or(""),
            ) || adapter_filter::virtual_name_for_os("windows", &name)
                || mac == "ac:de:48:00:11:22"
                || (!has_gateway(&entry)
                    && !ip_addresses.iter().any(|ip| adapter_filter::usable_ip(ip)))
                || !seen.insert(mac.clone())
            {
                return None;
            }
            Some(NetworkAdapter {
                name,
                mac_address: Some(mac),
                ip_addresses,
                dhcp_enabled: entry
                    .get("DHCPEnabled")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            })
        })
        .collect()
}

#[cfg(any(test, target_os = "windows"))]
fn has_gateway(entry: &Value) -> bool {
    entry
        .get("DefaultIPGateway")
        .and_then(Value::as_array)
        .is_some_and(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .any(adapter_filter::usable_ip)
        })
}

#[cfg(test)]
mod tests {
    use super::parse_network_adapters_json;

    #[test]
    fn rejects_virtual_inventory() {
        let raw = r#"[{"Description":"Intel NIC","MACAddress":"00:e0:99:00:1e:fd","IPAddress":["192.0.2.1"]},{"Description":"vEthernet (WSL)","MACAddress":"82:b9:7b:08:64:00","IPAddress":["192.0.2.2"]}]"#;
        assert_eq!(parse_network_adapters_json(raw).len(), 1);
    }

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
