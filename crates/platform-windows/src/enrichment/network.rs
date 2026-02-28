//! Network connection enrichment.
//!
//! On Windows, uses command-backed net connection queries to map
//! connections back to owning PIDs.

#[cfg(target_os = "windows")]
use crate::windows_cmd::POWERSHELL_EXE;
#[cfg(target_os = "windows")]
use std::process::Command;

#[cfg(any(test, target_os = "windows"))]
use serde_json::Value;

/// Resolved network connection context.
#[derive(Debug, Clone)]
pub struct NetworkContext {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
}

/// Look up the network context for a given PID.
pub fn resolve_network_context(pid: u32) -> Option<NetworkContext> {
    #[cfg(target_os = "windows")]
    {
        resolve_network_context_windows(pid)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid;
        None
    }
}

#[cfg(target_os = "windows")]
fn resolve_network_context_windows(pid: u32) -> Option<NetworkContext> {
    let cmd = format!(
        "Get-NetTCPConnection -OwningProcess {} | Select-Object -First 1 LocalAddress,LocalPort,RemoteAddress,RemotePort | ConvertTo-Json -Compress",
        pid
    );
    let output = Command::new(POWERSHELL_EXE)
        .args(["-NoProfile", "-NonInteractive", "-Command", &cmd])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let json = String::from_utf8_lossy(&output.stdout).trim().to_string();
    parse_network_context_json(&json)
}

#[cfg(any(test, target_os = "windows"))]
fn parse_network_context_json(raw: &str) -> Option<NetworkContext> {
    let value: Value = serde_json::from_str(raw).ok()?;
    Some(NetworkContext {
        local_addr: value
            .get("LocalAddress")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        local_port: value.get("LocalPort").and_then(Value::as_u64).unwrap_or(0) as u16,
        remote_addr: value
            .get("RemoteAddress")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        remote_port: value.get("RemotePort").and_then(Value::as_u64).unwrap_or(0) as u16,
    })
}

#[cfg(test)]
mod tests {
    use super::parse_network_context_json;

    #[test]
    fn parses_network_context_json() {
        let raw = r#"{"LocalAddress":"10.0.0.5","LocalPort":52341,"RemoteAddress":"203.0.113.10","RemotePort":443}"#;
        let parsed = parse_network_context_json(raw).expect("parsed network context");

        assert_eq!(parsed.local_addr, "10.0.0.5");
        assert_eq!(parsed.remote_port, 443);
    }
}
