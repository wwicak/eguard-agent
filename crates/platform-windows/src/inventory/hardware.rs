//! Hardware inventory via WMI.

#[cfg(target_os = "windows")]
use std::process::Command;

use serde::{Deserialize, Serialize};
#[cfg(any(test, target_os = "windows"))]
use serde_json::Value;

/// Hardware information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareInfo {
    pub computer_name: Option<String>,
    pub os_version: Option<String>,
    pub os_build: Option<String>,
    pub cpu_name: Option<String>,
    pub cpu_cores: Option<u32>,
    pub total_memory_mb: Option<u64>,
    pub bios_serial: Option<String>,
}

/// Collect hardware information.
pub fn collect_hardware_info() -> HardwareInfo {
    #[cfg(target_os = "windows")]
    {
        let cmd = "$cs=Get-CimInstance Win32_ComputerSystem | Select-Object -First 1 Name,TotalPhysicalMemory; $os=Get-CimInstance Win32_OperatingSystem | Select-Object -First 1 Version,BuildNumber; $cpu=Get-CimInstance Win32_Processor | Select-Object -First 1 Name,NumberOfCores; $bios=Get-CimInstance Win32_BIOS | Select-Object -First 1 SerialNumber; [pscustomobject]@{ computer_name=$cs.Name; os_version=$os.Version; os_build=$os.BuildNumber; cpu_name=$cpu.Name; cpu_cores=$cpu.NumberOfCores; total_memory_mb=[math]::Round($cs.TotalPhysicalMemory/1MB); bios_serial=$bios.SerialNumber } | ConvertTo-Json -Compress";
        if let Some(json) = run_powershell(cmd) {
            return parse_hardware_info_json(&json).unwrap_or_default();
        }
        HardwareInfo::default()
    }
    #[cfg(not(target_os = "windows"))]
    {
        tracing::warn!("collect_hardware_info is a stub on non-Windows");
        HardwareInfo::default()
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
fn parse_hardware_info_json(raw: &str) -> Option<HardwareInfo> {
    let value: Value = serde_json::from_str(raw).ok()?;
    Some(HardwareInfo {
        computer_name: value
            .get("computer_name")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        os_version: value
            .get("os_version")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        os_build: value
            .get("os_build")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        cpu_name: value
            .get("cpu_name")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        cpu_cores: value
            .get("cpu_cores")
            .and_then(Value::as_u64)
            .map(|v| v as u32),
        total_memory_mb: value.get("total_memory_mb").and_then(Value::as_u64),
        bios_serial: value
            .get("bios_serial")
            .and_then(Value::as_str)
            .map(ToString::to_string),
    })
}

impl Default for HardwareInfo {
    fn default() -> Self {
        Self {
            computer_name: None,
            os_version: None,
            os_build: None,
            cpu_name: None,
            cpu_cores: None,
            total_memory_mb: None,
            bios_serial: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_hardware_info_json;

    #[test]
    fn parses_hardware_info_json() {
        let raw = r#"{"computer_name":"WS-01","os_version":"10.0.19045","os_build":"19045","cpu_name":"Intel(R)","cpu_cores":8,"total_memory_mb":16384,"bios_serial":"ABC123"}"#;
        let parsed = parse_hardware_info_json(raw).expect("parsed hardware json");

        assert_eq!(parsed.computer_name.as_deref(), Some("WS-01"));
        assert_eq!(parsed.cpu_cores, Some(8));
        assert_eq!(parsed.total_memory_mb, Some(16384));
    }
}
