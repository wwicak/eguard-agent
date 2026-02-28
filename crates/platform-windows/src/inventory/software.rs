//! Installed software inventory from the Windows registry.

#[cfg(target_os = "windows")]
use crate::windows_cmd::POWERSHELL_EXE;
#[cfg(target_os = "windows")]
use std::process::Command;

use serde::{Deserialize, Serialize};
#[cfg(any(test, target_os = "windows"))]
use serde_json::Value;

/// An installed program entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledProgram {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub install_date: Option<String>,
}

/// Collect all installed software from the registry uninstall keys.
pub fn collect_installed_software() -> Vec<InstalledProgram> {
    #[cfg(target_os = "windows")]
    {
        let cmd = r#"Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -EA SilentlyContinue | Where-Object { $_.DisplayName } | Select-Object -First 250 | ForEach-Object { $d=$_.InstallDate; if(-not $d){ $loc=$_.InstallLocation; if($loc){ try{$d=(Get-Item $loc -EA Stop).CreationTime.ToString('yyyyMMdd')}catch{} } }; if(-not $d){ $ico=($_.DisplayIcon -replace ',.*$','').Trim('"'); if($ico -and (Test-Path $ico -EA SilentlyContinue)){ try{$d=(Get-Item $ico -EA Stop).CreationTime.ToString('yyyyMMdd')}catch{} } }; [pscustomobject]@{DisplayName=$_.DisplayName;DisplayVersion=$_.DisplayVersion;Publisher=$_.Publisher;InstallDate=$d} } | ConvertTo-Json -Compress"#;
        if let Some(json) = run_powershell(cmd) {
            return parse_installed_software_json(&json);
        }
        Vec::new()
    }
    #[cfg(not(target_os = "windows"))]
    {
        tracing::warn!("collect_installed_software is a stub on non-Windows");
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
fn parse_installed_software_json(raw: &str) -> Vec<InstalledProgram> {
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
                .get("DisplayName")
                .and_then(Value::as_str)
                .map(ToString::to_string)?;
            Some(InstalledProgram {
                name,
                version: entry
                    .get("DisplayVersion")
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
                publisher: entry
                    .get("Publisher")
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
                install_date: entry
                    .get("InstallDate")
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_installed_software_json;

    #[test]
    fn parses_installed_software_json() {
        let raw = r#"[{"DisplayName":"App A","DisplayVersion":"1.0","Publisher":"Vendor"},{"DisplayName":"App B","InstallDate":"20260220"}]"#;
        let parsed = parse_installed_software_json(raw);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "App A");
    }
}
