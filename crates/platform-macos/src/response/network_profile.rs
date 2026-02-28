//! macOS NAC network profile application.
//!
//! Accepts `config_change` payloads carrying `network_profile` config and
//! applies Wi-Fi profile changes via `networksetup`.

use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
use std::process::Command;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkSecurity {
    Open,
    Wpa2Psk,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkProfile {
    pub profile_id: String,
    pub ssid: String,
    pub security: NetworkSecurity,
    #[serde(default = "default_true")]
    pub auto_connect: bool,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub psk: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkProfileApplyReport {
    pub profile_id: String,
    pub profile_path: PathBuf,
    pub wifi_interface: String,
}

pub fn apply_network_profile_config_change(
    payload_json: &str,
    profile_dir: &Path,
) -> Result<Option<NetworkProfileApplyReport>, String> {
    let mut profile = match parse_network_profile_payload(payload_json)? {
        Some(profile) => profile,
        None => return Ok(None),
    };

    normalize_and_validate_profile(&mut profile)?;

    #[cfg(target_os = "macos")]
    {
        return apply_network_profile_macos(&profile, profile_dir).map(Some);
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (profile, profile_dir);
        Err("macOS network profile apply is only supported on macOS".to_string())
    }
}

fn parse_network_profile_payload(payload_json: &str) -> Result<Option<NetworkProfile>, String> {
    let payload: Value = serde_json::from_str(payload_json)
        .map_err(|err| format!("invalid config_change payload JSON: {err}"))?;

    let config_raw = payload
        .get("config_json")
        .ok_or_else(|| "config_json is required in config_change payload".to_string())?;

    let config_json = match config_raw {
        Value::String(raw) => serde_json::from_str::<Value>(raw)
            .map_err(|err| format!("config_json must be valid JSON: {err}"))?,
        Value::Object(_) | Value::Array(_) => config_raw.clone(),
        _ => {
            return Err("config_json must be JSON object/array/string".to_string());
        }
    };

    let config_obj = config_json
        .as_object()
        .ok_or_else(|| "config_json must be a JSON object".to_string())?;

    let config_type = config_obj
        .get("config_type")
        .or_else(|| config_obj.get("type"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    if config_type != "network_profile" {
        return Ok(None);
    }

    let profile_value = config_obj
        .get("profile")
        .cloned()
        .unwrap_or_else(|| config_json.clone());

    let profile: NetworkProfile = serde_json::from_value(profile_value)
        .map_err(|err| format!("invalid network_profile payload: {err}"))?;

    Ok(Some(profile))
}

fn normalize_and_validate_profile(profile: &mut NetworkProfile) -> Result<(), String> {
    profile.profile_id = sanitize_component(&profile.profile_id);
    if profile.profile_id.is_empty() {
        profile.profile_id = sanitize_component(&format!("nac-{}", profile.ssid));
    }
    if profile.profile_id.is_empty() {
        return Err("network profile id cannot be empty".to_string());
    }

    profile.ssid = profile.ssid.trim().to_string();
    if profile.ssid.is_empty() {
        return Err("network profile ssid is required".to_string());
    }

    if matches!(profile.security, NetworkSecurity::Wpa2Psk) {
        profile.psk = profile.psk.trim().to_string();
        if profile.psk.len() < 8 || profile.psk.len() > 63 {
            return Err("network profile psk must be 8-63 characters".to_string());
        }
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn apply_network_profile_macos(
    profile: &NetworkProfile,
    profile_dir: &Path,
) -> Result<NetworkProfileApplyReport, String> {
    std::fs::create_dir_all(profile_dir).map_err(|err| {
        format!(
            "failed creating profile directory {}: {err}",
            profile_dir.display()
        )
    })?;

    let profile_path =
        profile_dir.join(format!("{}.macos-network-profile.json", profile.profile_id));
    let profile_json = serde_json::to_string_pretty(profile)
        .map_err(|err| format!("serialize network profile JSON: {err}"))?;
    std::fs::write(&profile_path, profile_json)
        .map_err(|err| format!("failed writing profile {}: {err}", profile_path.display()))?;

    let wifi_interface = detect_wifi_interface()?;
    run_networksetup_apply(&wifi_interface, profile)?;

    Ok(NetworkProfileApplyReport {
        profile_id: profile.profile_id.clone(),
        profile_path,
        wifi_interface,
    })
}

#[cfg(target_os = "macos")]
fn detect_wifi_interface() -> Result<String, String> {
    let output = Command::new("networksetup")
        .arg("-listallhardwareports")
        .output()
        .map_err(|err| format!("spawn networksetup -listallhardwareports: {err}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!(
            "networksetup -listallhardwareports failed: {}",
            if stderr.is_empty() {
                format!("status {}", output.status)
            } else {
                stderr
            }
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_wifi_interface_from_hardware_ports(&stdout)
        .ok_or_else(|| "unable to detect Wi-Fi hardware interface".to_string())
}

#[cfg(any(test, target_os = "macos"))]
fn parse_wifi_interface_from_hardware_ports(raw: &str) -> Option<String> {
    // Example block:
    // Hardware Port: Wi-Fi
    // Device: en0
    // Ethernet Address: xx:xx:xx:xx:xx:xx
    let mut in_wifi_block = false;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            in_wifi_block = false;
            continue;
        }

        if let Some(port) = trimmed.strip_prefix("Hardware Port:") {
            let name = port.trim().to_ascii_lowercase();
            in_wifi_block = name == "wi-fi" || name == "airport";
            continue;
        }

        if in_wifi_block {
            if let Some(device) = trimmed.strip_prefix("Device:") {
                let iface = device.trim();
                if !iface.is_empty() {
                    return Some(iface.to_string());
                }
            }
        }
    }

    None
}

#[cfg(target_os = "macos")]
fn run_networksetup_apply(interface: &str, profile: &NetworkProfile) -> Result<(), String> {
    let mut args = vec![
        "-setairportnetwork".to_string(),
        interface.to_string(),
        profile.ssid.clone(),
    ];

    if matches!(profile.security, NetworkSecurity::Wpa2Psk) {
        args.push(profile.psk.clone());
    }

    let output = Command::new("networksetup")
        .args(&args)
        .output()
        .map_err(|err| format!("spawn networksetup {:?}: {err}", args))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if stderr.is_empty() { stdout } else { stderr };

    Err(if detail.is_empty() {
        format!(
            "networksetup {:?} failed with status {}",
            args, output.status
        )
    } else {
        format!("networksetup {:?} failed: {}", args, detail)
    })
}

fn sanitize_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.trim().chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('-');
        }
    }

    let out = out.trim_matches(|c| c == '-' || c == '_' || c == '.');
    if out.is_empty() {
        return String::new();
    }

    out.chars().take(64).collect()
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::{
        parse_network_profile_payload, parse_wifi_interface_from_hardware_ports,
        sanitize_component, NetworkSecurity,
    };

    #[test]
    fn parse_network_profile_payload_reads_nested_profile() {
        let payload = r#"{
            "config_json": {
                "config_type": "network_profile",
                "profile": {
                    "profile_id": "Corp-WiFi",
                    "ssid": "CorpWiFi",
                    "security": "wpa2_psk",
                    "psk": "correcthorse"
                }
            }
        }"#;

        let profile = parse_network_profile_payload(payload)
            .expect("payload parses")
            .expect("network profile present");

        assert_eq!(profile.profile_id, "Corp-WiFi");
        assert_eq!(profile.ssid, "CorpWiFi");
        assert!(matches!(profile.security, NetworkSecurity::Wpa2Psk));
    }

    #[test]
    fn parse_network_profile_payload_ignores_non_network_profile_types() {
        let payload = r#"{"config_json":{"config_type":"dns_policy","policy":{}}}"#;
        let profile = parse_network_profile_payload(payload).expect("payload parses");
        assert!(profile.is_none());
    }

    #[test]
    fn parse_wifi_interface_extracts_en_interface() {
        let raw = r#"Hardware Port: USB 10/100/1000 LAN
Device: en7
Ethernet Address: aa:bb:cc:dd:ee:ff

Hardware Port: Wi-Fi
Device: en0
Ethernet Address: 11:22:33:44:55:66
"#;

        assert_eq!(
            parse_wifi_interface_from_hardware_ports(raw).as_deref(),
            Some("en0")
        );
    }

    #[test]
    fn sanitize_component_rejects_path_segments() {
        assert_eq!(sanitize_component("../../corp-net"), "corp-net");
        assert_eq!(sanitize_component(""), "");
    }
}
