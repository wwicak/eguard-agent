use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::Deserialize;

use super::command_utils::run_command;
use super::sanitize::sanitize_profile_id;

#[derive(Debug, Deserialize, Default)]
struct WindowsNetworkProfile {
    #[serde(default)]
    profile_id: String,
    #[serde(default)]
    ssid: String,
    #[serde(default)]
    security: String,
    #[serde(default = "default_true")]
    auto_connect: bool,
    #[serde(default)]
    psk: String,
}

pub(super) fn apply_windows_network_profile_config_change(
    payload_json: &str,
    profile_dir: &Path,
) -> Result<Option<PathBuf>, String> {
    let payload: serde_json::Value = serde_json::from_str(payload_json)
        .map_err(|err| format!("invalid config_change payload JSON: {err}"))?;

    let config_raw = payload
        .get("config_json")
        .ok_or_else(|| "config_json is required in config_change payload".to_string())?;

    let config_json = match config_raw {
        serde_json::Value::String(raw) => serde_json::from_str::<serde_json::Value>(raw)
            .map_err(|err| format!("config_json must be valid JSON: {err}"))?,
        serde_json::Value::Object(_) | serde_json::Value::Array(_) => config_raw.clone(),
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
        .and_then(serde_json::Value::as_str)
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
    let mut profile: WindowsNetworkProfile = serde_json::from_value(profile_value)
        .map_err(|err| format!("invalid network_profile payload: {err}"))?;

    profile.ssid = profile.ssid.trim().to_string();
    if profile.ssid.is_empty() {
        return Err("network profile ssid is required".to_string());
    }

    profile.profile_id = if profile.profile_id.trim().is_empty() {
        sanitize_profile_id(&profile.ssid).map_err(ToString::to_string)?
    } else {
        sanitize_profile_id(&profile.profile_id).map_err(ToString::to_string)?
    };

    let security = profile.security.trim().to_ascii_lowercase();
    let auto_connect = profile.auto_connect;

    let xml = match security.as_str() {
        "open" => render_windows_wlan_open_profile_xml(&profile.ssid, auto_connect),
        "wpa2_psk" => {
            let psk = profile.psk.trim();
            if psk.len() < 8 || psk.len() > 63 {
                return Err("network profile psk must be 8-63 characters".to_string());
            }
            render_windows_wlan_wpa2_psk_profile_xml(&profile.ssid, psk, auto_connect)
        }
        other => {
            return Err(format!(
                "unsupported Windows network profile security mode: {}",
                other
            ));
        }
    };

    std::fs::create_dir_all(profile_dir).map_err(|err| {
        format!(
            "failed creating profile directory {}: {err}",
            profile_dir.display()
        )
    })?;

    let profile_path = profile_dir.join(format!("{}.xml", profile.profile_id));
    std::fs::write(&profile_path, xml).map_err(|err| {
        format!(
            "failed writing profile XML {}: {err}",
            profile_path.display()
        )
    })?;

    let filename_arg = format!("filename={}", profile_path.display());
    run_command(
        "netsh",
        &[
            "wlan".to_string(),
            "add".to_string(),
            "profile".to_string(),
            filename_arg,
            "user=all".to_string(),
        ],
    )
    .map_err(|err| format!("failed adding WLAN profile via netsh: {err}"))?;

    if auto_connect {
        let name_arg = format!("name={}", profile.ssid);
        let _ = run_command(
            "netsh",
            &[
                "wlan".to_string(),
                "set".to_string(),
                "profileparameter".to_string(),
                name_arg,
                "connectionmode=auto".to_string(),
            ],
        );
    }

    Ok(Some(profile_path))
}

fn render_windows_wlan_open_profile_xml(ssid: &str, auto_connect: bool) -> String {
    let ssid = escape_xml(ssid);
    let mode = if auto_connect { "auto" } else { "manual" };
    format!(
        r#"<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>{mode}</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>open</authentication>
                <encryption>none</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
        </security>
    </MSM>
</WLANProfile>
"#
    )
}

fn render_windows_wlan_wpa2_psk_profile_xml(ssid: &str, psk: &str, auto_connect: bool) -> String {
    let ssid = escape_xml(ssid);
    let psk = escape_xml(psk);
    let mode = if auto_connect { "auto" } else { "manual" };
    format!(
        r#"<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>{mode}</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{psk}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>
"#
    )
}

fn escape_xml(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

const fn default_true() -> bool {
    true
}
