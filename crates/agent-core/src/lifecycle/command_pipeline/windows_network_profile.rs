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
    #[serde(default)]
    eap_type: String,
    #[serde(default)]
    ca_cert_pem: String,
    #[serde(default)]
    client_cert_pem: String,
    #[serde(default)]
    client_key_pem: String,
    #[serde(default)]
    server_names: String,
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
        "wpa2_enterprise" | "wpa2-enterprise" | "802.1x" | "eap" => {
            if !profile.ca_cert_pem.is_empty() {
                import_ca_certificate(&profile.ca_cert_pem, profile_dir)?;
            }
            if !profile.client_cert_pem.is_empty() {
                import_client_certificate(
                    &profile.client_cert_pem,
                    &profile.client_key_pem,
                    profile_dir,
                )?;
            }
            let eap = profile.eap_type.trim().to_ascii_lowercase();
            render_windows_wlan_enterprise_profile_xml(
                &profile.ssid,
                &eap,
                &profile.server_names,
                auto_connect,
            )
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

/// Entry point for the `apply_profile` MDM command when the profile JSON
/// looks like a WiFi/802.1x configuration (contains "ssid" key).
pub(super) fn apply_wifi_profile_from_mdm(
    profile_json: &str,
    profile_dir: &Path,
) -> std::result::Result<Option<PathBuf>, String> {
    let value: serde_json::Value =
        serde_json::from_str(profile_json).map_err(|e| format!("invalid profile JSON: {e}"))?;
    let obj = match value.as_object() {
        Some(obj) => obj,
        None => return Ok(None),
    };

    // Only intercept if the profile JSON contains WiFi-specific fields.
    if !obj.contains_key("ssid") {
        return Ok(None);
    }

    let mut profile: WindowsNetworkProfile =
        serde_json::from_value(value).map_err(|e| format!("invalid WiFi profile: {e}"))?;

    profile.ssid = profile.ssid.trim().to_string();
    if profile.ssid.is_empty() {
        return Err("WiFi profile ssid is required".to_string());
    }

    if profile.profile_id.trim().is_empty() {
        profile.profile_id = sanitize_profile_id(&profile.ssid).map_err(ToString::to_string)?;
    } else {
        profile.profile_id =
            sanitize_profile_id(&profile.profile_id).map_err(ToString::to_string)?;
    }

    let security = profile.security.trim().to_ascii_lowercase();
    let auto_connect = profile.auto_connect;

    let xml = match security.as_str() {
        "" | "open" => render_windows_wlan_open_profile_xml(&profile.ssid, auto_connect),
        "wpa2_psk" | "wpa2-psk" => {
            let psk = profile.psk.trim();
            if psk.len() < 8 || psk.len() > 63 {
                return Err("WiFi profile psk must be 8-63 characters".to_string());
            }
            render_windows_wlan_wpa2_psk_profile_xml(&profile.ssid, psk, auto_connect)
        }
        "wpa2_enterprise" | "wpa2-enterprise" | "802.1x" | "eap" => {
            if !profile.ca_cert_pem.is_empty() {
                import_ca_certificate(&profile.ca_cert_pem, profile_dir)?;
            }
            if !profile.client_cert_pem.is_empty() {
                import_client_certificate(
                    &profile.client_cert_pem,
                    &profile.client_key_pem,
                    profile_dir,
                )?;
            }
            let eap = profile.eap_type.trim().to_ascii_lowercase();
            render_windows_wlan_enterprise_profile_xml(
                &profile.ssid,
                &eap,
                &profile.server_names,
                auto_connect,
            )
        }
        other => {
            return Err(format!("unsupported WiFi security mode: {other}"));
        }
    };

    std::fs::create_dir_all(profile_dir)
        .map_err(|e| format!("failed creating profile dir {}: {e}", profile_dir.display()))?;

    let profile_path = profile_dir.join(format!("{}.xml", profile.profile_id));
    std::fs::write(&profile_path, &xml)
        .map_err(|e| format!("failed writing WiFi XML {}: {e}", profile_path.display()))?;

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
    .map_err(|e| format!("failed adding WLAN profile via netsh: {e}"))?;

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

fn import_ca_certificate(pem: &str, profile_dir: &Path) -> std::result::Result<(), String> {
    let cert_path = profile_dir.join("ca-cert.cer");
    std::fs::create_dir_all(profile_dir).map_err(|e| format!("create cert dir: {e}"))?;
    std::fs::write(&cert_path, pem.as_bytes()).map_err(|e| format!("write CA cert: {e}"))?;

    run_command(
        "certutil",
        &[
            "-addstore".to_string(),
            "Root".to_string(),
            cert_path.to_string_lossy().to_string(),
        ],
    )
    .map_err(|e| format!("import CA cert to Root store: {e}"))
}

fn import_client_certificate(
    cert_pem: &str,
    key_pem: &str,
    profile_dir: &Path,
) -> std::result::Result<(), String> {
    std::fs::create_dir_all(profile_dir).map_err(|e| format!("create cert dir: {e}"))?;

    let cert_path = profile_dir.join("client-cert.pem");
    let mut combined = cert_pem.to_string();
    if !key_pem.is_empty() {
        combined.push('\n');
        combined.push_str(key_pem);
    }
    std::fs::write(&cert_path, combined.as_bytes())
        .map_err(|e| format!("write client cert: {e}"))?;

    run_command(
        "certutil",
        &[
            "-user".to_string(),
            "-importPFX".to_string(),
            cert_path.to_string_lossy().to_string(),
        ],
    )
    .map_err(|e| {
        format!(
            "import client cert (note: certutil -importPFX expects PKCS12; \
             PEM may need conversion): {e}"
        )
    })
}

fn render_windows_wlan_enterprise_profile_xml(
    ssid: &str,
    eap_type: &str,
    server_names: &str,
    auto_connect: bool,
) -> String {
    let ssid = escape_xml(ssid);
    let mode = if auto_connect { "auto" } else { "manual" };
    let server_validation = if server_names.is_empty() {
        String::new()
    } else {
        format!(
            "<ServerValidation><ServerNames>{}</ServerNames></ServerValidation>",
            escape_xml(server_names)
        )
    };

    // EAP Type IDs: 13 = EAP-TLS, 25 = PEAP, 21 = EAP-TTLS
    let eap_type_id = match eap_type {
        "tls" | "eap-tls" => 13,
        "ttls" | "eap-ttls" => 21,
        _ => 25, // default to PEAP
    };

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
                <authentication>WPA2</authentication>
                <encryption>AES</encryption>
                <useOneX>true</useOneX>
            </authEncryption>
            <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
                <authMode>user</authMode>
                <EAPConfig>
                    <EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
                        <EapMethod>
                            <Type xmlns="http://www.microsoft.com/provisioning/EapCommon">{eap_type_id}</Type>
                            <VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>
                            <VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>
                            <AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId>
                        </EapMethod>
                        {server_validation}
                    </EapHostConfig>
                </EAPConfig>
            </OneX>
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
