use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

const DEFAULT_EAP_METHOD: &str = "peap";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkSecurity {
    Open,
    Wpa2Psk,
    Wpa2Enterprise,
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
    #[serde(default)]
    pub identity: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub eap_method: String,
    #[serde(default)]
    pub phase2_auth: String,
    #[serde(default)]
    pub ca_cert_pem: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkProfileApplyReport {
    pub profile_id: String,
    pub connection_path: PathBuf,
    pub ca_cert_path: Option<PathBuf>,
}

pub fn apply_network_profile_config_change(
    payload_json: &str,
    profile_dir: &Path,
) -> Result<Option<NetworkProfileApplyReport>, String> {
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

    let mut profile: NetworkProfile = serde_json::from_value(profile_value)
        .map_err(|err| format!("invalid network_profile payload: {err}"))?;

    normalize_and_validate_profile(&mut profile)?;
    apply_network_profile(&profile, profile_dir).map(Some)
}

pub fn apply_network_profile(
    profile: &NetworkProfile,
    profile_dir: &Path,
) -> Result<NetworkProfileApplyReport, String> {
    fs::create_dir_all(profile_dir).map_err(|err| {
        format!(
            "failed creating profile directory {}: {err}",
            profile_dir.display()
        )
    })?;

    let profile_id = sanitize_component(&profile.profile_id);
    if profile_id.is_empty() {
        return Err("network profile id cannot be empty".to_string());
    }

    let connection_path = profile_dir.join(format!("{profile_id}.nmconnection"));

    let mut ca_cert_path = None;
    if matches!(profile.security, NetworkSecurity::Wpa2Enterprise)
        && !profile.ca_cert_pem.trim().is_empty()
    {
        let cert_path = profile_dir.join(format!("{profile_id}-ca.pem"));
        let cert_content = normalize_pem(&profile.ca_cert_pem);
        fs::write(&cert_path, cert_content).map_err(|err| {
            format!(
                "failed writing network profile CA certificate {}: {err}",
                cert_path.display()
            )
        })?;
        set_owner_only_permissions(&cert_path)?;
        ca_cert_path = Some(cert_path);
    }

    let content = render_nmconnection(profile, ca_cert_path.as_deref());
    fs::write(&connection_path, content).map_err(|err| {
        format!(
            "failed writing network profile connection file {}: {err}",
            connection_path.display()
        )
    })?;
    set_owner_only_permissions(&connection_path)?;

    Ok(NetworkProfileApplyReport {
        profile_id,
        connection_path,
        ca_cert_path,
    })
}

pub fn render_nmconnection(profile: &NetworkProfile, ca_cert_path: Option<&Path>) -> String {
    let mut out = Vec::new();

    out.push("[connection]".to_string());
    out.push(format!("id={}", profile.profile_id));
    out.push("type=wifi".to_string());
    out.push(format!("autoconnect={}", bool_to_nm(profile.auto_connect)));
    out.push(format!("autoconnect-priority={}", profile.priority));
    out.push(String::new());

    out.push("[wifi]".to_string());
    out.push("mode=infrastructure".to_string());
    out.push(format!("ssid={}", escape_nm_value(&profile.ssid)));
    out.push(String::new());

    match profile.security {
        NetworkSecurity::Open => {
            out.push("[wifi-security]".to_string());
            out.push("key-mgmt=none".to_string());
        }
        NetworkSecurity::Wpa2Psk => {
            out.push("[wifi-security]".to_string());
            out.push("key-mgmt=wpa-psk".to_string());
            out.push(format!("psk={}", escape_nm_value(&profile.psk)));
        }
        NetworkSecurity::Wpa2Enterprise => {
            out.push("[wifi-security]".to_string());
            out.push("key-mgmt=wpa-eap".to_string());
            out.push(String::new());

            out.push("[802-1x]".to_string());
            let eap_method = if profile.eap_method.trim().is_empty() {
                DEFAULT_EAP_METHOD
            } else {
                profile.eap_method.trim()
            };
            out.push(format!("eap={}", eap_method));
            out.push(format!("identity={}", escape_nm_value(&profile.identity)));
            if !profile.password.trim().is_empty() {
                out.push(format!("password={}", escape_nm_value(&profile.password)));
            }

            let phase2_auth = profile.phase2_auth.trim();
            if !phase2_auth.is_empty() {
                out.push(format!("phase2-auth={}", phase2_auth));
            }

            if let Some(path) = ca_cert_path {
                out.push(format!("ca-cert=file://{}", path.display()));
            }
        }
    }

    out.push(String::new());
    out.join("\n")
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

    match profile.security {
        NetworkSecurity::Open => {}
        NetworkSecurity::Wpa2Psk => {
            profile.psk = profile.psk.trim().to_string();
            if profile.psk.len() < 8 || profile.psk.len() > 63 {
                return Err("network profile psk must be 8-63 characters".to_string());
            }
        }
        NetworkSecurity::Wpa2Enterprise => {
            profile.identity = profile.identity.trim().to_string();
            if profile.identity.is_empty() {
                return Err("network profile identity is required".to_string());
            }

            let eap_method = profile.eap_method.trim().to_ascii_lowercase();
            profile.eap_method = if eap_method.is_empty() {
                DEFAULT_EAP_METHOD.to_string()
            } else {
                eap_method
            };
            match profile.eap_method.as_str() {
                "peap" | "tls" | "ttls" | "pwd" => {}
                _ => {
                    return Err("network profile eap_method is invalid".to_string());
                }
            }

            profile.phase2_auth = profile
                .phase2_auth
                .trim()
                .to_ascii_lowercase()
                .replace('-', "");
            if !profile.phase2_auth.is_empty() {
                match profile.phase2_auth.as_str() {
                    "mschapv2" | "pap" | "chap" | "gtc" => {}
                    _ => {
                        return Err("network profile phase2_auth is invalid".to_string());
                    }
                }
            }

            if !profile.ca_cert_pem.trim().is_empty()
                && (!profile.ca_cert_pem.contains("BEGIN CERTIFICATE")
                    || !profile.ca_cert_pem.contains("END CERTIFICATE"))
            {
                return Err("network profile ca_cert_pem must be PEM encoded".to_string());
            }
        }
    }

    Ok(())
}

fn set_owner_only_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|err| {
            format!(
                "failed setting owner-only permissions on {}: {err}",
                path.display()
            )
        })?;
    }

    #[cfg(not(unix))]
    {
        let _ = path;
    }

    Ok(())
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

fn normalize_pem(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.ends_with('\n') {
        trimmed.to_string()
    } else {
        format!("{trimmed}\n")
    }
}

fn escape_nm_value(raw: &str) -> String {
    raw.replace('\\', "\\\\")
        .replace('\n', "\\n")
        .trim()
        .to_string()
}

fn bool_to_nm(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn default_true() -> bool {
    true
}
