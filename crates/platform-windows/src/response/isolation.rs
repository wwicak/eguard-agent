//! Network isolation response action via Windows firewall commands.

#[cfg(any(test, target_os = "windows"))]
use std::collections::BTreeSet;
#[cfg(any(test, target_os = "windows"))]
use std::net::IpAddr;
#[cfg(target_os = "windows")]
use std::path::PathBuf;
#[cfg(target_os = "windows")]
use std::{fs, process::Command};

#[cfg(any(test, target_os = "windows"))]
use serde::{Deserialize, Serialize};

#[cfg(target_os = "windows")]
use crate::windows_cmd::POWERSHELL_EXE;

const ISOLATION_RULE_GROUP: &str = "eGuard Host Isolation";
#[cfg(any(test, target_os = "windows"))]
const MAX_ALLOWED_SERVER_IPS: usize = 64;
#[cfg(target_os = "windows")]
const ISOLATION_STATE_FILE: &str = "response/host-isolation-firewall-state.json";

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct FirewallProfileDefaults {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "DefaultInboundAction")]
    default_inbound_action: String,
    #[serde(rename = "DefaultOutboundAction")]
    default_outbound_action: String,
}

/// Isolate a host from the network, allowing only the specified server IPs.
pub fn isolate_host(allowed_server_ips: &[&str]) -> Result<(), super::process::ResponseError> {
    #[cfg(target_os = "windows")]
    {
        let normalized_ips = normalize_allowed_server_ips(allowed_server_ips)?;
        let (saved_defaults, had_saved_defaults) = load_or_persist_firewall_profile_defaults()?;

        if let Err(err) = run_powershell_script(&build_apply_isolation_script(&normalized_ips)) {
            let _ = run_powershell_script(&build_remove_isolation_rules_script());
            let _ = run_powershell_script(&build_restore_profiles_script(&saved_defaults));
            if !had_saved_defaults {
                let _ = clear_persisted_firewall_profile_defaults();
            }
            return Err(err);
        }

        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = allowed_server_ips;
        tracing::warn!("isolate_host is a stub on non-Windows");
        Ok(())
    }
}

/// Remove host network isolation.
pub fn remove_isolation() -> Result<(), super::process::ResponseError> {
    #[cfg(target_os = "windows")]
    {
        let saved_defaults = load_persisted_firewall_profile_defaults()?;
        run_powershell_script(&build_remove_isolation_rules_script())?;

        if let Some(defaults) = saved_defaults {
            run_powershell_script(&build_restore_profiles_script(&defaults))?;
            clear_persisted_firewall_profile_defaults()?;
        }

        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        tracing::warn!("remove_isolation is a stub on non-Windows");
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn load_or_persist_firewall_profile_defaults(
) -> Result<(Vec<FirewallProfileDefaults>, bool), super::process::ResponseError> {
    if let Some(saved) = load_persisted_firewall_profile_defaults()? {
        return Ok((saved, true));
    }

    let current = query_current_firewall_profile_defaults()?;
    persist_firewall_profile_defaults(&current)?;
    Ok((current, false))
}

#[cfg(target_os = "windows")]
fn query_current_firewall_profile_defaults(
) -> Result<Vec<FirewallProfileDefaults>, super::process::ResponseError> {
    let raw = run_powershell_script(
        "Get-NetFirewallProfile | Select-Object Name,@{Name='DefaultInboundAction';Expression={$_.DefaultInboundAction.ToString()}},@{Name='DefaultOutboundAction';Expression={$_.DefaultOutboundAction.ToString()}} | ConvertTo-Json -Compress",
    )?;
    parse_firewall_profile_defaults(&raw)
}

#[cfg(target_os = "windows")]
fn persist_firewall_profile_defaults(
    defaults: &[FirewallProfileDefaults],
) -> Result<(), super::process::ResponseError> {
    let path = resolve_isolation_state_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            super::process::ResponseError::OperationFailed(format!(
                "failed creating isolation state dir {}: {err}",
                parent.display()
            ))
        })?;
    }

    let raw = serde_json::to_vec(defaults).map_err(|err| {
        super::process::ResponseError::OperationFailed(format!(
            "failed encoding firewall profile defaults: {err}"
        ))
    })?;

    fs::write(&path, raw).map_err(|err| {
        super::process::ResponseError::OperationFailed(format!(
            "failed writing isolation state {}: {err}",
            path.display()
        ))
    })
}

#[cfg(target_os = "windows")]
fn load_persisted_firewall_profile_defaults(
) -> Result<Option<Vec<FirewallProfileDefaults>>, super::process::ResponseError> {
    let path = resolve_isolation_state_path();
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(super::process::ResponseError::OperationFailed(format!(
                "failed reading isolation state {}: {err}",
                path.display()
            )))
        }
    };

    parse_firewall_profile_defaults(&raw).map(Some)
}

#[cfg(target_os = "windows")]
fn clear_persisted_firewall_profile_defaults() -> Result<(), super::process::ResponseError> {
    let path = resolve_isolation_state_path();
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(super::process::ResponseError::OperationFailed(format!(
            "failed removing isolation state {}: {err}",
            path.display()
        ))),
    }
}

#[cfg(target_os = "windows")]
fn run_powershell_script(script: &str) -> Result<String, super::process::ResponseError> {
    let output = Command::new(POWERSHELL_EXE)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()
        .map_err(|err| {
            super::process::ResponseError::OperationFailed(format!(
                "failed spawning PowerShell isolation command: {err}"
            ))
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if output.status.success() {
        return Ok(stdout);
    }

    let detail = if stderr.is_empty() { stdout } else { stderr };
    Err(super::process::ResponseError::OperationFailed(detail))
}

#[cfg(target_os = "windows")]
fn resolve_isolation_state_path() -> PathBuf {
    let root = std::env::var("EGUARD_AGENT_DATA_DIR")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData\eGuard"));
    root.join(ISOLATION_STATE_FILE)
}

#[cfg(any(test, target_os = "windows"))]
fn powershell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(any(test, target_os = "windows"))]
fn build_remove_isolation_rules_script() -> String {
    let group = powershell_single_quote(ISOLATION_RULE_GROUP);
    format!(
        "$ErrorActionPreference='Stop'; $group={group}; $rules=@(Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue); if ($rules.Count -gt 0) {{ $rules | Remove-NetFirewallRule -Confirm:$false -ErrorAction SilentlyContinue | Out-Null; }}"
    )
}

#[cfg(any(test, target_os = "windows"))]
fn build_apply_isolation_script(allowed_ips: &[String]) -> String {
    let group = powershell_single_quote(ISOLATION_RULE_GROUP);
    let allowed = allowed_ips
        .iter()
        .map(|ip| powershell_single_quote(ip))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "$ErrorActionPreference='Stop'; {remove}; $group={group}; $allowed=@({allowed}); foreach ($ip in $allowed) {{ New-NetFirewallRule -DisplayName ('eGuard Allow Outbound ' + $ip) -Group $group -Direction Outbound -Action Allow -RemoteAddress $ip -Profile Any | Out-Null; New-NetFirewallRule -DisplayName ('eGuard Allow Inbound ' + $ip) -Group $group -Direction Inbound -Action Allow -RemoteAddress $ip -Profile Any | Out-Null; }} Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Block | Out-Null;",
        remove = build_remove_isolation_rules_script(),
    )
}

#[cfg(any(test, target_os = "windows"))]
fn build_restore_profiles_script(defaults: &[FirewallProfileDefaults]) -> String {
    let mut script = String::from("$ErrorActionPreference='Stop';");
    for profile in defaults {
        script.push_str(&format!(
            " Set-NetFirewallProfile -Profile {profile_name} -DefaultInboundAction {inbound} -DefaultOutboundAction {outbound} | Out-Null;",
            profile_name = powershell_single_quote(&profile.name),
            inbound = powershell_single_quote(&profile.default_inbound_action),
            outbound = powershell_single_quote(&profile.default_outbound_action),
        ));
    }
    script
}

#[cfg(any(test, target_os = "windows"))]
fn parse_firewall_profile_defaults(
    raw: &str,
) -> Result<Vec<FirewallProfileDefaults>, super::process::ResponseError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(super::process::ResponseError::OperationFailed(
            "firewall profile query returned empty output".to_string(),
        ));
    }

    let value = serde_json::from_str::<serde_json::Value>(trimmed).map_err(|err| {
        super::process::ResponseError::OperationFailed(format!(
            "invalid firewall profile JSON: {err}"
        ))
    })?;

    let mut profiles = match value {
        serde_json::Value::Array(items) => items
            .into_iter()
            .map(parse_firewall_profile_default_value)
            .collect::<Result<Vec<_>, _>>()?,
        serde_json::Value::Object(_) => vec![parse_firewall_profile_default_value(value)?],
        _ => {
            return Err(super::process::ResponseError::OperationFailed(
                "firewall profile query did not return an object/array".to_string(),
            ))
        }
    };

    if profiles.is_empty() {
        return Err(super::process::ResponseError::OperationFailed(
            "firewall profile query returned no profiles".to_string(),
        ));
    }

    profiles.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(profiles)
}

#[cfg(any(test, target_os = "windows"))]
fn parse_firewall_profile_default_value(
    value: serde_json::Value,
) -> Result<FirewallProfileDefaults, super::process::ResponseError> {
    serde_json::from_value(value).map_err(|err| {
        super::process::ResponseError::OperationFailed(format!(
            "invalid firewall profile entry: {err}"
        ))
    })
}

#[cfg(any(test, target_os = "windows"))]
fn normalize_allowed_server_ips(
    allowed_server_ips: &[&str],
) -> Result<Vec<String>, super::process::ResponseError> {
    let mut deduped = BTreeSet::new();

    for candidate in allowed_server_ips {
        let normalized = normalize_ip_or_cidr(candidate).ok_or_else(|| {
            super::process::ResponseError::OperationFailed(format!(
                "invalid isolation allowlist IP/CIDR: {candidate}"
            ))
        })?;
        deduped.insert(normalized);
    }

    if deduped.is_empty() {
        return Err(super::process::ResponseError::OperationFailed(
            "isolation requires at least one valid management server IP/CIDR".to_string(),
        ));
    }

    if deduped.len() > MAX_ALLOWED_SERVER_IPS {
        return Err(super::process::ResponseError::OperationFailed(format!(
            "isolation allowlist too large: {} entries (max {MAX_ALLOWED_SERVER_IPS})",
            deduped.len()
        )));
    }

    Ok(deduped.into_iter().collect())
}

#[cfg(any(test, target_os = "windows"))]
fn normalize_ip_or_cidr(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(ip.to_string());
    }

    let (ip_raw, prefix_raw) = trimmed.split_once('/')?;
    let ip = ip_raw.parse::<IpAddr>().ok()?;
    let prefix = prefix_raw.parse::<u8>().ok()?;

    let max_prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };

    if prefix > max_prefix {
        return None;
    }

    Some(format!("{ip}/{prefix}"))
}

#[cfg(test)]
mod tests {
    use super::{
        build_apply_isolation_script, build_restore_profiles_script, normalize_allowed_server_ips,
        normalize_ip_or_cidr, parse_firewall_profile_defaults, FirewallProfileDefaults,
    };

    #[test]
    fn normalize_ip_or_cidr_accepts_valid_inputs() {
        assert_eq!(
            normalize_ip_or_cidr("203.0.113.10").as_deref(),
            Some("203.0.113.10")
        );
        assert_eq!(
            normalize_ip_or_cidr("203.0.113.10/32").as_deref(),
            Some("203.0.113.10/32")
        );
        assert_eq!(
            normalize_ip_or_cidr("2001:db8::1").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(
            normalize_ip_or_cidr("2001:db8::1/128").as_deref(),
            Some("2001:db8::1/128")
        );
    }

    #[test]
    fn normalize_ip_or_cidr_rejects_invalid_inputs() {
        assert!(normalize_ip_or_cidr("").is_none());
        assert!(normalize_ip_or_cidr("  ").is_none());
        assert!(normalize_ip_or_cidr("not-an-ip").is_none());
        assert!(normalize_ip_or_cidr("203.0.113.10/64").is_none());
        assert!(normalize_ip_or_cidr("2001:db8::1/200").is_none());
    }

    #[test]
    fn normalize_allowed_server_ips_deduplicates_and_sorts() {
        let normalized = normalize_allowed_server_ips(&[
            "203.0.113.10",
            " 203.0.113.10 ",
            "2001:db8::1",
            "2001:db8::1/128",
        ])
        .expect("allowlist should be valid");

        assert_eq!(normalized.len(), 3);
        assert_eq!(normalized[0], "2001:db8::1");
        assert_eq!(normalized[1], "2001:db8::1/128");
        assert_eq!(normalized[2], "203.0.113.10");
    }

    #[test]
    fn normalize_allowed_server_ips_requires_non_empty_allowlist() {
        assert!(normalize_allowed_server_ips(&[]).is_err());
    }

    #[test]
    fn apply_isolation_script_uses_windows_firewall_cmdlets() {
        let script =
            build_apply_isolation_script(&["203.0.113.10".to_string(), "2001:db8::1".to_string()]);

        assert!(script.contains("New-NetFirewallRule"));
        assert!(script.contains("Remove-NetFirewallRule"));
        assert!(script.contains("Set-NetFirewallProfile"));
        assert!(script.contains("203.0.113.10"));
        assert!(script.contains("2001:db8::1"));
        assert!(!script.contains("advfirewall"));
        assert!(!script.contains("firewall add rule"));
        assert!(!script.contains("netsh"));
    }

    #[test]
    fn restore_profile_script_replays_saved_defaults() {
        let script = build_restore_profiles_script(&[
            FirewallProfileDefaults {
                name: "Domain".to_string(),
                default_inbound_action: "Allow".to_string(),
                default_outbound_action: "Block".to_string(),
            },
            FirewallProfileDefaults {
                name: "Public".to_string(),
                default_inbound_action: "Block".to_string(),
                default_outbound_action: "Allow".to_string(),
            },
        ]);

        assert!(script.contains("Set-NetFirewallProfile -Profile 'Domain' -DefaultInboundAction 'Allow' -DefaultOutboundAction 'Block'"));
        assert!(script.contains("Set-NetFirewallProfile -Profile 'Public' -DefaultInboundAction 'Block' -DefaultOutboundAction 'Allow'"));
    }

    #[test]
    fn parse_firewall_profile_defaults_accepts_profile_array_json() {
        let parsed = parse_firewall_profile_defaults(
            r#"[
                {"Name":"Public","DefaultInboundAction":"Block","DefaultOutboundAction":"Allow"},
                {"Name":"Domain","DefaultInboundAction":"Allow","DefaultOutboundAction":"Block"}
            ]"#,
        )
        .expect("profile defaults should parse");

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "Domain");
        assert_eq!(parsed[1].name, "Public");
    }
}
