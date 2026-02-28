//! Network isolation response action via Windows firewall commands.

#[cfg(any(test, target_os = "windows"))]
use std::collections::BTreeSet;
#[cfg(any(test, target_os = "windows"))]
use std::net::IpAddr;
#[cfg(target_os = "windows")]
use std::process::Command;

#[cfg(target_os = "windows")]
use crate::windows_cmd::NETSH_EXE;

#[cfg(target_os = "windows")]
const ISOLATION_RULE_GROUP: &str = "eGuard Host Isolation";
#[cfg(any(test, target_os = "windows"))]
const MAX_ALLOWED_SERVER_IPS: usize = 64;

/// Isolate a host from the network, allowing only the specified server IPs.
pub fn isolate_host(allowed_server_ips: &[&str]) -> Result<(), super::process::ResponseError> {
    #[cfg(target_os = "windows")]
    {
        let normalized_ips = normalize_allowed_server_ips(allowed_server_ips)?;

        // Clean old rules first to make operation idempotent.
        remove_isolation()?;

        for ip in &normalized_ips {
            if let Err(err) = add_allow_rule("out", ip) {
                let _ = remove_isolation();
                return Err(err);
            }
            if let Err(err) = add_allow_rule("in", ip) {
                let _ = remove_isolation();
                return Err(err);
            }
        }

        if let Err(err) = add_block_rule("out") {
            let _ = remove_isolation();
            return Err(err);
        }
        if let Err(err) = add_block_rule("in") {
            let _ = remove_isolation();
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
        let args = [
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("group={ISOLATION_RULE_GROUP}"),
        ];
        let _ = run_netsh(&args);
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        tracing::warn!("remove_isolation is a stub on non-Windows");
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn add_allow_rule(direction: &str, remote_ip: &str) -> Result<(), super::process::ResponseError> {
    let rule_name = format!("eGuard Allow {direction} {remote_ip}");
    let args = [
        "advfirewall",
        "firewall",
        "add",
        "rule",
        &format!("name={rule_name}"),
        &format!("group={ISOLATION_RULE_GROUP}"),
        &format!("dir={direction}"),
        "action=allow",
        &format!("remoteip={remote_ip}"),
        "profile=any",
    ];

    run_netsh(&args)
}

#[cfg(target_os = "windows")]
fn add_block_rule(direction: &str) -> Result<(), super::process::ResponseError> {
    let rule_name = format!("eGuard Block {direction} all");
    let args = [
        "advfirewall",
        "firewall",
        "add",
        "rule",
        &format!("name={rule_name}"),
        &format!("group={ISOLATION_RULE_GROUP}"),
        &format!("dir={direction}"),
        "action=block",
        "remoteip=any",
        "profile=any",
    ];

    run_netsh(&args)
}

#[cfg(target_os = "windows")]
fn run_netsh(args: &[&str]) -> Result<(), super::process::ResponseError> {
    let output = Command::new(NETSH_EXE).args(args).output().map_err(|err| {
        super::process::ResponseError::OperationFailed(format!(
            "failed spawning netsh {:?}: {err}",
            args
        ))
    })?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let detail = if stderr.trim().is_empty() {
        stdout
    } else {
        stderr
    };
    Err(super::process::ResponseError::OperationFailed(detail))
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
    use super::{normalize_allowed_server_ips, normalize_ip_or_cidr};

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
}
