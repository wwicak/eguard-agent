//! Network isolation response action via Windows firewall commands.

#[cfg(target_os = "windows")]
use std::process::Command;

#[cfg(target_os = "windows")]
const ISOLATION_RULE_GROUP: &str = "eGuard Host Isolation";

/// Isolate a host from the network, allowing only the specified server IPs.
pub fn isolate_host(allowed_server_ips: &[&str]) -> Result<(), super::process::ResponseError> {
    #[cfg(target_os = "windows")]
    {
        // Clean old rules first to make operation idempotent.
        remove_isolation()?;

        for ip in allowed_server_ips {
            add_allow_rule("out", ip)?;
            add_allow_rule("in", ip)?;
        }

        add_block_rule("out")?;
        add_block_rule("in")?;
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
    let output = Command::new("netsh").args(args).output().map_err(|err| {
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
