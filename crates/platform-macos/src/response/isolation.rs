//! Network isolation response action via macOS pf (packet filter).

#[cfg(target_os = "macos")]
use std::fs;
#[cfg(target_os = "macos")]
use std::process::Command;

#[cfg(target_os = "macos")]
const PF_ANCHOR_PATH: &str = "/etc/pf.anchors/com.eguard";
#[cfg(target_os = "macos")]
const PF_ANCHOR_NAME: &str = "com.eguard";

/// Isolate a host from the network, allowing only the specified server IPs.
pub fn isolate_host(allowed_server_ips: &[&str]) -> Result<(), super::ResponseError> {
    #[cfg(target_os = "macos")]
    {
        // Clean old rules first to make operation idempotent.
        remove_isolation()?;

        // Build pf rules: allow specified IPs, block everything else.
        let mut rules = String::new();
        for ip in allowed_server_ips {
            rules.push_str(&format!("pass out quick proto tcp to {ip}\n"));
            rules.push_str(&format!("pass in quick proto tcp from {ip}\n"));
        }
        // Allow loopback.
        rules.push_str("pass quick on lo0 all\n");
        // Block everything else.
        rules.push_str("block all\n");

        fs::write(PF_ANCHOR_PATH, &rules).map_err(|err| {
            super::ResponseError::OperationFailed(format!(
                "failed writing pf anchor {PF_ANCHOR_PATH}: {err}"
            ))
        })?;

        // Load the anchor into pf.
        run_pfctl(&["-a", PF_ANCHOR_NAME, "-f", PF_ANCHOR_PATH])?;
        // Enable pf if not already enabled.
        let _ = run_pfctl(&["-e"]);

        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = allowed_server_ips;
        tracing::warn!("isolate_host is a stub on non-macOS");
        Ok(())
    }
}

/// Remove host network isolation.
pub fn remove_isolation() -> Result<(), super::ResponseError> {
    #[cfg(target_os = "macos")]
    {
        // Flush the anchor rules.
        let _ = run_pfctl(&["-a", PF_ANCHOR_NAME, "-F", "all"]);
        // Remove anchor file.
        let _ = fs::remove_file(PF_ANCHOR_PATH);
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        tracing::warn!("remove_isolation is a stub on non-macOS");
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn run_pfctl(args: &[&str]) -> Result<(), super::ResponseError> {
    let output = Command::new("pfctl").args(args).output().map_err(|err| {
        super::ResponseError::OperationFailed(format!("failed spawning pfctl {:?}: {err}", args))
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
    Err(super::ResponseError::OperationFailed(detail))
}
