//! macOS Application Firewall compliance check.

#[cfg(target_os = "macos")]
use std::process::Command;

use serde::{Deserialize, Serialize};

/// macOS firewall status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallStatus {
    pub enabled: bool,
    pub stealth_mode: bool,
    pub details: String,
}

/// Check firewall status via `socketfilterfw`.
pub fn check_firewall() -> FirewallStatus {
    #[cfg(target_os = "macos")]
    {
        check_firewall_macos()
    }
    #[cfg(not(target_os = "macos"))]
    {
        tracing::warn!("check_firewall is a stub on non-macOS");
        FirewallStatus::default()
    }
}

#[cfg(target_os = "macos")]
fn check_firewall_macos() -> FirewallStatus {
    let output = match Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw")
        .arg("--getglobalstate")
        .output()
    {
        Ok(out) => out,
        Err(_) => return FirewallStatus::default(),
    };

    if !output.status.success() {
        return FirewallStatus::default();
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let lower = stdout.to_ascii_lowercase();
    let enabled = lower.contains("enabled");

    let stealth_mode = check_stealth_mode();

    FirewallStatus {
        enabled,
        stealth_mode,
        details: stdout.trim().to_string(),
    }
}

#[cfg(target_os = "macos")]
fn check_stealth_mode() -> bool {
    let output = match Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw")
        .arg("--getstealthmode")
        .output()
    {
        Ok(out) => out,
        Err(_) => return false,
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    stdout.to_ascii_lowercase().contains("enabled")
}

impl Default for FirewallStatus {
    fn default() -> Self {
        Self {
            enabled: false,
            stealth_mode: false,
            details: "unknown".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FirewallStatus;

    #[test]
    fn firewall_default_is_disabled() {
        let status = FirewallStatus::default();
        assert!(!status.enabled);
        assert!(!status.stealth_mode);
    }
}
