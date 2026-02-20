//! Gatekeeper compliance check.

#[cfg(target_os = "macos")]
use std::process::Command;

use serde::{Deserialize, Serialize};

/// Gatekeeper status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatekeeperStatus {
    pub enabled: bool,
    pub details: String,
}

/// Check Gatekeeper status via `spctl --status`.
pub fn check_gatekeeper() -> GatekeeperStatus {
    #[cfg(target_os = "macos")]
    {
        check_gatekeeper_macos()
    }
    #[cfg(not(target_os = "macos"))]
    {
        tracing::warn!("check_gatekeeper is a stub on non-macOS");
        GatekeeperStatus::default()
    }
}

#[cfg(target_os = "macos")]
fn check_gatekeeper_macos() -> GatekeeperStatus {
    let output = match Command::new("spctl").arg("--status").output() {
        Ok(out) => out,
        Err(_) => return GatekeeperStatus::default(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout} {stderr}");
    let lower = combined.to_ascii_lowercase();
    let enabled = lower.contains("enabled");

    GatekeeperStatus {
        enabled,
        details: combined.trim().to_string(),
    }
}

impl Default for GatekeeperStatus {
    fn default() -> Self {
        Self {
            enabled: false,
            details: "unknown".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::GatekeeperStatus;

    #[test]
    fn gatekeeper_default_is_disabled() {
        let status = GatekeeperStatus::default();
        assert!(!status.enabled);
    }
}
