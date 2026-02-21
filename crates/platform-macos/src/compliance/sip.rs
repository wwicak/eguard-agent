//! System Integrity Protection (SIP) compliance check.

#[cfg(target_os = "macos")]
use std::process::Command;

use serde::{Deserialize, Serialize};

/// SIP status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SipStatus {
    pub enabled: bool,
    pub details: String,
}

/// Check SIP status via `csrutil status`.
pub fn check_sip() -> SipStatus {
    #[cfg(target_os = "macos")]
    {
        check_sip_macos()
    }
    #[cfg(not(target_os = "macos"))]
    {
        tracing::warn!("check_sip is a stub on non-macOS");
        SipStatus::default()
    }
}

#[cfg(target_os = "macos")]
fn check_sip_macos() -> SipStatus {
    let output = match Command::new("csrutil").arg("status").output() {
        Ok(out) => out,
        Err(_) => return SipStatus::default(),
    };

    if !output.status.success() {
        return SipStatus::default();
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let lower = stdout.to_ascii_lowercase();
    // csrutil outputs "System Integrity Protection status: enabled."
    let enabled = lower.contains("enabled");

    SipStatus {
        enabled,
        details: stdout.trim().to_string(),
    }
}

impl Default for SipStatus {
    fn default() -> Self {
        Self {
            enabled: false,
            details: "unknown".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SipStatus;

    #[test]
    fn sip_default_is_disabled() {
        let status = SipStatus::default();
        assert!(!status.enabled);
        assert_eq!(status.details, "unknown");
    }
}
