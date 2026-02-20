//! MDM (Mobile Device Management) enrollment check.

#[cfg(target_os = "macos")]
use std::process::Command;

use serde::{Deserialize, Serialize};

/// MDM enrollment status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdmStatus {
    pub enrolled: bool,
    pub details: String,
}

/// Check MDM enrollment via `profiles status`.
pub fn check_mdm() -> MdmStatus {
    #[cfg(target_os = "macos")]
    {
        check_mdm_macos()
    }
    #[cfg(not(target_os = "macos"))]
    {
        tracing::warn!("check_mdm is a stub on non-macOS");
        MdmStatus::default()
    }
}

#[cfg(target_os = "macos")]
fn check_mdm_macos() -> MdmStatus {
    let output = match Command::new("profiles")
        .args(["status", "-type", "enrollment"])
        .output()
    {
        Ok(out) => out,
        Err(_) => return MdmStatus::default(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let lower = stdout.to_ascii_lowercase();
    let enrolled = lower.contains("yes");

    MdmStatus {
        enrolled,
        details: stdout.trim().to_string(),
    }
}

impl Default for MdmStatus {
    fn default() -> Self {
        Self {
            enrolled: false,
            details: "unknown".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MdmStatus;

    #[test]
    fn mdm_default_is_not_enrolled() {
        let status = MdmStatus::default();
        assert!(!status.enrolled);
    }
}
