//! FileVault (disk encryption) compliance check.

#[cfg(target_os = "macos")]
use std::process::Command;

use serde::{Deserialize, Serialize};

/// FileVault status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileVaultStatus {
    pub enabled: bool,
    pub details: String,
}

/// Check FileVault status via `fdesetup status`.
pub fn check_filevault() -> FileVaultStatus {
    #[cfg(target_os = "macos")]
    {
        check_filevault_macos()
    }
    #[cfg(not(target_os = "macos"))]
    {
        tracing::warn!("check_filevault is a stub on non-macOS");
        FileVaultStatus::default()
    }
}

#[cfg(target_os = "macos")]
fn check_filevault_macos() -> FileVaultStatus {
    let output = match Command::new("fdesetup").arg("status").output() {
        Ok(out) => out,
        Err(_) => return FileVaultStatus::default(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let lower = stdout.to_ascii_lowercase();
    let enabled = lower.contains("on");

    FileVaultStatus {
        enabled,
        details: stdout.trim().to_string(),
    }
}

impl Default for FileVaultStatus {
    fn default() -> Self {
        Self {
            enabled: false,
            details: "unknown".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FileVaultStatus;

    #[test]
    fn filevault_default_is_disabled() {
        let status = FileVaultStatus::default();
        assert!(!status.enabled);
    }
}
