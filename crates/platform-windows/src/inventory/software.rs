//! Installed software inventory from the Windows registry.

use serde::{Deserialize, Serialize};

/// An installed program entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledProgram {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub install_date: Option<String>,
}

/// Collect all installed software from the registry uninstall keys.
pub fn collect_installed_software() -> Vec<InstalledProgram> {
    #[cfg(target_os = "windows")]
    {
        // TODO: Enumerate HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
        // and HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
        Vec::new()
    }
    #[cfg(not(target_os = "windows"))]
    {
        tracing::warn!("collect_installed_software is a stub on non-Windows");
        Vec::new()
    }
}
