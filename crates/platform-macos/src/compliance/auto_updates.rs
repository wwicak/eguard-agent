//! Auto-updates compliance check.

#[cfg(target_os = "macos")]
use std::process::Command;

use serde::{Deserialize, Serialize};

/// Auto-update status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoUpdateStatus {
    pub automatic_check_enabled: bool,
    pub automatic_download: bool,
    pub auto_install_os_updates: bool,
    pub details: String,
}

/// Check automatic update settings.
///
/// Uses a single `defaults export` subprocess call to read all keys at once
/// (instead of 3 separate `defaults read` calls).
pub fn check_auto_updates() -> AutoUpdateStatus {
    #[cfg(target_os = "macos")]
    {
        check_auto_updates_macos()
    }
    #[cfg(not(target_os = "macos"))]
    {
        tracing::warn!("check_auto_updates is a stub on non-macOS");
        AutoUpdateStatus::default()
    }
}

#[cfg(target_os = "macos")]
fn check_auto_updates_macos() -> AutoUpdateStatus {
    // Single subprocess: export entire plist domain as XML, parse all keys at once.
    let xml = match export_software_update_plist() {
        Some(xml) => xml,
        None => return AutoUpdateStatus::default(),
    };

    let auto_check = plist_xml_bool_value(&xml, "AutomaticCheckEnabled");
    let auto_download = plist_xml_bool_value(&xml, "AutomaticDownload");
    let auto_install = plist_xml_bool_value(&xml, "AutomaticallyInstallMacOSUpdates");

    AutoUpdateStatus {
        automatic_check_enabled: auto_check,
        automatic_download: auto_download,
        auto_install_os_updates: auto_install,
        details: format!("check={auto_check},download={auto_download},install={auto_install}"),
    }
}

/// Export the entire SoftwareUpdate plist domain as XML via a single subprocess.
#[cfg(target_os = "macos")]
fn export_software_update_plist() -> Option<String> {
    let output = Command::new("defaults")
        .args([
            "export",
            "/Library/Preferences/com.apple.SoftwareUpdate",
            "-",
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Extract a boolean value from plist XML output.
///
/// Looks for `<key>NAME</key>` followed by `<true/>` or `<false/>`.
#[cfg(target_os = "macos")]
fn plist_xml_bool_value(xml: &str, key: &str) -> bool {
    let key_tag = format!("<key>{key}</key>");
    let Some(pos) = xml.find(&key_tag) else {
        return false;
    };
    let after_key = &xml[pos + key_tag.len()..];
    let trimmed = after_key.trim_start();
    trimmed.starts_with("<true/>")
}

impl Default for AutoUpdateStatus {
    fn default() -> Self {
        Self {
            automatic_check_enabled: false,
            automatic_download: false,
            auto_install_os_updates: false,
            details: "unknown".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AutoUpdateStatus;

    #[test]
    fn auto_updates_default_is_disabled() {
        let status = AutoUpdateStatus::default();
        assert!(!status.automatic_check_enabled);
        assert!(!status.automatic_download);
    }
}
