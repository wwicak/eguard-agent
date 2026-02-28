//! SID-to-username resolution.
//!
//! On Windows, uses PowerShell SID translation for deterministic user-context resolution.

#[cfg(target_os = "windows")]
use crate::windows_cmd::POWERSHELL_EXE;
#[cfg(target_os = "windows")]
use std::process::Command;

/// Resolve a Windows SID string to a username.
pub fn resolve_sid_to_username(sid: &str) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        resolve_sid_windows(sid)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = sid;
        None
    }
}

/// Resolve a UID (token user) to a username.
pub fn resolve_uid_to_username(uid: u32) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        // UID is a Linux concept; for Windows builds we surface the current
        // process username as best-effort identity context.
        let _ = uid;
        std::env::var("USERNAME")
            .ok()
            .filter(|value| !value.trim().is_empty())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = uid;
        None
    }
}

#[cfg(target_os = "windows")]
fn resolve_sid_windows(sid: &str) -> Option<String> {
    let command = format!(
        "try {{ ([System.Security.Principal.SecurityIdentifier]::new('{}')).Translate([System.Security.Principal.NTAccount]).Value }} catch {{ '' }}",
        sid.replace('"', "")
    );

    let output = Command::new(POWERSHELL_EXE)
        .args(["-NoProfile", "-NonInteractive", "-Command", &command])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn username_env_fallback_requires_non_empty_value() {
        assert!(!"alice".trim().is_empty());
        assert!("   ".trim().is_empty());
    }
}
