//! Screen lock compliance check.

#[cfg(target_os = "macos")]
use std::process::Command;

use serde::{Deserialize, Serialize};

/// Screen lock status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenLockStatus {
    pub enabled: bool,
    pub idle_time_seconds: Option<u32>,
    pub details: String,
}

/// Check screen lock configuration.
pub fn check_screen_lock() -> ScreenLockStatus {
    #[cfg(target_os = "macos")]
    {
        check_screen_lock_macos()
    }
    #[cfg(not(target_os = "macos"))]
    {
        tracing::warn!("check_screen_lock is a stub on non-macOS");
        ScreenLockStatus::default()
    }
}

#[cfg(target_os = "macos")]
fn check_screen_lock_macos() -> ScreenLockStatus {
    // Check if screen saver asks for password via defaults read.
    let output = match Command::new("defaults")
        .args(["read", "com.apple.screensaver", "askForPassword"])
        .output()
    {
        Ok(out) => out,
        Err(_) => return ScreenLockStatus::default(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let enabled = stdout == "1";

    let idle_time = Command::new("defaults")
        .args(["read", "com.apple.screensaver", "idleTime"])
        .output()
        .ok()
        .and_then(|out| {
            String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse::<u32>()
                .ok()
        });

    ScreenLockStatus {
        enabled,
        idle_time_seconds: idle_time,
        details: format!("askForPassword={stdout}"),
    }
}

impl Default for ScreenLockStatus {
    fn default() -> Self {
        Self {
            enabled: false,
            idle_time_seconds: None,
            details: "unknown".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ScreenLockStatus;

    #[test]
    fn screen_lock_default_is_disabled() {
        let status = ScreenLockStatus::default();
        assert!(!status.enabled);
        assert!(status.idle_time_seconds.is_none());
    }
}
