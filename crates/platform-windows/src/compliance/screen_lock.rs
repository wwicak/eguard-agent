//! Windows screen lock compliance checks.

use serde::{Deserialize, Serialize};

#[cfg(target_os = "windows")]
use super::registry::{read_reg_dword, read_reg_string};

#[cfg(target_os = "windows")]
const DESKTOP_KEY: &str = r"Control Panel\Desktop";
#[cfg(target_os = "windows")]
const SYSTEM_POLICIES_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

/// Windows screen lock status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenLockStatus {
    pub enabled: bool,
    pub idle_time_seconds: Option<u32>,
    pub details: String,
}

/// Check Windows screen lock configuration.
pub fn check_screen_lock() -> ScreenLockStatus {
    #[cfg(target_os = "windows")]
    {
        let screensaver_active = read_reg_string("HKCU", DESKTOP_KEY, "ScreenSaveActive")
            .map(|v| v.trim() == "1")
            .unwrap_or(false);
        let secure_on_resume = read_reg_string("HKCU", DESKTOP_KEY, "ScreenSaverIsSecure")
            .map(|v| v.trim() == "1")
            .unwrap_or(false);
        let screensaver_path = read_reg_string("HKCU", DESKTOP_KEY, "SCRNSAVE.EXE")
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        let screensaver_timeout = read_reg_string("HKCU", DESKTOP_KEY, "ScreenSaveTimeOut")
            .and_then(|v| v.trim().parse::<u32>().ok())
            .filter(|v| *v > 0);
        let inactivity_timeout = read_reg_dword("HKLM", SYSTEM_POLICIES_KEY, "InactivityTimeoutSecs")
            .filter(|v| *v > 0);

        let enabled = screensaver_active
            && secure_on_resume
            && screensaver_path.is_some()
            && (screensaver_timeout.is_some() || inactivity_timeout.is_some());
        let idle_time_seconds = inactivity_timeout.or(screensaver_timeout);

        ScreenLockStatus {
            enabled,
            idle_time_seconds,
            details: format!(
                "active={} secure={} saver={} timeout={:?} inactivity_timeout={:?}",
                screensaver_active,
                secure_on_resume,
                screensaver_path.is_some(),
                screensaver_timeout,
                inactivity_timeout
            ),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        tracing::warn!("check_screen_lock is a stub on non-Windows");
        ScreenLockStatus::default()
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
