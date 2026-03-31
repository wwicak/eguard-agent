//! Screen lock compliance check.

#[cfg(target_os = "macos")]
use std::process::Command;

#[cfg(target_os = "macos")]
use std::process::Stdio;

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
    let console_user = detect_console_user();
    let by_host = console_user
        .as_deref()
        .and_then(read_screensaver_settings_from_byhost);
    let current_host = read_screensaver_settings_from_defaults();

    let idle_time = by_host
        .as_ref()
        .and_then(|settings| settings.idle_time_seconds)
        .or_else(|| {
            current_host
                .as_ref()
                .and_then(|settings| settings.idle_time_seconds)
        });
    let ask_for_password = by_host
        .as_ref()
        .and_then(|settings| settings.ask_for_password)
        .or_else(|| {
            current_host
                .as_ref()
                .and_then(|settings| settings.ask_for_password)
        });
    let ask_for_password_delay = by_host
        .as_ref()
        .and_then(|settings| settings.ask_for_password_delay_seconds)
        .or_else(|| {
            current_host
                .as_ref()
                .and_then(|settings| settings.ask_for_password_delay_seconds)
        });
    let auth_required = read_screensaver_authorizationdb()
        .as_deref()
        .map(screen_unlock_requires_authentication)
        .unwrap_or(false);

    let idle_enabled = idle_time.is_some_and(|seconds| seconds > 0);
    let password_enforced = ask_for_password == Some(true)
        || (ask_for_password_delay == Some(0) && idle_enabled)
        || (auth_required && idle_enabled);
    let enabled = idle_enabled && password_enforced;
    let details = format!(
        "console_user={},idle_time={:?},ask_for_password={:?},ask_for_password_delay={:?},auth_required={}",
        console_user.as_deref().unwrap_or("unknown"),
        idle_time,
        ask_for_password,
        ask_for_password_delay,
        auth_required
    );

    ScreenLockStatus {
        enabled,
        idle_time_seconds: idle_time,
        details,
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Default)]
struct ScreenSaverSettings {
    idle_time_seconds: Option<u32>,
    ask_for_password: Option<bool>,
    ask_for_password_delay_seconds: Option<u32>,
}

#[cfg(target_os = "macos")]
fn detect_console_user() -> Option<String> {
    let output = Command::new("stat")
        .args(["-f", "%Su", "/dev/console"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let user = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if user.is_empty() || user == "root" {
        None
    } else {
        Some(user)
    }
}

#[cfg(target_os = "macos")]
fn read_screensaver_settings_from_defaults() -> Option<ScreenSaverSettings> {
    let output = Command::new("defaults")
        .args(["-currentHost", "read", "com.apple.screensaver"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    Some(parse_defaults_dictionary(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

#[cfg(target_os = "macos")]
fn read_screensaver_settings_from_byhost(user: &str) -> Option<ScreenSaverSettings> {
    let command = format!("plutil -p /Users/{user}/Library/Preferences/ByHost/com.apple.screensaver.*.plist 2>/dev/null");
    let output = Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdout(Stdio::piped())
        .output()
        .ok()?;
    if !output.status.success() || output.stdout.is_empty() {
        return None;
    }

    Some(parse_defaults_dictionary(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

#[cfg(target_os = "macos")]
fn read_screensaver_authorizationdb() -> Option<String> {
    let output = Command::new("security")
        .args(["authorizationdb", "read", "system.login.screensaver"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "macos")]
fn parse_defaults_dictionary(raw: &str) -> ScreenSaverSettings {
    let mut settings = ScreenSaverSettings::default();
    for line in raw.lines() {
        let trimmed = line.trim().trim_end_matches(';');
        if let Some(value) = trimmed
            .strip_prefix("\"idleTime\" =>")
            .or_else(|| trimmed.strip_prefix("idleTime ="))
        {
            settings.idle_time_seconds = value.trim().parse::<u32>().ok();
        } else if let Some(value) = trimmed
            .strip_prefix("\"askForPassword\" =>")
            .or_else(|| trimmed.strip_prefix("askForPassword ="))
        {
            settings.ask_for_password = parse_defaults_bool(value.trim());
        } else if let Some(value) = trimmed
            .strip_prefix("\"askForPasswordDelay\" =>")
            .or_else(|| trimmed.strip_prefix("askForPasswordDelay ="))
        {
            settings.ask_for_password_delay_seconds = value.trim().parse::<u32>().ok();
        }
    }
    settings
}

#[cfg(target_os = "macos")]
fn parse_defaults_bool(raw: &str) -> Option<bool> {
    match raw.trim().trim_matches('"') {
        "1" | "true" | "YES" => Some(true),
        "0" | "false" | "NO" => Some(false),
        _ => None,
    }
}

#[cfg(target_os = "macos")]
fn screen_unlock_requires_authentication(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    lower.contains("use-login-window-ui") || lower.contains("authenticate-session-owner-or-admin")
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
    use super::{
        parse_defaults_dictionary, screen_unlock_requires_authentication, ScreenLockStatus,
    };

    #[test]
    fn screen_lock_default_is_disabled() {
        let status = ScreenLockStatus::default();
        assert!(!status.enabled);
        assert!(status.idle_time_seconds.is_none());
    }

    #[test]
    fn parse_defaults_dictionary_extracts_relevant_screensaver_keys() {
        let raw = "{\n  \"askForPassword\" => 1\n  \"askForPasswordDelay\" => 0\n  \"idleTime\" => 600\n}";
        let settings = parse_defaults_dictionary(raw);

        assert_eq!(settings.ask_for_password, Some(true));
        assert_eq!(settings.ask_for_password_delay_seconds, Some(0));
        assert_eq!(settings.idle_time_seconds, Some(600));
    }

    #[test]
    fn authdb_rule_marks_screen_unlock_as_authenticated() {
        let raw = "<dict><key>rule</key><array><string>use-login-window-ui</string></array></dict>";
        assert!(screen_unlock_requires_authentication(raw));
    }
}
