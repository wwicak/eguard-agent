//! Platform-aware compliance snapshot converters.
//!
//! Maps platform-specific `ComplianceReport` types (from `platform-windows`
//! and `platform-macos`) into the platform-agnostic `SystemSnapshot` used
//! by the compliance evaluation engine.

#[cfg(target_os = "windows")]
use platform_windows::inventory::hardware::HardwareInfo;
#[cfg(any(target_os = "windows", target_os = "macos"))]
use std::collections::HashSet;
#[cfg(target_os = "macos")]
use std::process::Command;

use anyhow::Result;
use compliance::SystemSnapshot;

/// Collect a compliance snapshot for the current platform.
///
/// On Linux, delegates to the compliance crate's native `collect_linux_snapshot`.
/// On Windows/macOS, collects the platform report and converts it to a
/// `SystemSnapshot`.
pub(super) fn collect_platform_snapshot() -> Result<SystemSnapshot> {
    #[cfg(target_os = "linux")]
    {
        Ok(compliance::collect_linux_snapshot()?)
    }
    #[cfg(target_os = "windows")]
    {
        collect_windows_snapshot()
    }
    #[cfg(target_os = "macos")]
    {
        collect_macos_snapshot()
    }
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn collect_windows_snapshot() -> Result<SystemSnapshot> {
    let report = platform_windows::compliance::collect_compliance_report();
    let hardware = platform_windows::inventory::collect_hardware_info();

    let firewall_enabled = report.firewall.domain_profile_enabled
        && report.firewall.private_profile_enabled
        && report.firewall.public_profile_enabled;

    let root_fs_encrypted = Some(report.bitlocker.enabled);

    let antivirus_running = Some(report.defender.enabled && report.defender.real_time_protection);

    // Windows Update: no direct auto-update bool in UpdateStatus.
    // Use "no reboot required + no pending" as a best-effort proxy.
    let auto_updates_enabled = Some(report.updates.pending_count == 0);
    let screen_lock_enabled = Some(report.screen_lock.enabled);

    let kernel_version = hardware
        .os_version
        .clone()
        .unwrap_or_else(|| std::env::var("OS").unwrap_or_else(|_| "Windows".to_string()));

    let os_version = windows_os_version_label(&hardware);

    Ok(SystemSnapshot {
        firewall_enabled,
        kernel_version,
        os_version,
        root_fs_encrypted,
        ssh_root_login_permitted: None,
        installed_packages: None,
        running_services: None,
        password_policy_hardened: None,
        screen_lock_enabled,
        auto_updates_enabled,
        antivirus_running,
        agent_version: compliance::current_agent_version().to_string(),
        os_type: "windows".to_string(),
        capabilities: windows_capabilities(),
    })
}

#[cfg(target_os = "windows")]
fn windows_os_version_label(hardware: &HardwareInfo) -> Option<String> {
    let nt_current_version_key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

    let product_name = platform_windows::compliance::registry::read_reg_string(
        "HKLM",
        nt_current_version_key,
        "ProductName",
    )
    .map(|v| v.trim().to_string())
    .filter(|v| !v.is_empty());

    let display_version = platform_windows::compliance::registry::read_reg_string(
        "HKLM",
        nt_current_version_key,
        "DisplayVersion",
    )
    .or_else(|| {
        platform_windows::compliance::registry::read_reg_string(
            "HKLM",
            nt_current_version_key,
            "ReleaseId",
        )
    })
    .map(|v| v.trim().to_string())
    .filter(|v| !v.is_empty());

    if let Some(mut name) = product_name {
        if let Some(display) = display_version {
            let lname = name.to_ascii_lowercase();
            let ldisplay = display.to_ascii_lowercase();
            if !lname.contains(&ldisplay) {
                name = format!("{} {}", name, display);
            }
        }
        return Some(name);
    }

    match (&hardware.os_version, &hardware.os_build) {
        (Some(ver), Some(build)) => {
            Some(format!("Windows {} (build {})", ver.trim(), build.trim()))
        }
        (Some(ver), None) => Some(format!("Windows {}", ver.trim())),
        _ => None,
    }
}

#[cfg(target_os = "windows")]
fn windows_capabilities() -> HashSet<String> {
    [
        "firewall",
        "disk_encryption",
        "antivirus",
        "auto_updates",
        "screen_lock",
        "agent_version",
        "os_version",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

// ---------------------------------------------------------------------------
// macOS
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn collect_macos_snapshot() -> Result<SystemSnapshot> {
    let report = platform_macos::compliance::collect_compliance_report();

    let firewall_enabled = report.firewall.enabled;
    let root_fs_encrypted = Some(report.filevault.enabled);
    let screen_lock_enabled = Some(report.screen_lock.enabled);
    let auto_updates_enabled = Some(
        report.auto_updates.automatic_check_enabled && report.auto_updates.auto_install_os_updates,
    );

    let kernel_version = detect_macos_kernel_version()
        .unwrap_or_else(|| platform_macos::platform_name().to_string());
    let os_version = detect_macos_os_version_label();

    Ok(SystemSnapshot {
        firewall_enabled,
        kernel_version,
        os_version,
        root_fs_encrypted,
        ssh_root_login_permitted: None,
        installed_packages: None,
        running_services: None,
        password_policy_hardened: None,
        screen_lock_enabled,
        auto_updates_enabled,
        antivirus_running: None,
        agent_version: compliance::current_agent_version().to_string(),
        os_type: "macos".to_string(),
        capabilities: macos_capabilities(),
    })
}

#[cfg(target_os = "macos")]
fn macos_capabilities() -> HashSet<String> {
    [
        "firewall",
        "disk_encryption",
        "screen_lock",
        "auto_updates",
        "agent_version",
        "os_version",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

#[cfg(target_os = "macos")]
fn detect_macos_kernel_version() -> Option<String> {
    run_macos_command("/usr/sbin/sysctl", &["-n", "kern.osrelease"])
        .or_else(|| run_macos_command("/usr/bin/uname", &["-r"]))
}

#[cfg(target_os = "macos")]
fn detect_macos_os_version_label() -> Option<String> {
    let version = run_macos_command("/usr/bin/sw_vers", &["-productVersion"])
        .or_else(|| run_macos_command("/usr/sbin/sysctl", &["-n", "kern.osproductversion"]))?;

    Some(format_macos_version_label(&version))
}

#[cfg(target_os = "macos")]
fn run_macos_command(path: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(path).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let value = String::from_utf8(output.stdout).ok()?;
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[cfg(any(test, target_os = "macos"))]
fn format_macos_version_label(version: &str) -> String {
    let version = version.trim();
    let base = marketing_name_for_macos_version(version)
        .map(|name| format!("macOS {name} {version}"))
        .unwrap_or_else(|| format!("macOS {version}"));

    base
}

#[cfg(any(test, target_os = "macos"))]
fn marketing_name_for_macos_version(version: &str) -> Option<&'static str> {
    let major = version.trim().split('.').next()?.parse::<u32>().ok()?;

    match major {
        11 => Some("Big Sur"),
        12 => Some("Monterey"),
        13 => Some("Ventura"),
        14 => Some("Sonoma"),
        15 => Some("Sequoia"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{format_macos_version_label, marketing_name_for_macos_version};

    #[test]
    fn macos_marketing_name_maps_supported_releases() {
        assert_eq!(marketing_name_for_macos_version("13.6.7"), Some("Ventura"));
        assert_eq!(marketing_name_for_macos_version("14.5"), Some("Sonoma"));
        assert_eq!(marketing_name_for_macos_version("15.0"), Some("Sequoia"));
        assert_eq!(marketing_name_for_macos_version("10.15.7"), None);
        assert_eq!(marketing_name_for_macos_version("not-a-version"), None);
    }

    #[test]
    fn macos_version_label_includes_marketing_name_when_known() {
        assert_eq!(format_macos_version_label("14.6.1"), "macOS Sonoma 14.6.1");
        assert_eq!(format_macos_version_label("13.7"), "macOS Ventura 13.7");
    }

    #[test]
    fn macos_version_label_falls_back_to_numeric_version() {
        assert_eq!(format_macos_version_label("10.15.7"), "macOS 10.15.7");
        assert_eq!(format_macos_version_label(" 16.0 "), "macOS 16.0");
    }
}
