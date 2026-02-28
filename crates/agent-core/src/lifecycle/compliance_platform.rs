//! Platform-aware compliance snapshot converters.
//!
//! Maps platform-specific `ComplianceReport` types (from `platform-windows`
//! and `platform-macos`) into the platform-agnostic `SystemSnapshot` used
//! by the compliance evaluation engine.

#[cfg(any(target_os = "windows", target_os = "macos"))]
use std::collections::HashSet;
#[cfg(target_os = "windows")]
use platform_windows::inventory::hardware::HardwareInfo;

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
        screen_lock_enabled: None,
        auto_updates_enabled,
        antivirus_running,
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
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

    // Derive kernel version from platform_macos if available, else stub.
    let kernel_version = platform_macos::platform_name().to_string();
    let os_version = Some(kernel_version.clone());

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
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
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
