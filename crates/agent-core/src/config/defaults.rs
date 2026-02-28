use response::ResponseConfig;

use super::constants::DEFAULT_SERVER_ADDR;
use super::types::{AgentConfig, AgentMode};
use super::util::default_agent_id;

/// Detect the MAC address of the primary physical network interface.
///
/// Reads `/sys/class/net/*/address`, skipping loopback and common virtual
/// interfaces (veth, docker, bridge, virbr).  Prefers interfaces backed by a
/// physical device (`/sys/class/net/<iface>/device` exists).
#[cfg(target_os = "linux")]
fn detect_primary_mac() -> Option<String> {
    use std::path::Path;

    let net_dir = Path::new("/sys/class/net");
    let entries = std::fs::read_dir(net_dir).ok()?;

    let skip_prefixes = ["lo", "veth", "br-", "docker", "virbr"];

    let mut physical: Option<String> = None;
    let mut fallback: Option<String> = None;

    for entry in entries.flatten() {
        let iface = entry.file_name().to_string_lossy().into_owned();

        if skip_prefixes.iter().any(|p| iface.starts_with(p)) {
            continue;
        }

        let addr_path = net_dir.join(&iface).join("address");
        let mac = match std::fs::read_to_string(&addr_path) {
            Ok(m) => m.trim().to_string(),
            Err(_) => continue,
        };

        // Skip zero MAC or broadcast
        if mac.is_empty() || mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" {
            continue;
        }

        let has_device = net_dir.join(&iface).join("device").exists();
        if has_device && physical.is_none() {
            physical = Some(mac);
        } else if fallback.is_none() {
            fallback = Some(mac);
        }
    }

    physical.or(fallback)
}

#[cfg(target_os = "linux")]
fn default_data_root() -> &'static str {
    "/var/lib/eguard-agent"
}

/// Detect the MAC address of the primary network adapter on Windows.
///
/// Queries WMI via PowerShell for IP-enabled adapters and returns the first
/// non-null MAC address.  Falls back to `None` if PowerShell fails.
#[cfg(target_os = "windows")]
fn detect_primary_mac() -> Option<String> {
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | Select-Object -First 1 -ExpandProperty MACAddress)",
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let mac = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if mac.is_empty() || mac == "00:00:00:00:00:00" {
        return None;
    }

    // WMI returns "AA-BB-CC-DD-EE-FF" — normalise to "aa:bb:cc:dd:ee:ff"
    Some(mac.replace('-', ":").to_ascii_lowercase())
}

#[cfg(target_os = "windows")]
fn default_data_root() -> &'static str {
    r"C:\ProgramData\eGuard"
}

#[cfg(target_os = "macos")]
fn default_data_root() -> &'static str {
    "/Library/Application Support/eGuard"
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn default_data_root() -> &'static str {
    "/var/lib/eguard-agent"
}

#[cfg(target_os = "windows")]
fn default_offline_buffer_path() -> String {
    format!(r"{}\offline-events.db", default_data_root())
}

#[cfg(not(target_os = "windows"))]
fn default_offline_buffer_path() -> String {
    format!("{}/offline-events.db", default_data_root())
}

#[cfg(target_os = "windows")]
fn default_detection_sigma_dir() -> String {
    format!(r"{}\rules\sigma", default_data_root())
}

#[cfg(not(target_os = "windows"))]
fn default_detection_sigma_dir() -> String {
    format!("{}/rules/sigma", default_data_root())
}

#[cfg(target_os = "windows")]
fn default_detection_yara_dir() -> String {
    format!(r"{}\rules\yara", default_data_root())
}

#[cfg(not(target_os = "windows"))]
fn default_detection_yara_dir() -> String {
    format!("{}/rules/yara", default_data_root())
}

#[cfg(target_os = "windows")]
fn default_detection_ioc_dir() -> String {
    format!(r"{}\rules\ioc", default_data_root())
}

#[cfg(not(target_os = "windows"))]
fn default_detection_ioc_dir() -> String {
    format!("{}/rules/ioc", default_data_root())
}

impl Default for AgentConfig {
    fn default() -> Self {
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        let mac = detect_primary_mac().unwrap_or_else(|| "00:00:00:00:00:00".to_string());
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        let mac = "00:00:00:00:00:00".to_string();

        Self {
            agent_id: default_agent_id(),
            machine_id: None,
            mac,
            mode: AgentMode::Learning,
            transport_mode: "http".to_string(),
            server_addr: DEFAULT_SERVER_ADDR.to_string(),
            enrollment_token: None,
            tenant_id: None,
            response: ResponseConfig::default(),
            offline_buffer_backend: "sqlite".to_string(),
            offline_buffer_path: default_offline_buffer_path(),
            offline_buffer_cap_bytes: 100 * 1024 * 1024,
            tls_cert_path: None,
            tls_key_path: None,
            tls_ca_path: None,
            tls_pinned_ca_sha256: None,
            tls_ca_pin_path: None,
            tls_rotate_before_expiry_days: 30,
            heartbeat_interval_secs: 30,
            reconnect_backoff_max_secs: 300,
            telemetry_process_exec: true,
            telemetry_file_events: true,
            telemetry_network_connections: true,
            telemetry_dns_queries: true,
            telemetry_module_loads: true,
            telemetry_user_logins: true,
            telemetry_flush_interval_ms: 100,
            telemetry_max_batch_size: 100,
            detection_sigma_rules_dir: default_detection_sigma_dir(),
            detection_yara_rules_dir: default_detection_yara_dir(),
            detection_ioc_dir: default_detection_ioc_dir(),
            detection_bundle_path: String::new(),
            detection_scan_on_create: true,
            detection_max_file_scan_size_mb: 100,
            detection_memory_scan_enabled: false,
            detection_memory_scan_interval_secs: 900,
            detection_memory_scan_mode: "executable".to_string(),
            detection_memory_scan_max_pids: 8,
            detection_kernel_integrity_enabled: true,
            detection_kernel_integrity_interval_secs: 300,
            detection_ransomware_write_threshold: 25,
            detection_ransomware_write_window_secs: 20,
            detection_ransomware_adaptive_delta: 1e-6,
            detection_ransomware_adaptive_min_samples: 6,
            detection_ransomware_adaptive_floor: 5,
            detection_ransomware_learned_root_min_hits: 3,
            detection_ransomware_learned_root_max: 64,
            detection_ransomware_user_path_prefixes: Vec::new(),
            detection_ransomware_system_path_prefixes: Vec::new(),
            detection_ransomware_temp_path_tokens: Vec::new(),
            compliance_check_interval_secs: 300,
            compliance_auto_remediate: false,
            policy_refresh_interval_secs: 300,
            inventory_interval_secs: 3600,
            device_ownership: "unknown".to_string(),
            baseline_learning_period_days: 7,
            baseline_refresh_interval_days: 7,
            baseline_stale_after_days: 30,
            self_protection_integrity_check_interval_secs: 60,
            self_protection_prevent_uninstall: true,
            bootstrap_config_path: None,
        }
    }
}
