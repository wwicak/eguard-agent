use response::ResponseConfig;

use super::constants::DEFAULT_SERVER_ADDR;
use super::types::{AgentConfig, AgentMode};
use super::util::default_agent_id;

#[cfg(any(test, target_os = "windows", target_os = "macos"))]
const INVALID_MAC: &str = "00:00:00:00:00:00";

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

/// Detect the MAC address of the primary network interface on macOS.
///
/// Enumerates `getifaddrs(3)` link-layer entries, skips loopback and common
/// virtual interfaces, and prefers active `en*` adapters such as `en0`.
#[cfg(target_os = "macos")]
fn detect_primary_mac() -> Option<String> {
    use std::ffi::CStr;
    use std::ptr;

    let mut addrs: *mut libc::ifaddrs = ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut addrs) } != 0 || addrs.is_null() {
        return None;
    }

    struct IfAddrsGuard(*mut libc::ifaddrs);

    impl Drop for IfAddrsGuard {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) };
        }
    }

    let _guard = IfAddrsGuard(addrs);
    let mut best: Option<(u8, String)> = None;
    let mut current = addrs;

    while !current.is_null() {
        let ifa = unsafe { &*current };
        current = ifa.ifa_next;

        if ifa.ifa_name.is_null() || ifa.ifa_addr.is_null() {
            continue;
        }

        let flags = ifa.ifa_flags as i32;
        if flags & libc::IFF_UP == 0 || flags & libc::IFF_LOOPBACK != 0 {
            continue;
        }

        let family = unsafe { (*ifa.ifa_addr).sa_family as i32 };
        if family != libc::AF_LINK {
            continue;
        }

        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        if should_skip_macos_interface(&name) {
            continue;
        }

        let mac = unsafe { macos_link_address_to_string(ifa.ifa_addr as *const libc::sockaddr_dl) };
        let Some(mac) = mac else {
            continue;
        };

        let score = score_macos_interface(&name, flags);
        match &best {
            Some((best_score, _)) if score >= *best_score => {}
            _ => best = Some((score, mac)),
        }
    }

    best.map(|(_, mac)| mac)
}

#[cfg(target_os = "macos")]
unsafe fn macos_link_address_to_string(addr: *const libc::sockaddr_dl) -> Option<String> {
    if addr.is_null() {
        return None;
    }

    let addr = &*addr;
    let name_len = addr.sdl_nlen as usize;
    let addr_len = addr.sdl_alen as usize;
    if addr_len != 6 {
        return None;
    }

    let data = addr.sdl_data.as_ptr() as *const u8;
    let bytes = std::slice::from_raw_parts(data.add(name_len), addr_len);
    normalize_mac_bytes(bytes)
}

#[cfg(any(test, target_os = "macos"))]
fn normalize_mac_bytes(bytes: &[u8]) -> Option<String> {
    if bytes.len() != 6 {
        return None;
    }

    let mac = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":");

    if mac == INVALID_MAC || mac == "ff:ff:ff:ff:ff:ff" {
        return None;
    }

    Some(mac)
}

#[cfg(any(test, target_os = "macos"))]
fn should_skip_macos_interface(name: &str) -> bool {
    [
        "lo", "awdl", "llw", "utun", "bridge", "p2p", "anpi", "stf", "gif",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

#[cfg(any(test, target_os = "macos"))]
fn score_macos_interface(name: &str, flags: i32) -> u8 {
    let mut score = 200u8;

    if name == "en0" {
        score = 0;
    } else if name.starts_with("en") {
        score = 10;
    } else if name.starts_with("eth") {
        score = 20;
    }

    if flags & libc::IFF_RUNNING == 0 {
        score = score.saturating_add(40);
    }

    score
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
        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        let mac = detect_primary_mac().unwrap_or_else(|| INVALID_MAC.to_string());
        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        let mac = INVALID_MAC.to_string();

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
            detection_bundle_public_key: None,
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
            ztna_enabled: false,
            ztna_controller_base_url: "http://127.0.0.1:50054".to_string(),
            ztna_app_id: None,
            ztna_agent_wg_public_key: None,
            ztna_forward_host: None,
            ztna_forward_port: None,
            ztna_local_bind_addr: "127.0.0.1:0".to_string(),
            ztna_request_interval_secs: 30,
            ztna_idle_timeout_secs: 300,
            bootstrap_config_path: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{normalize_mac_bytes, score_macos_interface, should_skip_macos_interface};

    #[test]
    fn normalize_mac_bytes_rejects_invalid_values() {
        assert_eq!(
            normalize_mac_bytes(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]).as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert!(normalize_mac_bytes(&[0, 0, 0, 0, 0, 0]).is_none());
        assert!(normalize_mac_bytes(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_none());
        assert!(normalize_mac_bytes(&[0xaa, 0xbb, 0xcc]).is_none());
    }

    #[test]
    fn macos_interface_filters_skip_virtual_adapters() {
        assert!(should_skip_macos_interface("lo0"));
        assert!(should_skip_macos_interface("utun4"));
        assert!(should_skip_macos_interface("awdl0"));
        assert!(!should_skip_macos_interface("en0"));
        assert!(!should_skip_macos_interface("en7"));
    }

    #[test]
    fn macos_interface_scoring_prefers_primary_running_en_devices() {
        let running = libc::IFF_UP | libc::IFF_RUNNING;
        let up_only = libc::IFF_UP;

        assert!(score_macos_interface("en0", running) < score_macos_interface("en1", running));
        assert!(score_macos_interface("en1", running) < score_macos_interface("bridge0", running));
        assert!(score_macos_interface("en1", running) < score_macos_interface("en1", up_only));
    }
}
