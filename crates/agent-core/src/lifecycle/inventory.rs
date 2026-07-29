use std::collections::HashMap;
#[cfg(not(target_os = "windows"))]
use std::fs;
use std::net::UdpSocket;
#[cfg(target_os = "macos")]
use std::process::Command;

use grpc_client::InventoryEnvelope;

use super::compliance_platform::collect_platform_snapshot;
use super::AgentRuntime;

const DEFAULT_INVENTORY_INTERVAL_SECS: i64 = 3600;

impl AgentRuntime {
    pub(super) fn inventory_interval_secs(&self) -> i64 {
        if self.config.inventory_interval_secs == 0 {
            DEFAULT_INVENTORY_INTERVAL_SECS
        } else {
            self.config.inventory_interval_secs as i64
        }
    }

    pub(super) fn collect_inventory(&self, now_unix: i64) -> InventoryEnvelope {
        let snapshot = collect_platform_snapshot().ok();
        let facts = collect_inventory_facts();

        let mut attributes = HashMap::new();
        attributes.insert(
            "agent_version".to_string(),
            compliance::current_agent_version().to_string(),
        );
        if !self.compliance_policy_id.is_empty() {
            attributes.insert("policy_id".to_string(), self.compliance_policy_id.clone());
        }
        if !self.compliance_policy_version.is_empty() {
            attributes.insert(
                "policy_version".to_string(),
                self.compliance_policy_version.clone(),
            );
        }

        // Collect detailed hardware inventory (CPU, RAM, disk, GPU, network)
        // and merge hw.* prefixed keys into the attributes map.
        for (key, value) in collect_platform_hardware_inventory() {
            attributes.insert(key, value);
        }
        for (key, value) in collect_configured_gps_attributes(now_unix) {
            attributes.insert(key, value);
        }

        InventoryEnvelope {
            agent_id: self.config.agent_id.clone(),
            os_type: snapshot
                .as_ref()
                .map(|s| s.os_type.clone())
                .unwrap_or_else(default_os_type),
            os_version: snapshot
                .as_ref()
                .and_then(|s| s.os_version.clone())
                .unwrap_or_default(),
            kernel_version: snapshot
                .as_ref()
                .map(|s| s.kernel_version.clone())
                .unwrap_or_default(),
            hostname: facts.hostname,
            device_model: facts.device_model,
            device_serial: facts.device_serial,
            user: facts.user,
            ownership: self.config.device_ownership.clone(),
            disk_encrypted: snapshot
                .as_ref()
                .and_then(|s| s.root_fs_encrypted)
                .unwrap_or(false),
            jailbreak_detected: false,
            root_detected: facts.root_detected,
            mac: self.config.mac.clone(),
            ip_address: facts
                .ip_address
                .or_else(resolve_primary_ip)
                .unwrap_or_default(),
            collected_at_unix: now_unix,
            attributes,
        }
    }
}

#[derive(Debug, Default)]
struct InventoryFacts {
    hostname: String,
    device_model: String,
    device_serial: String,
    user: String,
    ip_address: Option<String>,
    root_detected: bool,
}

#[cfg(target_os = "linux")]
fn collect_inventory_facts() -> InventoryFacts {
    let hostname = read_trimmed("/etc/hostname")
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_default();
    let device_model = read_trimmed("/sys/class/dmi/id/product_name")
        .or_else(|| read_trimmed("/sys/devices/virtual/dmi/id/product_name"))
        .unwrap_or_default();
    let device_serial = read_trimmed("/sys/class/dmi/id/product_serial")
        .or_else(|| read_trimmed("/sys/devices/virtual/dmi/id/product_serial"))
        .or_else(|| read_trimmed("/etc/machine-id"))
        .unwrap_or_default();
    let user = std::env::var("SUDO_USER")
        .ok()
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_default();

    InventoryFacts {
        hostname,
        device_model,
        device_serial,
        user: user.clone(),
        ip_address: None,
        root_detected: user.eq_ignore_ascii_case("root"),
    }
}

#[cfg(target_os = "windows")]
fn collect_inventory_facts() -> InventoryFacts {
    let hardware = platform_windows::inventory::collect_hardware_info();
    let adapters = platform_windows::inventory::collect_network_adapters();

    let hostname = std::env::var("COMPUTERNAME")
        .ok()
        .or(hardware.computer_name)
        .unwrap_or_default();
    let device_model = hardware
        .cpu_name
        .or(hardware.os_version)
        .unwrap_or_default();
    let device_serial = hardware
        .bios_serial
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_default();
    let user = std::env::var("USERNAME").unwrap_or_default();

    let ip_address = adapters
        .into_iter()
        .flat_map(|adapter| adapter.ip_addresses.into_iter())
        .find(|ip| !ip.starts_with("127.") && !ip.eq_ignore_ascii_case("::1"));

    InventoryFacts {
        hostname,
        device_model,
        device_serial,
        user,
        ip_address,
        root_detected: false,
    }
}

#[cfg(target_os = "macos")]
fn collect_inventory_facts() -> InventoryFacts {
    let hostname = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| read_trimmed("/etc/hostname"))
        .or_else(|| {
            for key in ["HostName", "LocalHostName", "ComputerName"] {
                let output = std::process::Command::new("/usr/sbin/scutil")
                    .args(["--get", key])
                    .output()
                    .ok()?;
                if !output.status.success() {
                    continue;
                }
                let value = String::from_utf8(output.stdout).ok()?;
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
            None
        })
        .unwrap_or_default();
    let user = std::env::var("SUDO_USER")
        .ok()
        .or_else(|| {
            // /dev/console is a character device on macOS. Reading it as a
            // regular file can block a launchd root agent before heartbeat and
            // inventory uploads. Use the file owner metadata instead; `stat`
            // returns immediately and is the canonical way to identify the
            // active console user.
            let output = Command::new("/usr/bin/stat")
                .args(["-f", "%Su", "/dev/console"])
                .output()
                .ok()?;
            if !output.status.success() {
                return None;
            }
            let value = String::from_utf8(output.stdout).ok()?;
            let value = value.trim();
            if value.is_empty() || value.eq_ignore_ascii_case("root") {
                None
            } else {
                Some(value.to_string())
            }
        })
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_default();

    let device_model = read_macos_ioreg_field("model")
        .or_else(|| read_macos_ioreg_field("product-name"))
        .or_else(|| read_macos_system_profiler_value("Model Identifier"))
        .unwrap_or_else(|| std::env::consts::ARCH.to_string());

    let device_serial = read_macos_ioreg_field("IOPlatformSerialNumber")
        .or_else(|| read_macos_system_profiler_value("Serial Number"))
        .unwrap_or_default();

    InventoryFacts {
        hostname,
        device_model,
        device_serial,
        user: user.clone(),
        ip_address: None,
        root_detected: user.eq_ignore_ascii_case("root"),
    }
}

#[cfg(target_os = "macos")]
fn read_macos_ioreg_field(field: &str) -> Option<String> {
    let output = Command::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    for line in stdout.lines() {
        let trimmed = line.trim();
        let prefix = format!("\"{}\" = ", field);
        if let Some(rest) = trimmed.strip_prefix(&prefix) {
            if let Some(value) = parse_macos_ioreg_value(rest) {
                return Some(value);
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn parse_macos_ioreg_value(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.starts_with('"') && raw.ends_with('"') && raw.len() >= 2 {
        return Some(raw[1..raw.len() - 1].to_string());
    }
    if raw.starts_with("<\"") && raw.ends_with("\">") && raw.len() >= 4 {
        return Some(raw[2..raw.len() - 2].to_string());
    }
    None
}

#[cfg(target_os = "macos")]
fn read_macos_system_profiler_value(field: &str) -> Option<String> {
    let output = Command::new("/usr/sbin/system_profiler")
        .arg("SPHardwareDataType")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    for line in stdout.lines() {
        let trimmed = line.trim();
        let prefix = format!("{}: ", field);
        if let Some(value) = trimmed.strip_prefix(&prefix) {
            if !value.trim().is_empty() {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn collect_inventory_facts() -> InventoryFacts {
    let user = std::env::var("USER").unwrap_or_default();
    InventoryFacts {
        hostname: std::env::var("HOSTNAME").unwrap_or_default(),
        user: user.clone(),
        root_detected: user.eq_ignore_ascii_case("root"),
        ..InventoryFacts::default()
    }
}

#[cfg(target_os = "linux")]
fn default_os_type() -> String {
    "linux".to_string()
}

#[cfg(target_os = "windows")]
fn default_os_type() -> String {
    "windows".to_string()
}

#[cfg(target_os = "macos")]
fn default_os_type() -> String {
    "macos".to_string()
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn default_os_type() -> String {
    "unknown".to_string()
}

#[cfg(not(target_os = "windows"))]
fn read_trimmed(path: &str) -> Option<String> {
    let raw = fs::read_to_string(path).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub(super) fn resolve_primary_ip() -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    let _ = socket.connect("8.8.8.8:80");
    socket.local_addr().ok().map(|addr| addr.ip().to_string())
}

fn collect_configured_gps_attributes(now_unix: i64) -> HashMap<String, String> {
    let Some(latitude) = read_coordinate_env("EGUARD_GPS_LATITUDE", -90.0, 90.0) else {
        return HashMap::new();
    };
    let Some(longitude) = read_coordinate_env("EGUARD_GPS_LONGITUDE", -180.0, 180.0) else {
        return HashMap::new();
    };

    let mut attrs = HashMap::new();
    attrs.insert("gps.latitude".to_string(), latitude);
    attrs.insert("gps.longitude".to_string(), longitude);
    attrs.insert("gps.collected_at_unix".to_string(), now_unix.to_string());
    if let Some(accuracy) = read_non_negative_number_env("EGUARD_GPS_ACCURACY_METERS") {
        attrs.insert("gps.accuracy_meters".to_string(), accuracy);
    }
    if let Some(provider) = env_trimmed("EGUARD_GPS_PROVIDER") {
        attrs.insert("gps.provider".to_string(), provider);
    }
    attrs
}

fn read_coordinate_env(key: &str, min: f64, max: f64) -> Option<String> {
    let value = env_trimmed(key)?;
    let parsed = value.parse::<f64>().ok()?;
    if parsed.is_finite() && parsed >= min && parsed <= max {
        Some(value)
    } else {
        None
    }
}

fn read_non_negative_number_env(key: &str) -> Option<String> {
    let value = env_trimmed(key)?;
    let parsed = value.parse::<f64>().ok()?;
    if parsed.is_finite() && parsed >= 0.0 {
        Some(value)
    } else {
        None
    }
}

fn env_trimmed(key: &str) -> Option<String> {
    let value = std::env::var(key).ok()?;
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

// ---------------------------------------------------------------------------
// Platform-dispatched hardware inventory collection
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn collect_platform_hardware_inventory() -> HashMap<String, String> {
    platform_linux::inventory::collect_hardware_inventory()
}

#[cfg(target_os = "windows")]
fn collect_platform_hardware_inventory() -> HashMap<String, String> {
    platform_windows::inventory::collect_hardware_inventory()
}

#[cfg(target_os = "macos")]
fn collect_platform_hardware_inventory() -> HashMap<String, String> {
    platform_macos::inventory::collect_hardware_inventory()
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn collect_platform_hardware_inventory() -> HashMap<String, String> {
    HashMap::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn gps_env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    fn clear_gps_env() {
        for key in [
            "EGUARD_GPS_LATITUDE",
            "EGUARD_GPS_LONGITUDE",
            "EGUARD_GPS_ACCURACY_METERS",
            "EGUARD_GPS_PROVIDER",
        ] {
            std::env::remove_var(key);
        }
    }

    #[test]
    fn configured_gps_env_adds_inventory_attributes() {
        let _guard = gps_env_lock();
        clear_gps_env();
        std::env::set_var("EGUARD_GPS_LATITUDE", "-6.200000");
        std::env::set_var("EGUARD_GPS_LONGITUDE", "106.816666");
        std::env::set_var("EGUARD_GPS_ACCURACY_METERS", "25");
        std::env::set_var("EGUARD_GPS_PROVIDER", "manual");

        let attrs = collect_configured_gps_attributes(1_783_513_600);
        clear_gps_env();

        assert_eq!(
            attrs.get("gps.latitude").map(String::as_str),
            Some("-6.200000")
        );
        assert_eq!(
            attrs.get("gps.longitude").map(String::as_str),
            Some("106.816666")
        );
        assert_eq!(
            attrs.get("gps.accuracy_meters").map(String::as_str),
            Some("25")
        );
        assert_eq!(
            attrs.get("gps.provider").map(String::as_str),
            Some("manual")
        );
        assert_eq!(
            attrs.get("gps.collected_at_unix").map(String::as_str),
            Some("1783513600")
        );
    }

    #[test]
    fn configured_gps_env_requires_valid_latitude_and_longitude() {
        let _guard = gps_env_lock();
        clear_gps_env();
        std::env::set_var("EGUARD_GPS_LATITUDE", "999");
        std::env::set_var("EGUARD_GPS_LONGITUDE", "106.816666");

        let attrs = collect_configured_gps_attributes(1_783_513_600);
        clear_gps_env();

        assert!(attrs.is_empty());
    }

    #[test]
    fn macos_inventory_must_not_read_dev_console_as_file_content() {
        let source = include_str!("inventory.rs");
        let forbidden = concat!("read_trimmed(\"", "/dev/console", "\")");
        assert!(
            !source.contains(forbidden),
            "macOS inventory must use stat metadata for /dev/console; reading the character device can block launchd agents before heartbeat"
        );
    }
}
