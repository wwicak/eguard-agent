use std::collections::HashMap;
#[cfg(not(target_os = "windows"))]
use std::fs;
use std::net::UdpSocket;

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
            env!("CARGO_PKG_VERSION").to_string(),
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
        .unwrap_or_default();
    let user = std::env::var("USER").unwrap_or_default();

    InventoryFacts {
        hostname,
        device_model: std::env::consts::ARCH.to_string(),
        device_serial: read_trimmed("/etc/machine-id").unwrap_or_default(),
        user: user.clone(),
        ip_address: None,
        root_detected: user.eq_ignore_ascii_case("root"),
    }
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
