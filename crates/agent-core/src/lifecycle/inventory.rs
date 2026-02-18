use std::collections::HashMap;
use std::fs;
use std::net::UdpSocket;

use compliance::collect_linux_snapshot;
use grpc_client::InventoryEnvelope;

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
        let snapshot = collect_linux_snapshot().ok();
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

        InventoryEnvelope {
            agent_id: self.config.agent_id.clone(),
            os_type: snapshot
                .as_ref()
                .map(|s| s.os_type.clone())
                .unwrap_or_else(|| "linux".to_string()),
            os_version: snapshot
                .as_ref()
                .and_then(|s| s.os_version.clone())
                .unwrap_or_default(),
            kernel_version: snapshot
                .as_ref()
                .map(|s| s.kernel_version.clone())
                .unwrap_or_default(),
            hostname,
            device_model,
            device_serial,
            user,
            ownership: self.config.device_ownership.clone(),
            disk_encrypted: snapshot
                .as_ref()
                .and_then(|s| s.root_fs_encrypted)
                .unwrap_or(false),
            jailbreak_detected: false,
            root_detected: std::env::var("USER")
                .ok()
                .map(|u| u.eq_ignore_ascii_case("root"))
                .unwrap_or(false),
            mac: self.config.mac.clone(),
            ip_address: resolve_primary_ip().unwrap_or_default(),
            collected_at_unix: now_unix,
            attributes,
        }
    }
}

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
    socket
        .local_addr()
        .ok()
        .map(|addr| addr.ip().to_string())
}
