//! Network adapter inventory.

use serde::{Deserialize, Serialize};

/// A network adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAdapter {
    pub name: String,
    pub mac_address: Option<String>,
    pub ip_addresses: Vec<String>,
    pub dhcp_enabled: bool,
}

/// Collect all network adapters and their configuration.
pub fn collect_network_adapters() -> Vec<NetworkAdapter> {
    #[cfg(target_os = "windows")]
    {
        // TODO: WMI Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE
        Vec::new()
    }
    #[cfg(not(target_os = "windows"))]
    {
        tracing::warn!("collect_network_adapters is a stub on non-Windows");
        Vec::new()
    }
}
