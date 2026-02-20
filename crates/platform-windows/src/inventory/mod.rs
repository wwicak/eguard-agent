//! WMI-based inventory collection.
//!
//! Collects hardware, software, and network adapter information from
//! the Windows system via WMI queries.

pub mod hardware;
pub mod network;
pub mod software;

pub use hardware::collect_hardware_info;
pub use network::collect_network_adapters;
pub use software::collect_installed_software;

use serde::{Deserialize, Serialize};

/// Full system inventory snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInventory {
    pub hardware: hardware::HardwareInfo,
    pub software: Vec<software::InstalledProgram>,
    pub network_adapters: Vec<network::NetworkAdapter>,
}

/// Collect a full system inventory.
pub fn collect_inventory() -> SystemInventory {
    SystemInventory {
        hardware: collect_hardware_info(),
        software: collect_installed_software(),
        network_adapters: collect_network_adapters(),
    }
}
