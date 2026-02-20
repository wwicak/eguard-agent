//! Hardware inventory via WMI.

use serde::{Deserialize, Serialize};

/// Hardware information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareInfo {
    pub computer_name: Option<String>,
    pub os_version: Option<String>,
    pub os_build: Option<String>,
    pub cpu_name: Option<String>,
    pub cpu_cores: Option<u32>,
    pub total_memory_mb: Option<u64>,
    pub bios_serial: Option<String>,
}

/// Collect hardware information.
pub fn collect_hardware_info() -> HardwareInfo {
    #[cfg(target_os = "windows")]
    {
        // TODO: WMI Win32_ComputerSystem, Win32_OperatingSystem, Win32_Processor
        HardwareInfo {
            computer_name: None,
            os_version: None,
            os_build: None,
            cpu_name: None,
            cpu_cores: None,
            total_memory_mb: None,
            bios_serial: None,
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        tracing::warn!("collect_hardware_info is a stub on non-Windows");
        HardwareInfo {
            computer_name: None,
            os_version: None,
            os_build: None,
            cpu_name: None,
            cpu_cores: None,
            total_memory_mb: None,
            bios_serial: None,
        }
    }
}
