//! Registry-based compliance checks.
//!
//! Generic helpers for reading registry values used by other compliance modules.

/// Read a DWORD value from the registry.
pub fn read_reg_dword(hive: &str, subkey: &str, value_name: &str) -> Option<u32> {
    #[cfg(target_os = "windows")]
    {
        // TODO: RegOpenKeyExW + RegQueryValueExW
        let _ = (hive, subkey, value_name);
        None
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (hive, subkey, value_name);
        tracing::warn!("read_reg_dword is a stub on non-Windows");
        None
    }
}

/// Read a string value from the registry.
pub fn read_reg_string(hive: &str, subkey: &str, value_name: &str) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        // TODO: RegOpenKeyExW + RegQueryValueExW
        let _ = (hive, subkey, value_name);
        None
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (hive, subkey, value_name);
        tracing::warn!("read_reg_string is a stub on non-Windows");
        None
    }
}
