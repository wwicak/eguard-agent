//! ETW provider GUID constants and configuration.
//!
//! These are the canonical providers subscribed by the Windows telemetry
//! session. Keep this list aligned with the design doc section 30.2.1.

/// Microsoft-Windows-Kernel-Process provider.
pub const KERNEL_PROCESS: &str = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716";

/// Microsoft-Windows-Kernel-File provider.
pub const KERNEL_FILE: &str = "EDD08927-9CC4-4E65-B970-C2560FB5C289";

/// Microsoft-Windows-Kernel-Network provider.
pub const KERNEL_NETWORK: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";

/// Microsoft-Windows-Kernel-General provider.
pub const KERNEL_GENERAL: &str = "A68CA8B7-004F-D7B6-A698-04740DE3E9CF";

/// Microsoft-Windows-Kernel-Registry provider.
#[allow(dead_code)]
pub const KERNEL_REGISTRY: &str = "70EB4F03-C1DE-4F73-A051-33D13D5413BD";

/// Microsoft-Windows-DNS-Client provider.
pub const DNS_CLIENT: &str = "1C95126E-7EEA-49A9-A3FE-A378B03DDB4D";

/// Microsoft-Windows-Security-Auditing provider.
pub const SECURITY_AUDITING: &str = "54849625-5478-4994-A5BA-3E3B0328C30D";

/// Microsoft-Antimalware-Scan-Interface (AMSI) provider.
#[allow(dead_code)]
pub const AMSI_PROVIDER: &str = "2A576B87-09A7-520E-C21A-4942F0271D67";

/// Microsoft-Windows-WFP (Windows Filtering Platform) provider.
#[allow(dead_code)]
pub const WFP_PROVIDER: &str = "0C478C5B-0351-41B1-8C58-4A6737DA32E3";

/// Legacy image-load provider retained for backward compatibility.
///
/// Prefer `KERNEL_GENERAL` for new mappings.
pub const IMAGE_LOAD: &str = "2CB15D1D-5FC1-11D2-ABE1-00A0C911F518";

// ── Keyword masks (control event volume per provider) ────────────────

/// Kernel-Process: PROCESS (0x10) | IMAGE (0x40) — process lifecycle + DLL loads.
const KW_KERNEL_PROCESS: u64 = 0x10 | 0x40;

/// Kernel-File: FILENAME | CREATE | WRITE | DELETE_PATH | RENAME_SETLINK_PATH | CREATE_NEW_FILE.
/// Skips READ, FILEIO, OP_END (~80% volume reduction).
const KW_KERNEL_FILE: u64 = 0x10 | 0x80 | 0x200 | 0x400 | 0x800 | 0x1000;

/// Kernel-Network: IPV4 (0x10) | IPV6 (0x20) — all TCP connections.
const KW_KERNEL_NETWORK: u64 = 0x10 | 0x20;

/// All events (low-volume providers).
const KW_ALL: u64 = u64::MAX;

/// ETW trace level: Verbose (5) for maximum event detail.
const LEVEL_VERBOSE: u8 = 5;

/// Configuration for a single ETW provider.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub guid_str: &'static str,
    pub match_any_keyword: u64,
    pub level: u8,
}

/// Default provider set with tuned keyword masks.
pub const DEFAULT_PROVIDERS: &[ProviderConfig] = &[
    ProviderConfig {
        guid_str: KERNEL_PROCESS,
        match_any_keyword: KW_KERNEL_PROCESS,
        level: LEVEL_VERBOSE,
    },
    ProviderConfig {
        guid_str: KERNEL_FILE,
        match_any_keyword: KW_KERNEL_FILE,
        level: LEVEL_VERBOSE,
    },
    ProviderConfig {
        guid_str: KERNEL_NETWORK,
        match_any_keyword: KW_KERNEL_NETWORK,
        level: LEVEL_VERBOSE,
    },
    ProviderConfig {
        guid_str: DNS_CLIENT,
        match_any_keyword: KW_ALL,
        level: LEVEL_VERBOSE,
    },
    ProviderConfig {
        guid_str: KERNEL_GENERAL,
        match_any_keyword: KW_ALL,
        level: LEVEL_VERBOSE,
    },
    ProviderConfig {
        guid_str: SECURITY_AUDITING,
        match_any_keyword: KW_ALL,
        level: LEVEL_VERBOSE,
    },
];

/// Parse a GUID string ("XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX") into a
/// `windows::core::GUID`. Only available on Windows targets.
#[cfg(target_os = "windows")]
pub fn parse_guid(s: &str) -> Result<windows::core::GUID, String> {
    let s = s.trim().trim_start_matches('{').trim_end_matches('}');
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return Err(format!("invalid GUID format: {s}"));
    }

    let d1 = u32::from_str_radix(parts[0], 16).map_err(|e| format!("GUID d1: {e}"))?;
    let d2 = u16::from_str_radix(parts[1], 16).map_err(|e| format!("GUID d2: {e}"))?;
    let d3 = u16::from_str_radix(parts[2], 16).map_err(|e| format!("GUID d3: {e}"))?;

    // parts[3] (4 hex) + parts[4] (12 hex) = 16 hex chars = 8 bytes
    let d4_hex = format!("{}{}", parts[3], parts[4]);
    if d4_hex.len() != 16 {
        return Err(format!("invalid GUID d4 segment: {d4_hex}"));
    }
    let mut d4 = [0u8; 8];
    for (i, byte) in d4.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&d4_hex[i * 2..i * 2 + 2], 16).map_err(|e| format!("GUID d4[{i}]: {e}"))?;
    }

    Ok(windows::core::GUID {
        data1: d1,
        data2: d2,
        data3: d3,
        data4: d4,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_providers_match_guid_constants() {
        let guids: Vec<&str> = DEFAULT_PROVIDERS.iter().map(|p| p.guid_str).collect();
        assert!(guids.contains(&KERNEL_PROCESS));
        assert!(guids.contains(&KERNEL_FILE));
        assert!(guids.contains(&KERNEL_NETWORK));
        assert!(guids.contains(&DNS_CLIENT));
        assert!(guids.contains(&KERNEL_GENERAL));
        assert!(guids.contains(&SECURITY_AUDITING));
        assert_eq!(DEFAULT_PROVIDERS.len(), 6);
    }

    #[test]
    fn keyword_masks_are_nonzero() {
        for provider in DEFAULT_PROVIDERS {
            assert_ne!(provider.match_any_keyword, 0, "provider {} has zero keyword mask", provider.guid_str);
            assert!(provider.level > 0, "provider {} has zero level", provider.guid_str);
        }
    }
}
