use serde::{Deserialize, Serialize};

/// File Integrity Monitoring policy configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FimPolicyConfig {
    pub enabled: bool,
    pub watched_paths: Vec<String>,
    pub excluded_paths: Vec<String>,
    pub scan_interval_secs: u64,
}

impl Default for FimPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            watched_paths: Vec::new(),
            excluded_paths: Vec::new(),
            scan_interval_secs: 300,
        }
    }
}

/// USB device control policy configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UsbPolicyConfig {
    pub storage_blocked: bool,
    pub network_blocked: bool,
    pub log_all: bool,
    pub allowed_vendor_ids: Vec<String>,
}

impl Default for UsbPolicyConfig {
    fn default() -> Self {
        Self {
            storage_blocked: false,
            network_blocked: false,
            log_all: false,
            allowed_vendor_ids: Vec::new(),
        }
    }
}

/// Deception token policy configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeceptionPolicyConfig {
    pub enabled: bool,
    pub custom_paths: Vec<String>,
}

impl Default for DeceptionPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            custom_paths: Vec::new(),
        }
    }
}

/// Threat hunting policy configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HuntingPolicyConfig {
    pub enabled: bool,
    pub interval_secs: u64,
}

impl Default for HuntingPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: 3600,
        }
    }
}

/// Zero Trust endpoint scoring policy configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ZeroTrustPolicyConfig {
    pub enabled: bool,
    pub quarantine_threshold: u8,
    pub restrict_threshold: u8,
}

impl Default for ZeroTrustPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            quarantine_threshold: 30,
            restrict_threshold: 50,
        }
    }
}
