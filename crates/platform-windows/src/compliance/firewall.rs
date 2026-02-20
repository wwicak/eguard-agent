//! Windows Firewall compliance checks.

use serde::{Deserialize, Serialize};

/// Windows Firewall profile status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallStatus {
    pub domain_profile_enabled: bool,
    pub private_profile_enabled: bool,
    pub public_profile_enabled: bool,
}

/// Check Windows Firewall status across all profiles.
pub fn check_firewall() -> FirewallStatus {
    #[cfg(target_os = "windows")]
    {
        // TODO: INetFwPolicy2 or netsh advfirewall show allprofiles
        FirewallStatus {
            domain_profile_enabled: false,
            private_profile_enabled: false,
            public_profile_enabled: false,
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        tracing::warn!("check_firewall is a stub on non-Windows");
        FirewallStatus {
            domain_profile_enabled: false,
            private_profile_enabled: false,
            public_profile_enabled: false,
        }
    }
}
