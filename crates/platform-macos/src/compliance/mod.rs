//! macOS compliance orchestrator.
//!
//! Collects compliance posture from various macOS security subsystems
//! (SIP, Gatekeeper, FileVault, Firewall, Screen Lock, Auto Updates, MDM).

pub mod auto_updates;
pub mod filevault;
pub mod firewall;
pub mod gatekeeper;
pub mod mdm;
pub mod screen_lock;
pub mod sip;

use serde::{Deserialize, Serialize};

/// Aggregated macOS compliance report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub sip: sip::SipStatus,
    pub gatekeeper: gatekeeper::GatekeeperStatus,
    pub filevault: filevault::FileVaultStatus,
    pub firewall: firewall::FirewallStatus,
    pub screen_lock: screen_lock::ScreenLockStatus,
    pub auto_updates: auto_updates::AutoUpdateStatus,
    pub mdm: mdm::MdmStatus,
}

/// Collect a full compliance report.
pub fn collect_compliance_report() -> ComplianceReport {
    ComplianceReport {
        sip: sip::check_sip(),
        gatekeeper: gatekeeper::check_gatekeeper(),
        filevault: filevault::check_filevault(),
        firewall: firewall::check_firewall(),
        screen_lock: screen_lock::check_screen_lock(),
        auto_updates: auto_updates::check_auto_updates(),
        mdm: mdm::check_mdm(),
    }
}
