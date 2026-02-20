//! Windows compliance orchestrator.
//!
//! Collects compliance posture from various Windows security subsystems
//! (BitLocker, Defender, Firewall, ASR, UAC, Updates, Credential Guard).

pub mod asr;
pub mod bitlocker;
pub mod credential_guard;
pub mod defender;
pub mod firewall;
pub mod registry;
pub mod uac;
pub mod updates;

use serde::{Deserialize, Serialize};

/// Aggregated Windows compliance report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub bitlocker: bitlocker::BitLockerStatus,
    pub defender: defender::DefenderStatus,
    pub firewall: firewall::FirewallStatus,
    pub asr_rules: Vec<asr::AsrRule>,
    pub uac: uac::UacStatus,
    pub updates: updates::UpdateStatus,
    pub credential_guard: credential_guard::CredentialGuardStatus,
}

/// Collect a full compliance report.
pub fn collect_compliance_report() -> ComplianceReport {
    ComplianceReport {
        bitlocker: bitlocker::check_bitlocker(),
        defender: defender::check_defender(),
        firewall: firewall::check_firewall(),
        asr_rules: asr::list_asr_rules(),
        uac: uac::check_uac(),
        updates: updates::check_updates(),
        credential_guard: credential_guard::check_credential_guard(),
    }
}
