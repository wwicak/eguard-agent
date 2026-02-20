//! Attack Surface Reduction (ASR) rule compliance.

use serde::{Deserialize, Serialize};

/// An ASR rule and its current state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsrRule {
    pub guid: String,
    pub name: String,
    pub state: AsrState,
}

/// ASR rule enforcement state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AsrState {
    Disabled,
    Block,
    Audit,
    Warn,
    Unknown,
}

/// List all configured ASR rules and their states.
pub fn list_asr_rules() -> Vec<AsrRule> {
    #[cfg(target_os = "windows")]
    {
        // TODO: Get-MpPreference -> AttackSurfaceReductionRules_Ids/Actions
        Vec::new()
    }
    #[cfg(not(target_os = "windows"))]
    {
        tracing::warn!("list_asr_rules is a stub on non-Windows");
        Vec::new()
    }
}
