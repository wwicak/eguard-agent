use baseline::BaselineStatus;

use crate::config::AgentMode;

pub(super) fn derive_runtime_mode(
    config_mode: &AgentMode,
    baseline_status: BaselineStatus,
) -> AgentMode {
    match config_mode {
        AgentMode::Degraded => AgentMode::Degraded,
        AgentMode::Active => AgentMode::Active,
        AgentMode::Learning => {
            if matches!(baseline_status, BaselineStatus::Learning) {
                AgentMode::Learning
            } else {
                AgentMode::Active
            }
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn runtime_mode_label(mode: &AgentMode) -> &'static str {
    match mode {
        AgentMode::Learning => "learning",
        AgentMode::Active => "active",
        AgentMode::Degraded => "degraded",
    }
}
