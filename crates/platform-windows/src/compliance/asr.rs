//! Attack Surface Reduction (ASR) rule compliance.

use serde::{Deserialize, Serialize};
#[cfg(any(test, target_os = "windows"))]
use serde_json::Value;

#[cfg(target_os = "windows")]
use super::registry::run_powershell;

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
        let cmd = "$p = Get-MpPreference; $ids = @($p.AttackSurfaceReductionRules_Ids); $actions = @($p.AttackSurfaceReductionRules_Actions); $out = @(); for ($i = 0; $i -lt $ids.Count; $i++) { $out += [pscustomobject]@{ guid = $ids[$i]; action = $actions[$i] } }; $out | ConvertTo-Json -Compress";
        if let Some(json) = run_powershell(cmd) {
            return parse_asr_rules_json(&json);
        }
        Vec::new()
    }
    #[cfg(not(target_os = "windows"))]
    {
        tracing::warn!("list_asr_rules is a stub on non-Windows");
        Vec::new()
    }
}

#[cfg(any(test, target_os = "windows"))]
fn parse_asr_rules_json(raw: &str) -> Vec<AsrRule> {
    let value: Value = match serde_json::from_str(raw) {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };

    let entries = match value {
        Value::Array(arr) => arr,
        single => vec![single],
    };

    entries
        .into_iter()
        .filter_map(|entry| {
            let guid = entry.get("guid")?.as_str()?.to_string();
            let action = entry.get("action").and_then(Value::as_i64).unwrap_or(-1);
            Some(AsrRule {
                name: guid.clone(),
                guid,
                state: map_asr_action(action),
            })
        })
        .collect()
}

#[cfg(any(test, target_os = "windows"))]
fn map_asr_action(action: i64) -> AsrState {
    match action {
        0 => AsrState::Disabled,
        1 => AsrState::Block,
        2 => AsrState::Audit,
        6 => AsrState::Warn,
        _ => AsrState::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::{map_asr_action, parse_asr_rules_json, AsrState};

    #[test]
    fn maps_asr_action_values() {
        assert!(matches!(map_asr_action(0), AsrState::Disabled));
        assert!(matches!(map_asr_action(1), AsrState::Block));
        assert!(matches!(map_asr_action(2), AsrState::Audit));
        assert!(matches!(map_asr_action(6), AsrState::Warn));
    }

    #[test]
    fn parses_asr_json_array() {
        let raw = r#"[{"guid":"rule-a","action":1},{"guid":"rule-b","action":2}]"#;
        let rules = parse_asr_rules_json(raw);
        assert_eq!(rules.len(), 2);
        assert!(matches!(rules[0].state, AsrState::Block));
    }
}
