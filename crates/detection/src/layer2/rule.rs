use serde::Deserialize;

use super::predicate::TemporalPredicate;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleLevel {
    Informational,
    Low,
    Medium,
    #[default]
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct TemporalStage {
    pub predicate: TemporalPredicate,
    pub within_secs: u64,
}

#[derive(Debug, Clone)]
pub struct TemporalRule {
    pub name: String,
    pub stages: Vec<TemporalStage>,
    pub level: RuleLevel,
    pub any_order: bool,
}
