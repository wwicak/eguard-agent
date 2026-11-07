use super::predicate::TemporalPredicate;
use super::rule::{RuleLevel, TemporalRule};

#[derive(Debug, Clone)]
pub(super) struct MonitorTransition {
    pub(super) predicate: TemporalPredicate,
    pub(super) max_delay_secs: Option<u64>,
}

#[derive(Debug, Clone)]
pub(super) struct DeterministicMonitorAutomaton {
    pub(super) name: String,
    pub(super) transitions: Vec<MonitorTransition>,
    pub(super) max_window_secs: i64,
    pub(super) sibling_linked: bool,
    pub(super) level: RuleLevel,
}

impl DeterministicMonitorAutomaton {
    pub(super) fn from_rule(rule: TemporalRule) -> Self {
        let mut transitions = Vec::with_capacity(rule.stages.len());
        let mut max_window_secs: i64 = 0;

        for (idx, stage) in rule.stages.into_iter().enumerate() {
            max_window_secs = max_window_secs.saturating_add(stage.within_secs as i64);
            transitions.push(MonitorTransition {
                predicate: stage.predicate,
                max_delay_secs: if idx == 0 {
                    None
                } else {
                    Some(stage.within_secs)
                },
            });
        }

        if max_window_secs <= 0 {
            max_window_secs = 1;
        }

        let sibling_linked = transitions.iter().skip(1).any(|transition| {
            matches!(
                transition.predicate.link,
                super::predicate::TemporalLink::Sibling
                    | super::predicate::TemporalLink::SameProcessOrSibling
                    | super::predicate::TemporalLink::SiblingOrChild
                    | super::predicate::TemporalLink::SameProcessOrDescendantOrSibling
            )
        });
        Self {
            name: rule.name,
            transitions,
            max_window_secs,
            sibling_linked,
            level: rule.level,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct TemporalState {
    pub(super) stage_idx: usize,
    pub(super) first_match_ts: i64,
    pub(super) last_match_ts: i64,
    pub(super) exec_epoch: Option<u64>,
    pub(super) identity_fingerprint: u64,
    pub(super) pid: u32,
    pub(super) ppid: u32,
    pub(super) command_line: Option<String>,
}
