use super::predicate::TemporalPredicate;
use super::rule::TemporalRule;

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

        Self {
            name: rule.name,
            transitions,
            max_window_secs,
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
}
