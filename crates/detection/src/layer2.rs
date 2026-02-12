use std::collections::{HashMap, HashSet};

use crate::types::{EventClass, TelemetryEvent};
use crate::util::{set_of, set_u16};

#[derive(Debug, Clone)]
pub struct TemporalPredicate {
    pub event_class: EventClass,
    pub process_any_of: Option<HashSet<String>>,
    pub parent_any_of: Option<HashSet<String>>,
    pub uid_eq: Option<u32>,
    pub uid_ne: Option<u32>,
    pub dst_port_not_in: Option<HashSet<u16>>,
}

impl TemporalPredicate {
    pub fn matches(&self, event: &TelemetryEvent) -> bool {
        if self.event_class != event.event_class {
            return false;
        }

        if let Some(set) = &self.process_any_of {
            if !set.contains(&event.process) {
                return false;
            }
        }

        if let Some(set) = &self.parent_any_of {
            if !set.contains(&event.parent_process) {
                return false;
            }
        }

        if let Some(value) = self.uid_eq {
            if event.uid != value {
                return false;
            }
        }

        if let Some(value) = self.uid_ne {
            if event.uid == value {
                return false;
            }
        }

        if let Some(excluded_ports) = &self.dst_port_not_in {
            match event.dst_port {
                Some(port) => {
                    if excluded_ports.contains(&port) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }
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
}

#[derive(Debug, Clone)]
struct TemporalState {
    stage_idx: usize,
    first_match_ts: i64,
    last_match_ts: i64,
}

#[derive(Debug, Default)]
pub struct TemporalEngine {
    rules: Vec<TemporalRule>,
    states: HashMap<(usize, String), TemporalState>,
    subscriptions: HashMap<EventClass, Vec<usize>>,
    reorder_tolerance_secs: i64,
}

impl TemporalEngine {
    pub fn new() -> Self {
        Self {
            reorder_tolerance_secs: 2,
            ..Self::default()
        }
    }

    pub fn with_default_rules() -> Self {
        let mut engine = Self::new();

        let web_servers = set_of(["nginx", "apache2", "httpd", "caddy"]);
        let shells = set_of(["sh", "bash", "dash", "zsh", "ksh"]);
        let webshell = TemporalRule {
            name: "phi_webshell".to_string(),
            stages: vec![
                TemporalStage {
                    predicate: TemporalPredicate {
                        event_class: EventClass::ProcessExec,
                        process_any_of: Some(shells),
                        parent_any_of: Some(web_servers),
                        uid_eq: None,
                        uid_ne: None,
                        dst_port_not_in: None,
                    },
                    within_secs: 30,
                },
                TemporalStage {
                    predicate: TemporalPredicate {
                        event_class: EventClass::NetworkConnect,
                        process_any_of: None,
                        parent_any_of: None,
                        uid_eq: None,
                        uid_ne: None,
                        dst_port_not_in: Some(set_u16([80, 443])),
                    },
                    within_secs: 10,
                },
            ],
        };

        let priv_esc = TemporalRule {
            name: "phi_priv_esc".to_string(),
            stages: vec![
                TemporalStage {
                    predicate: TemporalPredicate {
                        event_class: EventClass::ProcessExec,
                        process_any_of: None,
                        parent_any_of: None,
                        uid_eq: None,
                        uid_ne: Some(0),
                        dst_port_not_in: None,
                    },
                    within_secs: 60,
                },
                TemporalStage {
                    predicate: TemporalPredicate {
                        event_class: EventClass::ProcessExec,
                        process_any_of: None,
                        parent_any_of: None,
                        uid_eq: Some(0),
                        uid_ne: None,
                        dst_port_not_in: None,
                    },
                    within_secs: 20,
                },
            ],
        };

        engine.add_rule(webshell);
        engine.add_rule(priv_esc);
        engine
    }

    pub fn add_rule(&mut self, rule: TemporalRule) {
        let rule_id = self.rules.len();
        for stage in &rule.stages {
            self.subscriptions
                .entry(stage.predicate.event_class)
                .or_default()
                .push(rule_id);
        }
        self.rules.push(rule);
    }

    pub fn observe(&mut self, event: &TelemetryEvent) -> Vec<String> {
        let mut hits = Vec::new();
        let Some(rule_ids) = self.subscriptions.get(&event.event_class).cloned() else {
            return hits;
        };

        let entity = event.entity_key();
        for rule_id in rule_ids {
            let Some(rule) = self.rules.get(rule_id) else {
                continue;
            };
            if rule.stages.is_empty() {
                continue;
            }

            let key = (rule_id, entity.clone());
            let current = self.states.get(&key).cloned();

            let mut next_state = current.clone();
            if let Some(state) = current {
                let stage_idx = state.stage_idx.min(rule.stages.len() - 1);
                let stage = &rule.stages[stage_idx];

                let monotonic_ok = event.ts_unix + self.reorder_tolerance_secs >= state.last_match_ts;
                let within = event.ts_unix - state.last_match_ts <= stage.within_secs as i64;
                if monotonic_ok && within && stage.predicate.matches(event) {
                    let advanced = stage_idx + 1;
                    if advanced >= rule.stages.len() {
                        hits.push(rule.name.clone());
                        self.states.remove(&key);
                        continue;
                    }
                    next_state = Some(TemporalState {
                        stage_idx: advanced,
                        first_match_ts: state.first_match_ts,
                        last_match_ts: event.ts_unix,
                    });
                } else if rule.stages[0].predicate.matches(event) {
                    if rule.stages.len() == 1 {
                        hits.push(rule.name.clone());
                        self.states.remove(&key);
                        continue;
                    }
                    next_state = Some(TemporalState {
                        stage_idx: 1,
                        first_match_ts: event.ts_unix,
                        last_match_ts: event.ts_unix,
                    });
                } else {
                    let max_window = rule.stages.iter().map(|s| s.within_secs as i64).sum::<i64>();
                    if event.ts_unix - state.first_match_ts > max_window {
                        next_state = None;
                    }
                }
            } else if rule.stages[0].predicate.matches(event) {
                if rule.stages.len() == 1 {
                    hits.push(rule.name.clone());
                    continue;
                }
                next_state = Some(TemporalState {
                    stage_idx: 1,
                    first_match_ts: event.ts_unix,
                    last_match_ts: event.ts_unix,
                });
            }

            match next_state {
                Some(state) => {
                    self.states.insert(key, state);
                }
                None => {
                    self.states.remove(&key);
                }
            }
        }

        hits
    }
}
