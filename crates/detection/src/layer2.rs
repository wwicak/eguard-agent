use std::collections::{HashMap, HashSet};

use crate::sigma::{compile_sigma_rule, SigmaCompileError};
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
struct MonitorTransition {
    predicate: TemporalPredicate,
    max_delay_secs: Option<u64>,
}

#[derive(Debug, Clone)]
struct DeterministicMonitorAutomaton {
    name: String,
    transitions: Vec<MonitorTransition>,
    max_window_secs: i64,
}

impl DeterministicMonitorAutomaton {
    fn from_rule(rule: TemporalRule) -> Self {
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
struct TemporalState {
    stage_idx: usize,
    first_match_ts: i64,
    last_match_ts: i64,
}

#[derive(Debug, Default)]
pub struct TemporalEngine {
    automata: Vec<DeterministicMonitorAutomaton>,
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
        let automaton = DeterministicMonitorAutomaton::from_rule(rule);
        let rule_id = self.automata.len();
        for transition in &automaton.transitions {
            self.subscriptions
                .entry(transition.predicate.event_class)
                .or_default()
                .push(rule_id);
        }
        self.automata.push(automaton);
    }

    pub fn add_sigma_rule_yaml(&mut self, yaml: &str) -> Result<String, SigmaCompileError> {
        let rule = compile_sigma_rule(yaml)?;
        let name = rule.name.clone();
        self.add_rule(rule);
        Ok(name)
    }

    pub fn observe(&mut self, event: &TelemetryEvent) -> Vec<String> {
        let mut hits = Vec::new();
        let Some(rule_ids) = self.subscriptions.get(&event.event_class).cloned() else {
            return hits;
        };

        let entity = event.entity_key();
        for rule_id in rule_ids {
            let Some(automaton) = self.automata.get(rule_id) else {
                continue;
            };
            if automaton.transitions.is_empty() {
                continue;
            }

            let key = (rule_id, entity.clone());
            let current = self.states.get(&key).cloned();

            let mut next_state = current.clone();
            if let Some(state) = current {
                let stage_idx = state.stage_idx.min(automaton.transitions.len() - 1);
                let transition = &automaton.transitions[stage_idx];

                let monotonic_ok =
                    event.ts_unix + self.reorder_tolerance_secs >= state.last_match_ts;
                let within = transition
                    .max_delay_secs
                    .map(|v| event.ts_unix - state.last_match_ts <= v as i64)
                    .unwrap_or(true);
                if monotonic_ok && within && transition.predicate.matches(event) {
                    let advanced = stage_idx + 1;
                    if advanced >= automaton.transitions.len() {
                        hits.push(automaton.name.clone());
                        self.states.remove(&key);
                        continue;
                    }
                    next_state = Some(TemporalState {
                        stage_idx: advanced,
                        first_match_ts: state.first_match_ts,
                        last_match_ts: event.ts_unix,
                    });
                } else if automaton.transitions[0].predicate.matches(event) {
                    if automaton.transitions.len() == 1 {
                        hits.push(automaton.name.clone());
                        self.states.remove(&key);
                        continue;
                    }
                    next_state = Some(TemporalState {
                        stage_idx: 1,
                        first_match_ts: event.ts_unix,
                        last_match_ts: event.ts_unix,
                    });
                } else {
                    if event.ts_unix - state.first_match_ts > automaton.max_window_secs {
                        next_state = None;
                    }
                }
            } else if automaton.transitions[0].predicate.matches(event) {
                if automaton.transitions.len() == 1 {
                    hits.push(automaton.name.clone());
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

    #[cfg(test)]
    pub(crate) fn debug_automata_count(&self) -> usize {
        self.automata.len()
    }

    #[cfg(test)]
    pub(crate) fn debug_subscription_edges(&self) -> usize {
        self.subscriptions.values().map(|v| v.len()).sum()
    }

    #[cfg(test)]
    pub(crate) fn debug_state_count(&self) -> usize {
        self.states.len()
    }
}
