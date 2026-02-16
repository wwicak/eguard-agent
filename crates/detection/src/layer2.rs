use std::collections::{hash_map::DefaultHasher, HashMap, HashSet};
use std::hash::{Hash, Hasher};

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
    pub file_path_any_of: Option<HashSet<String>>,
    pub file_path_contains: Option<HashSet<String>>,
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

        if self.file_path_any_of.is_some() || self.file_path_contains.is_some() {
            let Some(path) = event.file_path.as_deref() else {
                return false;
            };

            let exact_ok = self
                .file_path_any_of
                .as_ref()
                .map(|set| set.contains(path))
                .unwrap_or(false);
            let contains_ok = self
                .file_path_contains
                .as_ref()
                .map(|set| set.iter().any(|needle| path.contains(needle)))
                .unwrap_or(false);

            if !exact_ok && !contains_ok {
                return false;
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
    exec_epoch: Option<u64>,
    identity_fingerprint: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TemporalEvictionCounters {
    pub retention_prune: u64,
    pub state_cap_evict: u64,
    pub metadata_cap_evict: u64,
}

#[derive(Debug, Default)]
pub struct TemporalEngine {
    automata: Vec<DeterministicMonitorAutomaton>,
    states: HashMap<(usize, u32), TemporalState>,
    subscriptions: HashMap<EventClass, Vec<usize>>,
    pid_exec_epoch: HashMap<u32, u64>,
    pid_last_seen_ts: HashMap<u32, i64>,
    reorder_tolerance_secs: i64,
    max_observed_ts: i64,
    retention_slack_secs: i64,
    max_state_entries: usize,
    max_tracked_pids: usize,
    eviction_counters: TemporalEvictionCounters,
}

impl TemporalEngine {
    pub fn new() -> Self {
        Self {
            reorder_tolerance_secs: 2,
            max_observed_ts: i64::MIN,
            retention_slack_secs: 5,
            max_state_entries: 32_768,
            max_tracked_pids: 16_384,
            ..Self::default()
        }
    }

    #[cfg(test)]
    pub(crate) fn with_capacity_limits_for_test(
        max_state_entries: usize,
        max_tracked_pids: usize,
    ) -> Self {
        Self {
            max_state_entries: max_state_entries.max(1),
            max_tracked_pids: max_tracked_pids.max(1),
            ..Self::new()
        }
    }

    pub fn with_default_rules() -> Self {
        let mut engine = Self::new();
        engine.install_default_rules();
        engine
    }

    #[cfg(test)]
    pub(crate) fn with_default_rules_and_capacity_for_test(
        max_state_entries: usize,
        max_tracked_pids: usize,
    ) -> Self {
        let mut engine = Self::with_capacity_limits_for_test(max_state_entries, max_tracked_pids);
        engine.install_default_rules();
        engine
    }

    fn install_default_rules(&mut self) {
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
                        file_path_any_of: None,
                        file_path_contains: None,
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
                        file_path_any_of: None,
                        file_path_contains: None,
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
                        file_path_any_of: None,
                        file_path_contains: None,
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
                        file_path_any_of: None,
                        file_path_contains: None,
                    },
                    within_secs: 20,
                },
            ],
        };

        self.add_rule(webshell);
        self.add_rule(priv_esc);
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

        let horizon_ts = self.advance_observation_horizon(event.ts_unix);
        self.prune_stale_temporal_entries(horizon_ts);

        let entity = event.session_id;
        if self.event_is_reorder_stale(entity, event.ts_unix) {
            return hits;
        }

        if matches!(event.event_class, EventClass::ProcessExit) {
            self.teardown_entity(entity);
            self.enforce_capacity_limits();
            return hits;
        }

        self.record_entity_timestamp(entity, event.ts_unix);

        let current_exec_epoch = self.bump_exec_epoch(entity, event.event_class);
        let event_identity_fingerprint = Self::identity_fingerprint(event);
        let Some(rule_ids) = self.subscriptions.get(&event.event_class).cloned() else {
            self.enforce_capacity_limits();
            return hits;
        };

        for rule_id in rule_ids {
            let Some(automaton) = self.automata.get(rule_id) else {
                continue;
            };
            if automaton.transitions.is_empty() {
                continue;
            }

            let key = (rule_id, entity);
            let current = self.states.get(&key).cloned();

            let mut next_state = current.clone();
            if let Some(state) = current {
                let stage_idx = state.stage_idx.min(automaton.transitions.len() - 1);
                let transition = &automaton.transitions[stage_idx];
                let exec_epoch_ok =
                    Self::exec_epoch_compatible(&state, transition, current_exec_epoch);
                let identity_ok =
                    Self::identity_compatible(&state, transition, event_identity_fingerprint);

                let monotonic_ok =
                    event.ts_unix + self.reorder_tolerance_secs >= state.last_match_ts;
                let within = transition
                    .max_delay_secs
                    .map(|v| event.ts_unix - state.last_match_ts <= v as i64)
                    .unwrap_or(true);

                if exec_epoch_ok
                    && identity_ok
                    && monotonic_ok
                    && within
                    && transition.predicate.matches(event)
                {
                    let advanced = stage_idx + 1;
                    if advanced >= automaton.transitions.len() {
                        hits.push(automaton.name.clone());
                        self.states.remove(&key);
                        continue;
                    }

                    let mut next_exec_epoch = state.exec_epoch;
                    let mut next_identity_fingerprint = state.identity_fingerprint;
                    if matches!(event.event_class, EventClass::ProcessExec) {
                        next_exec_epoch = Some(current_exec_epoch);
                        next_identity_fingerprint = event_identity_fingerprint;
                    }

                    next_state = Some(TemporalState {
                        stage_idx: advanced,
                        first_match_ts: state.first_match_ts,
                        last_match_ts: event.ts_unix,
                        exec_epoch: next_exec_epoch,
                        identity_fingerprint: next_identity_fingerprint,
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
                        exec_epoch: Self::initial_exec_epoch(event, current_exec_epoch),
                        identity_fingerprint: event_identity_fingerprint,
                    });
                } else if !exec_epoch_ok
                    || !identity_ok
                    || event.ts_unix - state.first_match_ts > automaton.max_window_secs
                {
                    next_state = None;
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
                    exec_epoch: Self::initial_exec_epoch(event, current_exec_epoch),
                    identity_fingerprint: event_identity_fingerprint,
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

        self.enforce_capacity_limits();
        hits
    }

    fn enforce_capacity_limits(&mut self) {
        self.enforce_state_capacity();
        self.enforce_pid_metadata_capacity();
    }

    fn teardown_entity(&mut self, session_id: u32) {
        self.states
            .retain(|(_, state_session), _| *state_session != session_id);
        self.pid_last_seen_ts.remove(&session_id);
        self.pid_exec_epoch.remove(&session_id);
    }

    fn enforce_state_capacity(&mut self) {
        let capacity = self.max_state_entries.max(1);
        while self.states.len() > capacity {
            let Some(victim_key) = self
                .states
                .iter()
                .min_by(|(left_key, left_state), (right_key, right_state)| {
                    Self::state_eviction_order(left_key, left_state, right_key, right_state)
                })
                .map(|(key, _)| *key)
            else {
                break;
            };
            if self.states.remove(&victim_key).is_some() {
                self.eviction_counters.state_cap_evict =
                    self.eviction_counters.state_cap_evict.saturating_add(1);
            }
        }
    }

    fn state_eviction_order(
        left_key: &(usize, u32),
        left_state: &TemporalState,
        right_key: &(usize, u32),
        right_state: &TemporalState,
    ) -> std::cmp::Ordering {
        left_state
            .last_match_ts
            .cmp(&right_state.last_match_ts)
            .then_with(|| left_state.first_match_ts.cmp(&right_state.first_match_ts))
            .then_with(|| left_key.0.cmp(&right_key.0))
            .then_with(|| left_key.1.cmp(&right_key.1))
    }

    fn enforce_pid_metadata_capacity(&mut self) {
        let capacity = self.max_tracked_pids.max(1);
        let mut active_pids: HashSet<u32> = self.states.keys().map(|(_, pid)| *pid).collect();

        loop {
            let tracked_pids = self.collect_tracked_pids();
            if tracked_pids.len() <= capacity {
                break;
            }

            let Some(victim_pid) = self.pid_eviction_candidate(&tracked_pids, &active_pids) else {
                break;
            };

            if active_pids.remove(&victim_pid) {
                self.states.retain(|(_, pid), _| *pid != victim_pid);
            }

            let removed_last_seen = self.pid_last_seen_ts.remove(&victim_pid).is_some();
            let removed_exec_epoch = self.pid_exec_epoch.remove(&victim_pid).is_some();
            if removed_last_seen || removed_exec_epoch {
                self.eviction_counters.metadata_cap_evict =
                    self.eviction_counters.metadata_cap_evict.saturating_add(1);
            }
        }
    }

    fn collect_tracked_pids(&self) -> HashSet<u32> {
        let mut tracked =
            HashSet::with_capacity(self.pid_last_seen_ts.len() + self.pid_exec_epoch.len());
        tracked.extend(self.pid_last_seen_ts.keys().copied());
        tracked.extend(self.pid_exec_epoch.keys().copied());
        tracked
    }

    fn pid_eviction_candidate(
        &self,
        tracked_pids: &HashSet<u32>,
        active_pids: &HashSet<u32>,
    ) -> Option<u32> {
        tracked_pids
            .iter()
            .copied()
            .filter(|pid| !active_pids.contains(pid))
            .min_by(|left, right| self.pid_eviction_order(*left, *right))
            .or_else(|| {
                tracked_pids
                    .iter()
                    .copied()
                    .min_by(|left, right| self.pid_eviction_order(*left, *right))
            })
    }

    fn pid_eviction_order(&self, left_pid: u32, right_pid: u32) -> std::cmp::Ordering {
        let left_last_seen = self
            .pid_last_seen_ts
            .get(&left_pid)
            .copied()
            .unwrap_or(i64::MIN);
        let right_last_seen = self
            .pid_last_seen_ts
            .get(&right_pid)
            .copied()
            .unwrap_or(i64::MIN);

        left_last_seen
            .cmp(&right_last_seen)
            .then_with(|| left_pid.cmp(&right_pid))
    }

    fn advance_observation_horizon(&mut self, event_ts: i64) -> i64 {
        if event_ts > self.max_observed_ts {
            self.max_observed_ts = event_ts;
        }
        self.max_observed_ts
    }

    fn prune_stale_temporal_entries(&mut self, reference_ts: i64) {
        let retention_secs = self.state_retention_secs();
        if retention_secs <= 0 {
            return;
        }

        let before_states = self.states.len();
        self.states.retain(|_, state| {
            !Self::exceeds_retention(reference_ts, state.last_match_ts, retention_secs)
        });
        let removed_states = before_states.saturating_sub(self.states.len());

        let active_pids: HashSet<u32> = self.states.keys().map(|(_, pid)| *pid).collect();
        let before_last_seen = self.pid_last_seen_ts.len();
        self.pid_last_seen_ts.retain(|pid, last_seen_ts| {
            active_pids.contains(pid)
                || !Self::exceeds_retention(reference_ts, *last_seen_ts, retention_secs)
        });
        let removed_last_seen = before_last_seen.saturating_sub(self.pid_last_seen_ts.len());

        let tracked_pids: HashSet<u32> = self.pid_last_seen_ts.keys().copied().collect();
        let before_exec_epoch = self.pid_exec_epoch.len();
        self.pid_exec_epoch
            .retain(|pid, _| active_pids.contains(pid) || tracked_pids.contains(pid));
        let removed_exec_epoch = before_exec_epoch.saturating_sub(self.pid_exec_epoch.len());

        let total_pruned = (removed_states as u64)
            .saturating_add(removed_last_seen as u64)
            .saturating_add(removed_exec_epoch as u64);
        self.eviction_counters.retention_prune = self
            .eviction_counters
            .retention_prune
            .saturating_add(total_pruned);
    }

    fn state_retention_secs(&self) -> i64 {
        let max_window_secs = self
            .automata
            .iter()
            .map(|automaton| automaton.max_window_secs)
            .max()
            .unwrap_or(1)
            .max(1);

        max_window_secs
            .saturating_add(self.reorder_tolerance_secs.max(0))
            .saturating_add(self.retention_slack_secs.max(0))
    }

    fn exceeds_retention(reference_ts: i64, state_ts: i64, retention_secs: i64) -> bool {
        reference_ts
            .checked_sub(state_ts)
            .map(|elapsed| elapsed > retention_secs)
            .unwrap_or(true)
    }

    fn event_is_reorder_stale(&self, pid: u32, event_ts: i64) -> bool {
        self.pid_last_seen_ts
            .get(&pid)
            .map(|last_seen| event_ts.saturating_add(self.reorder_tolerance_secs) < *last_seen)
            .unwrap_or(false)
    }

    fn record_entity_timestamp(&mut self, pid: u32, event_ts: i64) {
        let entry = self.pid_last_seen_ts.entry(pid).or_insert(event_ts);
        if event_ts > *entry {
            *entry = event_ts;
        }
    }

    fn bump_exec_epoch(&mut self, pid: u32, event_class: EventClass) -> u64 {
        let entry = self.pid_exec_epoch.entry(pid).or_insert(0);
        if matches!(event_class, EventClass::ProcessExec) {
            *entry = entry.saturating_add(1);
        }
        *entry
    }

    fn initial_exec_epoch(event: &TelemetryEvent, current_exec_epoch: u64) -> Option<u64> {
        if matches!(event.event_class, EventClass::ProcessExec) {
            Some(current_exec_epoch)
        } else {
            None
        }
    }

    fn exec_epoch_compatible(
        state: &TemporalState,
        transition: &MonitorTransition,
        current_exec_epoch: u64,
    ) -> bool {
        if matches!(transition.predicate.event_class, EventClass::ProcessExec) {
            return true;
        }

        match state.exec_epoch {
            Some(epoch) => epoch == current_exec_epoch,
            None => true,
        }
    }

    fn identity_compatible(
        state: &TemporalState,
        transition: &MonitorTransition,
        event_identity_fingerprint: u64,
    ) -> bool {
        if matches!(transition.predicate.event_class, EventClass::ProcessExec) {
            return true;
        }

        state.identity_fingerprint == event_identity_fingerprint
    }

    fn identity_fingerprint(event: &TelemetryEvent) -> u64 {
        let mut hasher = DefaultHasher::new();
        event.process.hash(&mut hasher);
        event.parent_process.hash(&mut hasher);
        event.uid.hash(&mut hasher);
        event.session_id.hash(&mut hasher);
        hasher.finish()
    }

    pub fn eviction_counters(&self) -> TemporalEvictionCounters {
        self.eviction_counters
    }

    #[cfg(all(test, not(miri)))]
    pub(crate) fn debug_automata_count(&self) -> usize {
        self.automata.len()
    }

    #[cfg(all(test, not(miri)))]
    pub(crate) fn debug_subscription_edges(&self) -> usize {
        self.subscriptions.values().map(|v| v.len()).sum()
    }

    #[cfg(test)]
    pub(crate) fn debug_state_count(&self) -> usize {
        self.states.len()
    }

    #[cfg(test)]
    pub(crate) fn debug_pid_exec_epoch_count(&self) -> usize {
        self.pid_exec_epoch.len()
    }

    #[cfg(test)]
    pub(crate) fn debug_pid_last_seen_count(&self) -> usize {
        self.pid_last_seen_ts.len()
    }

    #[cfg(test)]
    pub(crate) fn debug_has_pid_metadata(&self, pid: u32) -> bool {
        self.pid_exec_epoch.contains_key(&pid) || self.pid_last_seen_ts.contains_key(&pid)
    }

    #[cfg(test)]
    pub(crate) fn debug_eviction_counters(&self) -> TemporalEvictionCounters {
        self.eviction_counters
    }
}
