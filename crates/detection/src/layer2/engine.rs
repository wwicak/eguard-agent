use std::collections::{hash_map::DefaultHasher, HashMap, HashSet};
use std::hash::{Hash, Hasher};

use crate::sigma::{compile_sigma_rule, SigmaCompileError};
use crate::types::{EventClass, TelemetryEvent};

use super::automaton::{DeterministicMonitorAutomaton, MonitorTransition, TemporalState};
use super::defaults::default_rules;
use super::predicate::TemporalLink;
use super::rule::{RuleLevel, TemporalRule};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TemporalEvictionCounters {
    pub retention_prune: u64,
    pub state_cap_evict: u64,
    pub metadata_cap_evict: u64,
}

#[derive(Debug, Default)]
pub struct TemporalEngine {
    automata: Vec<DeterministicMonitorAutomaton>,
    // Rule-local causal key: PID, or immediate parent for sibling pairs.
    states: HashMap<(usize, u32), TemporalState>,
    subscriptions: HashMap<EventClass, Vec<usize>>,
    pid_exec_epoch: HashMap<u32, u64>,
    pid_parents: HashMap<u32, u32>,
    // RAFIX shared: bounded with the existing PID metadata, never a host-root join.
    package_transactions: HashSet<u32>,
    pipe_high: bool,
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
        for rule in default_rules() {
            self.add_rule(rule);
        }
    }

    pub fn add_rule(&mut self, mut rule: TemporalRule) {
        if rule.any_order && rule.stages.len() == 2 {
            rule.any_order = false;
            let mut reversed = rule.clone();
            reversed.stages.reverse();
            reversed.stages[1].predicate.link = rule.stages[1].predicate.link;
            self.add_rule(reversed);
        }
        let automaton = DeterministicMonitorAutomaton::from_rule(rule);
        let rule_id = self.automata.len();
        for transition in &automaton.transitions {
            // Two stages on one class must not let a single event advance twice.
            let subscribers = self
                .subscriptions
                .entry(transition.predicate.event_class)
                .or_default();
            if !subscribers.contains(&rule_id) {
                subscribers.push(rule_id);
            }
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
        self.pipe_high = false;
        let mut hits = Vec::new();

        let horizon_ts = self.advance_observation_horizon(event.ts_unix);
        self.prune_stale_temporal_entries(horizon_ts);

        if self.event_is_reorder_stale(event.pid, event.ts_unix) {
            return hits;
        }

        if matches!(event.event_class, EventClass::ProcessExit) {
            self.teardown_entity(event.pid, event.session_id);
            self.enforce_capacity_limits();
            return hits;
        }

        self.record_entity_timestamp(event.pid, event.ts_unix);
        self.pid_parents.insert(event.pid, event.ppid);
        if event.event_class == EventClass::ProcessExec {
            self.package_transactions.remove(&event.pid);
            if crate::tamper::is_update_worker(event)
                || crate::tamper::is_package_manager(&event.process)
                || crate::tamper::is_package_manager(&event.parent_process)
                || self.package_transactions.contains(&event.ppid)
            {
                self.package_transactions.insert(event.pid);
            }
        }

        let current_exec_epoch = self.bump_exec_epoch(event.pid, event.event_class);
        let event_identity_fingerprint = Self::identity_fingerprint(event);
        let Some(rule_ids) = self.subscriptions.get(&event.event_class) else {
            self.enforce_capacity_limits();
            return hits;
        };

        for &rule_id in rule_ids {
            let Some(automaton) = self.automata.get(rule_id) else {
                continue;
            };
            if automaton.transitions.is_empty() {
                continue;
            }

            let initial_entity = if automaton.sibling_linked && event.ppid > 1 {
                event.ppid
            } else {
                event.pid
            };
            let mut candidates = vec![event.pid];
            let mut ancestor = event.ppid;
            for _ in 0..4 {
                if ancestor <= 1 {
                    break;
                }
                candidates.push(ancestor);
                ancestor = self.pid_parents.get(&ancestor).copied().unwrap_or(0);
            }
            let current_key = candidates.into_iter().find_map(|pid| {
                let key = (rule_id, pid);
                let state = self.states.get(&key)?;
                let transition = &automaton.transitions[state.stage_idx];
                self.link_compatible(state, transition, event)
                    .then_some(key)
            });
            let mut key = current_key.unwrap_or((rule_id, initial_entity));
            let current = current_key.and_then(|key| self.states.get(&key).cloned());

            if current.is_none() && !automaton.transitions[0].predicate.matches(event) {
                continue;
            }
            let mut next_state = current.clone();
            if let Some(state) = current {
                let stage_idx = state.stage_idx.min(automaton.transitions.len() - 1);
                let transition = &automaton.transitions[stage_idx];
                let same_pid = event.pid == state.pid;
                let exec_epoch_ok = !same_pid
                    || Self::exec_epoch_compatible(&state, transition, current_exec_epoch);
                let identity_ok = !same_pid
                    || Self::identity_compatible(&state, transition, event_identity_fingerprint);

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
                        if automaton.name == "phi_download_pipe_shell" {
                            // RAFIX shared: whichever sibling is the downloader supplies the URL.
                            self.pipe_high |= crate::exploit::download_is_high(
                                state
                                    .command_line
                                    .as_deref()
                                    .unwrap_or("")
                                    .split_whitespace()
                                    .chain(
                                        event
                                            .command_line
                                            .as_deref()
                                            .unwrap_or("")
                                            .split_whitespace(),
                                    ),
                                &event.parent_process,
                                event.uid,
                            );
                        }
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
                        pid: event.pid,
                        ppid: event.ppid,
                        command_line: event.command_line.clone(),
                    });
                } else if automaton.transitions[0].predicate.matches(event) {
                    // A child starting its own chain must not erase its parent's pending evidence.
                    key = (rule_id, initial_entity);
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
                        pid: event.pid,
                        ppid: event.ppid,
                        command_line: event.command_line.clone(),
                    });
                } else if (event.pid == state.pid && (!exec_epoch_ok || !identity_ok))
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
                    pid: event.pid,
                    ppid: event.ppid,
                    command_line: event.command_line.clone(),
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
        hits.sort();
        hits.dedup();
        hits
    }

    pub(crate) fn exec_epoch(&self, pid: u32) -> Option<u64> {
        self.pid_exec_epoch.get(&pid).copied()
    }
    pub(crate) fn in_package_transaction(&self, pid: u32) -> bool {
        self.package_transactions.contains(&pid)
    }

    pub fn rule_level(&self, name: &str) -> RuleLevel {
        if name == "phi_download_pipe_shell" && self.pipe_high {
            return RuleLevel::High;
        }
        self.automata
            .iter()
            .filter(|a| a.name == name)
            .map(|a| a.level)
            .max()
            .unwrap_or_default()
    }

    fn link_compatible(
        &self,
        state: &TemporalState,
        transition: &MonitorTransition,
        event: &TelemetryEvent,
    ) -> bool {
        let same = event.pid == state.pid;
        let child = event.ppid > 1 && event.ppid == state.pid;
        let sibling = event.ppid > 1 && event.ppid == state.ppid && !same;
        let mut ancestor = event.ppid;
        let descendant = (0..3).any(|_| {
            if ancestor <= 1 {
                return false;
            }
            let found = ancestor == state.pid;
            ancestor = self.pid_parents.get(&ancestor).copied().unwrap_or(0);
            found
        });
        // Fork-before-exec inherits argv. Do not join arbitrary child activity
        // for rules that explicitly require a single process.
        let fork = child
            && event.event_class != EventClass::ProcessExec
            && state.command_line.is_some()
            && state.command_line == event.command_line;
        let linked = match transition.predicate.link {
            TemporalLink::SameProcess => same || fork,
            TemporalLink::SameProcessOrChild => same || child,
            TemporalLink::SameProcessOrDescendant => same || descendant,
            TemporalLink::Sibling => sibling,
            TemporalLink::SameProcessOrSibling => same || sibling,
            TemporalLink::SiblingOrChild => sibling || child,
            TemporalLink::SameProcessOrDescendantOrSibling => same || descendant || sibling,
        };
        linked
            && (same
                || state
                    .exec_epoch
                    .is_none_or(|epoch| self.pid_exec_epoch.get(&state.pid) == Some(&epoch)))
    }

    fn enforce_capacity_limits(&mut self) {
        self.enforce_state_capacity();
        self.enforce_pid_metadata_capacity();
        self.pid_parents
            .retain(|pid, _| self.pid_last_seen_ts.contains_key(pid));
    }

    fn teardown_entity(&mut self, pid: u32, _session_id: u32) {
        self.states.retain(|(rule_id, _), state| {
            if state.pid != pid {
                return true;
            }
            // A completed downloader may exit before its sibling interpreter starts.
            let keep = self.automata[*rule_id].sibling_linked
                && self.automata[*rule_id].transitions[state.stage_idx]
                    .predicate
                    .event_class
                    == EventClass::ProcessExec;
            if keep {
                state.exec_epoch = None;
            }
            keep
        });
        self.pid_last_seen_ts.remove(&pid);
        self.pid_exec_epoch.remove(&pid);
        self.pid_parents.remove(&pid);
        self.package_transactions.remove(&pid);
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
        let mut active_pids: HashSet<u32> = self.states.values().map(|state| state.pid).collect();

        loop {
            let tracked_pids = self.collect_tracked_pids();
            if tracked_pids.len() <= capacity {
                break;
            }

            let Some(victim_pid) = self.pid_eviction_candidate(&tracked_pids, &active_pids) else {
                break;
            };

            if active_pids.remove(&victim_pid) {
                self.states.retain(|_, state| state.pid != victim_pid);
            }

            self.package_transactions.remove(&victim_pid);
            self.pid_parents.remove(&victim_pid);
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

        let active_pids: HashSet<u32> = self.states.values().map(|state| state.pid).collect();
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

        self.pid_parents.retain(|pid, _| tracked_pids.contains(pid));
        self.package_transactions
            .retain(|pid| tracked_pids.contains(pid));

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
        event.pid.hash(&mut hasher);
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

impl TemporalEngine {
    // RAFIX shared: loaded rule identities (APACKS)
    pub fn rule_names(&self) -> Vec<String> {
        self.automata.iter().map(|rule| rule.name.clone()).collect()
    }
}

#[cfg(test)]
mod rule_names_tests {
    use super::{TemporalEngine, TemporalRule};

    #[test]
    fn rule_names_preserve_insertion_order() {
        let mut engine = TemporalEngine::new();
        for name in ["first", "second"] {
            // RAFIX shared: additive core rule fields retain their default semantics.
            engine.add_rule(TemporalRule {
                name: name.into(),
                stages: Vec::new(),
                level: Default::default(),
                any_order: false,
            });
        }
        assert_eq!(engine.rule_names(), vec!["first", "second"]);
    }
}
