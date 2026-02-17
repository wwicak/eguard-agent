use std::collections::{HashMap, HashSet, VecDeque};

use crate::information;
use crate::types::{EventClass, TelemetryEvent};

use super::policy::{is_sensitive_credential_path, path_root_prefix, RansomwarePolicy};

#[derive(Debug, Clone)]
pub(super) struct GraphNode {
    pub(super) ppid: u32,
    pub(super) process: String,
    pub(super) uid: u32,
    pub(super) last_seen: i64,
    pub(super) network_non_web: bool,
    pub(super) module_loaded: bool,
    pub(super) sensitive_file_access: bool,
    pub(super) ransomware_write_burst: bool,
    pub(super) container_escape: bool,
    pub(super) container_privileged: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Layer4EvictionCounters {
    pub retention_prune: u64,
    pub node_cap_evict: u64,
    pub edge_cap_evict: u64,
}

#[derive(Debug, Clone, Default)]
struct WriteBaseline {
    samples: usize,
    mean: f64,
    m2: f64,
    max_rate: f64,
}

impl WriteBaseline {
    fn observe(&mut self, rate: f64) {
        self.samples = self.samples.saturating_add(1);
        let delta = rate - self.mean;
        self.mean += delta / self.samples as f64;
        let delta2 = rate - self.mean;
        self.m2 += delta * delta2;
        if rate > self.max_rate {
            self.max_rate = rate;
        }
    }

    fn variance(&self) -> f64 {
        if self.samples > 1 {
            self.m2 / (self.samples as f64 - 1.0)
        } else {
            0.0
        }
    }
}

#[derive(Debug, Clone)]
struct WriteBaselineWindow {
    window_start: i64,
    count: u32,
}

impl WriteBaselineWindow {
    fn new(ts: i64) -> Self {
        Self {
            window_start: ts,
            count: 0,
        }
    }
}

#[derive(Debug, Clone)]
struct WriteWindowState {
    timestamps: VecDeque<i64>,
    baseline: WriteBaseline,
    baseline_window: WriteBaselineWindow,
    last_seen: i64,
}

impl WriteWindowState {
    fn new(ts: i64) -> Self {
        Self {
            timestamps: VecDeque::new(),
            baseline: WriteBaseline::default(),
            baseline_window: WriteBaselineWindow::new(ts),
            last_seen: ts,
        }
    }
}

impl GraphNode {
    fn reset_runtime_signals(&mut self) {
        self.network_non_web = false;
        self.module_loaded = false;
        self.sensitive_file_access = false;
        self.ransomware_write_burst = false;
        self.container_escape = false;
        self.container_privileged = false;
    }
}

#[derive(Debug, Clone)]
pub(super) struct ProcessGraph {
    nodes: HashMap<u32, GraphNode>,
    children: HashMap<u32, HashSet<u32>>,
    window_secs: i64,
    max_nodes: usize,
    max_edges: usize,
    edge_count: usize,
    eviction_counters: Layer4EvictionCounters,
    ransomware_policy: RansomwarePolicy,
    ransomware_write_state: HashMap<u32, WriteWindowState>,
    ransomware_learned_roots: HashSet<String>,
    ransomware_root_hits: HashMap<String, u32>,
}

impl ProcessGraph {
    pub(super) fn with_capacity(window_secs: i64, max_nodes: usize, max_edges: usize) -> Self {
        Self {
            nodes: HashMap::new(),
            children: HashMap::new(),
            window_secs,
            max_nodes: max_nodes.max(1),
            max_edges: max_edges.max(1),
            edge_count: 0,
            eviction_counters: Layer4EvictionCounters::default(),
            ransomware_policy: RansomwarePolicy::default(),
            ransomware_write_state: HashMap::new(),
            ransomware_learned_roots: HashSet::new(),
            ransomware_root_hits: HashMap::new(),
        }
    }

    pub(super) fn with_capacity_and_policy(
        window_secs: i64,
        max_nodes: usize,
        max_edges: usize,
        ransomware_policy: RansomwarePolicy,
    ) -> Self {
        Self {
            nodes: HashMap::new(),
            children: HashMap::new(),
            window_secs,
            max_nodes: max_nodes.max(1),
            max_edges: max_edges.max(1),
            edge_count: 0,
            eviction_counters: Layer4EvictionCounters::default(),
            ransomware_policy: ransomware_policy.sanitized(),
            ransomware_write_state: HashMap::new(),
            ransomware_learned_roots: HashSet::new(),
            ransomware_root_hits: HashMap::new(),
        }
    }

    pub(super) fn observe(&mut self, event: &TelemetryEvent) {
        if matches!(event.event_class, EventClass::ProcessExit) {
            self.observe_process_exit(event.pid, event.ts_unix);
            self.prune(event.ts_unix);
            self.enforce_capacity();
            return;
        }

        let reset_for_exec = matches!(event.event_class, EventClass::ProcessExec);
        let (sensitive_access, ransomware_burst) = match event.event_class {
            EventClass::FileOpen => {
                if let Some(path) = &event.file_path {
                    let sensitive = is_sensitive_credential_path(path);
                    if event.file_write {
                        self.learn_ransomware_root(path);
                        if !self.ransomware_policy.is_system_or_temp(path) {
                            self.update_ransomware_baseline(event.pid, event.ts_unix);
                        }
                    }
                    let burst = if event.file_write && self.is_ransomware_candidate_path(path) {
                        let (hits, threshold) =
                            self.note_ransomware_write(event.pid, event.ts_unix);
                        hits >= threshold
                    } else {
                        false
                    };
                    (sensitive, burst)
                } else {
                    (false, false)
                }
            }
            _ => (false, false),
        };

        let previous_ppid = {
            let node = self.nodes.entry(event.pid).or_insert_with(|| GraphNode {
                ppid: event.ppid,
                process: event.process.clone(),
                uid: event.uid,
                last_seen: event.ts_unix,
                network_non_web: false,
                module_loaded: false,
                sensitive_file_access: false,
                ransomware_write_burst: false,
                container_escape: false,
                container_privileged: false,
            });

            let previous_ppid = node.ppid;

            if reset_for_exec {
                node.reset_runtime_signals();
            }

            node.ppid = event.ppid;
            node.process = event.process.clone();
            node.uid = event.uid;
            node.last_seen = event.ts_unix;
            node.container_escape = event.container_escape;
            node.container_privileged = event.container_privileged;

            match event.event_class {
                EventClass::NetworkConnect => {
                    if let Some(port) = event.dst_port {
                        if port != 80 && port != 443 {
                            node.network_non_web = true;
                        }
                    }
                }
                EventClass::ModuleLoad => {
                    node.module_loaded = true;
                }
                EventClass::FileOpen => {
                    if sensitive_access {
                        node.sensitive_file_access = true;
                    }
                    if ransomware_burst {
                        node.ransomware_write_burst = true;
                    }
                }
                _ => {}
            }

            previous_ppid
        };

        if reset_for_exec {
            self.ransomware_write_state.remove(&event.pid);
        }

        if reset_for_exec {
            self.remove_outgoing_links(event.pid);
        }

        if previous_ppid != event.ppid {
            self.remove_child_link(previous_ppid, event.pid);
        }

        self.insert_child_link(event.ppid, event.pid);

        self.prune(event.ts_unix);
        self.enforce_capacity();
    }

    pub(super) fn candidate_roots(&self, start_pid: u32, max_depth: usize) -> Vec<u32> {
        let mut out = Vec::with_capacity(max_depth.saturating_add(1));
        let mut visited = HashSet::new();

        let mut current = Some(start_pid);
        let mut depth = 0usize;

        while let Some(pid) = current {
            if !visited.insert(pid) {
                break;
            }
            out.push(pid);

            if depth >= max_depth {
                break;
            }

            let Some(node) = self.nodes.get(&pid) else {
                break;
            };

            if node.ppid == 0 || node.ppid == pid {
                break;
            }

            current = Some(node.ppid);
            depth = depth.saturating_add(1);
        }

        out
    }

    pub(super) fn node(&self, pid: u32) -> Option<&GraphNode> {
        self.nodes.get(&pid)
    }

    pub(super) fn children_of(&self, pid: u32) -> Option<&HashSet<u32>> {
        self.children.get(&pid)
    }

    pub(super) fn eviction_counters(&self) -> Layer4EvictionCounters {
        self.eviction_counters
    }

    #[cfg(test)]
    pub(super) fn node_count(&self) -> usize {
        self.nodes.len()
    }

    #[cfg(all(test, not(miri)))]
    pub(super) fn edge_count(&self) -> usize {
        self.edge_count
    }

    fn insert_child_link(&mut self, parent_pid: u32, child_pid: u32) {
        let inserted = self
            .children
            .entry(parent_pid)
            .or_default()
            .insert(child_pid);
        if inserted {
            self.edge_count = self.edge_count.saturating_add(1);
        }
    }

    fn remove_child_link(&mut self, parent_pid: u32, child_pid: u32) {
        let mut removed = false;
        let mut remove_parent = false;
        if let Some(children) = self.children.get_mut(&parent_pid) {
            removed = children.remove(&child_pid);
            remove_parent = children.is_empty();
        }

        if removed {
            self.edge_count = self.edge_count.saturating_sub(1);
        }

        if remove_parent {
            self.children.remove(&parent_pid);
        }
    }

    fn remove_outgoing_links(&mut self, pid: u32) {
        if let Some(children) = self.children.remove(&pid) {
            self.edge_count = self.edge_count.saturating_sub(children.len());
        }
    }

    fn remove_incoming_links(&mut self, pid: u32) {
        let mut empty_parents = Vec::new();
        for (parent_pid, children) in self.children.iter_mut() {
            if children.remove(&pid) {
                self.edge_count = self.edge_count.saturating_sub(1);
            }
            if children.is_empty() {
                empty_parents.push(*parent_pid);
            }
        }

        for parent_pid in empty_parents {
            self.children.remove(&parent_pid);
        }
    }

    fn remove_node(&mut self, pid: u32) -> bool {
        if self.nodes.remove(&pid).is_none() {
            return false;
        }
        self.ransomware_write_state.remove(&pid);
        self.remove_outgoing_links(pid);
        self.remove_incoming_links(pid);
        true
    }

    fn observe_process_exit(&mut self, pid: u32, event_ts: i64) {
        let Some(node) = self.nodes.get(&pid) else {
            return;
        };

        if event_ts < node.last_seen {
            return;
        }

        let _ = self.remove_node(pid);
    }

    fn select_oldest_pid(&self) -> Option<u32> {
        self.nodes
            .iter()
            .min_by(|(left_pid, left_node), (right_pid, right_node)| {
                left_node
                    .last_seen
                    .cmp(&right_node.last_seen)
                    .then_with(|| left_pid.cmp(right_pid))
            })
            .map(|(pid, _)| *pid)
    }

    fn enforce_capacity(&mut self) {
        while self.nodes.len() > self.max_nodes {
            let Some(evict_pid) = self.select_oldest_pid() else {
                break;
            };
            if self.remove_node(evict_pid) {
                self.eviction_counters.node_cap_evict =
                    self.eviction_counters.node_cap_evict.saturating_add(1);
            }
        }

        while self.edge_count > self.max_edges {
            let Some(evict_pid) = self.select_oldest_pid() else {
                break;
            };
            if self.remove_node(evict_pid) {
                self.eviction_counters.edge_cap_evict =
                    self.eviction_counters.edge_cap_evict.saturating_add(1);
            }
        }
    }

    fn prune(&mut self, now: i64) {
        let cutoff = now - self.window_secs;
        let stale: Vec<u32> = self
            .nodes
            .iter()
            .filter_map(|(pid, node)| {
                if node.last_seen < cutoff {
                    Some(*pid)
                } else {
                    None
                }
            })
            .collect();

        let mut pruned = 0u64;
        for pid in stale {
            if self.remove_node(pid) {
                pruned = pruned.saturating_add(1);
            }
        }

        self.eviction_counters.retention_prune = self
            .eviction_counters
            .retention_prune
            .saturating_add(pruned);

        self.prune_ransomware_counts(now);
    }

    fn note_ransomware_write(&mut self, pid: u32, ts: i64) -> (u32, u32) {
        let window = self.ransomware_policy.write_window_secs;
        let cutoff = ts - window;
        let (hits, baseline) = {
            let state = self
                .ransomware_write_state
                .entry(pid)
                .or_insert_with(|| WriteWindowState::new(ts));
            state.last_seen = ts;
            state.timestamps.push_back(ts);
            while let Some(front) = state.timestamps.front() {
                if *front < cutoff {
                    state.timestamps.pop_front();
                } else {
                    break;
                }
            }

            (state.timestamps.len() as u32, state.baseline.clone())
        };

        let threshold = self.ransomware_threshold(&baseline);
        (hits, threshold)
    }

    fn update_ransomware_baseline(&mut self, pid: u32, ts: i64) {
        let window = self.ransomware_policy.write_window_secs;
        let state = self
            .ransomware_write_state
            .entry(pid)
            .or_insert_with(|| WriteWindowState::new(ts));

        if ts - state.baseline_window.window_start >= window {
            state.baseline.observe(state.baseline_window.count as f64);
            state.baseline_window = WriteBaselineWindow::new(ts);
        }
        state.baseline_window.count = state.baseline_window.count.saturating_add(1);
        state.last_seen = ts;
    }

    fn prune_ransomware_counts(&mut self, now: i64) {
        let cutoff = now - self.ransomware_policy.write_window_secs;
        self.ransomware_write_state
            .retain(|_, state| {
                while let Some(front) = state.timestamps.front() {
                    if *front < cutoff {
                        state.timestamps.pop_front();
                    } else {
                        break;
                    }
                }
                state.last_seen >= cutoff || !state.timestamps.is_empty()
            });
    }

    fn ransomware_threshold(&self, baseline: &WriteBaseline) -> u32 {
        if baseline.samples < self.ransomware_policy.adaptive_min_samples {
            return self.ransomware_policy.write_threshold;
        }

        let range = baseline.max_rate.max(1.0);
        let variance = baseline.variance().max(0.0);
        let delta = self.ransomware_policy.adaptive_delta.max(1e-12);

        let h = information::hoeffding_threshold(baseline.samples, range, delta);
        let b = information::bernstein_threshold(baseline.samples, variance, range, delta);
        let drift = h.min(b).max(0.0);
        let threshold = (baseline.mean + drift).ceil() as u32;
        threshold.max(self.ransomware_policy.adaptive_floor)
    }

    fn is_ransomware_candidate_path(&self, path: &str) -> bool {
        if self.ransomware_policy.is_candidate_path(path) {
            return true;
        }
        let lower = path.to_ascii_lowercase();
        if lower.is_empty() {
            return false;
        }
        if self.ransomware_policy.is_system_or_temp(&lower) {
            return false;
        }
        self.ransomware_learned_roots
            .iter()
            .any(|root| lower.starts_with(root))
    }

    fn learn_ransomware_root(&mut self, path: &str) {
        if self.ransomware_learned_roots.len() >= self.ransomware_policy.learned_root_max {
            return;
        }
        if self.ransomware_policy.is_candidate_path(path) {
            return;
        }
        let lower = path.to_ascii_lowercase();
        if lower.is_empty() || self.ransomware_policy.is_system_or_temp(&lower) {
            return;
        }
        let Some(root) = path_root_prefix(&lower) else {
            return;
        };

        if self
            .ransomware_policy
            .user_path_prefixes
            .iter()
            .any(|prefix| root.starts_with(prefix))
        {
            return;
        }
        if self
            .ransomware_policy
            .system_path_prefixes
            .iter()
            .any(|prefix| root.starts_with(prefix))
        {
            return;
        }
        if self.ransomware_learned_roots.contains(&root) {
            return;
        }
        let hits = self.ransomware_root_hits.entry(root.clone()).or_insert(0);
        *hits = hits.saturating_add(1);
        if *hits >= self.ransomware_policy.learned_root_min_hits {
            self.ransomware_learned_roots.insert(root);
        }
    }
}
