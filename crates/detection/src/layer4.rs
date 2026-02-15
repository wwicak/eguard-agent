use std::collections::{HashMap, HashSet, VecDeque};

use crate::information;
use crate::types::{EventClass, TelemetryEvent};
use crate::util::set_of;

#[derive(Debug, Clone)]
struct GraphNode {
    ppid: u32,
    process: String,
    uid: u32,
    last_seen: i64,
    network_non_web: bool,
    module_loaded: bool,
    sensitive_file_access: bool,
    ransomware_write_burst: bool,
}

const DEFAULT_RANSOMWARE_WINDOW_SECS: i64 = 20;
const DEFAULT_RANSOMWARE_WRITE_THRESHOLD: u32 = 25;

const DEFAULT_RANSOMWARE_USER_PATH_PREFIXES: &[&str] = &[
    "/home/",
    "/users/",
    "/srv/",
    "/var/www/",
    "/mnt/",
    "/media/",
    "/volumes/",
    "\\\\",
];

const DEFAULT_RANSOMWARE_SYSTEM_PATH_PREFIXES: &[&str] = &[
    "/proc/",
    "/sys/",
    "/dev/",
    "/run/",
    "/tmp/",
    "/var/tmp/",
    "/var/run/",
    "/private/tmp/",
    "/private/var/",
    "/etc/",
    "/bin/",
    "/sbin/",
    "/lib/",
    "/lib64/",
    "/usr/",
    "/boot/",
    "/system/",
    "/library/",
    "c:\\windows",
    "c:/windows",
    "c:\\program files",
    "c:/program files",
    "c:\\program files (x86)",
    "c:/program files (x86)",
    "c:\\programdata",
    "c:/programdata",
    "c:\\temp",
    "c:/temp",
];

const DEFAULT_RANSOMWARE_TEMP_PATH_TOKENS: &[&str] = &[
    "/tmp/",
    "/temp/",
    "\\temp\\",
    "\\appdata\\",
    "/appdata/",
    "\\appdata\\local\\temp",
    "/appdata/local/temp",
];

#[derive(Debug, Clone)]
pub struct RansomwarePolicy {
    pub write_window_secs: i64,
    pub write_threshold: u32,
    pub adaptive_delta: f64,
    pub adaptive_min_samples: usize,
    pub adaptive_floor: u32,
    pub learned_root_min_hits: u32,
    pub learned_root_max: usize,
    pub user_path_prefixes: Vec<String>,
    pub system_path_prefixes: Vec<String>,
    pub temp_path_tokens: Vec<String>,
}

impl Default for RansomwarePolicy {
    fn default() -> Self {
        Self {
            write_window_secs: DEFAULT_RANSOMWARE_WINDOW_SECS,
            write_threshold: DEFAULT_RANSOMWARE_WRITE_THRESHOLD,
            adaptive_delta: 1e-6,
            adaptive_min_samples: 6,
            adaptive_floor: 5,
            learned_root_min_hits: 3,
            learned_root_max: 64,
            user_path_prefixes: DEFAULT_RANSOMWARE_USER_PATH_PREFIXES
                .iter()
                .map(|v| v.to_string())
                .collect(),
            system_path_prefixes: DEFAULT_RANSOMWARE_SYSTEM_PATH_PREFIXES
                .iter()
                .map(|v| v.to_string())
                .collect(),
            temp_path_tokens: DEFAULT_RANSOMWARE_TEMP_PATH_TOKENS
                .iter()
                .map(|v| v.to_string())
                .collect(),
        }
        .sanitized()
    }
}

impl RansomwarePolicy {
    pub fn sanitized(mut self) -> Self {
        if self.write_window_secs <= 0 {
            self.write_window_secs = DEFAULT_RANSOMWARE_WINDOW_SECS;
        }
        if self.write_threshold == 0 {
            self.write_threshold = DEFAULT_RANSOMWARE_WRITE_THRESHOLD;
        }
        if !(0.0..=1.0).contains(&self.adaptive_delta) {
            self.adaptive_delta = 1e-6;
        }
        if self.adaptive_min_samples == 0 {
            self.adaptive_min_samples = 6;
        }
        if self.adaptive_floor == 0 {
            self.adaptive_floor = 5;
        }
        if self.learned_root_min_hits == 0 {
            self.learned_root_min_hits = 3;
        }
        if self.learned_root_max == 0 {
            self.learned_root_max = 64;
        }
        self.user_path_prefixes = normalize_list(self.user_path_prefixes);
        self.system_path_prefixes = normalize_list(self.system_path_prefixes);
        self.temp_path_tokens = normalize_list(self.temp_path_tokens);
        if self.user_path_prefixes.is_empty() {
            self.user_path_prefixes = DEFAULT_RANSOMWARE_USER_PATH_PREFIXES
                .iter()
                .map(|v| v.to_string())
                .collect();
        }
        if self.system_path_prefixes.is_empty() {
            self.system_path_prefixes = DEFAULT_RANSOMWARE_SYSTEM_PATH_PREFIXES
                .iter()
                .map(|v| v.to_string())
                .collect();
        }
        if self.temp_path_tokens.is_empty() {
            self.temp_path_tokens = DEFAULT_RANSOMWARE_TEMP_PATH_TOKENS
                .iter()
                .map(|v| v.to_string())
                .collect();
        }
        self
    }

    fn is_system_or_temp(&self, path: &str) -> bool {
        let lower = path.to_ascii_lowercase();
        if lower.is_empty() {
            return false;
        }

        if self
            .system_path_prefixes
            .iter()
            .any(|prefix| lower.starts_with(prefix))
        {
            return true;
        }
        if self
            .temp_path_tokens
            .iter()
            .any(|token| lower.contains(token))
        {
            return true;
        }
        false
    }

    fn is_candidate_path(&self, path: &str) -> bool {
        let lower = path.to_ascii_lowercase();
        if lower.is_empty() {
            return false;
        }

        if self.is_system_or_temp(&lower) {
            return false;
        }
        if self
            .user_path_prefixes
            .iter()
            .any(|prefix| lower.starts_with(prefix))
        {
            return true;
        }

        let bytes = lower.as_bytes();
        if bytes.len() >= 3 && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/') {
            return true;
        }

        false
    }
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
    }
}

#[derive(Debug, Clone)]
pub struct TemplatePredicate {
    pub process_any_of: Option<HashSet<String>>,
    pub uid_eq: Option<u32>,
    pub uid_ne: Option<u32>,
    pub require_network_non_web: bool,
    pub require_module_loaded: bool,
    pub require_sensitive_file_access: bool,
    pub require_ransomware_write_burst: bool,
}

impl TemplatePredicate {
    fn matches(&self, node: &GraphNode) -> bool {
        if let Some(set) = &self.process_any_of {
            if !set.contains(&node.process) {
                return false;
            }
        }
        if let Some(uid) = self.uid_eq {
            if node.uid != uid {
                return false;
            }
        }
        if let Some(uid) = self.uid_ne {
            if node.uid == uid {
                return false;
            }
        }
        if self.require_network_non_web && !node.network_non_web {
            return false;
        }
        if self.require_module_loaded && !node.module_loaded {
            return false;
        }
        if self.require_sensitive_file_access && !node.sensitive_file_access {
            return false;
        }
        if self.require_ransomware_write_burst && !node.ransomware_write_burst {
            return false;
        }
        true
    }
}

#[derive(Debug, Clone)]
pub struct KillChainTemplate {
    pub name: String,
    pub stages: Vec<TemplatePredicate>,
    pub max_depth: usize,
    pub max_inter_stage_secs: i64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Layer4EvictionCounters {
    pub retention_prune: u64,
    pub node_cap_evict: u64,
    pub edge_cap_evict: u64,
}

const DEFAULT_LAYER4_MAX_NODES: usize = 8_192;
const DEFAULT_LAYER4_MAX_EDGES: usize = 32_768;

#[derive(Debug, Clone)]
struct ProcessGraph {
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
    fn with_capacity(window_secs: i64, max_nodes: usize, max_edges: usize) -> Self {
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

    fn with_capacity_and_policy(
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

    fn observe(&mut self, event: &TelemetryEvent) {
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
                    let sensitive = path.starts_with("/etc/shadow")
                        || path.starts_with("/etc/passwd")
                        || path.contains("credential");
                    if event.file_write {
                        self.learn_ransomware_root(path);
                        if !self.ransomware_policy.is_system_or_temp(path) {
                            self.update_ransomware_baseline(event.pid, event.ts_unix);
                        }
                    }
                    let burst =
                        if event.file_write && self.is_ransomware_candidate_path(path) {
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
            });

            let previous_ppid = node.ppid;

            if reset_for_exec {
                node.reset_runtime_signals();
            }

            node.ppid = event.ppid;
            node.process = event.process.clone();
            node.uid = event.uid;
            node.last_seen = event.ts_unix;

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

        // Ignore stale out-of-order exit records relative to the latest node observation.
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

    fn candidate_roots(&self, start_pid: u32, max_depth: usize) -> Vec<u32> {
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

pub struct Layer4Engine {
    graph: ProcessGraph,
    templates: Vec<KillChainTemplate>,
}

impl Layer4Engine {
    pub fn new(window_secs: i64) -> Self {
        Self::with_capacity(
            window_secs,
            DEFAULT_LAYER4_MAX_NODES,
            DEFAULT_LAYER4_MAX_EDGES,
        )
    }

    pub fn with_capacity(window_secs: i64, max_nodes: usize, max_edges: usize) -> Self {
        Self {
            graph: ProcessGraph::with_capacity(window_secs, max_nodes, max_edges),
            templates: Vec::new(),
        }
    }

    pub fn with_capacity_and_policy(
        window_secs: i64,
        max_nodes: usize,
        max_edges: usize,
        ransomware_policy: RansomwarePolicy,
    ) -> Self {
        Self {
            graph: ProcessGraph::with_capacity_and_policy(
                window_secs,
                max_nodes,
                max_edges,
                ransomware_policy,
            ),
            templates: Vec::new(),
        }
    }

    pub fn with_default_templates() -> Self {
        let mut engine = Self::with_capacity_and_policy(
            300,
            DEFAULT_LAYER4_MAX_NODES,
            DEFAULT_LAYER4_MAX_EDGES,
            RansomwarePolicy::default(),
        );

        engine.templates.push(KillChainTemplate {
            name: "killchain_webshell_network".to_string(),
            stages: vec![
                TemplatePredicate {
                    process_any_of: Some(set_of(["nginx", "apache2", "httpd", "caddy"])),
                    uid_eq: None,
                    uid_ne: None,
                    require_network_non_web: false,
                    require_module_loaded: false,
                    require_sensitive_file_access: false,
                    require_ransomware_write_burst: false,
                },
                TemplatePredicate {
                    process_any_of: Some(set_of(["bash", "sh", "dash", "zsh", "python", "perl"])),
                    uid_eq: None,
                    uid_ne: None,
                    require_network_non_web: true,
                    require_module_loaded: false,
                    require_sensitive_file_access: false,
                    require_ransomware_write_burst: false,
                },
            ],
            max_depth: 6,
            max_inter_stage_secs: 30,
        });

        engine.templates.push(KillChainTemplate {
            name: "killchain_user_root_module".to_string(),
            stages: vec![
                TemplatePredicate {
                    process_any_of: None,
                    uid_eq: None,
                    uid_ne: Some(0),
                    require_network_non_web: false,
                    require_module_loaded: false,
                    require_sensitive_file_access: false,
                    require_ransomware_write_burst: false,
                },
                TemplatePredicate {
                    process_any_of: None,
                    uid_eq: Some(0),
                    uid_ne: None,
                    require_network_non_web: false,
                    require_module_loaded: true,
                    require_sensitive_file_access: false,
                    require_ransomware_write_burst: false,
                },
            ],
            max_depth: 6,
            max_inter_stage_secs: 60,
        });

        engine.templates.push(KillChainTemplate {
            name: "killchain_ransomware_write_burst".to_string(),
            stages: vec![TemplatePredicate {
                process_any_of: None,
                uid_eq: None,
                uid_ne: None,
                require_network_non_web: false,
                require_module_loaded: false,
                require_sensitive_file_access: false,
                require_ransomware_write_burst: true,
            }],
            max_depth: 2,
            max_inter_stage_secs: 15,
        });

        engine
    }

    pub fn add_template(&mut self, template: KillChainTemplate) {
        self.templates.push(template);
    }

    pub fn observe(&mut self, event: &TelemetryEvent) -> Vec<String> {
        self.graph.observe(event);

        let mut hits = Vec::new();
        let candidate_roots = self
            .graph
            .candidate_roots(event.pid, self.max_template_depth());
        for template in &self.templates {
            for pid in &candidate_roots {
                if self.match_from(*pid, template, 0, 0, 0) {
                    hits.push(template.name.clone());
                    break;
                }
            }
        }

        hits
    }

    pub fn eviction_counters(&self) -> Layer4EvictionCounters {
        self.graph.eviction_counters
    }

    fn max_template_depth(&self) -> usize {
        self.templates
            .iter()
            .map(|template| template.max_depth.max(template.stages.len()))
            .max()
            .unwrap_or(0)
    }

    fn match_from(
        &self,
        pid: u32,
        template: &KillChainTemplate,
        stage_idx: usize,
        depth: usize,
        prev_ts: i64,
    ) -> bool {
        if stage_idx >= template.stages.len() || depth > template.max_depth {
            return false;
        }

        let Some(node) = self.graph.nodes.get(&pid) else {
            return false;
        };
        if stage_idx > 0 && node.last_seen - prev_ts > template.max_inter_stage_secs {
            return false;
        }

        if !template.stages[stage_idx].matches(node) {
            return false;
        }

        if stage_idx + 1 == template.stages.len() {
            return true;
        }

        if let Some(children) = self.graph.children.get(&pid) {
            for child in children {
                if self.match_from(*child, template, stage_idx + 1, depth + 1, node.last_seen) {
                    return true;
                }
            }
        }

        false
    }

    #[cfg(test)]
    pub(crate) fn debug_graph_node_count(&self) -> usize {
        self.graph.nodes.len()
    }

    #[cfg(test)]
    pub(crate) fn debug_template_count(&self) -> usize {
        self.templates.len()
    }

    #[cfg(test)]
    pub(crate) fn debug_contains_pid(&self, pid: u32) -> bool {
        self.graph.nodes.contains_key(&pid)
    }

    #[cfg(test)]
    pub(crate) fn debug_eviction_counters(&self) -> Layer4EvictionCounters {
        self.graph.eviction_counters
    }

    #[cfg(all(test, not(miri)))]
    pub(crate) fn debug_graph_edge_count(&self) -> usize {
        self.graph.edge_count
    }

    #[cfg(all(test, not(miri)))]
    pub(crate) fn debug_total_template_stages(&self) -> usize {
        self.templates.iter().map(|t| t.stages.len()).sum()
    }
}

impl Default for Layer4Engine {
    fn default() -> Self {
        Self::with_default_templates()
    }
}

fn normalize_list(values: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = values
        .into_iter()
        .filter_map(|v| {
            let trimmed = v.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_ascii_lowercase())
            }
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

fn path_root_prefix(path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    let bytes = path.as_bytes();
    if bytes.len() >= 3 && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/') {
        let drive = &path[..2];
        let sep = if bytes[2] == b'\\' { '\\' } else { '/' };
        let rest = &path[3..];
        let components: Vec<&str> = rest
            .split(|c| c == '/' || c == '\\')
            .filter(|c| !c.is_empty())
            .collect();
        if components.is_empty() {
            return Some(format!("{drive}{sep}"));
        }
        let mut root = format!("{drive}{sep}{}", components[0]);
        if components.len() > 1 {
            root.push(sep);
            root.push_str(components[1]);
        }
        root.push(sep);
        return Some(root);
    }

    if path.starts_with("\\\\") {
        let rest = &path[2..];
        let components: Vec<&str> = rest
            .split('\\')
            .filter(|c| !c.is_empty())
            .collect();
        if components.len() >= 2 {
            return Some(format!("\\\\{}\\{}\\", components[0], components[1]));
        }
        return None;
    }

    if path.starts_with('/') {
        let components: Vec<&str> = path
            .split('/')
            .filter(|c| !c.is_empty())
            .collect();
        if components.is_empty() {
            return None;
        }
        let mut root = format!("/{}/", components[0]);
        if components.len() > 1 {
            root.push_str(components[1]);
            root.push('/');
        }
        return Some(root);
    }

    None
}
