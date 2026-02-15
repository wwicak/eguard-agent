use std::collections::{HashMap, HashSet};

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
}

impl GraphNode {
    fn reset_runtime_signals(&mut self) {
        self.network_non_web = false;
        self.module_loaded = false;
        self.sensitive_file_access = false;
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

        let previous_ppid = {
            let node = self.nodes.entry(event.pid).or_insert_with(|| GraphNode {
                ppid: event.ppid,
                process: event.process.clone(),
                uid: event.uid,
                last_seen: event.ts_unix,
                network_non_web: false,
                module_loaded: false,
                sensitive_file_access: false,
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
                    if let Some(path) = &event.file_path {
                        if path.starts_with("/etc/shadow")
                            || path.starts_with("/etc/passwd")
                            || path.contains("credential")
                        {
                            node.sensitive_file_access = true;
                        }
                    }
                }
                _ => {}
            }

            previous_ppid
        };

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

    pub fn with_default_templates() -> Self {
        let mut engine = Self::new(300);

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
                },
                TemplatePredicate {
                    process_any_of: Some(set_of(["bash", "sh", "dash", "zsh", "python", "perl"])),
                    uid_eq: None,
                    uid_ne: None,
                    require_network_non_web: true,
                    require_module_loaded: false,
                    require_sensitive_file_access: false,
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
                },
                TemplatePredicate {
                    process_any_of: None,
                    uid_eq: Some(0),
                    uid_ne: None,
                    require_network_non_web: false,
                    require_module_loaded: true,
                    require_sensitive_file_access: false,
                },
            ],
            max_depth: 6,
            max_inter_stage_secs: 60,
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
