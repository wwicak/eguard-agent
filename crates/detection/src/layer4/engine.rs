use crate::types::TelemetryEvent;
use crate::util::set_of;

use super::graph::{KillChainWitness, Layer4EvictionCounters, ProcessGraph};
use super::policy::RansomwarePolicy;
use super::template::{KillChainTemplate, TemplatePredicate};
use serde::Serialize;

const DEFAULT_LAYER4_MAX_NODES: usize = 8_192;
const DEFAULT_LAYER4_MAX_EDGES: usize = 32_768;

#[derive(Debug, Clone, Serialize)]
pub struct KillChainEvidence {
    pub template: String,
    pub witnesses: Vec<KillChainWitness>,
    pub peer_ip: Option<String>,
    pub peer_port: Option<u16>,
    pub peer_is_configured_server: bool,
}

pub struct Layer4Engine {
    last_evidence: Vec<KillChainEvidence>,
    agent_pid: Option<u32>,
    configured_peers: std::collections::HashSet<(String, u16)>,
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
            last_evidence: Vec::new(),
            agent_pid: None,
            configured_peers: std::collections::HashSet::new(),
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
            last_evidence: Vec::new(),
            agent_pid: None,
            configured_peers: std::collections::HashSet::new(),
        }
    }

    pub fn with_default_templates() -> Self {
        Self::with_default_templates_and_policy(RansomwarePolicy::default())
    }

    pub fn with_default_templates_and_policy(policy: RansomwarePolicy) -> Self {
        let mut engine = Self::with_capacity_and_policy(300, DEFAULT_LAYER4_MAX_NODES, DEFAULT_LAYER4_MAX_EDGES, policy);
        // Credential access, webshell and reverse-shell families live in layer2.
        // Ransomware stays disabled until overwrite/rename evidence is available.
        engine.add_template(KillChainTemplate {
            name: "killchain_container_escape".into(),
            stages: vec![TemplatePredicate {
                require_container_context: true,
                command_line_any_of: Some(set_of(["nsenter -t 1 ", "nsenter --target 1 ", "nsenter -t1 ", "chroot /host", "/proc/1/root", "release_agent", "core_pattern", "mount /dev/sd", "mount /dev/nvme", "mount /dev/vd", "mount /dev/xvd"])),
                ..Default::default()
            }],
            max_depth: 4, max_inter_stage_secs: 300,
        });
        for (name, first) in [
            ("killchain_exploit_ptrace_fileless", TemplatePredicate { require_ptrace_activity: true, ..Default::default() }),
            ("killchain_exploit_proc_mem_fileless", TemplatePredicate { require_proc_mem_access: true, ..Default::default() }),
        ] {
            engine.add_template(KillChainTemplate {
                name: name.into(),
                stages: vec![first, TemplatePredicate { require_fileless_exec: true, ..Default::default() }],
                max_depth: 6, max_inter_stage_secs: 20,
            });
        }
        engine
    }

    pub fn template_names(&self) -> Vec<&str> {
        self.templates.iter().map(|template| template.name.as_str()).collect()
    }

    pub fn configure_control_plane(&mut self, agent_pid: u32, peers: Vec<(String, u16)>) {
        self.agent_pid = Some(agent_pid);
        self.configured_peers = peers.into_iter().collect();
    }

    pub(crate) fn peer_is_configured_server(&self, event: &TelemetryEvent) -> bool {
        if !matches!(event.event_class, crate::EventClass::NetworkConnect) {
            return false;
        }
        let Some(port) = event.dst_port else {
            return false;
        };
        [event.dst_ip.as_deref(), event.dst_domain.as_deref()]
            .into_iter()
            .flatten()
            .any(|host| {
                let host = host
                    .parse::<std::net::IpAddr>()
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|_| host.trim_end_matches('.').to_ascii_lowercase());
                self.configured_peers.contains(&(host, port))
            })
    }

    pub fn add_template(&mut self, template: KillChainTemplate) {
        self.templates.push(template);
    }

    pub fn observe(&mut self, event: &TelemetryEvent) -> Vec<String> {
        self.graph.observe(event);
        self.last_evidence.clear();

        let peer_is_configured_server = self.peer_is_configured_server(event);
        // Our live PID cannot be reused. Deeper lineage is generation-validated
        // by the agent's raw-event filter; stale graph ancestry is not authority.
        let own_control_plane = peer_is_configured_server
            && self
                .agent_pid
                .is_some_and(|pid| event.pid == pid || event.ppid == pid);
        let mut hits = Vec::new();
        let candidate_roots = self
            .graph
            .candidate_roots(event.pid, self.max_template_depth());
        for template in &self.templates {
            if own_control_plane
                && template
                    .stages
                    .last()
                    .is_some_and(|stage| stage.require_network_non_web)
            {
                continue;
            }
            for pid in &candidate_roots {
                if let Some(mut witnesses) = self.match_from(*pid, template, 0, 0, None, event.pid)
                {
                    if self.graph.mark_fired(
                        event.pid,
                        &template.name,
                        event.ts_unix,
                        template.max_inter_stage_secs,
                    ) {
                        let mut seen = std::collections::HashSet::new();
                        witnesses.retain(|witness| seen.insert(witness.event_id.clone()));
                        hits.push(template.name.clone());
                        self.last_evidence.push(KillChainEvidence {
                            template: template.name.clone(),
                            witnesses,
                            peer_ip: event.dst_ip.clone(),
                            peer_port: event.dst_port,
                            peer_is_configured_server,
                        });
                    }
                    break;
                }
            }
        }

        hits
    }

    pub fn eviction_counters(&self) -> Layer4EvictionCounters {
        self.graph.eviction_counters()
    }

    fn max_template_depth(&self) -> usize {
        self.templates
            .iter()
            .map(|template| template.max_depth.max(template.stages.len()))
            .max()
            .unwrap_or(0)
    }

    pub fn last_evidence(&self) -> &[KillChainEvidence] {
        &self.last_evidence
    }

    pub fn current_event_id(&self) -> &str {
        &self.graph.current_event_id
    }

    fn match_from(
        &self,
        pid: u32,
        template: &KillChainTemplate,
        stage_idx: usize,
        depth: usize,
        prev_ts: Option<(i64, bool)>,
        terminal_pid: u32,
    ) -> Option<Vec<KillChainWitness>> {
        if stage_idx >= template.stages.len() || depth > template.max_depth {
            return None;
        }
        let node = self.graph.node(pid)?;
        let mut witnesses = template.stages[stage_idx].witnesses(node)?;
        let stage_ts = witnesses.iter().map(|w| w.ts_unix).max()?;
        if prev_ts.is_some_and(|(prev, signal)| {
            let anchor = if signal { prev } else { node.identity_witness.ts_unix };
            stage_ts < anchor || stage_ts.saturating_sub(anchor) > template.max_inter_stage_secs
        }) {
            return None;
        }
        if stage_idx + 1 == template.stages.len() {
            return (pid == terminal_pid
                && witnesses
                    .iter()
                    .any(|w| w.event_id == self.graph.current_event_id))
            .then_some(witnesses);
        }
        if let Some(children) = self.graph.children_of(pid) {
            for child in children {
                if let Some(next) = self.match_descendant(
                    *child, template, stage_idx + 1, depth + 1,
                    (stage_ts, witnesses.len() > 1 || template.stages[stage_idx].command_line_any_of.is_some()),
                    terminal_pid,
                ) {
                    witnesses.extend(next);
                    return Some(witnesses);
                }
            }
        }
        None
    }

    fn match_descendant(
        &self, pid: u32, template: &KillChainTemplate, stage_idx: usize,
        depth: usize, prev: (i64, bool), terminal_pid: u32,
    ) -> Option<Vec<KillChainWitness>> {
        if depth > template.max_depth { return None; }
        if let Some(witnesses) = self.match_from(pid, template, stage_idx, depth, Some(prev), terminal_pid) {
            return Some(witnesses);
        }
        for child in self.graph.children_of(pid).into_iter().flatten() {
            if let Some(witnesses) = self.match_descendant(*child, template, stage_idx, depth + 1, prev, terminal_pid) {
                return Some(witnesses);
            }
        }
        None
    }

    #[cfg(test)]
    pub(crate) fn debug_graph_node_count(&self) -> usize {
        self.graph.node_count()
    }

    #[cfg(test)]
    pub(crate) fn debug_template_count(&self) -> usize {
        self.templates.len()
    }

    #[cfg(test)]
    pub(crate) fn debug_contains_pid(&self, pid: u32) -> bool {
        self.graph.node(pid).is_some()
    }

    #[cfg(test)]
    pub(crate) fn debug_eviction_counters(&self) -> Layer4EvictionCounters {
        self.graph.eviction_counters()
    }

    #[cfg(all(test, not(miri)))]
    pub(crate) fn debug_graph_edge_count(&self) -> usize {
        self.graph.edge_count()
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
