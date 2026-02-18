use crate::types::TelemetryEvent;
use crate::util::set_of;

use super::graph::{Layer4EvictionCounters, ProcessGraph};
use super::policy::RansomwarePolicy;
use super::template::{KillChainTemplate, TemplatePredicate};

const DEFAULT_LAYER4_MAX_NODES: usize = 8_192;
const DEFAULT_LAYER4_MAX_EDGES: usize = 32_768;

pub struct Layer4Engine {
    graph: ProcessGraph,
    templates: Vec<KillChainTemplate>,
}

impl Layer4Engine {
    pub fn new(window_secs: i64) -> Self {
        Self::with_capacity(window_secs, DEFAULT_LAYER4_MAX_NODES, DEFAULT_LAYER4_MAX_EDGES)
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
                    require_container_escape: false,
                    require_privileged_container: false,
                    require_ptrace_activity: false,
                    require_userfaultfd_activity: false,
                    require_execveat_activity: false,
                    require_proc_mem_access: false,
                    require_fileless_exec: false,
                },
                TemplatePredicate {
                    process_any_of: Some(set_of(["bash", "sh", "dash", "zsh", "python", "perl"])),
                    uid_eq: None,
                    uid_ne: None,
                    require_network_non_web: true,
                    require_module_loaded: false,
                    require_sensitive_file_access: false,
                    require_ransomware_write_burst: false,
                    require_container_escape: false,
                    require_privileged_container: false,
                    require_ptrace_activity: false,
                    require_userfaultfd_activity: false,
                    require_execveat_activity: false,
                    require_proc_mem_access: false,
                    require_fileless_exec: false,
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
                    require_container_escape: false,
                    require_privileged_container: false,
                    require_ptrace_activity: false,
                    require_userfaultfd_activity: false,
                    require_execveat_activity: false,
                    require_proc_mem_access: false,
                    require_fileless_exec: false,
                },
                TemplatePredicate {
                    process_any_of: None,
                    uid_eq: Some(0),
                    uid_ne: None,
                    require_network_non_web: false,
                    require_module_loaded: true,
                    require_sensitive_file_access: false,
                    require_ransomware_write_burst: false,
                    require_container_escape: false,
                    require_privileged_container: false,
                    require_ptrace_activity: false,
                    require_userfaultfd_activity: false,
                    require_execveat_activity: false,
                    require_proc_mem_access: false,
                    require_fileless_exec: false,
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
                require_container_escape: false,
                require_privileged_container: false,
                require_ptrace_activity: false,
                require_userfaultfd_activity: false,
                require_execveat_activity: false,
                require_proc_mem_access: false,
                require_fileless_exec: false,
            }],
            max_depth: 2,
            max_inter_stage_secs: 15,
        });

        engine.templates.push(KillChainTemplate {
            name: "killchain_credential_theft".to_string(),
            stages: vec![TemplatePredicate {
                process_any_of: None,
                uid_eq: None,
                uid_ne: Some(0),
                require_network_non_web: false,
                require_module_loaded: false,
                require_sensitive_file_access: true,
                require_ransomware_write_burst: false,
                require_container_escape: false,
                require_privileged_container: false,
                require_ptrace_activity: false,
                require_userfaultfd_activity: false,
                require_execveat_activity: false,
                require_proc_mem_access: false,
                require_fileless_exec: false,
            }],
            max_depth: 2,
            max_inter_stage_secs: 10,
        });

        engine.templates.push(KillChainTemplate {
            name: "killchain_container_escape".to_string(),
            stages: vec![TemplatePredicate {
                process_any_of: None,
                uid_eq: None,
                uid_ne: None,
                require_network_non_web: false,
                require_module_loaded: false,
                require_sensitive_file_access: false,
                require_ransomware_write_burst: false,
                require_container_escape: true,
                require_privileged_container: false,
                require_ptrace_activity: false,
                require_userfaultfd_activity: false,
                require_execveat_activity: false,
                require_proc_mem_access: false,
                require_fileless_exec: false,
            }],
            max_depth: 2,
            max_inter_stage_secs: 10,
        });

        engine.templates.push(KillChainTemplate {
            name: "killchain_container_privileged".to_string(),
            stages: vec![TemplatePredicate {
                process_any_of: None,
                uid_eq: None,
                uid_ne: None,
                require_network_non_web: false,
                require_module_loaded: false,
                require_sensitive_file_access: false,
                require_ransomware_write_burst: false,
                require_container_escape: false,
                require_privileged_container: true,
                require_ptrace_activity: false,
                require_userfaultfd_activity: false,
                require_execveat_activity: false,
                require_proc_mem_access: false,
                require_fileless_exec: false,
            }],
            max_depth: 2,
            max_inter_stage_secs: 10,
        });

        engine.templates.push(KillChainTemplate {
            name: "killchain_exploit_ptrace_fileless".to_string(),
            stages: vec![
                TemplatePredicate {
                    process_any_of: None,
                    uid_eq: None,
                    uid_ne: None,
                    require_network_non_web: false,
                    require_module_loaded: false,
                    require_sensitive_file_access: false,
                    require_ransomware_write_burst: false,
                    require_container_escape: false,
                    require_privileged_container: false,
                    require_ptrace_activity: true,
                    require_userfaultfd_activity: false,
                    require_execveat_activity: false,
                    require_proc_mem_access: false,
                    require_fileless_exec: false,
                },
                TemplatePredicate {
                    process_any_of: None,
                    uid_eq: None,
                    uid_ne: None,
                    require_network_non_web: false,
                    require_module_loaded: false,
                    require_sensitive_file_access: false,
                    require_ransomware_write_burst: false,
                    require_container_escape: false,
                    require_privileged_container: false,
                    require_ptrace_activity: false,
                    require_userfaultfd_activity: false,
                    require_execveat_activity: false,
                    require_proc_mem_access: false,
                    require_fileless_exec: true,
                },
            ],
            max_depth: 6,
            max_inter_stage_secs: 20,
        });

        engine.templates.push(KillChainTemplate {
            name: "killchain_exploit_userfaultfd_execveat".to_string(),
            stages: vec![
                TemplatePredicate {
                    process_any_of: None,
                    uid_eq: None,
                    uid_ne: None,
                    require_network_non_web: false,
                    require_module_loaded: false,
                    require_sensitive_file_access: false,
                    require_ransomware_write_burst: false,
                    require_container_escape: false,
                    require_privileged_container: false,
                    require_ptrace_activity: false,
                    require_userfaultfd_activity: true,
                    require_execveat_activity: false,
                    require_proc_mem_access: false,
                    require_fileless_exec: false,
                },
                TemplatePredicate {
                    process_any_of: None,
                    uid_eq: None,
                    uid_ne: None,
                    require_network_non_web: false,
                    require_module_loaded: false,
                    require_sensitive_file_access: false,
                    require_ransomware_write_burst: false,
                    require_container_escape: false,
                    require_privileged_container: false,
                    require_ptrace_activity: false,
                    require_userfaultfd_activity: false,
                    require_execveat_activity: true,
                    require_proc_mem_access: false,
                    require_fileless_exec: false,
                },
            ],
            max_depth: 6,
            max_inter_stage_secs: 20,
        });

        engine.templates.push(KillChainTemplate {
            name: "killchain_exploit_proc_mem_fileless".to_string(),
            stages: vec![
                TemplatePredicate {
                    process_any_of: None,
                    uid_eq: None,
                    uid_ne: None,
                    require_network_non_web: false,
                    require_module_loaded: false,
                    require_sensitive_file_access: false,
                    require_ransomware_write_burst: false,
                    require_container_escape: false,
                    require_privileged_container: false,
                    require_ptrace_activity: false,
                    require_userfaultfd_activity: false,
                    require_execveat_activity: false,
                    require_proc_mem_access: true,
                    require_fileless_exec: false,
                },
                TemplatePredicate {
                    process_any_of: None,
                    uid_eq: None,
                    uid_ne: None,
                    require_network_non_web: false,
                    require_module_loaded: false,
                    require_sensitive_file_access: false,
                    require_ransomware_write_burst: false,
                    require_container_escape: false,
                    require_privileged_container: false,
                    require_ptrace_activity: false,
                    require_userfaultfd_activity: false,
                    require_execveat_activity: false,
                    require_proc_mem_access: false,
                    require_fileless_exec: true,
                },
            ],
            max_depth: 6,
            max_inter_stage_secs: 20,
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
        self.graph.eviction_counters()
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

        let Some(node) = self.graph.node(pid) else {
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

        if let Some(children) = self.graph.children_of(pid) {
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
