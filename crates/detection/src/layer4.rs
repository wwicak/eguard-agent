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

#[derive(Debug, Clone)]
struct ProcessGraph {
    nodes: HashMap<u32, GraphNode>,
    children: HashMap<u32, HashSet<u32>>,
    window_secs: i64,
}

impl ProcessGraph {
    fn new(window_secs: i64) -> Self {
        Self {
            nodes: HashMap::new(),
            children: HashMap::new(),
            window_secs,
        }
    }

    fn observe(&mut self, event: &TelemetryEvent) {
        let node = self.nodes.entry(event.pid).or_insert_with(|| GraphNode {
            ppid: event.ppid,
            process: event.process.clone(),
            uid: event.uid,
            last_seen: event.ts_unix,
            network_non_web: false,
            module_loaded: false,
            sensitive_file_access: false,
        });

        node.ppid = event.ppid;
        node.process = event.process.clone();
        node.uid = event.uid;
        node.last_seen = event.ts_unix;

        self.children
            .entry(event.ppid)
            .or_default()
            .insert(event.pid);

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

        self.prune(event.ts_unix);
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

        for pid in stale {
            self.nodes.remove(&pid);
            self.children.remove(&pid);
            for child_set in self.children.values_mut() {
                child_set.remove(&pid);
            }
        }
    }
}

pub struct Layer4Engine {
    graph: ProcessGraph,
    templates: Vec<KillChainTemplate>,
}

impl Layer4Engine {
    pub fn new(window_secs: i64) -> Self {
        Self {
            graph: ProcessGraph::new(window_secs),
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
        let node_ids: Vec<u32> = self.graph.nodes.keys().copied().collect();
        for template in &self.templates {
            for pid in &node_ids {
                if self.match_from(*pid, template, 0, 0, 0) {
                    hits.push(template.name.clone());
                    break;
                }
            }
        }

        hits
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
}

impl Default for Layer4Engine {
    fn default() -> Self {
        Self::with_default_templates()
    }
}
