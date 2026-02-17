use std::collections::HashSet;

use super::graph::GraphNode;

#[derive(Debug, Clone)]
pub struct TemplatePredicate {
    pub process_any_of: Option<HashSet<String>>,
    pub uid_eq: Option<u32>,
    pub uid_ne: Option<u32>,
    pub require_network_non_web: bool,
    pub require_module_loaded: bool,
    pub require_sensitive_file_access: bool,
    pub require_ransomware_write_burst: bool,
    pub require_container_escape: bool,
    pub require_privileged_container: bool,
}

impl TemplatePredicate {
    pub(super) fn matches(&self, node: &GraphNode) -> bool {
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
        if self.require_container_escape && !node.container_escape {
            return false;
        }
        if self.require_privileged_container && !node.container_privileged {
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
