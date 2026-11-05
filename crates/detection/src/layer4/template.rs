use std::collections::HashSet;

use super::graph::{GraphNode, KillChainWitness};

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
    pub require_ptrace_activity: bool,
    pub require_userfaultfd_activity: bool,
    pub require_execveat_activity: bool,
    pub require_proc_mem_access: bool,
    pub require_fileless_exec: bool,
}

impl TemplatePredicate {
    pub(super) fn witnesses(&self, node: &GraphNode) -> Option<Vec<KillChainWitness>> {
        if !self.matches(node) {
            return None;
        }
        let mut witnesses = vec![node.identity_witness.clone()];
        for (signal, required) in [
            ("network_non_web", self.require_network_non_web),
            ("module_loaded", self.require_module_loaded),
            ("sensitive_file_access", self.require_sensitive_file_access),
            (
                "ransomware_write_burst",
                self.require_ransomware_write_burst,
            ),
            ("container_escape", self.require_container_escape),
            ("container_privileged", self.require_privileged_container),
            ("ptrace_activity", self.require_ptrace_activity),
            ("userfaultfd_activity", self.require_userfaultfd_activity),
            ("execveat_activity", self.require_execveat_activity),
            ("proc_mem_access", self.require_proc_mem_access),
            ("fileless_exec", self.require_fileless_exec),
        ] {
            if required {
                witnesses.push(node.signal_witnesses.get(signal)?.clone());
            }
        }
        Some(witnesses)
    }

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
        if self.require_ptrace_activity && !node.ptrace_activity {
            return false;
        }
        if self.require_userfaultfd_activity && !node.userfaultfd_activity {
            return false;
        }
        if self.require_execveat_activity && !node.execveat_activity {
            return false;
        }
        if self.require_proc_mem_access && !node.proc_mem_access {
            return false;
        }
        if self.require_fileless_exec && !node.fileless_exec {
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
