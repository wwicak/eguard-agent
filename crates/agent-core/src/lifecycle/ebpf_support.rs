#[cfg(test)]
use std::path::{Path, PathBuf};

use crate::platform::EbpfEngine;
#[cfg(test)]
use crate::platform::EbpfStats;

use super::ebpf_bootstrap;

pub(super) fn init_ebpf_engine() -> EbpfEngine {
    ebpf_bootstrap::init_ebpf_engine()
}

#[cfg(test)]
pub(super) fn default_ebpf_objects_dirs() -> Vec<PathBuf> {
    ebpf_bootstrap::default_ebpf_objects_dirs()
}

#[cfg(test)]
pub(super) fn candidate_ebpf_object_paths(objects_dir: &Path) -> Vec<PathBuf> {
    ebpf_bootstrap::candidate_ebpf_object_paths(objects_dir)
}

#[cfg(test)]
pub(super) fn preferred_ebpf_objects_dirs(capabilities: &EbpfStats) -> Vec<PathBuf> {
    ebpf_bootstrap::preferred_ebpf_objects_dirs(capabilities)
}

#[cfg(test)]
pub(super) fn candidate_ebpf_object_paths_for_capabilities(
    objects_dir: &Path,
    capabilities: &EbpfStats,
) -> Vec<PathBuf> {
    ebpf_bootstrap::candidate_ebpf_object_paths_for_capabilities(objects_dir, capabilities)
}
