#[cfg(test)]
use std::path::{Path, PathBuf};

use platform_linux::EbpfEngine;

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
