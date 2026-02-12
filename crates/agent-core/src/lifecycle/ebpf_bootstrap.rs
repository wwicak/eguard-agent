use std::path::{Path, PathBuf};

use platform_linux::EbpfEngine;
use tracing::{info, warn};

pub(super) fn init_ebpf_engine() -> EbpfEngine {
    let objects_dir = std::env::var("EGUARD_EBPF_OBJECTS_DIR")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from);
    let elf_path = std::env::var("EGUARD_EBPF_ELF")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from);
    let map_name = std::env::var("EGUARD_EBPF_RING_MAP")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "events".to_string());

    if let Some(dir) = objects_dir {
        if let Some(engine) = try_init_ebpf_from_object_dir(&dir, &map_name) {
            return engine;
        }
    }

    for dir in default_ebpf_objects_dirs() {
        if let Some(engine) = try_init_ebpf_from_object_dir(&dir, &map_name) {
            return engine;
        }
    }

    let Some(elf_path) = elf_path else {
        return EbpfEngine::disabled();
    };

    match EbpfEngine::from_elf(&elf_path, &map_name) {
        Ok(engine) => {
            info!(path = %elf_path.display(), map = %map_name, "eBPF engine initialized");
            engine
        }
        Err(err) => {
            warn!(error = %err, path = %elf_path.display(), map = %map_name, "failed to initialize eBPF engine; using disabled backend");
            EbpfEngine::disabled()
        }
    }
}

pub(super) fn try_init_ebpf_from_object_dir(
    objects_dir: &Path,
    map_name: &str,
) -> Option<EbpfEngine> {
    let object_paths = candidate_ebpf_object_paths(objects_dir);
    if object_paths.is_empty() {
        return None;
    }

    match EbpfEngine::from_elfs(&object_paths, map_name) {
        Ok(engine) => {
            info!(
                objects_dir = %objects_dir.display(),
                object_count = object_paths.len(),
                map = %map_name,
                "eBPF engine initialized from object directory"
            );
            Some(engine)
        }
        Err(err) => {
            warn!(
                error = %err,
                objects_dir = %objects_dir.display(),
                map = %map_name,
                "failed to initialize eBPF engine from object directory"
            );
            None
        }
    }
}

pub(super) fn default_ebpf_objects_dirs() -> Vec<PathBuf> {
    vec![
        PathBuf::from("./zig-out/ebpf"),
        PathBuf::from("zig-out/ebpf"),
        PathBuf::from("/usr/lib/eguard-agent/ebpf"),
    ]
}

pub(super) fn candidate_ebpf_object_paths(objects_dir: &Path) -> Vec<PathBuf> {
    const OBJECT_NAMES: [&str; 6] = [
        "process_exec_bpf.o",
        "file_open_bpf.o",
        "tcp_connect_bpf.o",
        "dns_query_bpf.o",
        "module_load_bpf.o",
        "lsm_block_bpf.o",
    ];

    let mut out = Vec::new();
    for name in OBJECT_NAMES {
        let candidate = objects_dir.join(name);
        if candidate.exists() {
            out.push(candidate);
        }
    }
    out
}
