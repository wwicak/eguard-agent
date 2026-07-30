#[cfg(any(test, target_os = "linux"))]
use std::path::{Path, PathBuf};

use crate::platform::{EbpfEngine, EbpfStats};
use tracing::{info, warn};

pub(super) fn init_ebpf_engine() -> EbpfEngine {
    #[cfg(target_os = "windows")]
    {
        match EbpfEngine::from_etw() {
            Ok(engine) => {
                info!("ETW collector initialized for Windows runtime");
                return engine;
            }
            Err(err) => {
                warn!(error = %err, "failed to initialize ETW collector; using disabled backend");
                return EbpfEngine::disabled();
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        match EbpfEngine::from_esf() {
            Ok(engine) => {
                info!("ESF collector initialized for macOS runtime");
                return engine;
            }
            Err(err) => {
                warn!(error = %err, "failed to initialize ESF collector; using disabled backend");
                return EbpfEngine::disabled();
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Priority 1: Replay backend (for testing without kernel hooks)
        if let Some(replay_path) = std::env::var("EGUARD_EBPF_REPLAY_PATH")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .map(PathBuf::from)
        {
            match EbpfEngine::from_replay(&replay_path) {
                Ok(engine) => {
                    info!(path = %replay_path.display(), "eBPF replay backend initialized");
                    return engine;
                }
                Err(err) => {
                    warn!(error = %err, path = %replay_path.display(), "failed to open replay backend; falling through to eBPF/disabled");
                }
            }
        }

        // Priority 2: Real eBPF from object directory
        let capability_snapshot = EbpfEngine::disabled().stats();
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
            if let Some(engine) =
                try_init_ebpf_from_object_dir(&dir, &map_name, &capability_snapshot)
            {
                return engine;
            }
        }

        for dir in preferred_ebpf_objects_dirs(&capability_snapshot) {
            if let Some(engine) =
                try_init_ebpf_from_object_dir(&dir, &map_name, &capability_snapshot)
            {
                return engine;
            }
        }

        let Some(elf_path) = elf_path else {
            return EbpfEngine::disabled();
        };

        match EbpfEngine::from_elf(&elf_path, &map_name) {
            Ok(engine) => {
                let stats = engine.stats();
                info!(
                    path = %elf_path.display(),
                    map = %map_name,
                    attached_programs = stats.attached_program_count,
                    programs = ?stats.attached_program_names,
                    "eBPF engine initialized"
                );
                engine
            }
            Err(err) => {
                warn!(error = %err, path = %elf_path.display(), map = %map_name, "failed to initialize eBPF engine; using disabled backend");
                EbpfEngine::disabled()
            }
        }
    }
}

#[cfg(any(test, target_os = "linux"))]
pub(super) fn try_init_ebpf_from_object_dir(
    objects_dir: &Path,
    map_name: &str,
    capabilities: &EbpfStats,
) -> Option<EbpfEngine> {
    let object_paths = candidate_ebpf_object_paths_for_capabilities(objects_dir, capabilities);
    if object_paths.is_empty() {
        return None;
    }

    match EbpfEngine::from_elfs(&object_paths, map_name) {
        Ok(engine) => {
            let stats = engine.stats();
            info!(
                objects_dir = %objects_dir.display(),
                object_count = object_paths.len(),
                attached_programs = stats.attached_program_count,
                programs = ?stats.attached_program_names,
                failed_probes = ?stats.failed_probes,
                map = %map_name,
                "eBPF engine initialized from object directory"
            );
            if stats.attached_program_count == 0 {
                warn!("eBPF engine loaded objects but NO programs attached to kernel hooks");
            }
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

#[cfg(any(test, target_os = "linux"))]
pub(super) fn default_ebpf_objects_dirs() -> Vec<PathBuf> {
    vec![
        PathBuf::from("./zig-out/ebpf"),
        PathBuf::from("zig-out/ebpf"),
        PathBuf::from("/usr/lib/eguard-agent/ebpf"),
        PathBuf::from("./zig-out/ebpf-perf"),
        PathBuf::from("zig-out/ebpf-perf"),
        PathBuf::from("/usr/lib/eguard-agent/ebpf-perf"),
    ]
}

#[cfg(any(test, target_os = "linux"))]
fn kernel_prefers_perf_objects(capabilities: &EbpfStats) -> bool {
    let stripped = capabilities
        .kernel_version
        .split(['-', ' '])
        .next()
        .unwrap_or("");
    let mut parts = stripped.split('.');
    let major = parts
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    let minor = parts
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    (major, minor) != (0, 0) && (major, minor) < (5, 8)
}

#[cfg(any(test, target_os = "linux"))]
pub(super) fn preferred_ebpf_objects_dirs(capabilities: &EbpfStats) -> Vec<PathBuf> {
    let mut ring_dirs = Vec::new();
    let mut perf_dirs = Vec::new();

    for dir in default_ebpf_objects_dirs() {
        if dir.to_string_lossy().contains("ebpf-perf") {
            perf_dirs.push(dir)
        } else {
            ring_dirs.push(dir)
        }
    }

    if kernel_prefers_perf_objects(capabilities) {
        perf_dirs.extend(ring_dirs);
        return perf_dirs;
    }

    ring_dirs.extend(perf_dirs);
    ring_dirs
}

#[cfg(any(test, target_os = "linux"))]
pub(super) fn candidate_ebpf_object_paths(objects_dir: &Path) -> Vec<PathBuf> {
    const OBJECT_NAMES: [&str; 9] = [
        "process_exec_bpf.o",
        "file_open_bpf.o",
        "file_write_bpf.o",
        "file_rename_bpf.o",
        "file_unlink_bpf.o",
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

#[cfg(any(test, target_os = "linux"))]
pub(super) fn candidate_ebpf_object_paths_for_capabilities(
    objects_dir: &Path,
    capabilities: &EbpfStats,
) -> Vec<PathBuf> {
    let mut out = candidate_ebpf_object_paths(objects_dir);
    if !capabilities.lsm_available {
        out.retain(|path| !path.to_string_lossy().contains("lsm_block_bpf.o"));
    }
    out
}
