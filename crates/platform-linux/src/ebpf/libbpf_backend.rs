#![cfg(feature = "ebpf-libbpf")]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use libbpf_rs::{MapCore, MapFlags};
use tracing::{debug, info, warn};

use super::backend::RingBufferBackend;
use super::codec::parse_fallback_dropped_events;
use super::types::{EbpfError, PollBatch, Result};

pub(super) struct LibbpfRingBufferBackend {
    // Drop order matters: ring_buffer must drop FIRST (releases map fd
    // references) before _loaded drops (detaches BPF programs from kernel
    // hooks and frees BPF objects).  Rust drops fields in declaration order.
    ring_buffer: libbpf_rs::RingBuffer<'static>,
    records: RecordSink,
    record_pool: RecordPool,
    drop_counter_sources: Vec<DropCounterSource>,
    failed_probes: Vec<String>,
    _loaded: Vec<LoadedObject>,
}

type RecordSink = Arc<Mutex<Vec<Vec<u8>>>>;
type RecordPool = Arc<Mutex<Vec<Vec<u8>>>>;

struct LoadedObject {
    path: PathBuf,
    object: libbpf_rs::Object,
    _links: Vec<libbpf_rs::Link>,
    attached_programs: Vec<String>,
}

struct DropCounterSource {
    owner_path: PathBuf,
    map_handle: libbpf_rs::MapHandle,
    last_seen: u64,
}

impl LibbpfRingBufferBackend {
    pub(super) fn new(elf_path: PathBuf, ring_buffer_map: &str) -> Result<Self> {
        Self::new_many(&[elf_path], ring_buffer_map)
    }

    pub(super) fn new_many(elf_paths: &[PathBuf], ring_buffer_map: &str) -> Result<Self> {
        if elf_paths.is_empty() {
            return Err(EbpfError::Backend("no eBPF ELF files provided".to_string()));
        }

        let mut failed_probes = Vec::new();
        let mut loaded = Vec::with_capacity(elf_paths.len());
        for path in elf_paths {
            loaded.push(load_object_with_degradation(
                path,
                ring_buffer_map,
                &mut failed_probes,
            )?);
        }

        let total_attached: usize = loaded.iter().map(|o| o.attached_programs.len()).sum();
        let attached_names: Vec<String> = loaded
            .iter()
            .flat_map(|o| o.attached_programs.iter().cloned())
            .collect();

        info!(
            objects = loaded.len(),
            attached = total_attached,
            failed = failed_probes.len(),
            programs = ?attached_names,
            "eBPF objects loaded"
        );

        if !failed_probes.is_empty() {
            warn!(probes = ?failed_probes, "some eBPF probes failed to attach (degraded mode)");
        }

        let drop_counter_sources = collect_drop_counter_sources(&loaded)?;

        let (ring_buffer, records, record_pool) = build_ring_buffer(&mut loaded, ring_buffer_map)?;

        Ok(Self {
            ring_buffer,
            records,
            record_pool,
            drop_counter_sources,
            failed_probes,
            _loaded: loaded,
        })
    }

    pub(super) fn attached_program_count(&self) -> usize {
        self._loaded.iter().map(|o| o.attached_programs.len()).sum()
    }

    pub(super) fn attached_program_names(&self) -> Vec<String> {
        self._loaded
            .iter()
            .flat_map(|o| o.attached_programs.iter().cloned())
            .collect()
    }
}

/// Load eBPF object with graceful degradation.
///
/// Attempts to attach each program individually. Programs that fail to attach
/// (e.g., LSM hooks on kernels without BPF LSM enabled) are recorded in
/// `failed_probes` but don't prevent the engine from working with the
/// remaining probes.
fn load_object_with_degradation(
    path: &Path,
    ring_buffer_map: &str,
    failed_probes: &mut Vec<String>,
) -> Result<LoadedObject> {
    let object = libbpf_rs::ObjectBuilder::default()
        .open_file(path)
        .map_err(|err| EbpfError::Backend(format!("open ELF '{}': {}", path.display(), err)))?
        .load()
        .map_err(|err| EbpfError::Backend(format!("load ELF '{}': {}", path.display(), err)))?;

    let map_exists = object.maps().any(|map| map.name() == ring_buffer_map);
    if !map_exists {
        return Err(EbpfError::Backend(format!(
            "ring buffer map '{}' missing in '{}'",
            ring_buffer_map,
            path.display()
        )));
    }

    let mut links = Vec::new();
    let mut attached_programs = Vec::new();
    let mut total_programs = 0usize;

    for program in object.progs_mut() {
        let name = program.name().to_string_lossy().into_owned();
        total_programs += 1;

        match program.attach() {
            Ok(link) => {
                debug!(
                    program = %name,
                    elf = %path.display(),
                    "eBPF program attached"
                );
                links.push(link);
                attached_programs.push(name);
            }
            Err(err) => {
                // LSM and some tracepoint hooks may fail on older kernels
                // or kernels without specific features enabled — record
                // the failure but continue with remaining probes.
                let is_optional =
                    name.contains("lsm") || name.contains("block") || name.contains("module_load");

                if is_optional {
                    failed_probes.push(format!("{}:{}", name, err));
                    eprintln!(
                        "eg-agent: optional eBPF probe '{}' from '{}' failed to attach (non-fatal): {}",
                        name,
                        path.display(),
                        err
                    );
                } else {
                    return Err(EbpfError::Backend(format!(
                        "attach program '{}' from '{}': {}",
                        name,
                        path.display(),
                        err
                    )));
                }
            }
        }
    }

    if attached_programs.is_empty() && total_programs > 0 {
        return Err(EbpfError::Backend(format!(
            "no programs attached from '{}' ({} total, all failed)",
            path.display(),
            total_programs
        )));
    }

    Ok(LoadedObject {
        path: path.to_path_buf(),
        object,
        _links: links,
        attached_programs,
    })
}

impl RingBufferBackend for LibbpfRingBufferBackend {
    fn poll_raw_events(&mut self, timeout: Duration) -> Result<PollBatch> {
        self.ring_buffer
            .poll(timeout)
            .map_err(|err| EbpfError::Backend(format!("poll ring buffer: {}", err)))?;

        let records = drain_record_sink(&self.records)?;
        let dropped = sample_drop_counters(&mut self.drop_counter_sources)?;

        Ok(PollBatch { records, dropped })
    }

    fn reclaim_raw_records(&mut self, mut records: Vec<Vec<u8>>) {
        const MAX_RECORD_POOL_ENTRIES: usize = 4_096;
        let Ok(mut pool) = self.record_pool.lock() else {
            return;
        };

        let available = MAX_RECORD_POOL_ENTRIES.saturating_sub(pool.len());
        if available == 0 {
            return;
        }

        if records.len() > available {
            records.truncate(available);
        }

        for mut record in records {
            record.clear();
            pool.push(record);
        }
    }

    fn failed_probes(&self) -> Vec<String> {
        self.failed_probes.clone()
    }

    fn attached_program_count(&self) -> usize {
        self.attached_program_count()
    }

    fn attached_program_names(&self) -> Vec<String> {
        self.attached_program_names()
    }
}

fn collect_drop_counter_sources(loaded: &[LoadedObject]) -> Result<Vec<DropCounterSource>> {
    let mut sources = Vec::new();

    for loaded_object in loaded {
        for map in loaded_object.object.maps() {
            let map_name = map.name().to_string_lossy();
            if !is_bss_map_name(&map_name) {
                continue;
            }

            let map_handle = libbpf_rs::MapHandle::try_from(&map).map_err(|err| {
                EbpfError::Backend(format!(
                    "clone drop-counter map '{}' from '{}': {}",
                    map_name,
                    loaded_object.path.display(),
                    err
                ))
            })?;

            sources.push(DropCounterSource {
                owner_path: loaded_object.path.clone(),
                map_handle,
                last_seen: 0,
            });
        }
    }

    Ok(sources)
}

fn is_bss_map_name(raw: &str) -> bool {
    raw == ".bss" || raw.ends_with(".bss")
}

fn build_ring_buffer(
    loaded: &mut [LoadedObject],
    ring_buffer_map: &str,
) -> Result<(libbpf_rs::RingBuffer<'static>, RecordSink, RecordPool)> {
    struct RingBufferMapSource {
        owner_path: PathBuf,
        attached_programs: usize,
        map_handle: libbpf_rs::MapHandle,
    }

    let records = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let record_pool = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let mut map_sources = Vec::<RingBufferMapSource>::new();

    for loaded_object in loaded {
        for map in loaded_object.object.maps_mut() {
            if map.name() != ring_buffer_map {
                continue;
            }

            let map_handle = libbpf_rs::MapHandle::try_from(&map).map_err(|err| {
                EbpfError::Backend(format!(
                    "clone ring buffer map '{}' from '{}': {}",
                    ring_buffer_map,
                    loaded_object.path.display(),
                    err
                ))
            })?;

            map_sources.push(RingBufferMapSource {
                owner_path: loaded_object.path.clone(),
                attached_programs: loaded_object.attached_programs.len(),
                map_handle,
            });
        }
    }

    if map_sources.is_empty() {
        return Err(EbpfError::Backend(format!(
            "ring buffer map '{}' not found in loaded objects",
            ring_buffer_map
        )));
    }

    let mut builder = libbpf_rs::RingBufferBuilder::new();

    for source in &map_sources {
        let records_sink = Arc::clone(&records);
        let pool_sink = Arc::clone(&record_pool);
        builder
            .add(&source.map_handle, move |raw| {
                let mut record = if let Ok(mut pool) = pool_sink.lock() {
                    pool.pop().unwrap_or_default()
                } else {
                    Vec::new()
                };
                record.clear();
                record.extend_from_slice(raw);

                if let Ok(mut guard) = records_sink.lock() {
                    guard.push(record);
                }
                0
            })
            .map_err(|err| {
                EbpfError::Backend(format!(
                    "add ring buffer callback for '{}' ({} programs): {}",
                    source.owner_path.display(),
                    source.attached_programs,
                    err
                ))
            })?;
    }

    let ring_buffer = builder
        .build()
        .map_err(|err| EbpfError::Backend(format!("build ring buffer: {}", err)))?;

    Ok((ring_buffer, records, record_pool))
}

fn drain_record_sink(records: &RecordSink) -> Result<Vec<Vec<u8>>> {
    let mut guard = records
        .lock()
        .map_err(|_| EbpfError::Backend("failed to collect ring buffer records".to_string()))?;
    Ok(std::mem::take(&mut *guard))
}

fn sample_drop_counters(sources: &mut [DropCounterSource]) -> Result<u64> {
    let mut dropped = 0u64;

    for source in sources {
        let key = 0u32.to_ne_bytes();
        let value = source
            .map_handle
            .lookup(&key, MapFlags::ANY)
            .map_err(|err| {
                EbpfError::Backend(format!(
                    "read drop-counter map from '{}': {}",
                    source.owner_path.display(),
                    err
                ))
            })?;

        let Some(raw) = value else {
            continue;
        };

        let Some(total) = parse_fallback_dropped_events(&raw) else {
            continue;
        };

        let delta = total.saturating_sub(source.last_seen);
        source.last_seen = total;
        dropped = dropped.saturating_add(delta);
    }

    Ok(dropped)
}
