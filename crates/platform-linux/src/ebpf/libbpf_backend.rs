// Module-level cfg is already applied in ebpf.rs; no need to duplicate here.

use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use libbpf_rs::{MapCore, MapFlags, MapType, PerfBuffer};
use tracing::{debug, info, warn};

use super::backend::RingBufferBackend;
use super::codec::parse_fallback_dropped_events;
use super::types::{EbpfError, PollBatch, Result};

pub(super) struct LibbpfRingBufferBackend {
    // Drop order matters: ring_buffer must drop FIRST (releases map fd
    // references) before _loaded drops (detaches BPF programs from kernel
    // hooks and frees BPF objects). Rust drops fields in declaration order.
    ring_buffer: libbpf_rs::RingBuffer<'static>,
    records: RecordSink,
    record_pool: RecordPool,
    drop_counter_sources: Vec<DropCounterSource>,
    failed_probes: Vec<String>,
    _loaded: Vec<LoadedObject>,
}

pub(super) struct LibbpfPerfBufferBackend {
    // Drop order matters: perf_buffers must drop FIRST (releases perf-event
    // array map fd references) before _loaded drops (detaches BPF programs
    // from kernel hooks and frees BPF objects).
    perf_buffers: Vec<PerfBufferSlot>,
    next_poll_buffer: usize,
    perf_lost_records: Arc<AtomicU64>,
    perf_lost_last_seen: u64,
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

struct EventMapSource {
    owner_path: PathBuf,
    attached_programs: usize,
    map_handle: libbpf_rs::MapHandle,
}

struct PerfBufferSlot {
    owner_path: PathBuf,
    buffer: PerfBuffer<'static>,
}

impl LibbpfRingBufferBackend {
    pub(super) fn new_many(elf_paths: &[PathBuf], event_map_name: &str) -> Result<Self> {
        let (mut loaded, failed_probes) = load_objects_with_degradation(elf_paths, event_map_name)?;
        let drop_counter_sources = collect_drop_counter_sources(&loaded)?;
        let (ring_buffer, records, record_pool) = build_ring_buffer(&mut loaded, event_map_name)?;

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

impl LibbpfPerfBufferBackend {
    pub(super) fn new_many(elf_paths: &[PathBuf], event_map_name: &str) -> Result<Self> {
        let (mut loaded, failed_probes) = load_objects_with_degradation(elf_paths, event_map_name)?;
        let drop_counter_sources = collect_drop_counter_sources(&loaded)?;
        let (perf_buffers, records, record_pool, perf_lost_records) =
            build_perf_buffers(&mut loaded, event_map_name)?;

        Ok(Self {
            perf_buffers,
            next_poll_buffer: 0,
            perf_lost_records,
            perf_lost_last_seen: 0,
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

fn load_objects_with_degradation(
    elf_paths: &[PathBuf],
    event_map_name: &str,
) -> Result<(Vec<LoadedObject>, Vec<String>)> {
    if elf_paths.is_empty() {
        return Err(EbpfError::Backend("no eBPF ELF files provided".to_string()));
    }

    let mut failed_probes = Vec::new();
    let mut loaded = Vec::with_capacity(elf_paths.len());
    for path in elf_paths {
        match load_object_with_degradation(path, event_map_name, &mut failed_probes) {
            Ok(object) => loaded.push(object),
            Err(err) if is_optional_ebpf_object_path(path) => {
                let optional = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("optional-ebpf-object");
                failed_probes.push(format!("{}:{}", optional, err));
                warn!(
                    error = %err,
                    path = %path.display(),
                    "optional eBPF object failed to load and will be skipped"
                );
            }
            Err(err) => return Err(err),
        }
    }

    if loaded.is_empty() {
        return Err(EbpfError::Backend(
            "no eBPF objects loaded successfully".to_string(),
        ));
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

    Ok((loaded, failed_probes))
}

/// Load eBPF object with graceful degradation.
///
/// Attempts to attach each program individually. Programs that fail to attach
/// (e.g., LSM hooks on kernels without BPF LSM enabled) are recorded in
/// `failed_probes` but don't prevent the engine from working with the
/// remaining probes.
fn load_object_with_degradation(
    path: &Path,
    event_map_name: &str,
    failed_probes: &mut Vec<String>,
) -> Result<LoadedObject> {
    let object = libbpf_rs::ObjectBuilder::default()
        .open_file(path)
        .map_err(|err| EbpfError::Backend(format!("open ELF '{}': {}", path.display(), err)))?
        .load()
        .map_err(|err| EbpfError::Backend(format!("load ELF '{}': {}", path.display(), err)))?;

    let map_exists = object.maps().any(|map| map.name() == event_map_name);
    if !map_exists {
        return Err(EbpfError::Backend(format!(
            "event map '{}' missing in '{}'",
            event_map_name,
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

    fn reclaim_raw_records(&mut self, records: Vec<Vec<u8>>) {
        reclaim_raw_records_to_pool(&self.record_pool, records);
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

impl RingBufferBackend for LibbpfPerfBufferBackend {
    fn poll_raw_events(&mut self, timeout: Duration) -> Result<PollBatch> {
        poll_perf_buffers(&self.perf_buffers, timeout, &mut self.next_poll_buffer)?;

        let records = drain_record_sink(&self.records)?;
        let dropped = sample_drop_counters(&mut self.drop_counter_sources)?.saturating_add(
            sample_perf_lost_records(&self.perf_lost_records, &mut self.perf_lost_last_seen),
        );

        Ok(PollBatch { records, dropped })
    }

    fn reclaim_raw_records(&mut self, records: Vec<Vec<u8>>) {
        reclaim_raw_records_to_pool(&self.record_pool, records);
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

pub(super) fn is_optional_ebpf_object_path(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };

    name.contains("lsm_block") || name.contains("module_load")
}

fn collect_event_map_sources(
    loaded: &mut [LoadedObject],
    event_map_name: &str,
) -> Result<Vec<EventMapSource>> {
    let mut map_sources = Vec::<EventMapSource>::new();

    for loaded_object in loaded {
        for map in loaded_object.object.maps_mut() {
            if map.name() != event_map_name {
                continue;
            }

            let map_handle = libbpf_rs::MapHandle::try_from(&map).map_err(|err| {
                EbpfError::Backend(format!(
                    "clone event map '{}' from '{}': {}",
                    event_map_name,
                    loaded_object.path.display(),
                    err
                ))
            })?;

            map_sources.push(EventMapSource {
                owner_path: loaded_object.path.clone(),
                attached_programs: loaded_object.attached_programs.len(),
                map_handle,
            });
        }
    }

    if map_sources.is_empty() {
        return Err(EbpfError::Backend(format!(
            "event map '{}' not found in loaded objects",
            event_map_name
        )));
    }

    Ok(map_sources)
}

fn build_ring_buffer(
    loaded: &mut [LoadedObject],
    event_map_name: &str,
) -> Result<(libbpf_rs::RingBuffer<'static>, RecordSink, RecordPool)> {
    let records = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let record_pool = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let map_sources = collect_event_map_sources(loaded, event_map_name)?;

    let mut builder = libbpf_rs::RingBufferBuilder::new();

    for source in &map_sources {
        if source.map_handle.map_type() != MapType::RingBuf {
            return Err(EbpfError::Backend(format!(
                "event map '{}' from '{}' is {:?}, not RingBuf",
                event_map_name,
                source.owner_path.display(),
                source.map_handle.map_type()
            )));
        }

        let records_sink = Arc::clone(&records);
        let pool_sink = Arc::clone(&record_pool);
        builder
            .add(&source.map_handle, move |raw| {
                push_raw_record(raw, &records_sink, &pool_sink);
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

fn build_perf_buffers(
    loaded: &mut [LoadedObject],
    event_map_name: &str,
) -> Result<(Vec<PerfBufferSlot>, RecordSink, RecordPool, Arc<AtomicU64>)> {
    let records = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let record_pool = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let perf_lost_records = Arc::new(AtomicU64::new(0));
    let map_sources = collect_event_map_sources(loaded, event_map_name)?;
    let mut perf_buffers = Vec::with_capacity(map_sources.len());

    for source in &map_sources {
        if source.map_handle.map_type() != MapType::PerfEventArray {
            return Err(EbpfError::Backend(format!(
                "event map '{}' from '{}' is {:?}, not PerfEventArray",
                event_map_name,
                source.owner_path.display(),
                source.map_handle.map_type()
            )));
        }

        let records_sink = Arc::clone(&records);
        let pool_sink = Arc::clone(&record_pool);
        let lost_sink = Arc::clone(&perf_lost_records);
        let perf_buffer = libbpf_rs::PerfBufferBuilder::new(&source.map_handle)
            .sample_cb(move |_cpu, raw| {
                push_raw_record(raw, &records_sink, &pool_sink);
            })
            .lost_cb(move |_cpu, count| {
                lost_sink.fetch_add(count, Ordering::Relaxed);
            })
            .build()
            .map_err(|err| {
                EbpfError::Backend(format!(
                    "build perf buffer for '{}' ({} programs): {}",
                    source.owner_path.display(),
                    source.attached_programs,
                    err
                ))
            })?;

        perf_buffers.push(PerfBufferSlot {
            owner_path: source.owner_path.clone(),
            buffer: perf_buffer,
        });
    }

    Ok((perf_buffers, records, record_pool, perf_lost_records))
}

fn push_raw_record(raw: &[u8], records_sink: &RecordSink, pool_sink: &RecordPool) {
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
}

fn poll_perf_buffers(
    perf_buffers: &[PerfBufferSlot],
    timeout: Duration,
    next_poll_buffer: &mut usize,
) -> Result<()> {
    if perf_buffers.is_empty() {
        return Ok(());
    }

    let start = *next_poll_buffer % perf_buffers.len();
    let total_ms = timeout.as_millis() as u64;
    let slot_count = perf_buffers.len() as u64;
    let base_ms = if slot_count == 0 {
        0
    } else {
        total_ms / slot_count
    };
    let extra_ms = if slot_count == 0 {
        0
    } else {
        total_ms % slot_count
    };

    for offset in 0..perf_buffers.len() {
        let idx = (start + offset) % perf_buffers.len();
        let timeout_ms = base_ms + if offset < extra_ms as usize { 1 } else { 0 };
        perf_buffers[idx]
            .buffer
            .poll(Duration::from_millis(timeout_ms))
            .map_err(|err| {
                EbpfError::Backend(format!(
                    "poll perf buffer from '{}': {}",
                    perf_buffers[idx].owner_path.display(),
                    err
                ))
            })?;
    }

    *next_poll_buffer = (start + 1) % perf_buffers.len();
    Ok(())
}

fn reclaim_raw_records_to_pool(record_pool: &RecordPool, mut records: Vec<Vec<u8>>) {
    const MAX_RECORD_POOL_ENTRIES: usize = 4_096;
    let Ok(mut pool) = record_pool.lock() else {
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

fn drain_record_sink(records: &RecordSink) -> Result<Vec<Vec<u8>>> {
    let mut guard = records
        .lock()
        .map_err(|_| EbpfError::Backend("failed to collect eBPF event records".to_string()))?;
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

fn sample_perf_lost_records(counter: &Arc<AtomicU64>, last_seen: &mut u64) -> u64 {
    let total = counter.load(Ordering::Relaxed);
    let delta = total.saturating_sub(*last_seen);
    *last_seen = total;
    delta
}
