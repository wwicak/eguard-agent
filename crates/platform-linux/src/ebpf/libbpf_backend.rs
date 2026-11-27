// Module-level cfg is already applied in ebpf.rs; no need to duplicate here.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use libbpf_rs::{ErrorKind, MapCore, MapFlags, MapType, PerfBuffer};
use tracing::{debug, info, warn};

use super::backend::RingBufferBackend;
use super::codec::parse_fallback_dropped_events;
use super::types::{
    EbpfError, PollBatch, ProbeHealth, Result, SensorLoss, FALLBACK_RINGBUF_STATE_SIZE,
};

pub(super) struct LibbpfRingBufferBackend {
    // Drop order matters: ring_buffer must drop FIRST (releases map fd
    // references) before _loaded drops (detaches BPF programs from kernel
    // hooks and frees BPF objects). Rust drops fields in declaration order.
    ring_buffer: libbpf_rs::RingBuffer<'static>,
    records: RecordSink,
    record_pool: RecordPool,
    record_budget: RecordBudget,
    drop_counter_sources: Vec<DropCounterSource>,
    failed_probes: Vec<ProbeFailure>,
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
    record_budget: RecordBudget,
    drop_counter_sources: Vec<DropCounterSource>,
    failed_probes: Vec<ProbeFailure>,
    _loaded: Vec<LoadedObject>,
}

type RecordSink = Arc<PendingRecords>;
type RecordPool = Arc<Mutex<Vec<Vec<u8>>>>;

#[derive(Default)]
struct PendingRecords {
    records: Mutex<VecDeque<Vec<u8>>>,
    evictions: AtomicU64,
}

fn pending_evictions(records: &RecordSink) -> u64 {
    records.evictions.load(Ordering::Relaxed)
}

struct ProbeFailure {
    health: ProbeHealth,
    diagnostic: String,
}

impl ProbeFailure {
    fn new(name: String, diagnostic: String, status: &'static str, reason: &'static str) -> Self {
        Self {
            diagnostic: format!("{name}:{diagnostic}"),
            health: ProbeHealth {
                name,
                status,
                reason,
            },
        }
    }

    fn attach(name: String, diagnostic: String, kind: ErrorKind) -> Self {
        match kind {
            ErrorKind::NotFound => Self::new(name, diagnostic, "unsupported", "hook_missing"),
            ErrorKind::Unsupported => {
                Self::new(name, diagnostic, "unsupported", "hook_unsupported")
            }
            _ => Self::new(name, diagnostic, "failed", "attach_failed"),
        }
    }
}

const LOW_MEMORY_HOST_THRESHOLD_BYTES: u64 = 3 * 1024 * 1024 * 1024;
const DEFAULT_MAX_PENDING_RAW_RECORDS: usize = 8_192;
const LOW_MEMORY_MAX_PENDING_RAW_RECORDS: usize = 1_024;
const DEFAULT_MAX_RECORD_POOL_ENTRIES: usize = 4_096;
const LOW_MEMORY_MAX_RECORD_POOL_ENTRIES: usize = 512;

#[derive(Clone, Copy)]
struct RecordBudget {
    max_pending_raw_records: usize,
    max_record_pool_entries: usize,
}

impl RecordBudget {
    fn for_host() -> Self {
        let low_memory_host = linux_host_mem_total_bytes()
            .map(|value| value > 0 && value <= LOW_MEMORY_HOST_THRESHOLD_BYTES)
            .unwrap_or(false);

        let pending_default = if low_memory_host {
            LOW_MEMORY_MAX_PENDING_RAW_RECORDS
        } else {
            DEFAULT_MAX_PENDING_RAW_RECORDS
        };
        let pool_default = if low_memory_host {
            LOW_MEMORY_MAX_RECORD_POOL_ENTRIES
        } else {
            DEFAULT_MAX_RECORD_POOL_ENTRIES
        };

        Self {
            max_pending_raw_records: parse_budget_env(
                "EGUARD_EBPF_PENDING_RAW_RECORDS_CAP",
                pending_default,
                128,
            ),
            max_record_pool_entries: parse_budget_env(
                "EGUARD_EBPF_RECORD_POOL_CAP",
                pool_default,
                64,
            ),
        }
    }
}

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
    cumulative: u64,
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
        let record_budget = RecordBudget::for_host();
        let (mut loaded, failed_probes) = load_objects_with_degradation(elf_paths, event_map_name)?;
        let drop_counter_sources = collect_drop_counter_sources(&loaded)?;
        let (ring_buffer, records, record_pool) =
            build_ring_buffer(&mut loaded, event_map_name, record_budget)?;

        Ok(Self {
            ring_buffer,
            records,
            record_pool,
            record_budget,
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
        let record_budget = RecordBudget::for_host();
        let (mut loaded, failed_probes) = load_objects_with_degradation(elf_paths, event_map_name)?;
        let drop_counter_sources = collect_drop_counter_sources(&loaded)?;
        let (perf_buffers, records, record_pool, perf_lost_records) =
            build_perf_buffers(&mut loaded, event_map_name, record_budget)?;

        Ok(Self {
            perf_buffers,
            next_poll_buffer: 0,
            perf_lost_records,
            perf_lost_last_seen: 0,
            records,
            record_pool,
            record_budget,
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
) -> Result<(Vec<LoadedObject>, Vec<ProbeFailure>)> {
    if elf_paths.is_empty() {
        return Err(EbpfError::Backend("no eBPF ELF files provided".to_string()));
    }

    let mut failed_probes = Vec::new();
    let mut loaded = Vec::with_capacity(elf_paths.len());
    for path in elf_paths {
        match load_object_with_degradation(path, event_map_name, &mut failed_probes) {
            Ok(Some(object)) => loaded.push(object),
            Ok(None) => {} // Individual optional attach outcomes are already recorded.
            Err(err) if is_optional_ebpf_object_path(path) => {
                let optional = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("optional-ebpf-object");
                failed_probes.push(ProbeFailure::new(
                    optional.to_string(),
                    err.to_string(),
                    "failed",
                    "object_load_failed",
                ));
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
        let diagnostics: Vec<_> = failed_probes
            .iter()
            .map(|probe| &probe.diagnostic)
            .collect();
        warn!(probes = ?diagnostics, "some eBPF probes failed to attach (degraded mode)");
    }

    Ok((loaded, failed_probes))
}

/// Load eBPF object with graceful degradation.
///
/// Attempts to attach each program individually. Programs that fail to attach
/// (e.g., LSM hooks on kernels without BPF LSM enabled) are recorded in
/// `failed_probes` but don't prevent the engine from working with the
/// remaining probes.
/// Perf-buffer page count for hosts with ≤ 3 GB RAM.
/// libbpf-rs defaults to 64 pages per CPU; we reduce to 32 pages on
/// constrained hosts to keep userspace mmap + kernel perf pages modest.
/// Ring-buffer map downsizing was tested and rejected because it materially
/// degraded Fedora battery coverage under load.
const LOW_MEMORY_PERF_BUFFER_PAGES: usize = 32;

/// Threshold below which a host is considered memory-constrained for event
/// transport sizing (matches `LOW_MEMORY_HOST_THRESHOLD_BYTES` used for
/// record budget).
const EVENT_TRANSPORT_LOW_MEM_THRESHOLD: u64 = LOW_MEMORY_HOST_THRESHOLD_BYTES;

fn load_object_with_degradation(
    path: &Path,
    event_map_name: &str,
    failed_probes: &mut Vec<ProbeFailure>,
) -> Result<Option<LoadedObject>> {
    let open_obj = libbpf_rs::ObjectBuilder::default()
        .open_file(path)
        .map_err(|err| EbpfError::Backend(format!("open ELF '{}': {}", path.display(), err)))?;

    let object = open_obj
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
                // LSM, module-load, and newer syscall hooks may fail on older
                // kernels — record the failure but continue with remaining
                // probes. openat2 was added in kernel 5.6; treat it as
                // optional so that kernels 5.4.x still get openat coverage.
                let is_optional = name.contains("lsm")
                    || name.contains("block")
                    || name.contains("module_load")
                    || name.contains("openat2");

                if is_optional {
                    eprintln!(
                        "eg-agent: optional eBPF probe '{}' from '{}' failed to attach (non-fatal): {}",
                        name,
                        path.display(),
                        err
                    );
                    failed_probes.push(ProbeFailure::attach(name, err.to_string(), err.kind()));
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
        // A wholly optional object with no hooks attached is still skipped.
        // Don't turn an unsupported hook into an object-level load failure.
        if is_optional_ebpf_object_path(path) {
            return Ok(None);
        }
        return Err(EbpfError::Backend(format!(
            "no programs attached from '{}' ({} total, all failed)",
            path.display(),
            total_programs
        )));
    }

    Ok(Some(LoadedObject {
        path: path.to_path_buf(),
        object,
        _links: links,
        attached_programs,
    }))
}

impl RingBufferBackend for LibbpfRingBufferBackend {
    fn sensor_transport(&self) -> &'static str {
        "ring_buffer"
    }

    fn sensor_loss(&self) -> SensorLoss {
        SensorLoss {
            kernel_drops: cumulative_kernel_drops(&self.drop_counter_sources),
            perf_lost_samples: 0,
            pending_queue_evictions: pending_evictions(&self.records),
        }
    }

    fn poll_raw_events(&mut self, timeout: Duration) -> Result<PollBatch> {
        if timeout.is_zero() {
            self.ring_buffer
                .consume()
                .map_err(|err| EbpfError::Backend(format!("consume ring buffer: {}", err)))?;
        } else {
            self.ring_buffer
                .poll(timeout)
                .map_err(|err| EbpfError::Backend(format!("poll ring buffer: {}", err)))?;
        }

        let records = drain_record_sink(&self.records)?;
        let dropped = sample_drop_counters(&mut self.drop_counter_sources)?;

        Ok(PollBatch { records, dropped })
    }

    fn reclaim_raw_records(&mut self, records: Vec<Vec<u8>>) {
        reclaim_raw_records_to_pool(
            &self.record_pool,
            records,
            self.record_budget.max_record_pool_entries,
        );
    }

    fn failed_probes(&self) -> Vec<String> {
        self.failed_probes
            .iter()
            .map(|probe| probe.diagnostic.clone())
            .collect()
    }

    fn unattached_probes(&self) -> Vec<ProbeHealth> {
        self.failed_probes
            .iter()
            .map(|probe| probe.health.clone())
            .collect()
    }

    fn attached_program_count(&self) -> usize {
        self.attached_program_count()
    }

    fn attached_program_names(&self) -> Vec<String> {
        self.attached_program_names()
    }
}

impl RingBufferBackend for LibbpfPerfBufferBackend {
    fn sensor_transport(&self) -> &'static str {
        "perf_buffer"
    }

    fn sensor_loss(&self) -> SensorLoss {
        SensorLoss {
            kernel_drops: cumulative_kernel_drops(&self.drop_counter_sources),
            perf_lost_samples: self.perf_lost_records.load(Ordering::Relaxed),
            pending_queue_evictions: pending_evictions(&self.records),
        }
    }

    fn poll_raw_events(&mut self, timeout: Duration) -> Result<PollBatch> {
        if timeout.is_zero() {
            consume_perf_buffers(&self.perf_buffers)?;
        } else {
            poll_perf_buffers(&self.perf_buffers, timeout, &mut self.next_poll_buffer)?;
        }

        let records = drain_record_sink(&self.records)?;
        let dropped = sample_drop_counters(&mut self.drop_counter_sources)?.saturating_add(
            sample_perf_lost_records(&self.perf_lost_records, &mut self.perf_lost_last_seen),
        );

        Ok(PollBatch { records, dropped })
    }

    fn reclaim_raw_records(&mut self, records: Vec<Vec<u8>>) {
        reclaim_raw_records_to_pool(
            &self.record_pool,
            records,
            self.record_budget.max_record_pool_entries,
        );
    }

    fn failed_probes(&self) -> Vec<String> {
        self.failed_probes
            .iter()
            .map(|probe| probe.diagnostic.clone())
            .collect()
    }

    fn unattached_probes(&self) -> Vec<ProbeHealth> {
        self.failed_probes
            .iter()
            .map(|probe| probe.health.clone())
            .collect()
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
            if map.value_size() < FALLBACK_RINGBUF_STATE_SIZE as u32 {
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
                cumulative: 0,
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
    record_budget: RecordBudget,
) -> Result<(libbpf_rs::RingBuffer<'static>, RecordSink, RecordPool)> {
    let records = RecordSink::default();
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
                push_raw_record(
                    raw,
                    &records_sink,
                    &pool_sink,
                    record_budget.max_pending_raw_records,
                );
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
    record_budget: RecordBudget,
) -> Result<(Vec<PerfBufferSlot>, RecordSink, RecordPool, Arc<AtomicU64>)> {
    let records = RecordSink::default();
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
            .pages(perf_buffer_pages_for_host(linux_host_mem_total_bytes()))
            .sample_cb(move |_cpu, raw| {
                push_raw_record(
                    raw,
                    &records_sink,
                    &pool_sink,
                    record_budget.max_pending_raw_records,
                );
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

fn push_raw_record(
    raw: &[u8],
    records_sink: &RecordSink,
    pool_sink: &RecordPool,
    max_pending_raw_records: usize,
) {
    let mut record = if let Ok(mut pool) = pool_sink.lock() {
        pool.pop().unwrap_or_default()
    } else {
        Vec::new()
    };
    record.clear();
    record.extend_from_slice(raw);

    let mut dropped_record = None;
    let lost = if let Ok(mut guard) = records_sink.records.lock() {
        if guard.len() >= max_pending_raw_records {
            dropped_record = guard.pop_front();
        }
        guard.push_back(record);
        dropped_record.is_some()
    } else {
        // The callback could not enqueue this record in the poisoned sink.
        true
    };
    if lost {
        // A u64 incremented once per lost record cannot realistically wrap.
        records_sink.evictions.fetch_add(1, Ordering::Relaxed);
    }

    if let Some(mut dropped) = dropped_record {
        dropped.clear();
        if let Ok(mut pool) = pool_sink.lock() {
            if pool.len() < max_pending_raw_records {
                pool.push(dropped);
            }
        }
    }
}

fn consume_perf_buffers(perf_buffers: &[PerfBufferSlot]) -> Result<()> {
    for slot in perf_buffers {
        slot.buffer.consume().map_err(|err| {
            EbpfError::Backend(format!(
                "consume perf buffer from '{}': {}",
                slot.owner_path.display(),
                err
            ))
        })?;
    }

    Ok(())
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

fn reclaim_raw_records_to_pool(
    record_pool: &RecordPool,
    mut records: Vec<Vec<u8>>,
    max_record_pool_entries: usize,
) {
    let Ok(mut pool) = record_pool.lock() else {
        return;
    };

    let available = max_record_pool_entries.saturating_sub(pool.len());
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
        .records
        .lock()
        .map_err(|_| EbpfError::Backend("failed to collect eBPF event records".to_string()))?;
    let drained = std::mem::take(&mut *guard);
    drop(guard);
    Ok(drained.into())
}

fn cumulative_kernel_drops(sources: &[DropCounterSource]) -> u64 {
    sources
        .iter()
        .fold(0, |total, source| total.saturating_add(source.cumulative))
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
        source.cumulative = source.cumulative.saturating_add(delta);
        dropped = dropped.saturating_add(delta);
    }

    Ok(dropped)
}

fn parse_budget_env(name: &str, default: usize, min_value: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .map(|value| value.max(min_value))
        .unwrap_or(default.max(min_value))
}

fn is_low_memory_host(total_mem_bytes: Option<u64>) -> bool {
    total_mem_bytes
        .map(|total| total > 0 && total <= EVENT_TRANSPORT_LOW_MEM_THRESHOLD)
        .unwrap_or(false)
}

fn perf_buffer_pages_for_host(total_mem_bytes: Option<u64>) -> usize {
    if is_low_memory_host(total_mem_bytes) {
        LOW_MEMORY_PERF_BUFFER_PAGES
    } else {
        64
    }
}

#[cfg(target_os = "linux")]
fn linux_host_mem_total_bytes() -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    meminfo.lines().find_map(parse_memtotal_line_bytes)
}

#[cfg(not(target_os = "linux"))]
fn linux_host_mem_total_bytes() -> Option<u64> {
    None
}

fn parse_memtotal_line_bytes(line: &str) -> Option<u64> {
    let trimmed = line.trim();
    let value = trimmed.strip_prefix("MemTotal:")?;
    let kib = value
        .split_whitespace()
        .next()
        .and_then(|raw| raw.parse::<u64>().ok())?;
    Some(kib.saturating_mul(1024))
}

fn sample_perf_lost_records(counter: &Arc<AtomicU64>, last_seen: &mut u64) -> u64 {
    let total = counter.load(Ordering::Relaxed);
    let delta = total.saturating_sub(*last_seen);
    *last_seen = total;
    delta
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_records_evict_oldest_and_preserve_arrival_order() {
        let records = RecordSink::default();
        let pool = RecordPool::default();

        for sample in 1..=5 {
            push_raw_record(&[sample], &records, &pool, 3);
        }
        assert_eq!(
            drain_record_sink(&records).unwrap(),
            vec![vec![3], vec![4], vec![5]],
            "overflow must retain the newest records in callback order"
        );

        for sample in 6..=7 {
            push_raw_record(&[sample], &records, &pool, 3);
        }
        assert_eq!(drain_record_sink(&records).unwrap(), vec![vec![6], vec![7]]);
    }

    #[test]
    fn pending_queue_health_counts_only_evictions() {
        let records = RecordSink::default();
        let pool = RecordPool::default();
        for sample in 1..=3 {
            push_raw_record(&[sample], &records, &pool, 3);
        }
        assert_eq!(pending_evictions(&records), 0);
        push_raw_record(&[4], &records, &pool, 3);
        assert_eq!(pending_evictions(&records), 1);
        push_raw_record(&[5], &records, &pool, 3);
        assert_eq!(pending_evictions(&records), 2);
        drain_record_sink(&records).unwrap();
        push_raw_record(&[6], &records, &pool, 3);
        assert_eq!(pending_evictions(&records), 2);
    }

    #[test]
    fn pending_queue_health_counts_rejection_on_poisoned_sink() {
        let records = RecordSink::default();
        let pool = RecordPool::default();
        let _ = std::panic::catch_unwind(|| {
            let _guard = records.records.lock().unwrap();
            panic!("poison fixture");
        });
        push_raw_record(&[1], &records, &pool, 3);
        assert_eq!(pending_evictions(&records), 1);
    }

    #[test]
    fn optional_attach_health_distinguishes_unsupported_and_failed() {
        for (kind, status, reason) in [
            (ErrorKind::Unsupported, "unsupported", "hook_unsupported"),
            (
                libbpf_rs::Error::from_raw_os_error(libc::ENOENT).kind(),
                "unsupported",
                "hook_missing",
            ),
            (ErrorKind::PermissionDenied, "failed", "attach_failed"),
        ] {
            let result =
                ProbeFailure::attach("fixture".to_string(), "local diagnostic".to_string(), kind);
            assert_eq!(result.health.name, "fixture");
            assert_eq!(result.health.status, status);
            assert_eq!(result.health.reason, reason);
            assert_eq!(result.diagnostic, "fixture:local diagnostic");
        }
    }

    #[test]
    fn parse_memtotal_line_reads_kib_value() {
        assert_eq!(
            parse_memtotal_line_bytes("MemTotal:       2006016 kB"),
            Some(2006016 * 1024)
        );
    }

    #[test]
    fn low_memory_transport_tuning_applies_under_threshold() {
        let low_mem = Some(2 * 1024 * 1024 * 1024);
        assert_eq!(
            perf_buffer_pages_for_host(low_mem),
            LOW_MEMORY_PERF_BUFFER_PAGES
        );
    }

    #[test]
    fn default_transport_tuning_remains_for_large_hosts() {
        let large_mem = Some(8 * 1024 * 1024 * 1024);
        assert_eq!(perf_buffer_pages_for_host(large_mem), 64);
    }
}
