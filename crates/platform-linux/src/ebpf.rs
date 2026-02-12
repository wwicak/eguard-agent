use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(feature = "ebpf-libbpf")]
use std::sync::{Arc, Mutex};

#[cfg(feature = "ebpf-libbpf")]
use libbpf_rs::{MapCore, MapFlags};

use crate::{EventType, RawEvent};

const EVENT_HEADER_SIZE: usize = 1 + 4 + 4 + 4 + 8;

#[cfg(any(test, feature = "ebpf-libbpf"))]
const FALLBACK_LAST_EVENT_DATA_SIZE: usize = 512;

#[cfg(any(test, feature = "ebpf-libbpf"))]
const fn align_up(value: usize, align: usize) -> usize {
    let rem = value % align;
    if rem == 0 {
        value
    } else {
        value + (align - rem)
    }
}

#[cfg(any(test, feature = "ebpf-libbpf"))]
const FALLBACK_DROPPED_OFFSET: usize = align_up(
    std::mem::size_of::<u32>() + FALLBACK_LAST_EVENT_DATA_SIZE,
    std::mem::size_of::<u64>(),
);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EbpfStats {
    pub events_received: u64,
    pub events_dropped: u64,
    pub parse_errors: u64,
}

#[derive(Debug)]
pub enum EbpfError {
    FeatureDisabled(&'static str),
    Backend(String),
    Parse(String),
}

impl fmt::Display for EbpfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FeatureDisabled(feature) => {
                write!(f, "feature '{}' is disabled in this build", feature)
            }
            Self::Backend(msg) => write!(f, "eBPF backend error: {}", msg),
            Self::Parse(msg) => write!(f, "eBPF parse error: {}", msg),
        }
    }
}

impl std::error::Error for EbpfError {}

pub type Result<T> = std::result::Result<T, EbpfError>;

#[derive(Debug, Default)]
pub struct PollBatch {
    pub records: Vec<Vec<u8>>,
    pub dropped: u64,
}

trait RingBufferBackend {
    fn poll_raw_events(&mut self, timeout: Duration) -> Result<PollBatch>;
}

pub struct EbpfEngine {
    backend: Box<dyn RingBufferBackend>,
    stats: EbpfStats,
}

impl EbpfEngine {
    pub fn disabled() -> Self {
        Self {
            backend: Box::<NoopRingBufferBackend>::default(),
            stats: EbpfStats::default(),
        }
    }

    #[cfg(feature = "ebpf-libbpf")]
    pub fn from_elf(elf_path: &Path, ring_buffer_map: &str) -> Result<Self> {
        let backend = LibbpfRingBufferBackend::new(elf_path.to_path_buf(), ring_buffer_map)?;
        Ok(Self {
            backend: Box::new(backend),
            stats: EbpfStats::default(),
        })
    }

    #[cfg(feature = "ebpf-libbpf")]
    pub fn from_elfs(elf_paths: &[PathBuf], ring_buffer_map: &str) -> Result<Self> {
        let backend = LibbpfRingBufferBackend::new_many(elf_paths, ring_buffer_map)?;
        Ok(Self {
            backend: Box::new(backend),
            stats: EbpfStats::default(),
        })
    }

    #[cfg(not(feature = "ebpf-libbpf"))]
    pub fn from_elf(_elf_path: &Path, _ring_buffer_map: &str) -> Result<Self> {
        Err(EbpfError::FeatureDisabled("ebpf-libbpf"))
    }

    #[cfg(not(feature = "ebpf-libbpf"))]
    pub fn from_elfs(_elf_paths: &[PathBuf], _ring_buffer_map: &str) -> Result<Self> {
        Err(EbpfError::FeatureDisabled("ebpf-libbpf"))
    }

    pub fn poll_once(&mut self, timeout: Duration) -> Result<Vec<RawEvent>> {
        let batch = self.backend.poll_raw_events(timeout)?;
        self.stats.events_dropped = self.stats.events_dropped.saturating_add(batch.dropped);

        let mut events = Vec::with_capacity(batch.records.len());
        for record in batch.records {
            self.stats.events_received = self.stats.events_received.saturating_add(1);
            match parse_raw_event(&record) {
                Ok(event) => events.push(event),
                Err(_) => {
                    self.stats.parse_errors = self.stats.parse_errors.saturating_add(1);
                }
            }
        }

        Ok(events)
    }

    pub fn poll_and_forward(
        &mut self,
        timeout: Duration,
        sender: &std::sync::mpsc::Sender<RawEvent>,
    ) -> Result<usize> {
        let events = self.poll_once(timeout)?;
        let mut forwarded = 0usize;
        for event in events {
            sender
                .send(event)
                .map_err(|_| EbpfError::Backend("event channel closed".to_string()))?;
            forwarded += 1;
        }
        Ok(forwarded)
    }

    pub fn stats(&self) -> EbpfStats {
        self.stats.clone()
    }
}

#[derive(Default)]
struct NoopRingBufferBackend;

impl RingBufferBackend for NoopRingBufferBackend {
    fn poll_raw_events(&mut self, _timeout: Duration) -> Result<PollBatch> {
        Ok(PollBatch::default())
    }
}

#[cfg(feature = "ebpf-libbpf")]
struct LibbpfRingBufferBackend {
    _loaded: Vec<LoadedObject>,
    drop_counter_sources: Vec<DropCounterSource>,
    ring_buffer: libbpf_rs::RingBuffer<'static>,
    records: RecordSink,
}

#[cfg(feature = "ebpf-libbpf")]
type RecordSink = Arc<Mutex<Vec<Vec<u8>>>>;

#[cfg(feature = "ebpf-libbpf")]
struct LoadedObject {
    path: PathBuf,
    object: libbpf_rs::Object,
    _links: Vec<libbpf_rs::Link>,
    attached_programs: Vec<String>,
}

#[cfg(feature = "ebpf-libbpf")]
struct DropCounterSource {
    owner_path: PathBuf,
    map_handle: libbpf_rs::MapHandle,
    last_seen: u64,
}

#[cfg(feature = "ebpf-libbpf")]
impl LibbpfRingBufferBackend {
    fn new(elf_path: PathBuf, ring_buffer_map: &str) -> Result<Self> {
        Self::new_many(&[elf_path], ring_buffer_map)
    }

    fn new_many(elf_paths: &[PathBuf], ring_buffer_map: &str) -> Result<Self> {
        if elf_paths.is_empty() {
            return Err(EbpfError::Backend("no eBPF ELF files provided".to_string()));
        }

        let mut loaded = Vec::with_capacity(elf_paths.len());
        for path in elf_paths {
            loaded.push(load_object(path, ring_buffer_map)?);
        }

        let drop_counter_sources = collect_drop_counter_sources(&loaded)?;

        let (ring_buffer, records) = build_ring_buffer(&mut loaded, ring_buffer_map)?;

        Ok(Self {
            _loaded: loaded,
            drop_counter_sources,
            ring_buffer,
            records,
        })
    }
}

#[cfg(feature = "ebpf-libbpf")]
fn load_object(path: &Path, ring_buffer_map: &str) -> Result<LoadedObject> {
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
    for program in object.progs_mut() {
        let name = program.name().to_string_lossy().into_owned();
        let link = program.attach().map_err(|err| {
            EbpfError::Backend(format!(
                "attach program '{}' from '{}': {}",
                name,
                path.display(),
                err
            ))
        })?;
        links.push(link);
        attached_programs.push(name);
    }

    if attached_programs.is_empty() {
        return Err(EbpfError::Backend(format!(
            "no programs found in '{}'",
            path.display()
        )));
    }

    Ok(LoadedObject {
        path: path.to_path_buf(),
        object,
        _links: links,
        attached_programs,
    })
}

#[cfg(feature = "ebpf-libbpf")]
impl RingBufferBackend for LibbpfRingBufferBackend {
    fn poll_raw_events(&mut self, timeout: Duration) -> Result<PollBatch> {
        self.ring_buffer
            .poll(timeout)
            .map_err(|err| EbpfError::Backend(format!("poll ring buffer: {}", err)))?;

        let records = drain_record_sink(&self.records)?;
        let dropped = sample_drop_counters(&mut self.drop_counter_sources)?;

        Ok(PollBatch { records, dropped })
    }
}

#[cfg(feature = "ebpf-libbpf")]
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

#[cfg(feature = "ebpf-libbpf")]
fn is_bss_map_name(raw: &str) -> bool {
    raw == ".bss" || raw.ends_with(".bss")
}

#[cfg(feature = "ebpf-libbpf")]
fn build_ring_buffer(
    loaded: &mut [LoadedObject],
    ring_buffer_map: &str,
) -> Result<(libbpf_rs::RingBuffer<'static>, RecordSink)> {
    struct RingBufferMapSource {
        owner_path: PathBuf,
        attached_programs: usize,
        map_handle: libbpf_rs::MapHandle,
    }

    let records = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
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
        builder
            .add(&source.map_handle, move |raw| {
                if let Ok(mut guard) = records_sink.lock() {
                    guard.push(raw.to_vec());
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

    Ok((ring_buffer, records))
}

#[cfg(feature = "ebpf-libbpf")]
fn drain_record_sink(records: &RecordSink) -> Result<Vec<Vec<u8>>> {
    let mut guard = records
        .lock()
        .map_err(|_| EbpfError::Backend("failed to collect ring buffer records".to_string()))?;
    Ok(std::mem::take(&mut *guard))
}

#[cfg(feature = "ebpf-libbpf")]
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

#[cfg(any(test, feature = "ebpf-libbpf"))]
fn parse_fallback_dropped_events(raw: &[u8]) -> Option<u64> {
    let end = FALLBACK_DROPPED_OFFSET.checked_add(std::mem::size_of::<u64>())?;
    let bytes = raw.get(FALLBACK_DROPPED_OFFSET..end)?;
    let mut out = [0u8; 8];
    out.copy_from_slice(bytes);
    Some(u64::from_le_bytes(out))
}

fn parse_raw_event(raw: &[u8]) -> Result<RawEvent> {
    if raw.len() < EVENT_HEADER_SIZE {
        return Err(EbpfError::Parse(format!(
            "event shorter than header: got {} bytes, need at least {}",
            raw.len(),
            EVENT_HEADER_SIZE
        )));
    }

    let event_type = parse_event_type(raw[0])?;
    let pid = read_u32_le(raw, 1)?;
    let uid = read_u32_le(raw, 9)?;
    let timestamp_ns = read_u64_le(raw, 13)?;
    let payload = parse_payload(event_type, &raw[EVENT_HEADER_SIZE..]);

    Ok(RawEvent {
        event_type,
        pid,
        uid,
        ts_ns: timestamp_ns,
        payload,
    })
}

fn parse_event_type(raw: u8) -> Result<EventType> {
    match raw {
        1 => Ok(EventType::ProcessExec),
        2 => Ok(EventType::FileOpen),
        3 => Ok(EventType::TcpConnect),
        4 => Ok(EventType::DnsQuery),
        5 => Ok(EventType::ModuleLoad),
        6 => Ok(EventType::LsmBlock),
        other => Err(EbpfError::Parse(format!("unknown event type id {}", other))),
    }
}

fn read_u16_le(raw: &[u8], offset: usize) -> Result<u16> {
    let end = offset.saturating_add(2);
    let bytes = raw
        .get(offset..end)
        .ok_or_else(|| EbpfError::Parse(format!("u16 out of bounds at offset {}", offset)))?;
    let mut out = [0u8; 2];
    out.copy_from_slice(bytes);
    Ok(u16::from_le_bytes(out))
}

fn read_u32_le(raw: &[u8], offset: usize) -> Result<u32> {
    let end = offset.saturating_add(4);
    let bytes = raw
        .get(offset..end)
        .ok_or_else(|| EbpfError::Parse(format!("u32 out of bounds at offset {}", offset)))?;
    let mut out = [0u8; 4];
    out.copy_from_slice(bytes);
    Ok(u32::from_le_bytes(out))
}

fn read_u64_le(raw: &[u8], offset: usize) -> Result<u64> {
    let end = offset.saturating_add(8);
    let bytes = raw
        .get(offset..end)
        .ok_or_else(|| EbpfError::Parse(format!("u64 out of bounds at offset {}", offset)))?;
    let mut out = [0u8; 8];
    out.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(out))
}

fn parse_payload(event_type: EventType, raw: &[u8]) -> String {
    match event_type {
        EventType::ProcessExec => parse_process_exec_payload(raw),
        EventType::FileOpen => parse_file_open_payload(raw),
        EventType::TcpConnect => parse_tcp_connect_payload(raw),
        EventType::DnsQuery => parse_dns_query_payload(raw),
        EventType::ModuleLoad => parse_module_load_payload(raw),
        EventType::LsmBlock => parse_lsm_block_payload(raw),
    }
}

fn parse_process_exec_payload(raw: &[u8]) -> String {
    if raw.len() < 4 + 8 + 32 {
        return parse_c_string(raw);
    }

    let ppid = read_u32_le(raw, 0).unwrap_or_default();
    let cgroup_id = read_u64_le(raw, 4).unwrap_or_default();
    let comm = parse_c_string(slice_window(raw, 12, 32));
    let path = parse_c_string(slice_window(raw, 44, 160));
    let cmdline = parse_c_string(slice_window(raw, 204, 160));

    if comm.is_empty() && path.is_empty() && cmdline.is_empty() {
        return parse_c_string(raw);
    }

    format!(
        "ppid={};cgroup_id={};comm={};path={};cmdline={}",
        ppid, cgroup_id, comm, path, cmdline
    )
}

fn parse_file_open_payload(raw: &[u8]) -> String {
    if raw.len() < 8 {
        return parse_c_string(raw);
    }

    let flags = read_u32_le(raw, 0).unwrap_or_default();
    let mode = read_u32_le(raw, 4).unwrap_or_default();
    let path = parse_c_string(slice_window(raw, 8, 256));
    if path.is_empty() {
        return parse_c_string(raw);
    }

    format!("path={};flags={};mode={}", path, flags, mode)
}

fn parse_tcp_connect_payload(raw: &[u8]) -> String {
    if raw.len() < 16 {
        return parse_c_string(raw);
    }

    let family = read_u16_le(raw, 0).unwrap_or_default();
    let sport = read_u16_le(raw, 2).unwrap_or_default();
    let dport = read_u16_le(raw, 4).unwrap_or_default();
    let protocol = raw.get(6).copied().unwrap_or_default();
    let saddr_v4 = read_u32_le(raw, 8).unwrap_or_default();
    let daddr_v4 = read_u32_le(raw, 12).unwrap_or_default();

    let (src_ip, dst_ip) = if family == 10 && raw.len() >= 48 {
        let src_v6 = read_ipv6(raw, 16);
        let dst_v6 = read_ipv6(raw, 32);
        match (src_v6, dst_v6) {
            (Some(src), Some(dst)) => (format_ipv6(src), format_ipv6(dst)),
            _ => (format_ipv4(saddr_v4), format_ipv4(daddr_v4)),
        }
    } else {
        (format_ipv4(saddr_v4), format_ipv4(daddr_v4))
    };

    format!(
        "family={};protocol={};src_ip={};src_port={};dst_ip={};dst_port={}",
        family, protocol, src_ip, sport, dst_ip, dport
    )
}

fn parse_dns_query_payload(raw: &[u8]) -> String {
    if raw.len() < 4 {
        return parse_c_string(raw);
    }

    let qtype = read_u16_le(raw, 0).unwrap_or_default();
    let qclass = read_u16_le(raw, 2).unwrap_or_default();
    let qname = parse_c_string(slice_window(raw, 4, 128));
    if qname.is_empty() {
        return parse_c_string(raw);
    }

    format!("qname={};qtype={};qclass={}", qname, qtype, qclass)
}

fn parse_module_load_payload(raw: &[u8]) -> String {
    let module_name = parse_c_string(slice_window(raw, 0, 64));
    if module_name.is_empty() {
        return parse_c_string(raw);
    }

    format!("module={}", module_name)
}

fn parse_lsm_block_payload(raw: &[u8]) -> String {
    if raw.len() < 4 {
        return parse_c_string(raw);
    }

    let reason = raw[0];
    let subject = parse_c_string(slice_window(raw, 4, 128));
    if subject.is_empty() {
        return format!("reason={}", reason);
    }

    format!("reason={};subject={}", reason, subject)
}

fn format_ipv4(ip: u32) -> String {
    let b = ip.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn format_ipv6(ip: [u8; 16]) -> String {
    std::net::Ipv6Addr::from(ip).to_string()
}

fn read_ipv6(raw: &[u8], offset: usize) -> Option<[u8; 16]> {
    let end = offset.checked_add(16)?;
    let bytes = raw.get(offset..end)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(bytes);
    Some(out)
}

fn parse_c_string(raw: &[u8]) -> String {
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

fn slice_window(raw: &[u8], offset: usize, max_len: usize) -> &[u8] {
    if offset >= raw.len() {
        return &[];
    }

    let end = raw.len().min(offset.saturating_add(max_len));
    &raw[offset..end]
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod tests_ring_contract;
