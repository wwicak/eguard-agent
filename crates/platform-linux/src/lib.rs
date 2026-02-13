mod ebpf;

use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crypto_accel::sha256_file_hex;
use serde::{Deserialize, Serialize};

pub use ebpf::{EbpfEngine, EbpfError, EbpfStats};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EventType {
    ProcessExec,
    ProcessExit,
    FileOpen,
    TcpConnect,
    DnsQuery,
    ModuleLoad,
    LsmBlock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvent {
    pub event_type: EventType,
    pub pid: u32,
    pub uid: u32,
    pub ts_ns: u64,
    pub payload: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedEvent {
    pub event: RawEvent,
    pub process_exe: Option<String>,
    pub process_exe_sha256: Option<String>,
    pub process_cmdline: Option<String>,
    pub parent_process: Option<String>,
    pub parent_chain: Vec<u32>,
    pub file_path: Option<String>,
    pub file_sha256: Option<String>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub dst_domain: Option<String>,
}

#[derive(Debug, Clone)]
struct ProcessCacheEntry {
    process_exe: Option<String>,
    process_cmdline: Option<String>,
    parent_process: Option<String>,
    parent_chain: Vec<u32>,
    last_seen_ns: u64,
}

#[derive(Debug, Clone)]
struct FileHashCacheEntry {
    mtime_secs: i64,
    size_bytes: u64,
    sha256: String,
}

#[derive(Debug)]
pub struct EnrichmentCache {
    process_cache: HashMap<u32, ProcessCacheEntry>,
    process_lru: VecDeque<u32>,
    file_hash_cache: HashMap<String, FileHashCacheEntry>,
    file_lru: VecDeque<String>,
    max_process_entries: usize,
    max_file_hash_entries: usize,
}

impl Default for EnrichmentCache {
    fn default() -> Self {
        Self::new(500, 10_000)
    }
}

impl EnrichmentCache {
    pub fn new(max_process_entries: usize, max_file_hash_entries: usize) -> Self {
        Self {
            process_cache: HashMap::new(),
            process_lru: VecDeque::new(),
            file_hash_cache: HashMap::new(),
            file_lru: VecDeque::new(),
            max_process_entries: max_process_entries.max(128),
            max_file_hash_entries: max_file_hash_entries.max(128),
        }
    }

    pub fn process_cache_len(&self) -> usize {
        self.process_cache.len()
    }

    pub fn file_hash_cache_len(&self) -> usize {
        self.file_hash_cache.len()
    }

    pub fn evict_process(&mut self, pid: u32) -> bool {
        if let Some(pos) = self
            .process_lru
            .iter()
            .position(|existing| *existing == pid)
        {
            self.process_lru.remove(pos);
        }
        self.process_cache.remove(&pid).is_some()
    }

    fn process_entry(&mut self, raw: &RawEvent) -> ProcessCacheEntry {
        if let Some(entry) = self.process_cache.get_mut(&raw.pid) {
            entry.last_seen_ns = raw.ts_ns;
            touch_lru_u32(&mut self.process_lru, raw.pid);
            return entry.clone();
        }

        let process_exe = fs::read_link(format!("/proc/{}/exe", raw.pid))
            .ok()
            .map(|p| p.to_string_lossy().into_owned());

        let process_cmdline = fs::read(format!("/proc/{}/cmdline", raw.pid))
            .ok()
            .and_then(|buf| {
                let parts: Vec<String> = buf
                    .split(|b| *b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).to_string())
                    .collect();
                if parts.is_empty() {
                    None
                } else {
                    Some(parts.join(" "))
                }
            });

        let parent_chain = collect_parent_chain(raw.pid, 5);
        let parent_process = parent_chain.first().and_then(|pid| read_process_name(*pid));

        let entry = ProcessCacheEntry {
            process_exe,
            process_cmdline,
            parent_process,
            parent_chain,
            last_seen_ns: raw.ts_ns,
        };

        self.process_cache.insert(raw.pid, entry.clone());
        touch_lru_u32(&mut self.process_lru, raw.pid);
        trim_process_cache(self);
        entry
    }

    fn hash_for_path(&mut self, path: &str) -> Option<String> {
        let metadata = fs::metadata(path).ok()?;
        let mtime_secs = metadata.mtime();
        let size_bytes = metadata.size();

        if let Some(cached) = self.file_hash_cache.get(path) {
            if cached.mtime_secs == mtime_secs && cached.size_bytes == size_bytes {
                touch_lru_str(&mut self.file_lru, path);
                return Some(cached.sha256.clone());
            }
        }

        let hash = compute_sha256_file(path).ok()?;
        self.file_hash_cache.insert(
            path.to_string(),
            FileHashCacheEntry {
                mtime_secs,
                size_bytes,
                sha256: hash.clone(),
            },
        );
        touch_lru_str(&mut self.file_lru, path);
        trim_file_hash_cache(self);
        Some(hash)
    }
}

pub fn platform_name() -> &'static str {
    "linux"
}

pub fn open_inotify_nonblocking() -> io::Result<i32> {
    let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

pub fn add_inotify_watch(fd: i32, path: &Path) -> io::Result<i32> {
    let raw = path.as_os_str().as_bytes();
    let c_path =
        CString::new(raw).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul byte"))?;
    let mask = libc::IN_CREATE
        | libc::IN_MODIFY
        | libc::IN_DELETE
        | libc::IN_MOVED_FROM
        | libc::IN_MOVED_TO;
    let watch_fd = unsafe { libc::inotify_add_watch(fd, c_path.as_ptr(), mask) };
    if watch_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(watch_fd)
}

pub fn enrich_event(raw: RawEvent) -> EnrichedEvent {
    let mut cache = EnrichmentCache::default();
    enrich_event_with_cache(raw, &mut cache)
}

pub fn enrich_event_with_cache(raw: RawEvent, cache: &mut EnrichmentCache) -> EnrichedEvent {
    let payload_meta = parse_payload_metadata(&raw.event_type, &raw.payload);
    if matches!(raw.event_type, EventType::ProcessExit) {
        let _ = cache.evict_process(raw.pid);
        return EnrichedEvent {
            event: raw,
            process_exe: None,
            process_exe_sha256: None,
            process_cmdline: payload_meta.command_line_hint,
            parent_process: None,
            parent_chain: Vec::new(),
            file_path: payload_meta.file_path,
            file_sha256: None,
            dst_ip: payload_meta.dst_ip,
            dst_port: payload_meta.dst_port,
            dst_domain: payload_meta.dst_domain,
        };
    }

    let entry = cache.process_entry(&raw);

    let process_exe_sha256 = entry
        .process_exe
        .as_deref()
        .and_then(|path| cache.hash_for_path(path));
    let file_sha256 = payload_meta
        .file_path
        .as_deref()
        .and_then(|path| cache.hash_for_path(path));

    EnrichedEvent {
        event: raw,
        process_exe: entry.process_exe,
        process_exe_sha256,
        process_cmdline: entry.process_cmdline.or(payload_meta.command_line_hint),
        parent_process: entry.parent_process,
        parent_chain: entry.parent_chain,
        file_path: payload_meta.file_path,
        file_sha256,
        dst_ip: payload_meta.dst_ip,
        dst_port: payload_meta.dst_port,
        dst_domain: payload_meta.dst_domain,
    }
}

fn read_ppid(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in status.lines() {
        if let Some(raw) = line.strip_prefix("PPid:") {
            return raw.trim().parse::<u32>().ok();
        }
    }
    None
}

fn read_process_name(pid: u32) -> Option<String> {
    let raw = fs::read_to_string(format!("/proc/{}/comm", pid)).ok()?;
    let name = raw.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

#[derive(Debug, Default)]
struct PayloadMetadata {
    file_path: Option<String>,
    command_line_hint: Option<String>,
    dst_ip: Option<String>,
    dst_port: Option<u16>,
    dst_domain: Option<String>,
}

fn parse_payload_metadata(event_type: &EventType, payload: &str) -> PayloadMetadata {
    let trimmed = payload.trim();
    if trimmed.is_empty() {
        return PayloadMetadata::default();
    }

    let fields = parse_kv_fields(trimmed);
    if fields.is_empty() {
        return parse_payload_fallback(event_type, trimmed);
    }

    let mut metadata = PayloadMetadata {
        file_path: fields
            .get("path")
            .cloned()
            .or_else(|| fields.get("file").cloned()),
        command_line_hint: fields
            .get("cmdline")
            .cloned()
            .or_else(|| fields.get("command_line").cloned())
            .or_else(|| fields.get("subject").cloned()),
        dst_ip: fields
            .get("dst_ip")
            .cloned()
            .or_else(|| fields.get("ip").cloned()),
        dst_port: fields
            .get("dst_port")
            .or_else(|| fields.get("port"))
            .and_then(|value| value.parse::<u16>().ok()),
        dst_domain: fields
            .get("dst_domain")
            .cloned()
            .or_else(|| fields.get("domain").cloned())
            .or_else(|| fields.get("qname").cloned()),
    };

    if metadata.dst_ip.is_none() || metadata.dst_port.is_none() {
        if let Some(endpoint) = fields.get("dst").or_else(|| fields.get("endpoint")) {
            let (ip, port) = parse_endpoint(endpoint);
            if metadata.dst_ip.is_none() {
                metadata.dst_ip = ip;
            }
            if metadata.dst_port.is_none() {
                metadata.dst_port = port;
            }
        }
    }

    metadata
}

fn parse_kv_fields(payload: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for segment in payload.split([';', ',']) {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }

        let Some((key, value)) = segment.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim().trim_matches('"').to_string();
        if !key.is_empty() && !value.is_empty() {
            out.insert(key, value);
        }
    }
    out
}

fn parse_payload_fallback(event_type: &EventType, payload: &str) -> PayloadMetadata {
    match event_type {
        EventType::FileOpen => PayloadMetadata {
            file_path: Some(payload.to_string()),
            ..PayloadMetadata::default()
        },
        EventType::DnsQuery => PayloadMetadata {
            dst_domain: Some(payload.to_string()),
            ..PayloadMetadata::default()
        },
        EventType::TcpConnect => {
            let (dst_ip, dst_port) = parse_endpoint(payload);
            PayloadMetadata {
                dst_ip,
                dst_port,
                ..PayloadMetadata::default()
            }
        }
        EventType::ProcessExec => PayloadMetadata {
            command_line_hint: Some(payload.to_string()),
            ..PayloadMetadata::default()
        },
        EventType::ProcessExit => PayloadMetadata::default(),
        EventType::ModuleLoad => PayloadMetadata::default(),
        EventType::LsmBlock => PayloadMetadata {
            command_line_hint: Some(payload.to_string()),
            ..PayloadMetadata::default()
        },
    }
}

fn parse_endpoint(raw: &str) -> (Option<String>, Option<u16>) {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return (None, None);
    }

    if let Some(stripped) = trimmed.strip_prefix('[') {
        if let Some((ip, rest)) = stripped.split_once(']') {
            let port = rest
                .strip_prefix(':')
                .and_then(|value| value.parse::<u16>().ok());
            return (Some(ip.to_string()), port);
        }
    }

    if let Some((ip, port)) = trimmed.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            return (Some(ip.to_string()), Some(port));
        }
    }

    (Some(trimmed.to_string()), None)
}

fn collect_parent_chain(pid: u32, depth: usize) -> Vec<u32> {
    let mut out = Vec::new();
    let mut current = pid;
    for _ in 0..depth {
        let Some(ppid) = read_ppid(current) else {
            break;
        };
        if ppid == 0 || ppid == current {
            break;
        }
        out.push(ppid);
        current = ppid;
    }
    out
}

fn touch_lru_u32(lru: &mut VecDeque<u32>, key: u32) {
    if let Some(pos) = lru.iter().position(|existing| *existing == key) {
        lru.remove(pos);
    }
    lru.push_back(key);
}

fn touch_lru_str(lru: &mut VecDeque<String>, key: &str) {
    if let Some(pos) = lru.iter().position(|existing| existing == key) {
        lru.remove(pos);
    }
    lru.push_back(key.to_string());
}

fn trim_process_cache(cache: &mut EnrichmentCache) {
    while cache.process_cache.len() > cache.max_process_entries {
        if let Some(oldest) = cache.process_lru.pop_front() {
            cache.process_cache.remove(&oldest);
        } else {
            break;
        }
    }
}

fn trim_file_hash_cache(cache: &mut EnrichmentCache) {
    while cache.file_hash_cache.len() > cache.max_file_hash_entries {
        if let Some(oldest) = cache.file_lru.pop_front() {
            cache.file_hash_cache.remove(&oldest);
        } else {
            break;
        }
    }
}

fn compute_sha256_file(path: &str) -> std::io::Result<String> {
    sha256_file_hex(Path::new(path)).map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests;
