pub mod container;
mod ebpf;
pub mod inventory;
mod kernel_integrity;

use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io;
use std::num::NonZeroUsize;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crypto_accel::sha256_file_hex;
use lru::LruCache;
use serde::{Deserialize, Serialize};

pub use container::{
    container_labels, detect_container, detect_container_escape, detect_privileged_container,
    get_namespace_info, ContainerContext, ContainerRuntime, NamespaceInfo,
};
pub use ebpf::{EbpfEngine, EbpfError, EbpfStats};
pub use kernel_integrity::{
    scan_kernel_integrity, KernelIntegrityReport, KernelIntegrityScanOptions,
};

const MAX_PARENT_CHAIN_DEPTH: usize = 12;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EventType {
    ProcessExec,
    ProcessExit,
    FileOpen,
    FileWrite,
    FileRename,
    FileUnlink,
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
    pub file_path_secondary: Option<String>,
    pub file_write: bool,
    pub file_sha256: Option<String>,
    pub event_size: Option<u64>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub dst_domain: Option<String>,
    /// Container runtime (e.g., "docker", "containerd", "host").
    pub container_runtime: Option<String>,
    /// Short container ID (12 chars).
    pub container_id: Option<String>,
    /// Whether the process may have escaped its container.
    pub container_escape: bool,
    /// Whether the container has elevated capabilities (SYS_ADMIN/SYS_PTRACE).
    pub container_privileged: bool,
}

#[derive(Debug, Clone)]
struct ProcessCacheEntry {
    process_exe: Option<String>,
    process_cmdline: Option<String>,
    parent_process: Option<String>,
    parent_chain: Vec<u32>,
    start_time_ticks: Option<u64>,
    last_seen_ns: u64,
}

const DEFAULT_HASH_FINALIZE_DELAY_MS: u64 = 1_200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileFingerprint {
    inode: u64,
    mtime_secs: i64,
    mtime_nsecs: i64,
    size_bytes: u64,
}

#[derive(Debug, Clone)]
struct FilePendingFingerprint {
    fingerprint: FileFingerprint,
    first_seen_ns: u64,
}

#[derive(Debug, Clone)]
struct FileHashCacheEntry {
    stable_fingerprint: Option<FileFingerprint>,
    sha256: Option<String>,
    pending: Option<FilePendingFingerprint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashMode {
    Immediate,
    ChurnAware,
}

#[derive(Debug)]
pub struct EnrichmentCache {
    process_cache: LruCache<u32, ProcessCacheEntry>,
    file_hash_cache: LruCache<String, FileHashCacheEntry>,
    hash_finalize_delay_ns: u64,
    strict_budget_mode: bool,
    expensive_path_exclusions: Vec<String>,
    expensive_process_exclusions: Vec<String>,
}

impl Default for EnrichmentCache {
    fn default() -> Self {
        Self::new(500, 10_000)
    }
}

impl EnrichmentCache {
    pub fn new(max_process_entries: usize, max_file_hash_entries: usize) -> Self {
        Self {
            process_cache: LruCache::new(capacity_from(max_process_entries)),
            file_hash_cache: LruCache::new(capacity_from(max_file_hash_entries)),
            hash_finalize_delay_ns: DEFAULT_HASH_FINALIZE_DELAY_MS.saturating_mul(1_000_000),
            strict_budget_mode: false,
            expensive_path_exclusions: Vec::new(),
            expensive_process_exclusions: Vec::new(),
        }
    }

    pub fn set_budget_mode(&mut self, enabled: bool) {
        self.strict_budget_mode = enabled;
    }

    pub fn set_hash_finalize_delay_ms(&mut self, delay_ms: u64) {
        self.hash_finalize_delay_ns = delay_ms.saturating_mul(1_000_000);
    }

    pub fn set_expensive_check_exclusions(
        &mut self,
        path_exclusions: Vec<String>,
        process_exclusions: Vec<String>,
    ) {
        self.expensive_path_exclusions = normalize_exclusions(path_exclusions);
        self.expensive_process_exclusions = normalize_exclusions(process_exclusions);
    }

    pub fn process_cache_len(&self) -> usize {
        self.process_cache.len()
    }

    pub fn file_hash_cache_len(&self) -> usize {
        self.file_hash_cache.len()
    }

    #[cfg(test)]
    pub(crate) fn file_hash_cache_contains_path(&self, path: &str) -> bool {
        self.file_hash_cache.peek(path).is_some()
    }

    pub fn evict_process(&mut self, pid: u32) -> bool {
        self.process_cache.pop(&pid).is_some()
    }

    fn process_entry(&mut self, raw: &RawEvent) -> ProcessCacheEntry {
        let current_start_time_ticks = read_process_start_time_ticks(raw.pid);
        if let Some(entry) = self.process_cache.get_mut(&raw.pid) {
            let same_process_instance = match (entry.start_time_ticks, current_start_time_ticks) {
                (Some(cached), Some(current)) => cached == current,
                _ => false,
            };
            if same_process_instance {
                entry.last_seen_ns = raw.ts_ns;
                return entry.clone();
            }
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

        let parent_chain = collect_parent_chain(raw.pid, MAX_PARENT_CHAIN_DEPTH);
        let parent_process = parent_chain.first().and_then(|pid| read_process_name(*pid));

        let entry = ProcessCacheEntry {
            process_exe,
            process_cmdline,
            parent_process,
            parent_chain,
            start_time_ticks: current_start_time_ticks,
            last_seen_ns: raw.ts_ns,
        };

        self.process_cache.put(raw.pid, entry.clone());
        entry
    }

    fn hash_for_path(&mut self, path: &str) -> Option<String> {
        self.hash_for_path_mode(path, HashMode::Immediate)
    }

    fn hash_for_path_churn_aware(&mut self, path: &str) -> Option<String> {
        self.hash_for_path_mode(path, HashMode::ChurnAware)
    }

    fn hash_for_path_mode(&mut self, path: &str, mode: HashMode) -> Option<String> {
        let metadata = fs::metadata(path).ok()?;
        let fingerprint = FileFingerprint {
            inode: metadata.ino(),
            mtime_secs: metadata.mtime(),
            mtime_nsecs: metadata.mtime_nsec(),
            size_bytes: metadata.size(),
        };

        let now_ns = unix_now_ns();
        let entry = self
            .file_hash_cache
            .get(path)
            .cloned()
            .unwrap_or(FileHashCacheEntry {
                stable_fingerprint: None,
                sha256: None,
                pending: None,
            });

        if entry.stable_fingerprint == Some(fingerprint) {
            return entry.sha256;
        }

        if matches!(mode, HashMode::Immediate) || self.hash_finalize_delay_ns == 0 {
            return self.compute_and_commit_hash(path, fingerprint, None);
        }

        let mut next_entry = entry.clone();
        match entry.pending {
            Some(pending) if pending.fingerprint == fingerprint => {
                if now_ns.saturating_sub(pending.first_seen_ns) >= self.hash_finalize_delay_ns {
                    return self.compute_and_commit_hash(path, fingerprint, Some(next_entry));
                }
            }
            _ => {
                next_entry.pending = Some(FilePendingFingerprint {
                    fingerprint,
                    first_seen_ns: now_ns,
                });
                self.file_hash_cache.put(path.to_string(), next_entry);
            }
        }

        entry.sha256
    }

    fn compute_and_commit_hash(
        &mut self,
        path: &str,
        fingerprint: FileFingerprint,
        existing_entry: Option<FileHashCacheEntry>,
    ) -> Option<String> {
        let hash = compute_sha256_file(path).ok()?;
        let mut entry = existing_entry.unwrap_or(FileHashCacheEntry {
            stable_fingerprint: None,
            sha256: None,
            pending: None,
        });
        entry.stable_fingerprint = Some(fingerprint);
        entry.sha256 = Some(hash.clone());
        entry.pending = None;
        self.file_hash_cache.put(path.to_string(), entry);
        Some(hash)
    }

    fn is_excluded_for_expensive_checks(
        &self,
        path: Option<&str>,
        process_exe: Option<&str>,
    ) -> bool {
        let process_excluded = process_exe
            .map(|value| matches_any_exclusion(value, &self.expensive_process_exclusions))
            .unwrap_or(false);

        if process_excluded {
            return true;
        }

        path.map(|value| matches_any_exclusion(value, &self.expensive_path_exclusions))
            .unwrap_or(false)
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
            file_path: payload_meta.file_path.or(payload_meta.file_path_secondary),
            file_path_secondary: None,
            file_write: payload_meta.file_write,
            file_sha256: None,
            event_size: payload_meta.event_size,
            dst_ip: payload_meta.dst_ip,
            dst_port: payload_meta.dst_port,
            dst_domain: payload_meta.dst_domain,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };
    }

    let entry = cache.process_entry(&raw);

    let process_exe_sha256 = entry.process_exe.as_deref().and_then(|path| {
        if cache.is_excluded_for_expensive_checks(None, Some(path)) {
            None
        } else {
            cache.hash_for_path(path)
        }
    });

    let file_sha256 = if cache.strict_budget_mode {
        None
    } else {
        let primary = payload_meta.file_path.as_deref().and_then(|path| {
            if cache.is_excluded_for_expensive_checks(Some(path), entry.process_exe.as_deref()) {
                None
            } else {
                cache.hash_for_path_churn_aware(path)
            }
        });

        primary.or_else(|| {
            payload_meta
                .file_path_secondary
                .as_deref()
                .and_then(|path| {
                    if cache
                        .is_excluded_for_expensive_checks(Some(path), entry.process_exe.as_deref())
                    {
                        None
                    } else {
                        cache.hash_for_path_churn_aware(path)
                    }
                })
        })
    };

    let mut parent_chain = entry.parent_chain.clone();
    if parent_chain.is_empty() {
        if let Some(ppid) = payload_meta.ppid {
            parent_chain = vec![ppid];
        }
    }

    // Container detection: extract runtime and ID from cgroup
    let (container_runtime, container_id, container_escape, container_privileged) = {
        match container::detect_container(raw.pid) {
            Some(ctx) => {
                let escape = container::detect_container_escape(raw.pid);
                let privileged = container::detect_privileged_container(raw.pid);
                (
                    Some(ctx.runtime.as_str().to_string()),
                    Some(ctx.container_id_short),
                    escape,
                    privileged,
                )
            }
            None => (Some("host".to_string()), None, false, false),
        }
    };

    // For process_exec events, fall back to the payload's executable path
    // when /proc/<pid>/exe is unavailable (e.g., replay or short-lived PIDs).
    let process_exe = entry.process_exe.or_else(|| {
        if matches!(raw.event_type, EventType::ProcessExec) {
            payload_meta.file_path.clone()
        } else {
            None
        }
    });

    EnrichedEvent {
        event: raw,
        process_exe,
        process_exe_sha256,
        process_cmdline: entry.process_cmdline.or(payload_meta.command_line_hint),
        parent_process: entry.parent_process,
        parent_chain,
        file_path: payload_meta.file_path.or(payload_meta.file_path_secondary),
        file_path_secondary: None,
        file_write: payload_meta.file_write,
        file_sha256,
        event_size: payload_meta.event_size,
        dst_ip: payload_meta.dst_ip,
        dst_port: payload_meta.dst_port,
        dst_domain: payload_meta.dst_domain,
        container_runtime,
        container_id,
        container_escape,
        container_privileged,
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

fn read_process_start_time_ticks(pid: u32) -> Option<u64> {
    let raw = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    parse_process_start_time_ticks(&raw)
}

fn parse_process_start_time_ticks(raw: &str) -> Option<u64> {
    // /proc/<pid>/stat format: pid (comm) state ppid ... starttime ...
    // starttime is field #22; after stripping the leading "pid (comm)",
    // it maps to index 19 in the remaining whitespace-separated fields.
    let rest = raw.rsplit_once(") ")?.1;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    fields.get(19)?.parse::<u64>().ok()
}

#[derive(Debug, Default)]
struct PayloadMetadata {
    file_path: Option<String>,
    file_path_secondary: Option<String>,
    command_line_hint: Option<String>,
    ppid: Option<u32>,
    dst_ip: Option<String>,
    dst_port: Option<u16>,
    dst_domain: Option<String>,
    file_write: bool,
    event_size: Option<u64>,
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
        file_path_secondary: fields
            .get("dst")
            .cloned()
            .or_else(|| fields.get("target").cloned())
            .or_else(|| fields.get("new").cloned()),
        command_line_hint: fields
            .get("cmdline")
            .cloned()
            .or_else(|| fields.get("command_line").cloned())
            .or_else(|| fields.get("subject").cloned()),
        ppid: fields
            .get("ppid")
            .and_then(|value| value.parse::<u32>().ok()),
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
        file_write: parse_file_write_flags(fields.get("flags"), fields.get("mode")),
        event_size: fields
            .get("size")
            .or_else(|| fields.get("bytes"))
            .and_then(|value| value.parse::<u64>().ok()),
    };

    if matches!(event_type, EventType::ModuleLoad) && metadata.file_path.is_none() {
        metadata.file_path = fields
            .get("module")
            .cloned()
            .or_else(|| fields.get("module_name").cloned());
    }

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
        EventType::FileOpen | EventType::FileWrite => {
            let fields = parse_kv_fields(payload);
            if fields.is_empty() {
                return PayloadMetadata {
                    file_path: Some(payload.to_string()),
                    file_write: matches!(event_type, EventType::FileWrite),
                    ..PayloadMetadata::default()
                };
            }
            PayloadMetadata {
                file_path: fields
                    .get("path")
                    .cloned()
                    .or_else(|| fields.get("file").cloned()),
                file_write: matches!(event_type, EventType::FileWrite)
                    || parse_file_write_flags(fields.get("flags"), fields.get("mode")),
                event_size: fields
                    .get("size")
                    .or_else(|| fields.get("bytes"))
                    .and_then(|value| value.parse::<u64>().ok()),
                ..PayloadMetadata::default()
            }
        }
        EventType::FileRename => {
            let fields = parse_kv_fields(payload);
            if fields.is_empty() {
                return PayloadMetadata::default();
            }
            PayloadMetadata {
                file_path: fields
                    .get("src")
                    .cloned()
                    .or_else(|| fields.get("old").cloned())
                    .or_else(|| fields.get("path").cloned()),
                file_path_secondary: fields
                    .get("dst")
                    .cloned()
                    .or_else(|| fields.get("new").cloned())
                    .or_else(|| fields.get("target").cloned()),
                ..PayloadMetadata::default()
            }
        }
        EventType::FileUnlink => {
            let fields = parse_kv_fields(payload);
            if fields.is_empty() {
                return PayloadMetadata {
                    file_path: Some(payload.to_string()),
                    ..PayloadMetadata::default()
                };
            }
            PayloadMetadata {
                file_path: fields
                    .get("path")
                    .cloned()
                    .or_else(|| fields.get("file").cloned()),
                ..PayloadMetadata::default()
            }
        }
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
        EventType::ModuleLoad => PayloadMetadata {
            file_path: Some(payload.to_string()),
            ..PayloadMetadata::default()
        },
        EventType::LsmBlock => PayloadMetadata {
            command_line_hint: Some(payload.to_string()),
            ..PayloadMetadata::default()
        },
    }
}

fn parse_file_write_flags(flags: Option<&String>, mode: Option<&String>) -> bool {
    let flags_val = flags
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    let mode_val = mode
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);

    const O_WRONLY: u32 = 1;
    const O_RDWR: u32 = 2;
    const O_CREAT: u32 = 0x40;
    const O_TRUNC: u32 = 0x200;

    let write_intent = (flags_val & O_WRONLY) != 0 || (flags_val & O_RDWR) != 0;
    let destructive = (flags_val & O_TRUNC) != 0 || (flags_val & O_CREAT) != 0;
    let executable_bit = (mode_val & 0o111) != 0;

    write_intent || destructive || executable_bit
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

fn normalize_exclusions(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect()
}

fn matches_any_exclusion(value: &str, exclusions: &[String]) -> bool {
    if exclusions.is_empty() {
        return false;
    }

    let lowered = value.trim().to_ascii_lowercase();
    if lowered.is_empty() {
        return false;
    }

    let basename = lowered.rsplit('/').next().unwrap_or(&lowered);
    exclusions.iter().any(|needle| {
        lowered.starts_with(needle)
            || lowered.contains(needle)
            || basename == needle
            || basename.contains(needle)
    })
}

fn unix_now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

fn capacity_from(raw: usize) -> NonZeroUsize {
    let bounded = raw.max(128);
    NonZeroUsize::new(bounded).expect("cache capacity is always non-zero")
}

fn compute_sha256_file(path: &str) -> std::io::Result<String> {
    sha256_file_hex(Path::new(path)).map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests;
