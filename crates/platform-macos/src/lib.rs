//! Platform-macos crate: macOS EDR platform abstraction.
//!
//! Provides the same public API as `platform-linux` (EventType, RawEvent,
//! EnrichedEvent, EnrichmentCache, enrich_event, enrich_event_with_cache,
//! platform_name) plus macOS-specific subsystems (ESF, compliance, etc.).

pub mod compliance;
pub mod enrichment;
pub mod esf;
pub mod inventory;
pub mod response;
pub mod self_protect;
pub mod service;

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::num::NonZeroUsize;
use std::time::UNIX_EPOCH;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use lru::LruCache;
use serde::{Deserialize, Serialize};

pub use esf::{EsfEngine, EsfError, EsfStats};

// -- Shared event types (mirrors platform-linux) ----------------------------

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
    pub container_runtime: Option<String>,
    pub container_id: Option<String>,
    pub container_escape: bool,
    pub container_privileged: bool,
}

// -- Cache types ------------------------------------------------------------

#[derive(Debug, Clone)]
struct ProcessCacheEntry {
    process_exe: Option<String>,
    process_cmdline: Option<String>,
    parent_process: Option<String>,
    parent_chain: Vec<u32>,
    #[allow(dead_code)]
    last_seen_ns: u64,
}

#[derive(Debug, Clone)]
struct FileHashCacheEntry {
    modified_ns: i128,
    size_bytes: u64,
    inode: u64,
    sha256: String,
}

#[derive(Debug)]
pub struct EnrichmentCache {
    process_cache: LruCache<u32, ProcessCacheEntry>,
    file_hash_cache: LruCache<String, FileHashCacheEntry>,
}

thread_local! {
    static DEFAULT_ENRICHMENT_CACHE: RefCell<EnrichmentCache> =
        RefCell::new(EnrichmentCache::default());
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
        }
    }

    pub fn process_cache_len(&self) -> usize {
        self.process_cache.len()
    }

    pub fn file_hash_cache_len(&self) -> usize {
        self.file_hash_cache.len()
    }

    pub fn evict_process(&mut self, pid: u32) -> bool {
        self.process_cache.pop(&pid).is_some()
    }

    fn process_entry(&mut self, raw: &RawEvent) -> ProcessCacheEntry {
        if let Some(entry) = self.process_cache.get_mut(&raw.pid) {
            entry.last_seen_ns = raw.ts_ns;
            return entry.clone();
        }

        let info = enrichment::process::query_process_info(raw.pid);

        let entry = ProcessCacheEntry {
            process_exe: info.exe_path,
            process_cmdline: info.command_line,
            parent_process: info.parent_name,
            parent_chain: info.parent_chain,
            last_seen_ns: raw.ts_ns,
        };

        self.process_cache.put(raw.pid, entry.clone());
        entry
    }

    fn hash_for_path(&mut self, path: &str) -> Option<String> {
        let metadata = fs::metadata(path).ok()?;
        let modified_ns = metadata
            .modified()
            .ok()
            .and_then(|mtime| mtime.duration_since(UNIX_EPOCH).ok())
            .map(|duration| {
                (duration.as_secs() as i128)
                    .saturating_mul(1_000_000_000)
                    .saturating_add(duration.subsec_nanos() as i128)
            })
            .unwrap_or(0);
        let size_bytes = metadata.len();
        let inode = file_inode(&metadata);

        if let Some(cached) = self.file_hash_cache.get(path) {
            if cached.modified_ns == modified_ns
                && cached.size_bytes == size_bytes
                && cached.inode == inode
            {
                return Some(cached.sha256.clone());
            }
        }

        let hash = enrichment::file::compute_sha256(path).ok()?;
        self.file_hash_cache.put(
            path.to_string(),
            FileHashCacheEntry {
                modified_ns,
                size_bytes,
                inode,
                sha256: hash.clone(),
            },
        );
        Some(hash)
    }
}

// -- Public API -------------------------------------------------------------

pub fn platform_name() -> &'static str {
    "macos"
}

pub fn enrich_event(raw: RawEvent) -> EnrichedEvent {
    DEFAULT_ENRICHMENT_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        enrich_event_with_cache(raw, &mut cache)
    })
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
            file_path: payload_meta
                .file_path
                .or_else(|| payload_meta.file_path_secondary),
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

    let process_exe_sha256 = entry
        .process_exe
        .as_deref()
        .and_then(|p| cache.hash_for_path(p));

    let file_path = payload_meta
        .file_path
        .or_else(|| matches!(raw.event_type, EventType::ModuleLoad).then(|| raw.payload.clone()));

    let file_sha256 = file_path.as_deref().and_then(|p| cache.hash_for_path(p));

    // macOS does not use containers in the same way as Linux.
    EnrichedEvent {
        event: raw,
        process_exe: entry.process_exe,
        process_exe_sha256,
        process_cmdline: entry.process_cmdline.or(payload_meta.command_line_hint),
        parent_process: entry.parent_process,
        parent_chain: entry.parent_chain,
        file_path,
        file_path_secondary: payload_meta.file_path_secondary,
        file_write: payload_meta.file_write,
        file_sha256,
        event_size: payload_meta.event_size,
        dst_ip: payload_meta.dst_ip,
        dst_port: payload_meta.dst_port,
        dst_domain: payload_meta.dst_domain,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    }
}

#[derive(Debug, Default)]
struct PayloadMetadata {
    file_path: Option<String>,
    file_path_secondary: Option<String>,
    command_line_hint: Option<String>,
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
            .or_else(|| fields.get("file").cloned())
            .or_else(|| fields.get("src").cloned()),
        file_path_secondary: fields
            .get("dst")
            .cloned()
            .or_else(|| fields.get("target").cloned())
            .or_else(|| fields.get("new").cloned()),
        command_line_hint: fields
            .get("cmdline")
            .cloned()
            .or_else(|| fields.get("command_line").cloned()),
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
        EventType::FileOpen | EventType::FileWrite => PayloadMetadata {
            file_path: Some(payload.to_string()),
            file_write: matches!(event_type, EventType::FileWrite),
            ..PayloadMetadata::default()
        },
        EventType::FileRename => PayloadMetadata {
            file_path: Some(payload.to_string()),
            ..PayloadMetadata::default()
        },
        EventType::FileUnlink => PayloadMetadata {
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

    const O_WRONLY: u32 = 0x0001;
    const O_RDWR: u32 = 0x0002;
    // macOS (BSD) values from <sys/fcntl.h>; differ from Linux.
    const O_CREAT: u32 = 0x0200;
    const O_TRUNC: u32 = 0x0400;

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
        if !ip.contains(':') {
            if let Ok(port) = port.parse::<u16>() {
                return (Some(ip.to_string()), Some(port));
            }
        }
    }

    (Some(trimmed.to_string()), None)
}

// -- Helpers ----------------------------------------------------------------

#[cfg(unix)]
fn file_inode(metadata: &fs::Metadata) -> u64 {
    metadata.ino()
}

#[cfg(not(unix))]
fn file_inode(_metadata: &fs::Metadata) -> u64 {
    0
}

fn capacity_from(raw: usize) -> NonZeroUsize {
    let bounded = raw.max(128);
    NonZeroUsize::new(bounded).expect("cache capacity is always non-zero")
}

#[cfg(test)]
mod tests {
    use super::{enrich_event_with_cache, EnrichmentCache, EventType, RawEvent};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn enrich_macos_process_event_uses_cmdline_payload_hint() {
        let raw = RawEvent {
            event_type: EventType::ProcessExec,
            pid: 4242,
            uid: 0,
            ts_ns: 1,
            payload: "path=/usr/bin/python3;cmdline=python3 -c import os".to_string(),
        };

        let mut cache = EnrichmentCache::default();
        let enriched = enrich_event_with_cache(raw, &mut cache);

        assert_eq!(
            enriched.process_cmdline.as_deref(),
            Some("python3 -c import os")
        );
        assert_eq!(enriched.file_path.as_deref(), Some("/usr/bin/python3"));
    }

    #[test]
    fn enrich_macos_tcp_event_parses_endpoint_from_payload() {
        let raw = RawEvent {
            event_type: EventType::TcpConnect,
            pid: 1337,
            uid: 0,
            ts_ns: 2,
            payload: "dst=203.0.113.10:443".to_string(),
        };

        let mut cache = EnrichmentCache::default();
        let enriched = enrich_event_with_cache(raw, &mut cache);

        assert_eq!(enriched.dst_ip.as_deref(), Some("203.0.113.10"));
        assert_eq!(enriched.dst_port, Some(443));
    }

    #[test]
    fn file_hash_cache_rehashes_when_file_size_changes() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "eguard-macos-hash-cache-test-{}-{}",
            std::process::id(),
            nonce
        ));

        fs::write(&path, b"v1").expect("write v1 payload");

        let mut cache = EnrichmentCache::default();
        let first = cache
            .hash_for_path(&path.to_string_lossy())
            .expect("hash for v1");

        fs::write(&path, b"version-two").expect("write v2 payload");
        let second = cache
            .hash_for_path(&path.to_string_lossy())
            .expect("hash for v2");

        assert_ne!(
            first, second,
            "hash must refresh after file content changes"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn file_hash_cache_rehashes_when_file_changes_but_size_matches() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "eguard-macos-hash-cache-size-stable-test-{}-{}",
            std::process::id(),
            nonce
        ));

        fs::write(&path, b"AAAA").expect("write v1 payload");

        let mut cache = EnrichmentCache::default();
        let first = cache
            .hash_for_path(&path.to_string_lossy())
            .expect("hash for v1");

        std::thread::sleep(std::time::Duration::from_millis(10));
        fs::write(&path, b"BBBB").expect("write v2 payload");
        let second = cache
            .hash_for_path(&path.to_string_lossy())
            .expect("hash for v2");

        assert_ne!(
            first, second,
            "hash must refresh even when size is unchanged"
        );
        let _ = fs::remove_file(path);
    }
}
