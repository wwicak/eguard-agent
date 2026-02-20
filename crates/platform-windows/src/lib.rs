//! Platform-windows crate: Windows EDR platform abstraction.
//!
//! Provides the same public API as `platform-linux` (EventType, RawEvent,
//! EnrichedEvent, EnrichmentCache, enrich_event, enrich_event_with_cache,
//! platform_name) plus Windows-specific subsystems (ETW, AMSI, WFP, etc.).

pub mod amsi;
pub mod compliance;
pub mod enrichment;
pub mod etw;
pub mod inventory;
pub mod response;
pub mod self_protect;
pub mod service;
pub mod wfp;

use std::num::NonZeroUsize;

use lru::LruCache;
use serde::{Deserialize, Serialize};

pub use etw::{EtwEngine, EtwError, EtwStats};

// ── Shared event types (mirrors platform-linux) ────────────────────────

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

// ── Cache types ────────────────────────────────────────────────────────

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
    #[allow(dead_code)]
    mtime_secs: i64,
    #[allow(dead_code)]
    size_bytes: u64,
    sha256: String,
}

#[derive(Debug)]
pub struct EnrichmentCache {
    process_cache: LruCache<u32, ProcessCacheEntry>,
    file_hash_cache: LruCache<String, FileHashCacheEntry>,
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
        if let Some(cached) = self.file_hash_cache.get(path) {
            return Some(cached.sha256.clone());
        }

        let hash = enrichment::file::compute_sha256(path).ok()?;
        self.file_hash_cache.put(
            path.to_string(),
            FileHashCacheEntry {
                mtime_secs: 0,
                size_bytes: 0,
                sha256: hash.clone(),
            },
        );
        Some(hash)
    }
}

// ── Public API ─────────────────────────────────────────────────────────

pub fn platform_name() -> &'static str {
    "windows"
}

pub fn enrich_event(raw: RawEvent) -> EnrichedEvent {
    let mut cache = EnrichmentCache::default();
    enrich_event_with_cache(raw, &mut cache)
}

pub fn enrich_event_with_cache(raw: RawEvent, cache: &mut EnrichmentCache) -> EnrichedEvent {
    if matches!(raw.event_type, EventType::ProcessExit) {
        let _ = cache.evict_process(raw.pid);
        return EnrichedEvent {
            event: raw,
            process_exe: None,
            process_exe_sha256: None,
            process_cmdline: None,
            parent_process: None,
            parent_chain: Vec::new(),
            file_path: None,
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
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

    // Windows does not use containers in the same way as Linux.
    EnrichedEvent {
        event: raw,
        process_exe: entry.process_exe,
        process_exe_sha256,
        process_cmdline: entry.process_cmdline,
        parent_process: entry.parent_process,
        parent_chain: entry.parent_chain,
        file_path: None,
        file_path_secondary: None,
        file_write: false,
        file_sha256: None,
        event_size: None,
        dst_ip: None,
        dst_port: None,
        dst_domain: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    }
}

// ── Helpers ────────────────────────────────────────────────────────────

fn capacity_from(raw: usize) -> NonZeroUsize {
    let bounded = raw.max(128);
    NonZeroUsize::new(bounded).expect("cache capacity is always non-zero")
}
