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

mod windows_cmd;

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::time::UNIX_EPOCH;

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

const DEFAULT_HASH_FINALIZE_DELAY_MS: u64 = 1_200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileFingerprint {
    modified_ns: i128,
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
    file_object_cache: LruCache<String, String>,
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
            file_object_cache: LruCache::new(capacity_from(max_file_hash_entries)),
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

    pub fn evict_process(&mut self, pid: u32) -> bool {
        self.process_cache.pop(&pid).is_some()
    }

    pub fn prime_process_metadata(&mut self, raw: &RawEvent) {
        if matches!(raw.event_type, EventType::ProcessExec) {
            let payload_meta = parse_payload_metadata(&raw.event_type, &raw.payload);
            let _ = self.process_entry(raw, &payload_meta);
        }
    }

    fn process_entry(
        &mut self,
        raw: &RawEvent,
        payload_meta: &PayloadMetadata,
    ) -> ProcessCacheEntry {
        let authoritative_process_exec = matches!(raw.event_type, EventType::ProcessExec);
        let hinted_parent_chain = self.parent_chain_from_hint(payload_meta.parent_pid);
        let hinted_parent_name = payload_meta
            .parent_process_hint
            .clone()
            .or_else(|| self.parent_name_from_hint(payload_meta.parent_pid));

        if let Some(mut entry) = self.process_cache.get(&raw.pid).cloned() {
            entry.last_seen_ns = raw.ts_ns;
            if entry.process_exe.is_none()
                || (authoritative_process_exec
                    && entry
                        .process_exe
                        .as_deref()
                        .map(is_weak_windows_identity)
                        .unwrap_or(true))
            {
                entry.process_exe = payload_meta.process_path_hint.clone().or(entry.process_exe);
            }
            if let Some(candidate_cmdline) = payload_meta.command_line_hint.clone() {
                if should_upgrade_windows_cmdline(
                    entry.process_cmdline.as_deref(),
                    &candidate_cmdline,
                ) {
                    entry.process_cmdline = Some(candidate_cmdline);
                }
            }
            if entry.parent_chain.is_empty() {
                entry.parent_chain = hinted_parent_chain.clone();
            }
            if entry.parent_process.is_none()
                || entry
                    .parent_process
                    .as_deref()
                    .map(is_weak_windows_identity)
                    .unwrap_or(true)
            {
                entry.parent_process = hinted_parent_name.clone().or(entry.parent_process);
            }

            let needs_refresh = entry.process_exe.is_none()
                || entry.process_cmdline.is_none()
                || entry
                    .parent_process
                    .as_deref()
                    .map(is_weak_windows_identity)
                    .unwrap_or(true)
                || entry.parent_chain.is_empty();
            if needs_refresh {
                let info = enrichment::process::query_process_info(raw.pid);
                if entry.process_exe.is_none() {
                    entry.process_exe = info.exe_path;
                }
                if entry.process_cmdline.is_none() {
                    entry.process_cmdline = info.command_line;
                }
                if entry.parent_chain.is_empty() && !info.parent_chain.is_empty() {
                    entry.parent_chain = info.parent_chain;
                }
                if entry
                    .parent_process
                    .as_deref()
                    .map(is_weak_windows_identity)
                    .unwrap_or(true)
                {
                    entry.parent_process = hinted_parent_name.clone().or_else(|| {
                        info.parent_name.or_else(|| {
                            entry
                                .parent_chain
                                .first()
                                .copied()
                                .and_then(|pid| self.process_name_for_pid(pid))
                        })
                    });
                }
            }

            self.rewrite_proxy_process_context(&mut entry);
            self.process_cache.put(raw.pid, entry.clone());
            return entry;
        }

        let info = enrichment::process::query_process_info(raw.pid);
        let parent_chain = if info.parent_chain.is_empty() {
            hinted_parent_chain
        } else {
            info.parent_chain
        };
        let parent_process = hinted_parent_name.clone().or_else(|| {
            info.parent_name.or_else(|| {
                parent_chain
                    .first()
                    .copied()
                    .and_then(|pid| self.process_name_for_pid(pid))
            })
        });

        let mut entry = ProcessCacheEntry {
            process_exe: if authoritative_process_exec {
                payload_meta.process_path_hint.clone().or(info.exe_path)
            } else {
                info.exe_path
                    .or_else(|| payload_meta.process_path_hint.clone())
            },
            process_cmdline: if authoritative_process_exec {
                payload_meta.command_line_hint.clone().or(info.command_line)
            } else {
                info.command_line
                    .or_else(|| payload_meta.command_line_hint.clone())
            },
            parent_process,
            parent_chain,
            last_seen_ns: raw.ts_ns,
        };

        self.rewrite_proxy_process_context(&mut entry);
        self.process_cache.put(raw.pid, entry.clone());
        entry
    }

    fn process_name_for_pid(&mut self, pid: u32) -> Option<String> {
        if let Some(cached) = self.process_cache.peek(&pid) {
            if let Some(path) = cached.process_exe.as_deref() {
                return Some(process_basename(path).to_string());
            }
            if let Some(cmdline) = cached.process_cmdline.as_deref() {
                return process_name_from_cmdline(cmdline).map(ToString::to_string);
            }
            if let Some(parent) = cached.parent_process.as_deref() {
                return Some(parent.to_string());
            }
        }

        let info = enrichment::process::query_process_info(pid);
        let entry = ProcessCacheEntry {
            process_exe: info.exe_path,
            process_cmdline: info.command_line,
            parent_process: info.parent_name,
            parent_chain: info.parent_chain,
            last_seen_ns: 0,
        };

        let name = process_name_from_entry(&entry)
            .or_else(|| entry.parent_process.clone())
            .filter(|value| !value.trim().is_empty());
        if name.is_some() || !entry.parent_chain.is_empty() {
            self.process_cache.put(pid, entry.clone());
        }
        name
    }

    fn rewrite_proxy_process_context(&mut self, entry: &mut ProcessCacheEntry) {
        let current_name = process_name_from_entry(entry);
        let Some(ancestor) = self.first_meaningful_ancestor_entry(&entry.parent_chain) else {
            return;
        };
        let ancestor_name = process_name_from_entry(&ancestor);
        let ancestor_parent = ancestor
            .parent_process
            .clone()
            .filter(|value| !is_weak_windows_identity(value));

        if entry
            .parent_process
            .as_deref()
            .map(is_weak_windows_identity)
            .unwrap_or(true)
        {
            entry.parent_process = ancestor_parent.or_else(|| ancestor_name.clone());
        }

        let current_is_weak = current_name
            .as_deref()
            .map(is_weak_windows_identity)
            .unwrap_or(true);
        if current_is_weak {
            if entry.process_cmdline.is_none() {
                entry.process_cmdline = ancestor.process_cmdline.clone();
            }
            if entry.process_exe.is_none() {
                entry.process_exe = ancestor
                    .process_exe
                    .clone()
                    .or_else(|| ancestor_name.clone());
            }
        }
    }

    fn first_meaningful_ancestor_entry(
        &mut self,
        parent_chain: &[u32],
    ) -> Option<ProcessCacheEntry> {
        for pid in parent_chain {
            let candidate = if let Some(cached) = self.process_cache.peek(pid) {
                cached.clone()
            } else {
                let info = enrichment::process::query_process_info(*pid);
                let entry = ProcessCacheEntry {
                    process_exe: info.exe_path,
                    process_cmdline: info.command_line,
                    parent_process: info.parent_name,
                    parent_chain: info.parent_chain,
                    last_seen_ns: 0,
                };
                if process_name_from_entry(&entry).is_some() || !entry.parent_chain.is_empty() {
                    self.process_cache.put(*pid, entry.clone());
                }
                entry
            };

            if let Some(name) = process_name_from_entry(&candidate) {
                if !is_weak_windows_identity(&name) {
                    return Some(candidate);
                }
            }
        }

        None
    }

    fn parent_chain_from_hint(&mut self, parent_pid: Option<u32>) -> Vec<u32> {
        let Some(ppid) = parent_pid.filter(|value| *value > 0) else {
            return Vec::new();
        };

        let mut chain = vec![ppid];
        let info = enrichment::process::query_process_info(ppid);
        for ancestor in info.parent_chain {
            if ancestor == 0 || chain.contains(&ancestor) {
                continue;
            }
            chain.push(ancestor);
        }
        chain
    }

    fn parent_name_from_hint(&mut self, parent_pid: Option<u32>) -> Option<String> {
        parent_pid
            .filter(|value| *value > 0)
            .and_then(|pid| self.process_name_for_pid(pid))
    }

    fn remember_file_object_path(
        &mut self,
        file_object: Option<&str>,
        file_object_secondary: Option<&str>,
        path: Option<&str>,
    ) {
        let Some(path) = path
            .map(normalize_windows_path)
            .filter(|value| !value.is_empty())
        else {
            return;
        };

        for key in [file_object, file_object_secondary] {
            let Some(key) = key.map(str::trim).filter(|value| !value.is_empty()) else {
                continue;
            };
            self.file_object_cache
                .put(key.to_ascii_lowercase(), path.clone());
        }
    }

    fn remember_inferred_process_exe(&mut self, pid: u32, process_exe: String) {
        if pid <= 4 {
            return;
        }

        let normalized = normalize_windows_path(&process_exe);
        if normalized.is_empty() {
            return;
        }

        if let Some(mut entry) = self.process_cache.get(&pid).cloned() {
            if entry
                .process_exe
                .as_deref()
                .map(is_weak_windows_identity)
                .unwrap_or(true)
            {
                entry.process_exe = Some(normalized.clone());
                self.process_cache.put(pid, entry);
            }
            return;
        }

        self.process_cache.put(
            pid,
            ProcessCacheEntry {
                process_exe: Some(normalized),
                process_cmdline: None,
                parent_process: None,
                parent_chain: Vec::new(),
                last_seen_ns: 0,
            },
        );
    }

    fn file_path_from_object(
        &mut self,
        file_object: Option<&str>,
        file_object_secondary: Option<&str>,
    ) -> Option<String> {
        for key in [file_object, file_object_secondary] {
            let Some(key) = key.map(str::trim).filter(|value| !value.is_empty()) else {
                continue;
            };
            let key = key.to_ascii_lowercase();
            if let Some(path) = self.file_object_cache.get(&key).cloned() {
                return Some(path);
            }
        }
        None
    }

    fn hash_for_path(&mut self, path: &str) -> Option<String> {
        self.hash_for_path_mode(path, HashMode::Immediate)
    }

    fn hash_for_path_churn_aware(&mut self, path: &str) -> Option<String> {
        self.hash_for_path_mode(path, HashMode::ChurnAware)
    }

    fn hash_for_path_mode(&mut self, path: &str, mode: HashMode) -> Option<String> {
        let metadata = std::fs::metadata(path).ok()?;
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
        let fingerprint = FileFingerprint {
            modified_ns,
            size_bytes: metadata.len(),
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
        let hash = enrichment::file::compute_sha256(path).ok()?;
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

// ── Public API ─────────────────────────────────────────────────────────

pub fn platform_name() -> &'static str {
    "windows"
}

pub fn enrich_event(raw: RawEvent) -> EnrichedEvent {
    let mut cache = EnrichmentCache::default();
    enrich_event_with_cache(raw, &mut cache)
}

pub fn enrich_event_with_cache(raw: RawEvent, cache: &mut EnrichmentCache) -> EnrichedEvent {
    let payload_meta = parse_payload_metadata(&raw.event_type, &raw.payload);

    if matches!(raw.event_type, EventType::ProcessExit) {
        let cached = cache.process_cache.peek(&raw.pid).cloned();
        let hinted_parent_chain = cache.parent_chain_from_hint(payload_meta.parent_pid);
        let hinted_parent_name = payload_meta
            .parent_process_hint
            .clone()
            .or_else(|| cache.parent_name_from_hint(payload_meta.parent_pid));
        let process_exe = cached
            .as_ref()
            .and_then(|entry| entry.process_exe.clone())
            .or_else(|| payload_meta.process_path_hint.clone());
        let process_cmdline = cached
            .as_ref()
            .and_then(|entry| entry.process_cmdline.clone())
            .or_else(|| payload_meta.command_line_hint.clone());
        let parent_process = cached
            .as_ref()
            .and_then(|entry| entry.parent_process.clone())
            .or(hinted_parent_name);
        let parent_chain = cached
            .as_ref()
            .map(|entry| entry.parent_chain.clone())
            .filter(|chain| !chain.is_empty())
            .unwrap_or(hinted_parent_chain);

        let _ = cache.evict_process(raw.pid);
        return EnrichedEvent {
            event: raw,
            process_exe,
            process_exe_sha256: None,
            process_cmdline,
            parent_process,
            parent_chain,
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

    let entry = cache.process_entry(&raw, &payload_meta);

    let file_path = payload_meta
        .file_path
        .clone()
        .or_else(|| {
            cache.file_path_from_object(
                payload_meta.file_object.as_deref(),
                payload_meta.file_object_secondary.as_deref(),
            )
        })
        .or_else(|| {
            matches!(raw.event_type, EventType::ModuleLoad)
                .then(|| normalize_windows_path(&raw.payload))
        });

    cache.remember_file_object_path(
        payload_meta.file_object.as_deref(),
        payload_meta.file_object_secondary.as_deref(),
        file_path.as_deref(),
    );

    let mut process_exe = entry
        .process_exe
        .clone()
        .or_else(|| payload_meta.process_path_hint.clone());
    if process_exe
        .as_deref()
        .map(is_weak_windows_identity)
        .unwrap_or(true)
    {
        if let Some(inferred) = file_path
            .as_deref()
            .and_then(infer_windows_process_exe_from_file_path)
        {
            process_exe = Some(inferred.to_string());
            cache.remember_inferred_process_exe(raw.pid, inferred.to_string());
        }
    }

    let process_exe_sha256 = process_exe.as_deref().and_then(|path| {
        if cache.is_excluded_for_expensive_checks(None, Some(path)) {
            None
        } else {
            cache.hash_for_path(path)
        }
    });

    let file_sha256 = if cache.strict_budget_mode {
        None
    } else {
        let primary = file_path.as_deref().and_then(|path| {
            if cache.is_excluded_for_expensive_checks(Some(path), process_exe.as_deref()) {
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
                    if cache.is_excluded_for_expensive_checks(Some(path), process_exe.as_deref()) {
                        None
                    } else {
                        cache.hash_for_path_churn_aware(path)
                    }
                })
        })
    };

    // Windows does not use containers in the same way as Linux.
    EnrichedEvent {
        event: raw,
        process_exe,
        process_exe_sha256,
        process_cmdline: entry
            .process_cmdline
            .or_else(|| payload_meta.command_line_hint.clone()),
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
    process_path_hint: Option<String>,
    command_line_hint: Option<String>,
    parent_pid: Option<u32>,
    parent_process_hint: Option<String>,
    file_object: Option<String>,
    file_object_secondary: Option<String>,
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

    let file_path = match *event_type {
        EventType::FileOpen
        | EventType::FileWrite
        | EventType::FileRename
        | EventType::FileUnlink => fields
            .get("path")
            .or_else(|| fields.get("file"))
            .or_else(|| fields.get("src"))
            .map(|value| normalize_windows_path(value)),
        EventType::ModuleLoad => fields
            .get("path")
            .or_else(|| fields.get("file"))
            .map(|value| normalize_windows_path(value)),
        _ => None,
    };

    let process_path_hint = match *event_type {
        EventType::ProcessExec | EventType::ProcessExit => fields
            .get("process_path")
            .or_else(|| fields.get("process_image"))
            .or_else(|| fields.get("path"))
            .or_else(|| fields.get("exe"))
            .or_else(|| fields.get("image"))
            .map(|value| normalize_windows_path(value)),
        _ => fields
            .get("process_path")
            .or_else(|| fields.get("process_image"))
            .or_else(|| fields.get("exe"))
            .or_else(|| fields.get("image"))
            .map(|value| normalize_windows_path(value)),
    };

    let mut primary_file_object = fields
        .get("file_object")
        .or_else(|| fields.get("fileobj"))
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    let mut secondary_file_object = fields
        .get("file_key")
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    if primary_file_object.is_none() {
        primary_file_object = secondary_file_object.clone();
        secondary_file_object = None;
    }

    let mut metadata = PayloadMetadata {
        file_path,
        file_path_secondary: fields
            .get("dst")
            .or_else(|| fields.get("target"))
            .or_else(|| fields.get("new"))
            .map(|value| normalize_windows_path(value)),
        process_path_hint,
        command_line_hint: fields
            .get("cmdline")
            .or_else(|| fields.get("command_line"))
            .map(|value| sanitize_windows_command_line(value)),
        parent_pid: fields
            .get("ppid")
            .or_else(|| fields.get("parent_pid"))
            .and_then(|value| parse_windows_u32_hint(value)),
        parent_process_hint: fields
            .get("parent_process")
            .or_else(|| fields.get("parent_process_name"))
            .or_else(|| fields.get("parent_name"))
            .map(|value| process_basenameish(value)),
        file_object: primary_file_object,
        file_object_secondary: secondary_file_object,
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

    if matches!(event_type, EventType::FileWrite) {
        metadata.file_write = true;
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
        let value = decode_payload_value(value.trim().trim_matches('"'));
        if !key.is_empty() && !value.is_empty() {
            out.insert(key, value);
        }
    }
    out
}

fn decode_payload_value(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = &raw[index + 1..index + 3];
            if let Ok(value) = u8::from_str_radix(hex, 16) {
                out.push(value as char);
                index += 3;
                continue;
            }
        }

        if let Some(ch) = raw[index..].chars().next() {
            out.push(ch);
            index += ch.len_utf8();
        } else {
            break;
        }
    }

    out
}

fn parse_payload_fallback(event_type: &EventType, payload: &str) -> PayloadMetadata {
    match event_type {
        EventType::FileOpen | EventType::FileWrite => PayloadMetadata {
            file_path: Some(normalize_windows_path(payload)),
            file_write: matches!(event_type, EventType::FileWrite),
            ..PayloadMetadata::default()
        },
        EventType::FileRename => PayloadMetadata {
            file_path: Some(normalize_windows_path(payload)),
            ..PayloadMetadata::default()
        },
        EventType::FileUnlink => PayloadMetadata {
            file_path: Some(normalize_windows_path(payload)),
            ..PayloadMetadata::default()
        },
        EventType::DnsQuery => PayloadMetadata {
            dst_domain: Some(sanitize_windows_text(payload)),
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
            command_line_hint: Some(sanitize_windows_command_line(payload)),
            ..PayloadMetadata::default()
        },
        EventType::ProcessExit => PayloadMetadata::default(),
        EventType::ModuleLoad => PayloadMetadata {
            file_path: Some(normalize_windows_path(payload)),
            ..PayloadMetadata::default()
        },
        EventType::LsmBlock => PayloadMetadata {
            command_line_hint: Some(sanitize_windows_command_line(payload)),
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
        if !ip.contains(':') {
            if let Ok(port) = port.parse::<u16>() {
                return (Some(ip.to_string()), Some(port));
            }
        }
    }

    (Some(trimmed.to_string()), None)
}

fn sanitize_windows_text(raw: &str) -> String {
    raw.chars()
        .filter(|ch| !ch.is_control())
        .collect::<String>()
        .trim()
        .trim_matches('"')
        .to_string()
}

fn sanitize_windows_command_line(raw: &str) -> String {
    raw.chars()
        .filter(|ch| !ch.is_control())
        .collect::<String>()
        .trim()
        .to_string()
}

fn normalize_windows_path(raw: &str) -> String {
    let mut value = sanitize_windows_text(raw).replace('/', "\\");
    if let Some(stripped) = value.strip_prefix(r"\\?\") {
        value = stripped.to_string();
    }
    if let Some(stripped) = value.strip_prefix(r"\??\") {
        value = stripped.to_string();
    }
    if let Some(stripped) = value.strip_prefix(r"\Device\Mup\") {
        value = format!(r"\\{}", stripped.trim_start_matches('\\'));
    }
    while value.contains("\\\\") && !value.starts_with(r"\\") {
        value = value.replace("\\\\", "\\");
    }
    value = translate_harddisk_volume_to_dos(&value);
    value.trim().trim_matches('"').to_string()
}

fn translate_harddisk_volume_to_dos(raw: &str) -> String {
    let trimmed = raw.trim_start_matches('\\');
    let lowered = trimmed.to_ascii_lowercase();

    for prefix in ["device\\harddiskvolume", "harddiskvolume", "rddiskvolume"] {
        if let Some(rest) = lowered.strip_prefix(prefix) {
            let digits_len = rest.chars().take_while(|ch| ch.is_ascii_digit()).count();
            if digits_len == 0 {
                continue;
            }
            let remainder = &trimmed[prefix.len() + digits_len..];
            if remainder.starts_with('\\') {
                return format!(r"C:{}", remainder);
            }
        }
    }

    raw.to_string()
}

fn process_basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn process_basenameish(raw: &str) -> String {
    process_basename(&sanitize_windows_text(raw)).to_string()
}

fn parse_windows_u32_hint(raw: &str) -> Option<u32> {
    let trimmed = raw.trim().trim_matches('"');
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16)
            .ok()
            .and_then(|value| u32::try_from(value).ok());
    }
    trimmed.parse::<u32>().ok()
}

fn process_name_from_cmdline(cmdline: &str) -> Option<&str> {
    let first = cmdline
        .split(['\0', ' '])
        .find(|segment| !segment.trim().is_empty())?
        .trim();
    if first.is_empty() {
        None
    } else {
        Some(process_basename(first))
    }
}

fn should_upgrade_windows_cmdline(existing: Option<&str>, candidate: &str) -> bool {
    let candidate = candidate.trim();
    if candidate.is_empty() {
        return false;
    }

    let Some(existing) = existing.map(str::trim).filter(|value| !value.is_empty()) else {
        return true;
    };

    if existing.eq_ignore_ascii_case(candidate) {
        return false;
    }

    let existing_score = windows_cmdline_signal_score(existing);
    let candidate_score = windows_cmdline_signal_score(candidate);
    candidate_score > existing_score || candidate.len() > existing.len().saturating_add(16)
}

fn windows_cmdline_signal_score(cmdline: &str) -> usize {
    let trimmed = cmdline.trim();
    if trimmed.is_empty() {
        return 0;
    }

    let token_count = trimmed.split_whitespace().take(6).count();
    let mut score = 0;
    if token_count > 1 {
        score += 2;
    }
    if trimmed.contains('\\') || trimmed.contains('/') {
        score += 1;
    }
    if trimmed.len() > 40 {
        score += 1;
    }
    if trimmed.contains('"') || trimmed.contains('=') {
        score += 1;
    }
    score
}

fn process_name_from_entry(entry: &ProcessCacheEntry) -> Option<String> {
    entry
        .process_exe
        .as_deref()
        .map(process_basename)
        .map(ToString::to_string)
        .or_else(|| {
            entry
                .process_cmdline
                .as_deref()
                .and_then(process_name_from_cmdline)
                .map(ToString::to_string)
        })
        .or_else(|| entry.parent_process.clone())
        .filter(|value| !value.trim().is_empty())
}

fn infer_windows_process_exe_from_file_path(path: &str) -> Option<&'static str> {
    let mut normalized = path.replace('\\', "/").to_ascii_lowercase();
    while normalized.contains("//") {
        normalized = normalized.replace("//", "/");
    }

    if normalized.is_empty() {
        return None;
    }

    if normalized.contains("__psscriptpolicytest_")
        || normalized.contains("windowspowershell/v1.0")
        || normalized.contains("windows powershell")
        || normalized.contains("powershell/modules")
        || normalized.contains("/psreadline/")
    {
        return Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
    }

    if normalized.contains("program files/openssh")
        || normalized.contains("windows/system32/openssh")
    {
        return Some(r"C:\Program Files\OpenSSH\sshd.exe");
    }

    None
}

fn is_weak_windows_identity(name: &str) -> bool {
    let lowered = name.trim().to_ascii_lowercase();
    lowered.is_empty()
        || lowered == "unknown"
        || lowered == "system"
        || matches!(
            lowered.as_str(),
            "conhost.exe" | "conhost" | "csrss.exe" | "csrss"
        )
}

fn normalize_exclusions(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| {
            normalize_windows_path(&value)
                .replace('\\', "/")
                .to_ascii_lowercase()
        })
        .filter(|value| !value.is_empty())
        .collect()
}

fn matches_any_exclusion(value: &str, exclusions: &[String]) -> bool {
    if exclusions.is_empty() {
        return false;
    }

    let lowered = normalize_windows_path(value)
        .replace('\\', "/")
        .to_ascii_lowercase();
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

// ── Helpers ────────────────────────────────────────────────────────────

fn capacity_from(raw: usize) -> NonZeroUsize {
    let bounded = raw.max(128);
    NonZeroUsize::new(bounded).expect("cache capacity is always non-zero")
}

#[cfg(test)]
mod tests {
    use super::{
        enrich_event_with_cache, normalize_windows_path, parse_payload_metadata, EnrichmentCache,
        EventType, RawEvent,
    };
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_path(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "eguard-windows-{}-{}-{}",
            label,
            std::process::id(),
            nonce
        ))
    }

    #[test]
    fn process_exec_payload_uses_path_as_process_hint() {
        let metadata = parse_payload_metadata(
            &EventType::ProcessExec,
            r#"path=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe;cmdline=powershell -enc AAA;ppid=321"#,
        );
        assert_eq!(
            metadata.process_path_hint.as_deref(),
            Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        );
        assert_eq!(
            metadata.command_line_hint.as_deref(),
            Some("powershell -enc AAA")
        );
        assert_eq!(metadata.parent_pid, Some(321));
    }

    #[test]
    fn process_exec_payload_decodes_percent_escaped_command_line_and_parent() {
        let metadata = parse_payload_metadata(
            &EventType::ProcessExec,
            r#"path=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe;cmdline=powershell.exe -Command %22Get-Process%3B Get-Service%22;ppid=0x3c8;parent_process=C:\Windows\System32\cmd.exe"#,
        );
        assert_eq!(metadata.parent_pid, Some(968));
        assert_eq!(metadata.parent_process_hint.as_deref(), Some("cmd.exe"));
        assert_eq!(
            metadata.command_line_hint.as_deref(),
            Some(r#"powershell.exe -Command "Get-Process; Get-Service""#)
        );
    }

    #[test]
    fn enrich_windows_process_event_uses_payload_hints_for_cache() {
        let raw = RawEvent {
            event_type: EventType::ProcessExec,
            pid: 4242,
            uid: 0,
            ts_ns: 1,
            payload: r#"path=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe;cmdline=powershell -enc AAA;ppid=321"#
                .to_string(),
        };

        let mut cache = EnrichmentCache::default();
        let enriched = enrich_event_with_cache(raw, &mut cache);

        assert_eq!(
            enriched.process_exe.as_deref(),
            Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        );
        assert_eq!(
            enriched.process_cmdline.as_deref(),
            Some("powershell -enc AAA")
        );
        assert_eq!(enriched.parent_chain.first().copied(), Some(321));
        assert_eq!(
            enriched.file_path, None,
            "process start payloads should seed process identity without reusing it as a file object"
        );
    }

    #[test]
    fn process_exec_parent_process_hint_beats_unknown_parent() {
        let raw = RawEvent {
            event_type: EventType::ProcessExec,
            pid: 4243,
            uid: 0,
            ts_ns: 2,
            payload: r#"path=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe;cmdline=powershell -NoProfile;ppid=0x3c8;parent_process=C:\Windows\System32\cmd.exe"#
                .to_string(),
        };

        let mut cache = EnrichmentCache::default();
        let enriched = enrich_event_with_cache(raw, &mut cache);

        assert_eq!(enriched.parent_chain.first().copied(), Some(968));
        assert_eq!(enriched.parent_process.as_deref(), Some("cmd.exe"));
    }

    #[test]
    fn authoritative_process_exec_upgrades_weak_cached_cmdline() {
        let mut cache = EnrichmentCache::default();

        let weak = RawEvent {
            event_type: EventType::ProcessExec,
            pid: 4244,
            uid: 0,
            ts_ns: 1,
            payload: "powershell.exe".to_string(),
        };
        let _ = enrich_event_with_cache(weak, &mut cache);

        let richer = RawEvent {
            event_type: EventType::ProcessExec,
            pid: 4244,
            uid: 0,
            ts_ns: 2,
            payload: r#"path=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe;cmdline=powershell.exe -EncodedCommand AAA;ppid=0x3c8;parent_process=C:\Windows\System32\cmd.exe"#
                .to_string(),
        };
        let enriched = enrich_event_with_cache(richer, &mut cache);

        assert_eq!(
            enriched.process_cmdline.as_deref(),
            Some("powershell.exe -EncodedCommand AAA")
        );
        assert_eq!(enriched.parent_process.as_deref(), Some("cmd.exe"));
    }

    #[test]
    fn process_exit_reuses_cached_process_context_before_eviction() {
        let mut cache = EnrichmentCache::default();

        let test_pid = 9_999_991;
        let exec = RawEvent {
            event_type: EventType::ProcessExec,
            pid: test_pid,
            uid: 0,
            ts_ns: 1,
            payload: r#"path=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe;cmdline=powershell.exe -NoProfile -File C:\Windows\Temp\demo.ps1;ppid=0x3c8;parent_process=C:\Windows\System32\cmd.exe"#
                .to_string(),
        };
        let _ = enrich_event_with_cache(exec, &mut cache);

        let exit = RawEvent {
            event_type: EventType::ProcessExit,
            pid: test_pid,
            uid: 0,
            ts_ns: 2,
            payload: String::new(),
        };
        let enriched = enrich_event_with_cache(exit, &mut cache);

        assert_eq!(
            enriched.process_exe.as_deref(),
            Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        );
        assert_eq!(
            enriched.process_cmdline.as_deref(),
            Some("powershell.exe -NoProfile -File C:\\Windows\\Temp\\demo.ps1")
        );
        assert_eq!(enriched.parent_process.as_deref(), Some("cmd.exe"));
        assert_eq!(enriched.parent_chain.first().copied(), Some(968));
        assert!(
            !cache.evict_process(test_pid),
            "process exit should evict the cached PID after reusing its identity"
        );
    }

    #[test]
    fn file_open_payload_path_does_not_pollute_process_identity() {
        let raw = RawEvent {
            event_type: EventType::FileOpen,
            pid: 9001,
            uid: 0,
            ts_ns: 2,
            payload: r"path=C:\Windows\Temp\artifact.txt".to_string(),
        };

        let mut cache = EnrichmentCache::default();
        let enriched = enrich_event_with_cache(raw, &mut cache);

        assert_eq!(
            enriched.file_path.as_deref(),
            Some(r"C:\Windows\Temp\artifact.txt")
        );
        assert!(
            enriched
                .process_exe
                .as_deref()
                .map(|value| !value.eq_ignore_ascii_case(r"C:\Windows\Temp\artifact.txt"))
                .unwrap_or(true),
            "file object paths should not be reused as process image hints"
        );
    }

    #[test]
    fn weak_windows_file_event_infers_powershell_process_exe() {
        let raw = RawEvent {
            event_type: EventType::FileOpen,
            pid: 424_242,
            uid: 0,
            ts_ns: 3,
            payload: r"path=C:\Windows\System32\WindowsPowerShell\v1.0\Modules\ServerManager\ServerManager.psd1".to_string(),
        };

        let mut cache = EnrichmentCache::default();
        let enriched = enrich_event_with_cache(raw, &mut cache);

        assert_eq!(
            enriched.process_exe.as_deref(),
            Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        );
    }

    #[test]
    fn inferred_powershell_identity_sticks_for_same_pid() {
        let mut cache = EnrichmentCache::default();

        let first = RawEvent {
            event_type: EventType::FileOpen,
            pid: 424_243,
            uid: 0,
            ts_ns: 4,
            payload: r"path=C:\Windows\System32\WindowsPowerShell\v1.0\Modules\ServerManager\ServerManager.psd1".to_string(),
        };
        let _ = enrich_event_with_cache(first, &mut cache);

        let second = RawEvent {
            event_type: EventType::FileOpen,
            pid: 424_243,
            uid: 0,
            ts_ns: 5,
            payload: r"path=C:\Windows\System32\ncrypt.dll".to_string(),
        };
        let enriched = enrich_event_with_cache(second, &mut cache);

        assert_eq!(
            enriched.process_exe.as_deref(),
            Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        );
    }

    #[test]
    fn inferred_identity_does_not_stick_to_system_pid() {
        let mut cache = EnrichmentCache::default();

        let first = RawEvent {
            event_type: EventType::FileOpen,
            pid: 4,
            uid: 0,
            ts_ns: 4,
            payload: r"path=C:\Windows\System32\WindowsPowerShell\v1.0\Modules\ServerManager\ServerManager.psd1".to_string(),
        };
        let first_enriched = enrich_event_with_cache(first, &mut cache);
        assert_eq!(
            first_enriched.process_exe.as_deref(),
            Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        );

        let second = RawEvent {
            event_type: EventType::FileOpen,
            pid: 4,
            uid: 0,
            ts_ns: 5,
            payload: r"path=C:\Windows\System32\drivers\etc\hosts".to_string(),
        };
        let second_enriched = enrich_event_with_cache(second, &mut cache);

        assert!(
            second_enriched
                .process_exe
                .as_deref()
                .map(|value| !value.eq_ignore_ascii_case(
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
                ))
                .unwrap_or(true),
            "system pid entries should not retain inferred userland identities across unrelated events"
        );
    }

    #[test]
    fn enrich_windows_tcp_event_parses_endpoint_from_payload() {
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
    fn strict_budget_mode_skips_file_hashing_for_windows_events() {
        let path = unique_temp_path("strict-budget");
        fs::write(&path, b"payload").expect("write payload");

        let raw = RawEvent {
            event_type: EventType::FileWrite,
            pid: std::process::id(),
            uid: 0,
            ts_ns: 10,
            payload: format!("path={}", path.to_string_lossy()),
        };

        let mut cache = EnrichmentCache::default();
        cache.set_budget_mode(true);
        let enriched = enrich_event_with_cache(raw, &mut cache);

        assert_eq!(enriched.file_sha256, None);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn expensive_path_exclusion_skips_windows_hashing() {
        let path = unique_temp_path("path-exclusion");
        fs::write(&path, b"payload").expect("write payload");

        let mut cache = EnrichmentCache::default();
        cache.set_expensive_check_exclusions(vec![path.to_string_lossy().to_string()], Vec::new());

        let raw = RawEvent {
            event_type: EventType::FileWrite,
            pid: std::process::id(),
            uid: 0,
            ts_ns: 11,
            payload: format!("path={}", path.to_string_lossy()),
        };

        let enriched = enrich_event_with_cache(raw, &mut cache);
        assert_eq!(enriched.file_sha256, None);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn expensive_path_exclusion_normalizes_windows_style_separators() {
        let path = unique_temp_path("path-exclusion-windows-separators");
        fs::write(&path, b"payload").expect("write payload");

        let windows_style = path.to_string_lossy().replace('/', "\\");

        let mut cache = EnrichmentCache::default();
        cache.set_expensive_check_exclusions(vec![windows_style], Vec::new());

        let raw = RawEvent {
            event_type: EventType::FileWrite,
            pid: std::process::id(),
            uid: 0,
            ts_ns: 12,
            payload: format!("path={}", path.to_string_lossy()),
        };

        let enriched = enrich_event_with_cache(raw, &mut cache);
        assert_eq!(enriched.file_sha256, None);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn hash_finalize_delay_defers_windows_churn_hash_until_stable() {
        let path = unique_temp_path("finalize-delay");
        fs::write(&path, b"v1").expect("write v1 payload");

        let mut cache = EnrichmentCache::default();
        cache.set_hash_finalize_delay_ms(20);

        let first = cache.hash_for_path_churn_aware(&path.to_string_lossy());
        assert_eq!(first, None, "first churn-aware hash should defer");

        std::thread::sleep(std::time::Duration::from_millis(30));
        let second = cache.hash_for_path_churn_aware(&path.to_string_lossy());
        assert!(second.is_some(), "hash should finalize after delay");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn file_write_recovers_path_from_file_object_cache() {
        let path = unique_temp_path("file-object-cache");
        fs::write(&path, b"payload").expect("write payload");
        let normalized = path.to_string_lossy().replace('/', "\\");

        let mut cache = EnrichmentCache::default();
        let open = RawEvent {
            event_type: EventType::FileOpen,
            pid: 77,
            uid: 0,
            ts_ns: 20,
            payload: format!("file_object=0x99;path={normalized}"),
        };
        let _ = enrich_event_with_cache(open, &mut cache);

        let write = RawEvent {
            event_type: EventType::FileWrite,
            pid: 77,
            uid: 0,
            ts_ns: 21,
            payload: "file_object=0x99;size=7".to_string(),
        };
        let enriched = enrich_event_with_cache(write, &mut cache);

        assert_eq!(
            enriched.file_path.as_deref(),
            Some(normalized.as_str()),
            "file write should recover file path from prior file_object mapping"
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn file_write_recovers_path_from_file_key_cache() {
        let path = unique_temp_path("file-key-cache");
        fs::write(&path, b"payload").expect("write payload");
        let normalized = path.to_string_lossy().replace('/', "\\");

        let mut cache = EnrichmentCache::default();
        let name_event = RawEvent {
            event_type: EventType::FileOpen,
            pid: 88,
            uid: 0,
            ts_ns: 30,
            payload: format!("file_key=0x55;path={normalized}"),
        };
        let _ = enrich_event_with_cache(name_event, &mut cache);

        let write = RawEvent {
            event_type: EventType::FileWrite,
            pid: 88,
            uid: 0,
            ts_ns: 31,
            payload: "file_object=0x99;file_key=0x55;size=7".to_string(),
        };
        let enriched = enrich_event_with_cache(write, &mut cache);

        assert_eq!(
            enriched.file_path.as_deref(),
            Some(normalized.as_str()),
            "file write should recover file path from prior file_key mapping"
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn normalize_windows_path_strips_common_kernel_prefixes() {
        assert_eq!(
            normalize_windows_path(r"\\?\C:\Windows\Temp\a.exe"),
            r"C:\Windows\Temp\a.exe"
        );
        assert_eq!(
            normalize_windows_path("\u{0007}\\??\\C:\\Windows\\Temp\\b.exe"),
            r"C:\Windows\Temp\b.exe"
        );
        assert_eq!(
            normalize_windows_path(r"\Device\HarddiskVolume1\Windows\System32\conhost.exe"),
            r"C:\Windows\System32\conhost.exe"
        );
        assert_eq!(
            normalize_windows_path(r"rddiskVolume1\Windows\Temp\sample.txt"),
            r"C:\Windows\Temp\sample.txt"
        );
    }
}
