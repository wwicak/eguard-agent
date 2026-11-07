use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, Weak};

mod cache;
mod dedup;
mod files;
#[cfg(any(test, not(feature = "yara-x")))]
mod literal;
#[cfg(feature = "yara-x")]
mod real;
use cache::FileKey;
use files::{is_executable, open_regular};
#[cfg(any(test, not(feature = "yara-x")))]
use literal::parse_rules;

use crate::types::{EventClass, TelemetryEvent};

const DEFAULT_MAX_SCAN_BYTES: usize = 1024 * 1024;
pub const MAX_EXECUTABLE_SCAN_BYTES: usize = 4 * 1024 * 1024;
const MAX_CACHED_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_RULE_SOURCE_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaraHit {
    pub rule_name: String,
    pub source: String,
    pub matched_literal: String,
    pub severity: crate::Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct YaraIncomplete {
    pub reason: String,
    pub path: String,
    pub sha256: String,
    pub pack_hash: String,
}

#[derive(Default)]
pub struct YaraStatus {
    size_executable: std::sync::atomic::AtomicU64,
    size_other: std::sync::atomic::AtomicU64,
    budget_executable: std::sync::atomic::AtomicU64,
    budget_other: std::sync::atomic::AtomicU64,
    scan_errors: std::sync::atomic::AtomicU64,
    compile_errors: std::sync::atomic::AtomicU64,
    incomplete_epoch: std::sync::atomic::AtomicU64,
    incomplete_evictions: std::sync::atomic::AtomicU64,
    pack_hash: Mutex<[u8; 32]>,
    pending: Mutex<Vec<YaraIncomplete>>,
    backend: Mutex<&'static str>,
}
fn incomplete_dedup() -> &'static Mutex<dedup::IncompleteDedup> {
    static DEDUP: OnceLock<Mutex<dedup::IncompleteDedup>> = OnceLock::new();
    DEDUP.get_or_init(|| Mutex::new(dedup::IncompleteDedup::default()))
}
impl YaraStatus {
    fn activate_pack(pack: [u8; 32]) {
        incomplete_dedup()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .activate(pack);
    }
    fn size_skip(&self, executable: bool) {
        (if executable {
            &self.size_executable
        } else {
            &self.size_other
        })
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    fn budget_skip(&self, executable: bool) {
        self.incomplete_epoch
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        (if executable {
            &self.budget_executable
        } else {
            &self.budget_other
        })
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    fn record_incomplete(&self, reason: &str, path: &str, digest: [u8; 32], pack: [u8; 32]) {
        self.incomplete_epoch
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.scan_errors
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (emit, evicted) = incomplete_dedup()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(pack, digest);
        if evicted {
            self.incomplete_evictions
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        if emit {
            tracing::error!(
                reason,
                path,
                "YARA scan incomplete; alert-only diagnostic queued"
            );
            self.pending
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(YaraIncomplete {
                    reason: reason.to_string(),
                    path: path.to_string(),
                    sha256: digest_hex(&digest),
                    pack_hash: digest_hex(&pack),
                });
        }
    }
    pub fn scan_error_count(&self) -> u64 {
        self.scan_errors.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub fn health(&self) -> String {
        use std::sync::atomic::Ordering::Relaxed;
        format!("yara_backend={} yara_pack={} yara_scan_errors={} yara_compile_errors={} yara_size_exec_skips={} yara_size_other_skips={} yara_budget_exec_skips={} yara_budget_other_skips={} yara_incomplete_evictions={}", *self.backend.lock().unwrap_or_else(|p| p.into_inner()),
            digest_hex(&self.pack_hash.lock().unwrap_or_else(|p|p.into_inner())), self.scan_errors.load(Relaxed),self.compile_errors.load(Relaxed),self.size_executable.load(Relaxed),self.size_other.load(Relaxed),self.budget_executable.load(Relaxed),self.budget_other.load(Relaxed),self.incomplete_evictions.load(Relaxed))
    }
}
fn digest_hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug)]
pub enum YaraError {
    Parse(String),
    Io(String),
    Backend(String),
}

impl fmt::Display for YaraError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(msg) => write!(f, "yara parse error: {}", msg),
            Self::Io(msg) => write!(f, "yara io error: {}", msg),
            Self::Backend(msg) => write!(f, "yara backend error: {}", msg),
        }
    }
}

impl std::error::Error for YaraError {}

pub type Result<T> = std::result::Result<T, YaraError>;

trait FileScanPermit {}
struct UnbudgetedFileScan;
impl FileScanPermit for UnbudgetedFileScan {}

trait YaraBackend: Send {
    fn begin_file_scan(&self, _header: &[u8]) -> Option<Box<dyn FileScanPermit>> {
        Some(Box::new(UnbudgetedFileScan))
    }
    fn name(&self) -> &'static str {
        "substring"
    }
    fn pack_hash(&self) -> [u8; 32] {
        [0; 32]
    }
    fn rule_names(&self) -> Vec<String> {
        Vec::new()
    }
    fn scan_file_bytes(&self, source: &str, bytes: &[u8]) -> Vec<YaraHit> {
        self.scan_bytes(source, bytes)
    }
    fn load_rules_str(&mut self, source: &str) -> Result<usize>;
    fn scan_bytes(&self, source: &str, bytes: &[u8]) -> Vec<YaraHit>;
    fn max_file_size(&self) -> Option<u64> {
        None
    }
}

pub struct YaraEngine {
    backend: Box<dyn YaraBackend + Send>,
    max_scan_bytes: usize,
    excluded_path_prefixes: Vec<String>,
    verdicts: Mutex<HashMap<(FileKey, [u8; 32], [u8; 32]), Vec<YaraHit>>>,
    status: Arc<YaraStatus>,
}

/// Default path prefixes excluded from YARA file scanning.
///
/// System library directories produce extreme false-positive rates with
/// community YARA rule sets (e.g., CobaltStrike, Autumn_Backdoor matching
/// benign shared objects like `libkrb5support.so`).
const DEFAULT_EXCLUDED_PATH_PREFIXES: &[&str] = &[
    "/etc/ld.so.cache",
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/lib/x86_64-linux-gnu/",
    "/lib/",
    "/lib64/",
    "/lib/x86_64-linux-gnu/",
    "/var/log/journal/",
];

/// System executable roots excluded from YARA file scans on process_exec.
///
/// Community YARA bundles frequently contain low-entropy literals that match
/// common ELF binaries (`x86`, `linux`, `file`, `http`, etc.). Scanning every
/// system executable launch causes alert storms on benign tools like `cat`,
/// `bash`, `sudo`, `systemctl`, and `sshd-session`, which masks real
/// user-space file evidence.
const DEFAULT_PROCESS_EXEC_EXCLUDED_PATH_PREFIXES: &[&str] = &[
    "/usr/bin/",
    "/bin/",
    "/usr/sbin/",
    "/sbin/",
    "/usr/libexec/",
];

impl YaraEngine {
    pub fn new() -> Self {
        let status = Arc::new(YaraStatus::default());
        let backend = default_backend(Arc::clone(&status));
        *status.backend.lock().unwrap_or_else(|p| p.into_inner()) = backend.name();
        Self {
            backend,
            max_scan_bytes: DEFAULT_MAX_SCAN_BYTES,
            excluded_path_prefixes: load_excluded_path_prefixes(),
            verdicts: Mutex::new(HashMap::new()),
            status,
        }
    }

    pub fn with_max_scan_bytes(max_scan_bytes: usize) -> Self {
        Self {
            max_scan_bytes: max_scan_bytes.clamp(4096, DEFAULT_MAX_SCAN_BYTES),
            ..Self::new()
        }
    }
    pub fn backend_name(&self) -> &'static str {
        self.backend.name()
    }
    pub fn rule_names(&self) -> Vec<String> {
        let mut names = self.backend.rule_names();
        names.sort();
        names
    }
    pub fn status_handle(&self) -> Arc<YaraStatus> {
        Arc::clone(&self.status)
    }
    pub fn take_incomplete(&self) -> Vec<YaraIncomplete> {
        std::mem::take(
            &mut *self
                .status
                .pending
                .lock()
                .unwrap_or_else(|p| p.into_inner()),
        )
    }

    pub fn add_excluded_path_prefix(&mut self, prefix: String) {
        if !self.excluded_path_prefixes.contains(&prefix) {
            self.excluded_path_prefixes.push(prefix);
        }
    }

    fn is_excluded_path(&self, path: &str) -> bool {
        if is_platform_system_path(&normalized_path(path)) {
            return true;
        }
        self.excluded_path_prefixes
            .iter()
            .any(|prefix| normalized_path(path).starts_with(&normalized_path(prefix)))
    }

    pub fn load_rules_str(&mut self, source: &str) -> Result<usize> {
        let loaded = self.backend.load_rules_str(source).map_err(|error| {
            self.status.compile_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::error!(backend = self.backend.name(), error = %error, "YARA rule compilation failed");
            error
        })?;
        *self
            .status
            .pack_hash
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = self.backend.pack_hash();
        self.verdicts
            .get_mut()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
        Ok(loaded)
    }

    pub fn load_rules_from_dir(&mut self, dir: &Path) -> Result<usize> {
        let mut entries = Vec::new();
        let mut directories = vec![(dir.to_path_buf(), 0usize)];
        let mut visited = 0usize;
        while let Some((directory, depth)) = directories.pop() {
            let reader = fs::read_dir(&directory).map_err(|err| {
                YaraError::Io(format!("read_dir {}: {}", directory.display(), err))
            })?;
            for entry in reader {
                let entry = entry.map_err(|err| YaraError::Io(err.to_string()))?;
                visited += 1;
                if visited > 1024 {
                    return Err(YaraError::Io("rule directory entry limit exceeded".into()));
                }
                let kind = entry
                    .file_type()
                    .map_err(|err| YaraError::Io(err.to_string()))?;
                if kind.is_dir() {
                    if depth >= 8 {
                        return Err(YaraError::Io("rule directory depth limit exceeded".into()));
                    }
                    directories.push((entry.path(), depth + 1));
                } else if kind.is_file() && is_yara_file(&entry.path()) {
                    entries.push(entry.path());
                }
            }
        }
        entries.sort();

        let mut loaded = 0usize;
        for path in entries {
            let file = open_regular(&path)
                .map_err(|err| YaraError::Io(format!("open {}: {}", path.display(), err)))?;
            let mut src = String::new();
            file.take(MAX_RULE_SOURCE_BYTES as u64 + 1)
                .read_to_string(&mut src)
                .map_err(|err| YaraError::Io(format!("read {}: {}", path.display(), err)))?;
            if src.len() > MAX_RULE_SOURCE_BYTES {
                return Err(YaraError::Parse("rule source byte limit exceeded".into()));
            }
            loaded += self.load_rules_str(&src)?;
        }
        Ok(loaded)
    }

    /// Scan raw bytes with all loaded YARA rules.
    ///
    /// `source` is an identifier for the data source (e.g., file path,
    /// "mem:PID:0xADDR" for memory regions).
    pub fn scan_bytes(&self, source: &str, bytes: &[u8]) -> Vec<YaraHit> {
        if bytes.len() > self.scan_cap(bytes) {
            self.status.size_skip(is_executable(bytes));
            return Vec::new();
        }
        dedup_hits(self.backend.scan_bytes(source, bytes))
    }

    pub fn scan_cap(&self, bytes: &[u8]) -> usize {
        let cap = if is_executable(bytes) {
            MAX_EXECUTABLE_SCAN_BYTES
        } else {
            self.max_scan_bytes
        };
        self.backend
            .max_file_size()
            .map_or(cap, |max| cap.min(max as usize))
    }

    pub fn scan_event(&self, event: &TelemetryEvent) -> Vec<YaraHit> {
        if event.event_class != EventClass::ProcessExec
            && !(event.event_class == EventClass::FileOpen && event.file_write)
        {
            return Vec::new();
        }
        let Some(path) = event.file_path.as_deref() else {
            return Vec::new();
        };
        if self.is_excluded_path(path)
            || (event.event_class == EventClass::ProcessExec && is_excluded_process_exec_path(path))
            || !is_scannable_regular_file(Path::new(path))
        {
            return Vec::new();
        }
        if event.file_write {
            self.verdicts
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clear();
        }
        let Ok(mut file) = open_regular(Path::new(path)) else {
            return Vec::new();
        };
        let Ok(metadata) = file.metadata() else {
            return Vec::new();
        };
        let key = FileKey::new(path, &file, &metadata);
        let mut header = [0; 4];
        let Ok(count) = file.read(&mut header) else {
            return Vec::new();
        };
        let cap = self.scan_cap(&header[..count]);
        if metadata.len() > cap as u64 {
            self.status.size_skip(is_executable(&header[..count]));
            return Vec::new();
        }
        let Some(_permit) = self.backend.begin_file_scan(&header[..count]) else {
            return Vec::new();
        };
        if count > metadata.len() as usize {
            return Vec::new();
        }
        // Fixed allocation avoids read_to_end growing a full capped buffer at EOF.
        let mut content = vec![0; metadata.len() as usize];
        content[..count].copy_from_slice(&header[..count]);
        if file.read_exact(&mut content[count..]).is_err()
            || file
                .metadata()
                .ok()
                .is_none_or(|current| current.len() != content.len() as u64)
        {
            return Vec::new();
        }
        let digest: [u8; 32] = Sha256::digest(&content).into();
        let cache_key = key.map(|key| (key, digest, self.backend.pack_hash()));
        if let Some(key) = cache_key.as_ref() {
            if !key.0.still_matches(path, &file) {
                self.status.record_incomplete(
                    "file_changed",
                    path,
                    digest,
                    self.backend.pack_hash(),
                );
                return Vec::new();
            }
            if let Some(hits) = self
                .verdicts
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(key)
            {
                return hits.clone();
            }
        }
        let epoch = self
            .status
            .incomplete_epoch
            .load(std::sync::atomic::Ordering::Relaxed);
        let hits = dedup_hits(self.backend.scan_file_bytes(path, &content));
        // Never publish a signature over content observed changing during its read/scan.
        if let Some(key) = cache_key.as_ref() {
            if !key.0.still_matches(path, &file) {
                self.status.record_incomplete(
                    "file_changed",
                    path,
                    digest,
                    self.backend.pack_hash(),
                );
                return Vec::new();
            }
        }
        // Never cache an incomplete/budget-skipped scan as a clean verdict.
        if let Some(key) = cache_key {
            if self
                .status
                .incomplete_epoch
                .load(std::sync::atomic::Ordering::Relaxed)
                == epoch
            {
                let mut cache = self.verdicts.lock().unwrap_or_else(|p| p.into_inner());
                let payload_bytes = |hits: &Vec<YaraHit>| {
                    hits.capacity() * std::mem::size_of::<YaraHit>()
                        + hits
                            .iter()
                            .map(|hit| {
                                hit.rule_name.capacity()
                                    + hit.source.capacity()
                                    + hit.matched_literal.capacity()
                            })
                            .sum::<usize>()
                };
                let new_bytes = key.0.cache_bytes() + 64 + payload_bytes(&hits);
                if cache.len() >= 512
                    || cache
                        .iter()
                        .map(|(key, hits)| key.0.cache_bytes() + 64 + payload_bytes(hits))
                        .sum::<usize>()
                        .saturating_add(new_bytes)
                        > MAX_CACHED_PAYLOAD_BYTES
                {
                    cache.clear();
                }
                if new_bytes <= MAX_CACHED_PAYLOAD_BYTES {
                    cache.insert(key, hits.clone());
                }
            }
        }
        hits
    }
}

impl Default for YaraEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn default_backend(status: Arc<YaraStatus>) -> Box<dyn YaraBackend + Send> {
    #[cfg(feature = "yara-x")]
    {
        Box::new(real::RealYaraBackend::new(status))
    }
    #[cfg(not(feature = "yara-x"))]
    {
        let _ = status;
        Box::<SubstringYaraBackend>::default()
    }
}

#[cfg(any(test, not(feature = "yara-x")))]
#[derive(Debug, Clone)]
struct SubstringRule {
    name: String,
    literal: Vec<u8>,
}

#[cfg(any(test, not(feature = "yara-x")))]
#[derive(Default)]
struct SubstringYaraBackend {
    rules: Vec<Arc<Vec<SubstringRule>>>,
    pack_hash: [u8; 32],
}

#[cfg(any(test, not(feature = "yara-x")))]
impl YaraBackend for SubstringYaraBackend {
    fn pack_hash(&self) -> [u8; 32] {
        self.pack_hash
    }
    fn rule_names(&self) -> Vec<String> {
        self.rules
            .iter()
            .flat_map(|rules| rules.iter().map(|rule| rule.name.clone()))
            .collect()
    }
    fn load_rules_str(&mut self, source: &str) -> Result<usize> {
        type SharedRules = HashMap<[u8; 32], Weak<Vec<SubstringRule>>>;
        static COMPILED: OnceLock<Mutex<SharedRules>> = OnceLock::new();
        let digest: [u8; 32] = Sha256::digest(source.as_bytes()).into();
        let mut cache = COMPILED
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let rules = match cache.get(&digest).and_then(Weak::upgrade) {
            Some(rules) => rules,
            None => {
                let rules = Arc::new(parse_rules(source)?);
                cache.retain(|_, weak| weak.strong_count() > 0);
                if cache.len() >= 512 {
                    cache.clear();
                }
                cache.insert(digest, Arc::downgrade(&rules));
                rules
            }
        };
        let loaded = rules.len();
        self.rules.push(rules);
        self.pack_hash =
            Sha256::digest([self.pack_hash.as_slice(), digest.as_slice()].concat()).into();
        Ok(loaded)
    }

    fn max_file_size(&self) -> Option<u64> {
        Some(128)
    }

    fn scan_bytes(&self, source: &str, bytes: &[u8]) -> Vec<YaraHit> {
        if bytes.len() > 128 {
            return Vec::new();
        }
        self.rules
            .iter()
            .flat_map(|rules| rules.iter())
            .filter(|rule| bytes.starts_with(&rule.literal))
            .map(|rule| YaraHit {
                rule_name: rule.name.clone(),
                source: source.to_string(),
                matched_literal: String::from_utf8_lossy(&rule.literal).into_owned(),
                severity: crate::Confidence::High,
            })
            .collect()
    }
}

fn is_yara_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("yar") | Some("yara")
    )
}

fn is_scannable_regular_file(path: &Path) -> bool {
    let normalized = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    if normalized.starts_with("/proc/")
        || normalized.starts_with("/sys/")
        || normalized.starts_with("/dev/")
        || normalized.starts_with("/run/")
        || normalized.starts_with("/var/run/")
    {
        return false;
    }

    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
}

fn load_excluded_path_prefixes() -> Vec<String> {
    if let Ok(val) = std::env::var("EGUARD_YARA_EXCLUDED_PATHS") {
        let val = val.trim();
        if !val.is_empty() {
            return val.split(',').map(|s| s.trim().to_string()).collect();
        }
    }
    DEFAULT_EXCLUDED_PATH_PREFIXES
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

pub(crate) fn is_excluded_process_exec_path(path: &str) -> bool {
    let path = normalized_path(path);
    DEFAULT_PROCESS_EXEC_EXCLUDED_PATH_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(&normalized_path(prefix)))
        || is_platform_system_path(&path)
}

fn dedup_hits(hits: Vec<YaraHit>) -> Vec<YaraHit> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for hit in hits {
        let key = format!("{}:{}:{}", hit.rule_name, hit.source, hit.matched_literal);
        if seen.insert(key) {
            out.push(hit);
        }
    }
    out
}

#[cfg(test)]
mod tests;

fn normalized_path(path: &str) -> String {
    path.replace('\\', "/").to_ascii_lowercase()
}

fn is_platform_system_path(path: &str) -> bool {
    // Match any Windows system drive, not just C:; keep component boundaries.
    let windows = path.as_bytes().get(1) == Some(&b':')
        && path.get(2..).is_some_and(|p| {
            [
                "/windows/system32/",
                "/windows/syswow64/",
                "/windows/winsxs/",
            ]
            .iter()
            .any(|root| p.starts_with(root))
        });
    // Windows Temp/Tasks and macOS Data volumes contain user-controlled files.
    windows
        || path.starts_with("/system/library/")
        || path.starts_with("/system/applications/")
        || path.starts_with("/usr/libexec/")
}
