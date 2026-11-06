use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, Weak};

mod cache;
mod literal;
use cache::FileKey;
use literal::parse_rules;

use crate::types::{EventClass, TelemetryEvent};

const DEFAULT_MAX_SCAN_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaraHit {
    pub rule_name: String,
    pub source: String,
    pub matched_literal: String,
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

trait YaraBackend: Send {
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
    verdicts: Mutex<HashMap<FileKey, Vec<YaraHit>>>,
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
        Self {
            backend: default_backend(),
            max_scan_bytes: DEFAULT_MAX_SCAN_BYTES,
            excluded_path_prefixes: load_excluded_path_prefixes(),
            verdicts: Mutex::new(HashMap::new()),
        }
    }

    pub fn with_max_scan_bytes(max_scan_bytes: usize) -> Self {
        Self {
            backend: default_backend(),
            max_scan_bytes: max_scan_bytes.max(4096),
            excluded_path_prefixes: load_excluded_path_prefixes(),
            verdicts: Mutex::new(HashMap::new()),
        }
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
        let loaded = self.backend.load_rules_str(source)?;
        self.verdicts
            .get_mut()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
        Ok(loaded)
    }

    pub fn load_rules_from_dir(&mut self, dir: &Path) -> Result<usize> {
        let mut entries = Vec::new();
        let reader = fs::read_dir(dir)
            .map_err(|err| YaraError::Io(format!("read_dir {}: {}", dir.display(), err)))?;
        for entry in reader {
            let entry = entry.map_err(|err| {
                YaraError::Io(format!("iterate dir entry {}: {}", dir.display(), err))
            })?;
            let path = entry.path();
            if is_yara_file(&path) {
                entries.push(path);
            }
        }
        entries.sort();

        let mut loaded = 0usize;
        for path in entries {
            let src = fs::read_to_string(&path)
                .map_err(|err| YaraError::Io(format!("read {}: {}", path.display(), err)))?;
            loaded += self.load_rules_str(&src)?;
        }
        Ok(loaded)
    }

    /// Scan raw bytes with all loaded YARA rules.
    ///
    /// `source` is an identifier for the data source (e.g., file path,
    /// "mem:PID:0xADDR" for memory regions).
    pub fn scan_bytes(&self, source: &str, bytes: &[u8]) -> Vec<YaraHit> {
        dedup_hits(self.backend.scan_bytes(source, bytes))
    }

    pub fn scan_event(&self, event: &TelemetryEvent) -> Vec<YaraHit> {
        let Some(path) = event.file_path.as_deref() else {
            return Vec::new();
        };
        if self.is_excluded_path(path)
            || (event.event_class == EventClass::ProcessExec && is_excluded_process_exec_path(path))
            || !is_scannable_regular_file(Path::new(path))
        {
            return Vec::new();
        }
        // Use one open handle for identity, content and post-read metadata.
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // A path replaced by a FIFO after stat must not block the event loop.
            options.custom_flags(libc::O_NONBLOCK);
        }
        let Ok(mut file) = options.open(path) else {
            return Vec::new();
        };
        let Ok(metadata) = file.metadata() else {
            return Vec::new();
        };
        if !metadata.is_file()
            || self
                .backend
                .max_file_size()
                .is_some_and(|cap| metadata.len() > cap)
        {
            return Vec::new();
        }
        let key = FileKey::new(path, &file, &metadata);
        if let Some(key) = key.as_ref() {
            if let Some(hits) = self
                .verdicts
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(key)
            {
                return hits.clone();
            }
        }
        let mut content = Vec::new();
        if (&mut file)
            .take(self.max_scan_bytes as u64)
            .read_to_end(&mut content)
            .is_err()
        {
            return Vec::new();
        }
        // A truncated file must never satisfy filesize/offset conditions.
        if metadata.len() > content.len() as u64 {
            return Vec::new();
        }
        let hits = self.scan_bytes(path, &content);
        if let Some(key) = key {
            if file
                .metadata()
                .ok()
                .and_then(|m| FileKey::new(path, &file, &m))
                .as_ref()
                == Some(&key)
            {
                let mut cache = self.verdicts.lock().unwrap_or_else(|p| p.into_inner());
                if cache.len() >= 512 {
                    cache.clear();
                }
                cache.insert(key, hits.clone());
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

fn default_backend() -> Box<dyn YaraBackend + Send> {
    #[cfg(feature = "yara-rust")]
    {
        if let Ok(backend) = YaraRustBackend::new() {
            return Box::new(backend);
        }
    }

    Box::<SubstringYaraBackend>::default()
}

#[cfg(feature = "yara-rust")]
struct YaraRustBackend {
    rulesets: Vec<yara::Rules>,
}

#[cfg(feature = "yara-rust")]
impl YaraRustBackend {
    fn new() -> Result<Self> {
        let _ = yara::Yara::new().map_err(|err| YaraError::Backend(err.to_string()))?;
        Ok(Self {
            rulesets: Vec::new(),
        })
    }
}

#[cfg(feature = "yara-rust")]
impl YaraBackend for YaraRustBackend {
    fn load_rules_str(&mut self, source: &str) -> Result<usize> {
        let compiler = yara::Compiler::new().map_err(|err| YaraError::Backend(err.to_string()))?;
        let compiler = compiler
            .add_rules_str(source)
            .map_err(|err| YaraError::Parse(err.to_string()))?;
        let rules = compiler
            .compile_rules()
            .map_err(|err| YaraError::Backend(err.to_string()))?;

        let loaded = count_rule_blocks(source);
        self.rulesets.push(rules);
        Ok(loaded.max(1))
    }

    fn scan_bytes(&self, source: &str, bytes: &[u8]) -> Vec<YaraHit> {
        let mut hits = Vec::new();

        for rules in &self.rulesets {
            let matched_rules = match rules.scan_mem(bytes, 5) {
                Ok(value) => value,
                Err(_) => continue,
            };

            for rule in matched_rules {
                if rule.strings.is_empty() {
                    hits.push(YaraHit {
                        rule_name: rule.identifier.to_string(),
                        source: source.to_string(),
                        matched_literal: "<condition>".to_string(),
                    });
                    continue;
                }

                for yr_string in rule.strings {
                    if yr_string.matches.is_empty() {
                        hits.push(YaraHit {
                            rule_name: rule.identifier.to_string(),
                            source: source.to_string(),
                            matched_literal: yr_string.identifier.to_string(),
                        });
                        continue;
                    }

                    for m in yr_string.matches {
                        hits.push(YaraHit {
                            rule_name: rule.identifier.to_string(),
                            source: source.to_string(),
                            matched_literal: String::from_utf8_lossy(&m.data).into_owned(),
                        });
                    }
                }
            }
        }

        hits
    }
}

#[derive(Debug, Clone)]
struct SubstringRule {
    name: String,
    literal: Vec<u8>,
}

#[derive(Default)]
struct SubstringYaraBackend {
    rules: Vec<Arc<Vec<SubstringRule>>>,
}

impl YaraBackend for SubstringYaraBackend {
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
            })
            .collect()
    }
}

#[cfg(feature = "yara-rust")]
fn count_rule_blocks(source: &str) -> usize {
    source
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("rule "))
        .count()
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

    fs::metadata(path)
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

fn is_excluded_process_exec_path(path: &str) -> bool {
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
        && path.get(2..).is_some_and(|p| p.starts_with("/windows/"));
    windows || path.starts_with("/system/") || path.starts_with("/usr/libexec/")
}
