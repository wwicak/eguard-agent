use std::fmt;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::types::TelemetryEvent;

const DEFAULT_MAX_SCAN_BYTES: usize = 1024 * 1024;

/// Maximum wall-clock time the SubstringYaraBackend is allowed to spend
/// scanning a single buffer.  Matches the 5-second timeout used by
/// `YaraRustBackend::scan_mem`.
const SUBSTRING_SCAN_BUDGET: Duration = Duration::from_secs(5);

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
}

pub struct YaraEngine {
    backend: Box<dyn YaraBackend + Send>,
    max_scan_bytes: usize,
    excluded_path_prefixes: Vec<String>,
}

/// Default path prefixes excluded from YARA file scanning.
///
/// System library directories produce extreme false-positive rates with
/// community YARA rule sets (e.g., CobaltStrike, Autumn_Backdoor matching
/// benign shared objects like `libkrb5support.so`).
const DEFAULT_EXCLUDED_PATH_PREFIXES: &[&str] = &[
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/lib/x86_64-linux-gnu/",
    "/lib/",
    "/lib64/",
    "/lib/x86_64-linux-gnu/",
];

impl YaraEngine {
    pub fn new() -> Self {
        Self {
            backend: default_backend(),
            max_scan_bytes: DEFAULT_MAX_SCAN_BYTES,
            excluded_path_prefixes: load_excluded_path_prefixes(),
        }
    }

    pub fn with_max_scan_bytes(max_scan_bytes: usize) -> Self {
        Self {
            backend: default_backend(),
            max_scan_bytes: max_scan_bytes.max(4096),
            excluded_path_prefixes: load_excluded_path_prefixes(),
        }
    }

    pub fn add_excluded_path_prefix(&mut self, prefix: String) {
        if !self.excluded_path_prefixes.contains(&prefix) {
            self.excluded_path_prefixes.push(prefix);
        }
    }

    fn is_excluded_path(&self, path: &str) -> bool {
        self.excluded_path_prefixes
            .iter()
            .any(|prefix| path.starts_with(prefix.as_str()))
    }

    pub fn load_rules_str(&mut self, source: &str) -> Result<usize> {
        self.backend.load_rules_str(source)
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
        let mut hits = Vec::new();

        // Only scan file content, not command lines.  Command-line string
        // scanning produces extreme false-positive rates with community rule
        // sets (common strings like "bash", "/bin/", "GET" match thousands
        // of rules on every process exec).
        if let Some(path) = event.file_path.as_deref() {
            // Skip system library directories to avoid false positives from
            // broad community rules matching benign shared objects.
            if self.is_excluded_path(path) {
                return hits;
            }
            if let Ok(content) = read_limited_file(Path::new(path), self.max_scan_bytes) {
                hits.extend(self.backend.scan_bytes(path, &content));
            }
        }

        dedup_hits(hits)
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
    literals: Vec<Vec<u8>>,
}

#[derive(Default)]
struct SubstringYaraBackend {
    rules: Vec<SubstringRule>,
}

impl YaraBackend for SubstringYaraBackend {
    fn load_rules_str(&mut self, source: &str) -> Result<usize> {
        let parsed = parse_rules(source)?;
        let loaded = parsed.len();
        self.rules.extend(parsed);
        Ok(loaded)
    }

    fn scan_bytes(&self, source: &str, bytes: &[u8]) -> Vec<YaraHit> {
        let mut hits = Vec::new();
        let deadline = Instant::now() + SUBSTRING_SCAN_BUDGET;
        for (idx, rule) in self.rules.iter().enumerate() {
            // Check the deadline every 64 rules to avoid calling Instant::now
            // on every iteration while still bailing out promptly.
            if idx & 63 == 63 && Instant::now() >= deadline {
                break;
            }
            for literal in &rule.literals {
                if contains_subslice(bytes, literal) {
                    hits.push(YaraHit {
                        rule_name: rule.name.clone(),
                        source: source.to_string(),
                        matched_literal: String::from_utf8_lossy(literal).into_owned(),
                    });
                    break;
                }
            }
        }
        hits
    }
}

fn parse_rules(source: &str) -> Result<Vec<SubstringRule>> {
    let mut out = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_literals: Vec<Vec<u8>> = Vec::new();
    let mut in_rule = false;

    for raw_line in source.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }

        if !in_rule {
            if line.starts_with("rule ") {
                let name = parse_rule_name(line).ok_or_else(|| {
                    YaraError::Parse(format!("invalid rule declaration: '{}'", line))
                })?;
                current_name = Some(name);
                current_literals.clear();
                in_rule = true;
            }
            continue;
        }

        if line.starts_with('}') || line.ends_with('}') {
            let name = current_name
                .take()
                .ok_or_else(|| YaraError::Parse("rule close without rule name".to_string()))?;
            if current_literals.is_empty() {
                return Err(YaraError::Parse(format!(
                    "rule '{}' has no quoted string literals",
                    name
                )));
            }
            out.push(SubstringRule {
                name,
                literals: std::mem::take(&mut current_literals),
            });
            in_rule = false;
            continue;
        }

        if let Some(literal) = parse_quoted_literal(line) {
            current_literals.push(literal.into_bytes());
        }
    }

    if in_rule {
        return Err(YaraError::Parse("unterminated rule block".to_string()));
    }
    if out.is_empty() {
        return Err(YaraError::Parse(
            "no YARA rule blocks found in source".to_string(),
        ));
    }
    Ok(out)
}

fn parse_rule_name(line: &str) -> Option<String> {
    let tail = line.strip_prefix("rule")?.trim_start();
    let mut name = String::new();
    for ch in tail.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            name.push(ch);
        } else {
            break;
        }
    }
    if name.is_empty() {
        None
    } else {
        Some(name)
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

fn parse_quoted_literal(line: &str) -> Option<String> {
    let bytes = line.as_bytes();
    let start = bytes.iter().position(|b| *b == b'"')? + 1;
    let mut out = Vec::new();
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => return Some(String::from_utf8_lossy(&out).into_owned()),
            b'\\' if i + 1 < bytes.len() => {
                let escaped = match bytes[i + 1] {
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'\\' => b'\\',
                    b'"' => b'"',
                    other => other,
                };
                out.push(escaped);
                i += 2;
            }
            value => {
                out.push(value);
                i += 1;
            }
        }
    }
    None
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return false;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn is_yara_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("yar") | Some("yara")
    )
}

fn read_limited_file(path: &Path, cap: usize) -> std::io::Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    let mut out = vec![0u8; cap];
    let n = file.read(&mut out)?;
    out.truncate(n);
    Ok(out)
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
