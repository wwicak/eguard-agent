use std::fmt;
use std::fs;
use std::io::Read;
use std::path::Path;

use crate::types::TelemetryEvent;

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

trait YaraBackend {
    fn load_rules_str(&mut self, source: &str) -> Result<usize>;
    fn scan_bytes(&self, source: &str, bytes: &[u8]) -> Vec<YaraHit>;
}

pub struct YaraEngine {
    backend: Box<dyn YaraBackend>,
    max_scan_bytes: usize,
}

impl YaraEngine {
    pub fn new() -> Self {
        Self {
            backend: default_backend(),
            max_scan_bytes: DEFAULT_MAX_SCAN_BYTES,
        }
    }

    pub fn with_max_scan_bytes(max_scan_bytes: usize) -> Self {
        Self {
            backend: default_backend(),
            max_scan_bytes: max_scan_bytes.max(4096),
        }
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

    pub fn scan_event(&self, event: &TelemetryEvent) -> Vec<YaraHit> {
        let mut hits = Vec::new();

        if let Some(cmd) = &event.command_line {
            hits.extend(self.backend.scan_bytes("command_line", cmd.as_bytes()));
        }

        if let Some(path) = event.file_path.as_deref() {
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

fn default_backend() -> Box<dyn YaraBackend> {
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
        for rule in &self.rules {
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
mod tests {
    use super::*;

    #[test]
    fn parses_and_scans_rule_source() {
        let src = r#"
rule test_rule {
  strings:
    $a = "evil_payload"
  condition:
    $a
}
"#;

        let mut engine = YaraEngine::new();
        let loaded = engine.load_rules_str(src).expect("load rules");
        assert_eq!(loaded, 1);

        let event = TelemetryEvent {
            ts_unix: 1,
            event_class: crate::EventClass::ProcessExec,
            pid: 1,
            ppid: 0,
            uid: 0,
            process: "bash".to_string(),
            parent_process: "sshd".to_string(),
            file_path: None,
            file_hash: None,
            dst_port: None,
            dst_ip: None,
            dst_domain: None,
            command_line: Some("echo evil_payload".to_string()),
        };

        let hits = engine.scan_event(&event);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_name, "test_rule");
    }

    #[test]
    fn loads_rules_from_directory() {
        let base = std::env::temp_dir().join(format!(
            "eguard-yara-rules-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&base).expect("create rules dir");

        let path = base.join("sample.yar");
        std::fs::write(
            &path,
            r#"
rule sample_from_dir {
  strings:
    $x = "abc123"
  condition:
    $x
}
"#,
        )
        .expect("write rule file");

        let mut engine = YaraEngine::new();
        let loaded = engine.load_rules_from_dir(&base).expect("load rule dir");
        assert_eq!(loaded, 1);

        let event = TelemetryEvent {
            ts_unix: 1,
            event_class: crate::EventClass::FileOpen,
            pid: 1,
            ppid: 0,
            uid: 0,
            process: "cat".to_string(),
            parent_process: "bash".to_string(),
            file_path: Some(path.to_string_lossy().into_owned()),
            file_hash: None,
            dst_port: None,
            dst_ip: None,
            dst_domain: None,
            command_line: None,
        };

        let sample = base.join("payload.bin");
        std::fs::write(&sample, b"xxabc123yy").expect("write payload");
        let payload_event = TelemetryEvent {
            file_path: Some(sample.to_string_lossy().into_owned()),
            ..event
        };
        let hits = engine.scan_event(&payload_event);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_name, "sample_from_dir");

        let _ = std::fs::remove_file(sample);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir(base);
    }

    #[cfg(feature = "yara-rust")]
    #[test]
    fn yara_rust_backend_compiles_and_scans() {
        let mut backend = YaraRustBackend::new().expect("init yara backend");
        let loaded = backend
            .load_rules_str(
                r#"
rule rust_backend_rule {
  strings:
    $x = "abc123xyz"
  condition:
    $x
}
"#,
            )
            .expect("load rule");
        assert_eq!(loaded, 1);

        let hits = backend.scan_bytes("memory", b"hello abc123xyz world");
        assert!(hits.iter().any(|h| h.rule_name == "rust_backend_rule"));
    }
}
