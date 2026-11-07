use super::*;
use std::time::{Duration, Instant};

pub(super) const MAX_RULES: usize = 64;
pub(super) const MAX_PATTERNS: usize = 1024;
const MAX_MATCHES_PER_PATTERN: usize = 128;
const SCAN_TIMEOUT: Duration = Duration::from_secs(2);
const SCAN_BUDGET_US: i64 = 50_000;

struct ScanControl {
    updated: Instant,
    available_us: i64,
}
struct Compiled {
    rules: yara_x::Rules,
    control: Mutex<ScanControl>,
    file_active: std::sync::atomic::AtomicBool,
}
struct Permit {
    compiled: Arc<Compiled>,
    started: Instant,
}
impl FileScanPermit for Permit {}
impl Drop for Permit {
    fn drop(&mut self) {
        let mut control = self
            .compiled
            .control
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        control.available_us = control
            .available_us
            .saturating_sub(self.started.elapsed().as_micros().min(i64::MAX as u128) as i64);
        self.compiled
            .file_active
            .store(false, std::sync::atomic::Ordering::Release);
    }
}

pub(super) struct RealYaraBackend {
    sources: Vec<String>,
    compiled: Option<Arc<Compiled>>,
    pack_hash: [u8; 32],
    status: Arc<YaraStatus>,
}
impl RealYaraBackend {
    pub(super) fn new(status: Arc<YaraStatus>) -> Self {
        Self {
            sources: Vec::new(),
            compiled: None,
            pack_hash: [0; 32],
            status,
        }
    }

    fn scan(&self, source: &str, bytes: &[u8], budgeted: bool) -> Vec<YaraHit> {
        let Some(compiled) = &self.compiled else {
            return Vec::new();
        };
        let mut control = if budgeted {
            match compiled.control.try_lock() {
                Ok(control) => control,
                Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => {
                    self.status.budget_skip(is_executable(bytes));
                    return Vec::new();
                }
            }
        } else {
            compiled.control.lock().unwrap_or_else(|p| p.into_inner())
        };
        let now = Instant::now();
        let refill =
            (now.duration_since(control.updated).as_micros() / 20).min(i64::MAX as u128) as i64;
        control.available_us = control
            .available_us
            .saturating_add(refill)
            .min(SCAN_BUDGET_US);
        control.updated = now;
        if budgeted && control.available_us <= 0 {
            self.status.budget_skip(is_executable(bytes));
            return Vec::new();
        }
        YaraStatus::activate_pack(self.pack_hash);
        let mut scanner = yara_x::Scanner::new(&compiled.rules);
        scanner.set_timeout(SCAN_TIMEOUT);
        scanner.max_matches_per_pattern(MAX_MATCHES_PER_PATTERN);
        scanner.fast_scan(true);
        let mut incomplete = None;
        let hits = match scanner.scan(bytes) {
            Ok(results) => {
                // Truncated match counts can make #a == cap falsely true.
                let saturated = results
                    .matching_rules()
                    .include_private(true)
                    .chain(results.non_matching_rules().include_private(true))
                    .any(|rule| {
                        rule.patterns()
                            .include_private(true)
                            .any(|pattern| pattern.matches().len() >= MAX_MATCHES_PER_PATTERN)
                    });
                if saturated {
                    incomplete = Some("match_limit");
                    Vec::new()
                } else {
                    results
                        .matching_rules()
                        .map(|rule| {
                            let score =
                                rule.metadata().find_map(|(key, value)| match (key, value) {
                                    ("score", yara_x::MetaValue::Integer(value)) => Some(value),
                                    _ => None,
                                });
                            YaraHit {
                                rule_name: rule.identifier().to_string(),
                                source: source.to_string(),
                                matched_literal: "<condition>".to_string(),
                                severity: if score.is_some_and(|score| score >= 70) {
                                    crate::Confidence::High
                                } else {
                                    crate::Confidence::Medium
                                },
                            }
                        })
                        .collect()
                }
            }
            Err(error) => {
                incomplete = Some(match error {
                    yara_x::ScanError::Timeout => "timeout",
                    yara_x::ScanError::ModuleError { .. } => "module_error",
                    yara_x::ScanError::ProtoError { .. } => "proto_error",
                    yara_x::ScanError::UnknownModule { .. } => "unknown_module",
                    _ => "scan_error",
                });
                tracing::error!(backend = "yara-x", error = %error, "YARA scan incomplete");
                Vec::new()
            }
        };
        if let Some(reason) = incomplete {
            self.status.record_incomplete(
                reason,
                source,
                Sha256::digest(bytes).into(),
                self.pack_hash,
            );
        }
        hits
    }
}
#[cfg(test)]
#[path = "real_tests.rs"]
mod tests;

impl YaraBackend for RealYaraBackend {
    fn begin_file_scan(&self, header: &[u8]) -> Option<Box<dyn FileScanPermit>> {
        let Some(compiled) = &self.compiled else {
            return Some(Box::new(UnbudgetedFileScan));
        };
        let mut control = match compiled.control.try_lock() {
            Ok(control) => control,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                self.status.budget_skip(is_executable(header));
                return None;
            }
        };
        let now = Instant::now();
        let refill =
            (now.duration_since(control.updated).as_micros() / 20).min(i64::MAX as u128) as i64;
        control.available_us = control
            .available_us
            .saturating_add(refill)
            .min(SCAN_BUDGET_US);
        control.updated = now;
        if control.available_us <= 0
            || compiled
                .file_active
                .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            self.status.budget_skip(is_executable(header));
            return None;
        }
        Some(Box::new(Permit {
            compiled: Arc::clone(compiled),
            started: now,
        }))
    }
    fn name(&self) -> &'static str {
        "yara-x"
    }
    fn pack_hash(&self) -> [u8; 32] {
        self.pack_hash
    }
    fn rule_names(&self) -> Vec<String> {
        self.compiled.as_ref().map_or_else(Vec::new, |value| {
            value
                .rules
                .iter()
                .map(|rule| rule.identifier().to_string())
                .collect()
        })
    }
    fn load_rules_str(&mut self, source: &str) -> Result<usize> {
        let size = self
            .sources
            .iter()
            .map(String::len)
            .sum::<usize>()
            .saturating_add(source.len());
        if size > MAX_RULE_SOURCE_BYTES {
            return Err(YaraError::Parse("rule source byte limit exceeded".into()));
        }
        let mut digest = Sha256::new();
        for src in self
            .sources
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(source))
        {
            digest.update((src.len() as u64).to_le_bytes());
            digest.update(src.as_bytes());
        }
        let key: [u8; 32] = digest.finalize().into();
        static CACHE: OnceLock<Mutex<HashMap<[u8; 32], Weak<Compiled>>>> = OnceLock::new();
        let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        let existing = cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&key)
            .and_then(Weak::upgrade);
        let compiled = if let Some(compiled) = existing {
            compiled
        } else {
            let mut compiler = yara_x::Compiler::new();
            compiler.enable_includes(false).error_on_slow_loop(true);
            for (index, src) in self
                .sources
                .iter()
                .map(String::as_str)
                .chain(std::iter::once(source))
                .enumerate()
            {
                compiler.new_namespace(format!("source_{index}").as_str());
                compiler
                    .add_source(src)
                    .map_err(|error| YaraError::Parse(error.to_string()))?;
            }
            let rules = compiler.build();
            if rules.iter().len() > MAX_RULES {
                return Err(YaraError::Parse("rule count limit exceeded".into()));
            }
            if rules
                .iter()
                .map(|rule| rule.patterns().include_private(true).len())
                .sum::<usize>()
                > MAX_PATTERNS
            {
                return Err(YaraError::Parse("pattern count limit exceeded".into()));
            }
            let compiled = Arc::new(Compiled {
                rules,
                file_active: std::sync::atomic::AtomicBool::new(false),
                control: Mutex::new(ScanControl {
                    updated: Instant::now(),
                    available_us: SCAN_BUDGET_US,
                }),
            });
            let mut cache = cache.lock().unwrap_or_else(|p| p.into_inner());
            cache.retain(|_, value| value.strong_count() > 0);
            if cache.len() >= 64 {
                cache.clear();
            }
            cache.insert(key, Arc::downgrade(&compiled));
            compiled
        };
        let previous = self
            .compiled
            .as_ref()
            .map_or(0, |value| value.rules.iter().len());
        let loaded = compiled.rules.iter().len() - previous;
        self.sources.push(source.to_string());
        self.compiled = Some(compiled);
        self.pack_hash = key;
        Ok(loaded)
    }
    fn scan_bytes(&self, source: &str, bytes: &[u8]) -> Vec<YaraHit> {
        self.scan(source, bytes, false)
    }
    fn scan_file_bytes(&self, source: &str, bytes: &[u8]) -> Vec<YaraHit> {
        self.scan(source, bytes, true)
    }
}
