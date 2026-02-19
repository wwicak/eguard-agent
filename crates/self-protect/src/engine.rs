use crate::debugger::{detect_debugger, DebuggerCheckConfig, DebuggerObservation};
use crate::integrity::{hash_file_sha256, measure_self_integrity, IntegrityMeasurement};
use std::path::Path;
use std::sync::OnceLock;

const COMPILETIME_EXPECTED_SHA256: Option<&str> =
    option_env!("EGUARD_SELF_PROTECT_EXPECTED_SHA256");
const DEFAULT_RUNTIME_INTEGRITY_PATHS: [&str; 1] = ["/proc/self/exe"];
const DEFAULT_RUNTIME_CONFIG_PATHS: [&str; 1] = ["/etc/eguard-agent/agent.conf"];

pub fn default_runtime_integrity_paths() -> Vec<String> {
    DEFAULT_RUNTIME_INTEGRITY_PATHS
        .iter()
        .map(|path| (*path).to_string())
        .collect()
}

pub fn default_runtime_config_paths() -> Vec<String> {
    DEFAULT_RUNTIME_CONFIG_PATHS
        .iter()
        .map(|path| (*path).to_string())
        .collect()
}

#[derive(Debug, Clone)]
pub struct SelfProtectConfig {
    pub expected_integrity_sha256_hex: Option<String>,
    pub debugger: DebuggerCheckConfig,
    pub runtime_integrity_paths: Vec<String>,
    pub runtime_config_paths: Vec<String>,
}

impl Default for SelfProtectConfig {
    fn default() -> Self {
        Self {
            expected_integrity_sha256_hex: resolve_expected_integrity_sha256(),
            debugger: DebuggerCheckConfig::default(),
            runtime_integrity_paths: env_path_list(
                "EGUARD_SELF_PROTECT_RUNTIME_INTEGRITY_PATHS",
                default_runtime_integrity_paths(),
            ),
            runtime_config_paths: env_path_list(
                "EGUARD_SELF_PROTECT_RUNTIME_CONFIG_PATHS",
                default_runtime_config_paths(),
            ),
        }
    }
}

#[derive(Debug, Clone)]
struct RuntimeHash {
    path: String,
    sha256_hex: String,
}

#[derive(Debug, Default)]
struct RuntimeBaseline {
    integrity: Vec<RuntimeHash>,
    config: Vec<RuntimeHash>,
}

impl RuntimeBaseline {
    fn capture(config: &SelfProtectConfig) -> Self {
        Self {
            integrity: capture_runtime_hashes(&config.runtime_integrity_paths),
            config: capture_runtime_hashes(&config.runtime_config_paths),
        }
    }
}

fn capture_runtime_hashes(paths: &[String]) -> Vec<RuntimeHash> {
    let mut out = Vec::new();
    for path in paths {
        let trimmed = path.trim();
        if trimmed.is_empty() {
            continue;
        }
        let path_ref = Path::new(trimmed);
        if !path_ref.exists() {
            continue;
        }
        if let Ok(sha256_hex) = hash_file_sha256(path_ref) {
            out.push(RuntimeHash {
                path: trimmed.to_string(),
                sha256_hex,
            });
        }
    }
    out
}

#[derive(Debug)]
pub struct SelfProtectEngine {
    config: SelfProtectConfig,
    runtime_baseline: OnceLock<RuntimeBaseline>,
}

impl SelfProtectEngine {
    pub fn from_env() -> Self {
        let config = SelfProtectConfig::default();
        Self::new(config)
    }

    pub fn new(config: SelfProtectConfig) -> Self {
        let runtime_baseline = OnceLock::new();
        if !env_flag_enabled("EGUARD_SELF_PROTECT_LAZY_BASELINE") {
            let _ = runtime_baseline.set(RuntimeBaseline::capture(&config));
        }
        Self {
            config,
            runtime_baseline,
        }
    }

    pub fn config(&self) -> &SelfProtectConfig {
        &self.config
    }

    fn runtime_baseline(&self) -> &RuntimeBaseline {
        self.runtime_baseline
            .get_or_init(|| RuntimeBaseline::capture(&self.config))
    }

    fn append_runtime_integrity(&self, report: &mut SelfProtectReport) {
        for entry in &self.runtime_baseline().integrity {
            match hash_file_sha256(Path::new(&entry.path)) {
                Ok(observed_sha256) => {
                    if observed_sha256 != entry.sha256_hex {
                        report
                            .violations
                            .push(SelfProtectViolation::RuntimeIntegrityMismatch {
                                path: entry.path.clone(),
                                expected_sha256: entry.sha256_hex.clone(),
                                observed_sha256,
                            });
                    }
                }
                Err(err) => {
                    report
                        .violations
                        .push(SelfProtectViolation::RuntimeIntegrityProbeFailed {
                            path: entry.path.clone(),
                            detail: err,
                        });
                }
            }
        }
    }

    fn append_runtime_config(&self, report: &mut SelfProtectReport) {
        for entry in &self.runtime_baseline().config {
            match hash_file_sha256(Path::new(&entry.path)) {
                Ok(observed_sha256) => {
                    if observed_sha256 != entry.sha256_hex {
                        report
                            .violations
                            .push(SelfProtectViolation::RuntimeConfigTamper {
                                path: entry.path.clone(),
                                expected_sha256: entry.sha256_hex.clone(),
                                observed_sha256,
                            });
                    }
                }
                Err(err) => {
                    report
                        .violations
                        .push(SelfProtectViolation::RuntimeConfigProbeFailed {
                            path: entry.path.clone(),
                            detail: err,
                        });
                }
            }
        }
    }

    pub fn evaluate(&self) -> SelfProtectReport {
        let mut report = SelfProtectReport::default();

        self.append_runtime_integrity(&mut report);
        self.append_runtime_config(&mut report);

        if let Some(expected_raw) = self.config.expected_integrity_sha256_hex.as_ref() {
            match normalize_sha256_hex(expected_raw) {
                Some(expected_sha256) => match measure_self_integrity() {
                    Ok(measurement) => {
                        let observed_sha256 = measurement.combined_sha256_hex.clone();
                        report.integrity_measurement = Some(measurement);
                        if observed_sha256 != expected_sha256 {
                            report
                                .violations
                                .push(SelfProtectViolation::IntegrityMismatch {
                                    expected_sha256,
                                    observed_sha256,
                                });
                        }
                    }
                    Err(err) => {
                        report
                            .violations
                            .push(SelfProtectViolation::IntegrityProbeFailed { detail: err });
                    }
                },
                None => {
                    report
                        .violations
                        .push(SelfProtectViolation::IntegrityProbeFailed {
                            detail: "invalid expected SHA-256 hex value".to_string(),
                        });
                }
            }
        }

        let debugger_observation = detect_debugger(&self.config.debugger);
        for signal in &debugger_observation.signals {
            report
                .violations
                .push(SelfProtectViolation::DebuggerSignal {
                    code: signal.code().to_string(),
                    detail: signal.to_string(),
                });
        }
        report.debugger_observation = debugger_observation;
        report
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfProtectViolation {
    IntegrityMismatch {
        expected_sha256: String,
        observed_sha256: String,
    },
    IntegrityProbeFailed {
        detail: String,
    },
    RuntimeIntegrityMismatch {
        path: String,
        expected_sha256: String,
        observed_sha256: String,
    },
    RuntimeIntegrityProbeFailed {
        path: String,
        detail: String,
    },
    RuntimeConfigTamper {
        path: String,
        expected_sha256: String,
        observed_sha256: String,
    },
    RuntimeConfigProbeFailed {
        path: String,
        detail: String,
    },
    DebuggerSignal {
        code: String,
        detail: String,
    },
}

impl SelfProtectViolation {
    pub fn code(&self) -> &'static str {
        match self {
            Self::IntegrityMismatch { .. } => "integrity_mismatch",
            Self::IntegrityProbeFailed { .. } => "integrity_probe_failed",
            Self::RuntimeIntegrityMismatch { .. } => "runtime_integrity_mismatch",
            Self::RuntimeIntegrityProbeFailed { .. } => "runtime_integrity_probe_failed",
            Self::RuntimeConfigTamper { .. } => "runtime_config_tamper",
            Self::RuntimeConfigProbeFailed { .. } => "runtime_config_probe_failed",
            Self::DebuggerSignal { .. } => "debugger_detected",
        }
    }

    pub fn detail(&self) -> String {
        match self {
            Self::IntegrityMismatch {
                expected_sha256,
                observed_sha256,
            } => format!(
                "integrity mismatch: expected={} observed={}",
                expected_sha256, observed_sha256
            ),
            Self::IntegrityProbeFailed { detail } => detail.clone(),
            Self::RuntimeIntegrityMismatch {
                path,
                expected_sha256,
                observed_sha256,
            } => format!(
                "runtime integrity mismatch: path={} expected={} observed={}",
                path, expected_sha256, observed_sha256
            ),
            Self::RuntimeIntegrityProbeFailed { path, detail } => {
                format!(
                    "runtime integrity probe failed: path={} detail={}",
                    path, detail
                )
            }
            Self::RuntimeConfigTamper {
                path,
                expected_sha256,
                observed_sha256,
            } => format!(
                "runtime config tamper: path={} expected={} observed={}",
                path, expected_sha256, observed_sha256
            ),
            Self::RuntimeConfigProbeFailed { path, detail } => {
                format!(
                    "runtime config probe failed: path={} detail={}",
                    path, detail
                )
            }
            Self::DebuggerSignal { code, detail } => {
                format!("debugger signal {}: {}", code, detail)
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SelfProtectReport {
    pub integrity_measurement: Option<IntegrityMeasurement>,
    pub debugger_observation: DebuggerObservation,
    pub violations: Vec<SelfProtectViolation>,
}

impl SelfProtectReport {
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }

    pub fn violation_codes(&self) -> Vec<String> {
        self.violations
            .iter()
            .map(|violation| match violation {
                SelfProtectViolation::DebuggerSignal { code, .. } => {
                    format!("{}:{}", violation.code(), code)
                }
                _ => violation.code().to_string(),
            })
            .collect()
    }

    pub fn tampered_paths(&self) -> Vec<String> {
        let mut out = Vec::new();
        for violation in &self.violations {
            match violation {
                SelfProtectViolation::RuntimeIntegrityMismatch { path, .. }
                | SelfProtectViolation::RuntimeIntegrityProbeFailed { path, .. }
                | SelfProtectViolation::RuntimeConfigTamper { path, .. }
                | SelfProtectViolation::RuntimeConfigProbeFailed { path, .. } => {
                    out.push(path.clone());
                }
                _ => {}
            }
        }
        out.sort();
        out.dedup();
        out
    }

    pub fn summary(&self) -> String {
        if self.violations.is_empty() {
            return "ok".to_string();
        }

        self.violations
            .iter()
            .map(SelfProtectViolation::detail)
            .collect::<Vec<_>>()
            .join("; ")
    }
}

pub fn normalize_sha256_hex(raw: &str) -> Option<String> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.len() != 64 {
        return None;
    }
    if !normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    Some(normalized)
}

fn resolve_expected_integrity_sha256() -> Option<String> {
    if let Ok(raw) = std::env::var("EGUARD_SELF_PROTECT_EXPECTED_SHA256") {
        if let Some(value) = normalize_sha256_hex(&raw) {
            return Some(value);
        }
    }

    if let Ok(path) = std::env::var("EGUARD_SELF_PROTECT_EXPECTED_SHA256_FILE") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            if let Ok(content) = std::fs::read_to_string(trimmed) {
                if let Some(value) = normalize_sha256_hex(&content) {
                    return Some(value);
                }
            }
        }
    }

    COMPILETIME_EXPECTED_SHA256.and_then(normalize_sha256_hex)
}

fn env_path_list(name: &str, fallback: Vec<String>) -> Vec<String> {
    let Ok(raw) = std::env::var(name) else {
        return fallback;
    };
    let mut out = Vec::new();
    for part in raw.split(',') {
        let trimmed = part.trim();
        if !trimmed.is_empty() {
            out.push(trimmed.to_string());
        }
    }
    if out.is_empty() {
        fallback
    } else {
        out
    }
}

fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|raw| {
            matches!(
                raw.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}
