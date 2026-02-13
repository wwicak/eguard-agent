use crate::debugger::{detect_debugger, DebuggerCheckConfig, DebuggerObservation};
use crate::integrity::{measure_self_integrity, IntegrityMeasurement};

const COMPILETIME_EXPECTED_SHA256: Option<&str> =
    option_env!("EGUARD_SELF_PROTECT_EXPECTED_SHA256");

#[derive(Debug, Clone)]
pub struct SelfProtectConfig {
    pub expected_integrity_sha256_hex: Option<String>,
    pub debugger: DebuggerCheckConfig,
}

impl Default for SelfProtectConfig {
    fn default() -> Self {
        Self {
            expected_integrity_sha256_hex: resolve_expected_integrity_sha256(),
            debugger: DebuggerCheckConfig::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SelfProtectEngine {
    config: SelfProtectConfig,
}

impl SelfProtectEngine {
    pub fn from_env() -> Self {
        Self {
            config: SelfProtectConfig::default(),
        }
    }

    pub fn new(config: SelfProtectConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &SelfProtectConfig {
        &self.config
    }

    pub fn evaluate(&self) -> SelfProtectReport {
        let mut report = SelfProtectReport::default();

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
