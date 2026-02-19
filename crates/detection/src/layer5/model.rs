use serde::{Deserialize, Serialize};

use super::constants::{FEATURE_COUNT, FEATURE_NAMES};

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
                let scale = self
                    .feature_scales
                    .get(*name)
                    .copied()
                    .unwrap_or(1.0)
                    .max(1e-10);
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
                3.5, // z1_ioc_hit             — IOC exact match is very strong
                2.0, // z2_temporal_count       — temporal rule hits
                1.5, // z3_anomaly_high         — high anomaly threshold
                0.5, // z3_anomaly_med          — medium anomaly (weak signal)
                2.5, // z4_killchain_count      — kill chain graph match
                3.0, // yara_hit_count          — YARA file match
                1.8, // string_sig_count        — Aho-Corasick string signature
                0.8, // event_class_risk        — base risk of event type
                0.3, // uid_is_root             — root execution
                0.6, // dst_port_risk           — suspicious port
                0.1, // has_command_line         — has cmdline (slight indicator)
                0.4, // cmdline_length_norm      — long/obfuscated cmdlines
                0.2, // prefilter_hit           — Cuckoo prefilter positive
                1.2, // multi_layer_count       — multiple layers agree
                // Information-theoretic weights
                0.7, // cmdline_renyi_h2        — collision entropy anomaly
                0.9, // cmdline_compression     — high compression = encrypted/packed
                0.5, // cmdline_min_entropy      — low min-entropy = predictable pattern
                0.6, // cmdline_entropy_gap      — flat spectrum = random/encrypted
                0.7, // dns_entropy             — high-entropy labels (DGA/tunnel)
            ],
            bias: -3.6, // slight bias shift for dns_entropy
            threshold: 0.5,
            feature_names: FEATURE_NAMES.iter().map(|s| s.to_string()).collect(),
        }
    }
}

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
                write!(
                    f,
                    "weight dimension mismatch: expected {expected}, got {got}"
                )
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
