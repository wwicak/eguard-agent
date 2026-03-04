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
    /// Decision threshold: score >= threshold -> "ml positive".
    pub threshold: f64,
    /// Feature names (for validation; must match FEATURE_NAMES order).
    #[serde(default)]
    pub feature_names: Vec<String>,
    /// Number of CI model features not mapped to runtime feature vector.
    #[serde(default)]
    pub ci_features_dropped: usize,
    /// Number of runtime features with no corresponding CI model weight.
    #[serde(default)]
    pub runtime_features_unmapped: usize,
    /// Inference family used by runtime.
    #[serde(default)]
    pub family: ModelFamily,
    /// Tree ensemble base score (used when family=Tree).
    #[serde(default)]
    pub tree_base_score: f64,
    /// Optional tree ensemble for non-linear inference.
    #[serde(default)]
    pub trees: Vec<TreeModel>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ModelFamily {
    #[default]
    Linear,
    GbdtTree,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeModel {
    pub weight: f64,
    pub nodes: Vec<TreeNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeNode {
    pub id: i32,
    #[serde(default)]
    pub feature: String,
    #[serde(default)]
    pub threshold: Option<f64>,
    #[serde(default)]
    pub left: Option<i32>,
    #[serde(default)]
    pub right: Option<i32>,
    #[serde(default)]
    pub leaf: Option<f64>,
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
    /// Optional decision threshold from CI training pipeline.
    #[serde(default)]
    pub threshold: Option<f64>,
    /// Optional calibration scores for conformal prediction.
    /// When present, the runtime engine constructs a ConformalCalibrator
    /// from these scores to provide finite-sample FP-rate guarantees.
    #[serde(default)]
    pub calibration_scores: Option<Vec<f64>>,
    #[serde(default)]
    pub base_score: Option<f64>,
    #[serde(default)]
    pub trees: Option<Vec<TreeModel>>,
}

impl CiTrainedModel {
    /// Load from JSON file (the `signature-ml-model.json` from CI bundle).
    pub fn from_json(json: &str) -> Result<Self, MlError> {
        serde_json::from_str(json).map_err(MlError::ParseJson)
    }

    /// Validate the CI-trained model before conversion to runtime format.
    pub fn validate(&self) -> Result<(), MlError> {
        if self.features.is_empty() {
            return Err(MlError::EmptyFeatures);
        }
        for (name, &weight) in &self.weights {
            if !weight.is_finite() {
                return Err(MlError::NonFiniteCiWeight {
                    name: name.clone(),
                    value: weight,
                });
            }
        }
        if !self.bias.is_finite() {
            return Err(MlError::NonFiniteBias(self.bias));
        }
        for (name, &scale) in &self.feature_scales {
            if !(1e-10..=1e6).contains(&scale) {
                return Err(MlError::UnreasonableScale {
                    name: name.clone(),
                    value: scale,
                });
            }
        }
        Ok(())
    }

    /// Convert CI-trained model to runtime `MlModel`.
    ///
    /// Maps named weights to positional feature vector using `FEATURE_NAMES`.
    /// Features in the CI model that don't exist in `FEATURE_NAMES` are
    /// tracked via `ci_features_dropped`. Features in `FEATURE_NAMES` not
    /// present in the CI model get weight 0.0 (safe default) and are tracked
    /// via `runtime_features_unmapped`.
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

        // Fix 10d: Use CI-trained threshold if available and within sane bounds
        let threshold = self
            .threshold
            .filter(|&t| (0.05..=0.95).contains(&t))
            .unwrap_or(0.5);

        // Fix 10f: Track feature mapping mismatches
        let mut ci_features_dropped = 0usize;
        let mut runtime_features_unmapped = 0usize;

        // Count features in CI model not mapped to runtime
        for ci_feature in &self.features {
            if !FEATURE_NAMES.contains(&ci_feature.as_str()) {
                ci_features_dropped += 1;
            }
        }

        // Count runtime features missing from CI model
        for name in FEATURE_NAMES.iter() {
            if !self.weights.contains_key(*name) {
                runtime_features_unmapped += 1;
            }
        }

        let mut model = MlModel {
            model_id: format!("ci-{}", self.model_version),
            model_version: self.model_version.clone(),
            weights,
            bias: self.bias,
            threshold,
            feature_names: FEATURE_NAMES.iter().map(|s| s.to_string()).collect(),
            ci_features_dropped,
            runtime_features_unmapped,
            family: ModelFamily::Linear,
            tree_base_score: 0.0,
            trees: Vec::new(),
        };

        let model_type = self.model_type.to_ascii_lowercase();
        if (model_type.contains("tree") || model_type.contains("gbdt"))
            && self.trees.as_ref().is_some_and(|t| !t.is_empty())
        {
            model.family = ModelFamily::GbdtTree;
            model.tree_base_score = self.base_score.unwrap_or(0.0);
            model.trees = self.trees.clone().unwrap_or_default();
            if !self.bias.is_finite() || self.bias == 0.0 {
                model.bias = model.tree_base_score;
            }
        }

        model
    }
}

impl MlModel {
    /// Load from JSON, auto-detecting CI-trained vs native format.
    pub fn from_json_auto(json: &str) -> Result<Self, MlError> {
        // Try CI format first (has "suite" field)
        if json.contains("\"suite\"") && json.contains("\"feature_scales\"") {
            if let Ok(ci) = CiTrainedModel::from_json(json) {
                // Fix 10e: Validate CI model before conversion
                ci.validate()?;
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
        if self.family == ModelFamily::GbdtTree {
            if !self.tree_base_score.is_finite() {
                return Err(MlError::NonFiniteBias(self.tree_base_score));
            }
            for (i, tree) in self.trees.iter().enumerate() {
                if !tree.weight.is_finite() {
                    return Err(MlError::InvalidTreeModel(format!(
                        "tree[{i}] has non-finite weight"
                    )));
                }
                if tree.nodes.is_empty() {
                    return Err(MlError::InvalidTreeModel(format!("tree[{i}] has no nodes")));
                }
            }
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
                // Extended feature weights (Fix 6)
                0.2, // event_size_norm         — normalized event size
                0.4, // container_risk          — container escape/privileged risk
                0.3, // file_path_entropy       — Shannon entropy of file path
                0.2, // file_path_depth         — normalized path depth
                0.5, // behavioral_alarm_count  — behavioral alarm count
                0.8, // z1_z2_interaction       — IOC + temporal = strong
                0.7, // z1_z4_interaction       — IOC + kill chain = strong
                0.6, // anomaly_behavioral      — anomaly + multi-signal = moderate
                // Process tree / lineage
                0.3, // process_tree_depth_norm
                0.6, // rare_parent_child_pair
                0.3, // parent_cmdline_hash_risk
                0.3, // parent_child_cmdline_distance
                0.4, // sibling_spawn_burst_norm
                // File mutation behavior
                0.3, // sensitive_path_write_velocity
                0.2, // rename_churn_norm
                0.1, // extension_entropy
                0.2, // executable_write_ratio
                0.2, // temp_to_system_write_ratio
                // Network graph / beaconing
                0.3, // conn_fanout_norm
                0.2, // unique_dst_ip_norm
                0.2, // unique_dst_port_norm
                0.7, // beacon_periodicity_score
                0.2, // network_graph_centrality
                // Credential access indicators
                0.5, // credential_access_indicator
                0.4, // lsass_access_indicator
                0.3, // sam_access_indicator
                0.3, // token_theft_indicator
                0.3, // lolbin_credential_chain
                // Cross-domain interactions
                0.3, // network_credential_interaction
                0.2, // tree_network_interaction
                0.2, // file_behavior_interaction
            ],
            bias: -3.6, // slight bias shift for dns_entropy
            threshold: 0.5,
            feature_names: FEATURE_NAMES.iter().map(|s| s.to_string()).collect(),
            ci_features_dropped: 0,
            runtime_features_unmapped: 0,
            family: ModelFamily::Linear,
            tree_base_score: 0.0,
            trees: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub enum MlError {
    DimensionMismatch {
        expected: usize,
        got: usize,
    },
    InvalidThreshold(f64),
    NonFiniteWeight {
        index: usize,
        value: f64,
    },
    NonFiniteBias(f64),
    ParseJson(serde_json::Error),
    Io(std::io::Error),
    /// CI model has an empty feature list.
    EmptyFeatures,
    /// CI model weight is NaN or infinite.
    NonFiniteCiWeight {
        name: String,
        value: f64,
    },
    /// CI model feature scale is outside reasonable bounds.
    UnreasonableScale {
        name: String,
        value: f64,
    },
    InvalidTreeModel(String),
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
            Self::EmptyFeatures => write!(f, "CI model has empty feature list"),
            Self::NonFiniteCiWeight { name, value } => {
                write!(f, "CI model weight for '{name}' is non-finite: {value}")
            }
            Self::UnreasonableScale { name, value } => {
                write!(
                    f,
                    "CI model feature scale for '{name}' is unreasonable: {value}"
                )
            }
            Self::InvalidTreeModel(reason) => write!(f, "invalid tree model: {reason}"),
        }
    }
}

impl std::error::Error for MlError {}
