use super::constants::FEATURE_NAMES;
use super::features::MlFeatures;
use super::math::{dot, sigmoid};
use super::model::{MlError, MlModel, ModelFamily};
use crate::information::ConformalCalibrator;

/// Very high-confidence model scores bypass conformal gating.
///
/// This protects recall for extreme detections in the unlikely case where
/// calibration data becomes stale or overly conservative.
const CONFORMAL_BYPASS_SCORE: f64 = 0.995;

/// The ML inference engine. Stateless — call `score()` per event.
#[derive(Debug, Clone)]
pub struct MlEngine {
    model: MlModel,
    /// Optional conformal calibrator for finite-sample FP-rate guarantees.
    calibrator: Option<ConformalCalibrator>,
}

/// Result of ML scoring for a single event.
#[derive(Debug, Clone)]
pub struct MlScore {
    /// Probability score in [0, 1].
    pub score: f64,
    /// Final ML decision after threshold + optional conformal gating.
    pub positive: bool,
    /// Raw model decision using only the configured model threshold.
    pub raw_positive: bool,
    /// Whether a raw-positive event was suppressed by conformal gating.
    pub conformal_gated: bool,
    /// Effective decision threshold used for observability.
    ///
    /// When conformal calibration is active this is the maximum of model and
    /// conformal thresholds; otherwise this is the model threshold.
    pub decision_threshold: f64,
    /// Top contributing features (for explainability).
    pub top_features: Vec<(String, f64)>,
    /// Conformal p-value (if calibrator is loaded and raw-positive).
    /// Low p-value (e.g., < 0.01) means the score is unusually high
    /// relative to the calibration set — strong evidence of anomaly.
    pub conformal_p_value: Option<f64>,
}

impl MlEngine {
    /// Create engine with default model.
    pub fn new() -> Self {
        Self {
            model: MlModel::default(),
            calibrator: None,
        }
    }

    /// Create engine with a specific model.
    pub fn with_model(model: MlModel) -> Self {
        Self {
            model,
            calibrator: None,
        }
    }

    /// Create engine with a model and calibration scores for conformal prediction.
    pub fn with_model_and_calibration(
        model: MlModel,
        calibration_scores: Vec<f64>,
        alpha: f64,
    ) -> Self {
        Self {
            calibrator: Some(ConformalCalibrator::new(calibration_scores, alpha)),
            model,
        }
    }

    /// Load conformal calibration scores (e.g., from CI model bundle).
    pub fn load_calibration(&mut self, scores: Vec<f64>, alpha: f64) {
        self.calibrator = Some(ConformalCalibrator::new(scores, alpha));
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

    /// Snapshot current loaded model (for safe reload continuity fallback).
    pub fn model_snapshot(&self) -> MlModel {
        self.model.clone()
    }

    /// Whether conformal calibration is active.
    pub fn has_calibration(&self) -> bool {
        self.calibrator.is_some()
    }

    /// Compute ML risk score for one event.
    pub fn score(&self, features: &MlFeatures) -> MlScore {
        // Linear combination by default; switch to tree traversal when available.
        let z = match self.model.family {
            ModelFamily::GbdtTree => self.score_tree_logit(features),
            ModelFamily::Linear => dot(&self.model.weights, &features.values) + self.model.bias,
        };

        // Logistic sigmoid: σ(z) = 1 / (1 + e^(-z))
        let score = sigmoid(z);
        let raw_positive = score >= self.model.threshold;

        let mut positive = raw_positive;
        let mut conformal_gated = false;
        let mut decision_threshold = self.model.threshold;

        // Conformal p-value — compute only on raw-positive events for hot-path efficiency.
        let conformal_p_value = if raw_positive {
            self.calibrator.as_ref().map(|cal| {
                decision_threshold = decision_threshold.max(cal.threshold);
                let p = cal.p_value(score);

                if score < CONFORMAL_BYPASS_SCORE && !cal.is_anomalous(score) {
                    positive = false;
                    conformal_gated = true;
                }

                p
            })
        } else {
            None
        };

        // Top contributing features (for audit trail / explainability)
        let mut contributions: Vec<(String, f64)> = FEATURE_NAMES
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let contribution = self.model.weights[i] * features.values[i];
                (name.to_string(), contribution)
            })
            .filter(|(_, c)| c.abs() > 0.01)
            .collect();
        contributions.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        contributions.truncate(5);

        MlScore {
            score,
            positive,
            raw_positive,
            conformal_gated,
            decision_threshold,
            top_features: contributions,
            conformal_p_value,
        }
    }

    fn score_tree_logit(&self, features: &MlFeatures) -> f64 {
        let mut z = self.model.tree_base_score;

        for tree in &self.model.trees {
            let mut current_id = 0i32;
            let mut steps = 0usize;
            let mut leaf_value = 0.0f64;

            while steps < 64 {
                steps += 1;
                let node = match tree.nodes.iter().find(|n| n.id == current_id) {
                    Some(n) => n,
                    None => break,
                };

                if let Some(leaf) = node.leaf {
                    leaf_value = leaf;
                    break;
                }

                let threshold = node.threshold.unwrap_or(0.0);
                let feature_idx = FEATURE_NAMES.iter().position(|name| *name == node.feature);
                let feature_value = feature_idx.map(|idx| features.values[idx]).unwrap_or(0.0);

                current_id = if feature_value <= threshold {
                    node.left.unwrap_or(current_id)
                } else {
                    node.right.unwrap_or(current_id)
                };
            }

            z += tree.weight * leaf_value;
        }

        z
    }
}

impl Default for MlEngine {
    fn default() -> Self {
        Self::new()
    }
}
