use super::constants::FEATURE_NAMES;
use super::features::MlFeatures;
use super::math::{dot, sigmoid};
use super::model::{MlError, MlModel};

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
            .filter(|(_, c)| c.abs() > 0.01)
            .collect();
        contributions.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        contributions.truncate(5);

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
