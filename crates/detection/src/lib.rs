mod engine;
mod layer1;
mod layer2;
mod layer3;
mod layer4;
mod math;
mod policy;
mod types;
mod util;

pub use engine::{DetectionEngine, DetectionOutcome};
pub use layer1::{IocExactStore, IocLayer1, Layer1EventHit, Layer1Result};
pub use layer2::{TemporalEngine, TemporalPredicate, TemporalRule, TemporalStage};
pub use layer3::{AnomalyConfig, AnomalyDecision, AnomalyEngine};
pub use layer4::{KillChainTemplate, Layer4Engine, TemplatePredicate};
pub use policy::confidence_policy;
pub use types::{Confidence, DetectionSignals, EventClass, TelemetryEvent};

#[cfg(test)]
mod tests;
