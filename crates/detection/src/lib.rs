mod calibration;
mod engine;
mod layer1;
mod layer2;
mod layer3;
mod layer4;
mod math;
mod policy;
mod replay;
mod sigma;
mod types;
mod util;
mod yara_engine;

pub use calibration::{calibrate_thresholds, sanov_upper_bound, tau_delta, ThresholdCalibration};
pub use engine::{DetectionEngine, DetectionOutcome, SigmaLoadError};
pub use layer1::{IocExactStore, IocLayer1, Layer1EventHit, Layer1Result};
pub use layer2::{TemporalEngine, TemporalPredicate, TemporalRule, TemporalStage};
pub use layer3::{AnomalyConfig, AnomalyDecision, AnomalyEngine};
pub use layer4::{KillChainTemplate, Layer4Engine, TemplatePredicate};
pub use policy::confidence_policy;
pub use replay::{replay_events, ReplayAlert, ReplaySummary};
pub use sigma::{
    compile_sigma_ast, compile_sigma_rule, BoundedTemporalAst, SigmaCompileError, TemporalExpr,
};
pub use types::{Confidence, DetectionSignals, EventClass, TelemetryEvent};
pub use yara_engine::{YaraEngine, YaraError, YaraHit};

#[cfg(test)]
mod tests;
