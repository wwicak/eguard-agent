pub mod beaconing;
pub mod behavioral;
mod bench_detection;
mod calibration;
mod engine;
mod exploit;
pub mod information;
mod kernel_integrity;
mod layer1;
mod layer2;
mod layer3;
mod layer4;
pub mod layer5;
mod math;
pub mod memory_scanner;
mod policy;
mod replay;
mod sigma;
mod tamper;
mod types;
pub mod util;
mod yara_engine;

pub use behavioral::{BehavioralAlarm, BehavioralEngine};
pub use calibration::{calibrate_thresholds, sanov_upper_bound, tau_delta, ThresholdCalibration};
pub use engine::{DetectionAllowlist, DetectionEngine, DetectionOutcome, SigmaLoadError};
pub use kernel_integrity::detect_kernel_integrity_indicators;
pub use layer1::{IocExactStore, IocLayer1, Layer1EventHit, Layer1Result};
pub use layer2::{
    TemporalEngine, TemporalEvictionCounters, TemporalPredicate, TemporalRule, TemporalStage,
};
pub use layer3::{AnomalyConfig, AnomalyDecision, AnomalyEngine};
pub use layer4::{
    KillChainTemplate, Layer4Engine, Layer4EvictionCounters, RansomwarePolicy, TemplatePredicate,
};
pub use beaconing::{BeaconingResult, BeaconingTracker};
pub use layer5::{MlEngine, MlError, MlExtraContext, MlFeatures, MlModel, MlScore};
pub use policy::confidence_policy;
pub use replay::{
    correlate_campaign_iocs, correlate_cross_agent_iocs, replay_events, report_drift_indicators,
    AdvisoryIncident, CampaignIncident, CampaignSeverity, CampaignSignal, CorrelationSignal,
    DriftIndicators, ProcessDriftQuantiles, ReplayAlert, ReplaySummary,
};
pub use sigma::{
    compile_sigma_ast, compile_sigma_rule, BoundedTemporalAst, SigmaCompileError, TemporalExpr,
};
pub use tamper::detect_tamper_indicators;
pub use types::{Confidence, DetectionSignals, EventClass, TelemetryEvent};
pub use yara_engine::{YaraEngine, YaraError, YaraHit};

#[cfg(test)]
mod tests;
#[cfg(all(test, not(miri)))]
mod tests_resource_budget;
#[cfg(all(test, not(miri)))]
mod tests_stub_completion;
