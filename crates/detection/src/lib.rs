pub mod attack_coverage;
pub mod beaconing;
pub mod behavioral;
mod bench_detection;
mod calibration;
pub mod deception;
mod engine;
mod exploit;
pub mod fim;
pub mod information;
mod kernel_integrity;
pub mod lateral_movement;
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
pub mod threat_hunting;
mod types;
pub mod usb_control;
pub mod util;
pub mod vulnerability;
mod yara_engine;
pub mod zero_trust;

pub use attack_coverage::{
    critical_gaps, generate_coverage, AttackCoverageReport, TacticCoverage, TechniqueCoverage,
};
pub use beaconing::{BeaconingResult, BeaconingTracker};
pub use behavioral::{BehavioralAlarm, BehavioralEngine};
pub use calibration::{calibrate_thresholds, sanov_upper_bound, tau_delta, ThresholdCalibration};
pub use deception::{DeceptionAlert, DeceptionEngine, DeceptionToken, TokenType};
pub use engine::{DetectionAllowlist, DetectionEngine, DetectionOutcome, SigmaLoadError};
pub use fim::{
    default_fim_paths, FimBaseline, FimChange, FimChangeType, FimEntry, FimError,
    DEFAULT_FIM_PATHS, DEFAULT_FIM_SCAN_INTERVAL_SECS,
};
pub use kernel_integrity::detect_kernel_integrity_indicators;
pub use lateral_movement::{LateralMovementAlert, LateralMovementDetector, LateralTechnique};
pub use layer1::{IocExactStore, IocLayer1, Layer1EventHit, Layer1Result};
pub use layer2::{
    TemporalEngine, TemporalEvictionCounters, TemporalPredicate, TemporalRule, TemporalStage,
};
pub use layer3::{AnomalyConfig, AnomalyDecision, AnomalyEngine};
pub use layer4::{
    KillChainTemplate, Layer4Engine, Layer4EvictionCounters, RansomwarePolicy, TemplatePredicate,
};
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
pub use threat_hunting::{
    evaluate_file_presence_check, evaluate_port_check, evaluate_process_check,
    match_process_pattern, HuntingCheck, HuntingEngine, HuntingFinding, HuntingQuery,
};
pub use types::{Confidence, DetectionSignals, EventClass, TelemetryEvent};
pub use usb_control::{
    parse_usb_class, UsbAction, UsbDeviceClass, UsbEvent, UsbPolicy, UsbViolation,
};
pub use vulnerability::{CveDatabase, CveRecord, VulnerabilityMatch};
pub use yara_engine::{YaraEngine, YaraError, YaraHit};
pub use zero_trust::{
    compute_score as compute_device_score, default_factors as default_health_factors,
    recommend_action, DeviceHealthScore, ScoreFactor, TrustAction,
};

#[cfg(test)]
mod tests;
#[cfg(all(test, not(miri)))]
mod tests_resource_budget;
#[cfg(all(test, not(miri)))]
mod tests_stub_completion;
