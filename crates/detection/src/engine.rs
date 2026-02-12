use crate::layer1::{IocLayer1, Layer1EventHit, Layer1Result};
use crate::layer2::TemporalEngine;
use crate::layer3::{AnomalyDecision, AnomalyEngine};
use crate::layer4::Layer4Engine;
use crate::policy::confidence_policy;
use crate::types::{Confidence, DetectionSignals, TelemetryEvent};

#[derive(Debug, Clone)]
pub struct DetectionOutcome {
    pub confidence: Confidence,
    pub signals: DetectionSignals,
    pub temporal_hits: Vec<String>,
    pub kill_chain_hits: Vec<String>,
    pub anomaly: Option<AnomalyDecision>,
    pub layer1: Layer1EventHit,
}

pub struct DetectionEngine {
    pub layer1: IocLayer1,
    pub layer2: TemporalEngine,
    pub layer3: AnomalyEngine,
    pub layer4: Layer4Engine,
}

impl DetectionEngine {
    pub fn new(
        layer1: IocLayer1,
        layer2: TemporalEngine,
        layer3: AnomalyEngine,
        layer4: Layer4Engine,
    ) -> Self {
        Self {
            layer1,
            layer2,
            layer3,
            layer4,
        }
    }

    pub fn default_with_rules() -> Self {
        Self {
            layer1: IocLayer1::new(),
            layer2: TemporalEngine::with_default_rules(),
            layer3: AnomalyEngine::default(),
            layer4: Layer4Engine::with_default_templates(),
        }
    }

    pub fn process_event(&mut self, event: &TelemetryEvent) -> DetectionOutcome {
        let layer1 = self.layer1.check_event(event);
        let temporal_hits = self.layer2.observe(event);
        let anomaly = self.layer3.observe(event);
        let kill_chain_hits = self.layer4.observe(event);

        let signals = DetectionSignals {
            z1_exact_ioc: layer1.result == Layer1Result::ExactMatch,
            z2_temporal: !temporal_hits.is_empty(),
            z3_anomaly_high: anomaly.as_ref().map(|a| a.high).unwrap_or(false),
            z3_anomaly_med: anomaly.as_ref().map(|a| a.medium).unwrap_or(false),
            z4_kill_chain: !kill_chain_hits.is_empty(),
            l1_prefilter_hit: layer1.prefilter_hit,
        };

        let confidence = confidence_policy(&signals);
        DetectionOutcome {
            confidence,
            signals,
            temporal_hits,
            kill_chain_hits,
            anomaly,
            layer1,
        }
    }
}

impl Default for DetectionEngine {
    fn default() -> Self {
        Self::default_with_rules()
    }
}
