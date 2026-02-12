use std::fmt;
use std::path::Path;

use crate::layer1::{IocLayer1, Layer1EventHit, Layer1Result};
use crate::layer2::TemporalEngine;
use crate::layer3::{AnomalyDecision, AnomalyEngine};
use crate::layer4::Layer4Engine;
use crate::policy::confidence_policy;
use crate::types::{Confidence, DetectionSignals, TelemetryEvent};
use crate::yara_engine::{Result as YaraResult, YaraEngine, YaraHit};
use crate::SigmaCompileError;

#[derive(Debug)]
pub enum SigmaLoadError {
    Io(std::io::Error),
    Compile(SigmaCompileError),
}

impl fmt::Display for SigmaLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "io error: {}", err),
            Self::Compile(err) => write!(f, "compile error: {}", err),
        }
    }
}

impl std::error::Error for SigmaLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Compile(err) => Some(err),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DetectionOutcome {
    pub confidence: Confidence,
    pub signals: DetectionSignals,
    pub temporal_hits: Vec<String>,
    pub kill_chain_hits: Vec<String>,
    pub yara_hits: Vec<YaraHit>,
    pub anomaly: Option<AnomalyDecision>,
    pub layer1: Layer1EventHit,
}

pub struct DetectionEngine {
    pub layer1: IocLayer1,
    pub layer2: TemporalEngine,
    pub layer3: AnomalyEngine,
    pub layer4: Layer4Engine,
    pub yara: YaraEngine,
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
            yara: YaraEngine::new(),
        }
    }

    pub fn with_yara(
        layer1: IocLayer1,
        layer2: TemporalEngine,
        layer3: AnomalyEngine,
        layer4: Layer4Engine,
        yara: YaraEngine,
    ) -> Self {
        Self {
            layer1,
            layer2,
            layer3,
            layer4,
            yara,
        }
    }

    pub fn default_with_rules() -> Self {
        Self {
            layer1: IocLayer1::new(),
            layer2: TemporalEngine::with_default_rules(),
            layer3: AnomalyEngine::default(),
            layer4: Layer4Engine::with_default_templates(),
            yara: YaraEngine::new(),
        }
    }

    pub fn load_yara_rules_str(&mut self, source: &str) -> YaraResult<usize> {
        self.yara.load_rules_str(source)
    }

    pub fn load_yara_rules_from_dir(&mut self, dir: &std::path::Path) -> YaraResult<usize> {
        self.yara.load_rules_from_dir(dir)
    }

    pub fn load_sigma_rule_yaml(
        &mut self,
        source: &str,
    ) -> std::result::Result<String, SigmaLoadError> {
        self.layer2
            .add_sigma_rule_yaml(source)
            .map_err(SigmaLoadError::Compile)
    }

    pub fn load_sigma_rules_from_dir(
        &mut self,
        dir: &Path,
    ) -> std::result::Result<usize, SigmaLoadError> {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(dir).map_err(SigmaLoadError::Io)? {
            let entry = entry.map_err(SigmaLoadError::Io)?;
            let path = entry.path();
            if matches!(
                path.extension().and_then(|ext| ext.to_str()),
                Some("yml") | Some("yaml")
            ) {
                entries.push(path);
            }
        }
        entries.sort();

        let mut loaded = 0usize;
        for path in entries {
            let source = std::fs::read_to_string(&path).map_err(SigmaLoadError::Io)?;
            self.layer2
                .add_sigma_rule_yaml(&source)
                .map_err(SigmaLoadError::Compile)?;
            loaded += 1;
        }

        Ok(loaded)
    }

    pub fn process_event(&mut self, event: &TelemetryEvent) -> DetectionOutcome {
        let layer1 = self.layer1.check_event(event);
        let yara_hits = self.yara.scan_event(event);
        let temporal_hits = self.layer2.observe(event);
        let anomaly = self.layer3.observe(event);
        let kill_chain_hits = self.layer4.observe(event);

        let signals = DetectionSignals {
            z1_exact_ioc: layer1.result == Layer1Result::ExactMatch || !yara_hits.is_empty(),
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
            yara_hits,
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
