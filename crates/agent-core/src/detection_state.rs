use std::sync::{Arc, RwLock};

use anyhow::{anyhow, Result};
use detection::{DetectionEngine, DetectionOutcome, TelemetryEvent};
use tracing::info;

struct DetectionSnapshot {
    engine: DetectionEngine,
    version: Option<String>,
}

#[derive(Clone)]
pub struct SharedDetectionState {
    inner: Arc<RwLock<DetectionSnapshot>>,
}

#[derive(Debug, Clone)]
pub enum EmergencyRuleType {
    IocHash,
    IocDomain,
    IocIP,
    Signature,
}

#[derive(Debug, Clone)]
pub struct EmergencyRule {
    pub name: String,
    pub rule_type: EmergencyRuleType,
    pub rule_content: String,
}

impl SharedDetectionState {
    pub fn new(engine: DetectionEngine, version: Option<String>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(DetectionSnapshot { engine, version })),
        }
    }

    pub fn process_event(&self, event: &TelemetryEvent) -> Result<DetectionOutcome> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| anyhow!("detection state lock poisoned"))?;
        Ok(guard.engine.process_event(event))
    }

    pub fn swap_engine(&self, version: String, next: DetectionEngine) -> Result<()> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| anyhow!("detection state lock poisoned"))?;
        guard.engine = next;
        guard.version = Some(version);
        Ok(())
    }

    pub fn version(&self) -> Result<Option<String>> {
        let guard = self
            .inner
            .read()
            .map_err(|_| anyhow!("detection state lock poisoned"))?;
        Ok(guard.version.clone())
    }

    pub fn apply_emergency_rule(&self, rule: EmergencyRule) -> Result<()> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| anyhow!("detection state lock poisoned"))?;

        info!(rule_name = %rule.name, rule_type = ?rule.rule_type, "applying emergency rule to detection state");

        match rule.rule_type {
            EmergencyRuleType::IocHash => {
                guard.engine.layer1.load_hashes([rule.rule_content]);
            }
            EmergencyRuleType::IocDomain => {
                guard.engine.layer1.load_domains([rule.rule_content]);
            }
            EmergencyRuleType::IocIP => {
                guard.engine.layer1.load_ips([rule.rule_content]);
            }
            EmergencyRuleType::Signature => {
                guard
                    .engine
                    .layer1
                    .append_string_signatures([rule.rule_content]);
            }
        }

        Ok(())
    }
}
