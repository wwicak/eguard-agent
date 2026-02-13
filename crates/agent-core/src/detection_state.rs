use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use arc_swap::ArcSwap;
use detection::{DetectionEngine, DetectionOutcome, EventClass, TelemetryEvent};
use tracing::info;

struct DetectionSnapshot {
    engine: Mutex<DetectionEngine>,
    version: Option<String>,
}

impl DetectionSnapshot {
    fn new(engine: DetectionEngine, version: Option<String>) -> Self {
        Self {
            engine: Mutex::new(engine),
            version,
        }
    }
}

#[derive(Clone)]
pub struct SharedDetectionState {
    inner: Arc<ArcSwap<DetectionSnapshot>>,
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
            inner: Arc::new(ArcSwap::from_pointee(DetectionSnapshot::new(
                engine, version,
            ))),
        }
    }

    pub fn process_event(&self, event: &TelemetryEvent) -> Result<DetectionOutcome> {
        let snapshot = self.inner.load();
        let mut engine = snapshot
            .engine
            .lock()
            .map_err(|_| anyhow!("detection engine lock poisoned"))?;
        Ok(engine.process_event(event))
    }

    pub fn swap_engine(&self, version: String, next: DetectionEngine) -> Result<()> {
        self.inner
            .store(Arc::new(DetectionSnapshot::new(next, Some(version))));
        Ok(())
    }

    pub fn version(&self) -> Result<Option<String>> {
        let snapshot = self.inner.load();
        Ok(snapshot.version.clone())
    }

    pub fn apply_emergency_rule(&self, rule: EmergencyRule) -> Result<()> {
        let snapshot = self.inner.load();
        let mut engine = snapshot
            .engine
            .lock()
            .map_err(|_| anyhow!("detection engine lock poisoned"))?;

        info!(rule_name = %rule.name, rule_type = ?rule.rule_type, "applying emergency rule to detection state");

        match rule.rule_type {
            EmergencyRuleType::IocHash => {
                engine.layer1.load_hashes([rule.rule_content]);
            }
            EmergencyRuleType::IocDomain => {
                engine.layer1.load_domains([rule.rule_content]);
            }
            EmergencyRuleType::IocIP => {
                engine.layer1.load_ips([rule.rule_content]);
            }
            EmergencyRuleType::Signature => {
                engine.layer1.append_string_signatures([rule.rule_content]);
            }
        }

        Ok(())
    }

    pub fn set_anomaly_baseline(
        &self,
        process_key: String,
        distribution: HashMap<EventClass, f64>,
    ) -> Result<()> {
        let snapshot = self.inner.load();
        let mut engine = snapshot
            .engine
            .lock()
            .map_err(|_| anyhow!("detection engine lock poisoned"))?;
        engine.layer3.set_baseline(process_key, distribution);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
