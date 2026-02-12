use std::sync::{Arc, RwLock};

use anyhow::{anyhow, Result};
use detection::{DetectionEngine, DetectionOutcome, TelemetryEvent};

struct DetectionSnapshot {
    engine: DetectionEngine,
    version: Option<String>,
}

#[derive(Clone)]
pub struct SharedDetectionState {
    inner: Arc<RwLock<DetectionSnapshot>>,
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
}
