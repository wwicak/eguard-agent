use std::collections::HashMap;
use std::sync::{mpsc, Arc};

use anyhow::{anyhow, Result};
use arc_swap::ArcSwap;
use detection::{DetectionEngine, DetectionOutcome, EventClass, TelemetryEvent};
use tracing::info;

enum ShardCommand {
    ProcessEvent {
        event: TelemetryEvent,
        response: mpsc::Sender<std::result::Result<DetectionOutcome, String>>,
    },
    ScanProcessMemory {
        pid: u32,
        mode: detection::memory_scanner::ScanMode,
        response:
            mpsc::Sender<std::result::Result<detection::memory_scanner::MemoryScanResult, String>>,
    },
    ApplyEmergencyRule {
        rule_type: EmergencyRuleType,
        rule_content: String,
        response: mpsc::Sender<std::result::Result<(), String>>,
    },
    SetAnomalyBaseline {
        process_key: String,
        distribution: HashMap<EventClass, f64>,
        response: mpsc::Sender<std::result::Result<(), String>>,
    },
    SwapEngine {
        engine: Box<DetectionEngine>,
        response: mpsc::Sender<std::result::Result<(), String>>,
    },
    UpdateAllowlist {
        processes: Vec<String>,
        path_prefixes: Vec<String>,
        response: mpsc::Sender<std::result::Result<(), String>>,
    },
}

#[derive(Clone)]
struct DetectionShard {
    tx: mpsc::Sender<ShardCommand>,
}

impl DetectionShard {
    fn spawn(shard_idx: usize, initial_engine: DetectionEngine) -> Self {
        let (tx, rx) = mpsc::channel();
        let thread_name = format!("eguard-detection-shard-{shard_idx}");
        std::thread::Builder::new()
            .name(thread_name)
            .spawn(move || shard_worker_loop(initial_engine, rx))
            .unwrap_or_else(|err| {
                panic!("failed spawning detection shard worker {shard_idx}: {err}")
            });
        Self { tx }
    }

    fn process_event(&self, event: TelemetryEvent) -> Result<DetectionOutcome> {
        let (response_tx, response_rx) = mpsc::channel();
        self.tx
            .send(ShardCommand::ProcessEvent {
                event,
                response: response_tx,
            })
            .map_err(|_| anyhow!("detection shard channel closed"))?;
        response_rx
            .recv()
            .map_err(|_| anyhow!("detection shard response channel closed"))?
            .map_err(|err| anyhow!(err))
    }

    fn apply_emergency_rule(
        &self,
        rule_type: EmergencyRuleType,
        rule_content: String,
    ) -> Result<()> {
        let (response_tx, response_rx) = mpsc::channel();
        self.tx
            .send(ShardCommand::ApplyEmergencyRule {
                rule_type,
                rule_content,
                response: response_tx,
            })
            .map_err(|_| anyhow!("detection shard channel closed"))?;
        response_rx
            .recv()
            .map_err(|_| anyhow!("detection shard response channel closed"))?
            .map_err(|err| anyhow!(err))
    }

    fn set_anomaly_baseline(
        &self,
        process_key: String,
        distribution: HashMap<EventClass, f64>,
    ) -> Result<()> {
        let (response_tx, response_rx) = mpsc::channel();
        self.tx
            .send(ShardCommand::SetAnomalyBaseline {
                process_key,
                distribution,
                response: response_tx,
            })
            .map_err(|_| anyhow!("detection shard channel closed"))?;
        response_rx
            .recv()
            .map_err(|_| anyhow!("detection shard response channel closed"))?
            .map_err(|err| anyhow!(err))
    }

    fn swap_engine(&self, engine: DetectionEngine) -> Result<()> {
        let (response_tx, response_rx) = mpsc::channel();
        self.tx
            .send(ShardCommand::SwapEngine {
                engine: Box::new(engine),
                response: response_tx,
            })
            .map_err(|_| anyhow!("detection shard channel closed"))?;
        response_rx
            .recv()
            .map_err(|_| anyhow!("detection shard response channel closed"))?
            .map_err(|err| anyhow!(err))
    }

    fn update_allowlist(&self, processes: Vec<String>, path_prefixes: Vec<String>) -> Result<()> {
        let (response_tx, response_rx) = mpsc::channel();
        self.tx
            .send(ShardCommand::UpdateAllowlist {
                processes,
                path_prefixes,
                response: response_tx,
            })
            .map_err(|_| anyhow!("detection shard channel closed"))?;
        response_rx
            .recv()
            .map_err(|_| anyhow!("detection shard response channel closed"))?
            .map_err(|err| anyhow!(err))
    }

    fn scan_process_memory(
        &self,
        pid: u32,
        mode: detection::memory_scanner::ScanMode,
    ) -> Result<detection::memory_scanner::MemoryScanResult> {
        let (response_tx, response_rx) = mpsc::channel();
        self.tx
            .send(ShardCommand::ScanProcessMemory {
                pid,
                mode,
                response: response_tx,
            })
            .map_err(|_| anyhow!("detection shard channel closed"))?;
        response_rx
            .recv()
            .map_err(|_| anyhow!("detection shard response channel closed"))?
            .map_err(|err| anyhow!(err))
    }
}

fn shard_worker_loop(mut engine: DetectionEngine, rx: mpsc::Receiver<ShardCommand>) {
    while let Ok(command) = rx.recv() {
        match command {
            ShardCommand::ProcessEvent { event, response } => {
                let outcome = engine.process_event(&event);
                let _ = response.send(Ok(outcome));
            }
            ShardCommand::ScanProcessMemory {
                pid,
                mode,
                response,
            } => {
                let result =
                    detection::memory_scanner::scan_process_memory(&engine.yara, pid, mode);
                let _ = response.send(Ok(result));
            }
            ShardCommand::ApplyEmergencyRule {
                rule_type,
                rule_content,
                response,
            } => {
                let result = apply_emergency_rule_to_engine(&mut engine, rule_type, &rule_content);
                let _ = response.send(result);
            }
            ShardCommand::SetAnomalyBaseline {
                process_key,
                distribution,
                response,
            } => {
                engine.layer3.set_baseline(process_key, distribution);
                let _ = response.send(Ok(()));
            }
            ShardCommand::SwapEngine {
                engine: replacement,
                response,
            } => {
                engine = *replacement;
                let _ = response.send(Ok(()));
            }
            ShardCommand::UpdateAllowlist {
                processes,
                path_prefixes,
                response,
            } => {
                engine.allowlist.load_from_lists(processes, path_prefixes);
                let _ = response.send(Ok(()));
            }
        }
    }
}

fn apply_emergency_rule_to_engine(
    engine: &mut DetectionEngine,
    rule_type: EmergencyRuleType,
    rule_content: &str,
) -> std::result::Result<(), String> {
    let content = rule_content.to_string();
    match rule_type {
        EmergencyRuleType::IocHash => {
            engine.layer1.load_hashes([content]);
        }
        EmergencyRuleType::IocDomain => {
            engine.layer1.load_domains([content]);
        }
        EmergencyRuleType::IocIP => {
            engine.layer1.load_ips([content]);
        }
        EmergencyRuleType::Signature => {
            engine.layer1.append_string_signatures([content]);
        }
    }
    Ok(())
}

struct DetectionStateInner {
    shards: Vec<DetectionShard>,
    version: ArcSwap<Option<String>>,
}

#[derive(Clone)]
pub struct SharedDetectionState {
    inner: Arc<DetectionStateInner>,
}

#[derive(Debug, Clone, Copy)]
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
    #[cfg(test)]
    pub fn new(engine: DetectionEngine, version: Option<String>) -> Self {
        Self::new_with_shards(engine, version, 1, DetectionEngine::default_with_rules)
    }

    pub fn new_with_shards<F>(
        engine: DetectionEngine,
        version: Option<String>,
        shard_count: usize,
        mut shard_engine_builder: F,
    ) -> Self
    where
        F: FnMut() -> DetectionEngine,
    {
        let shard_count = shard_count.max(1);
        let mut shards = Vec::with_capacity(shard_count);
        shards.push(DetectionShard::spawn(0, engine));
        for idx in 1..shard_count {
            shards.push(DetectionShard::spawn(idx, shard_engine_builder()));
        }

        Self {
            inner: Arc::new(DetectionStateInner {
                shards,
                version: ArcSwap::new(Arc::new(version)),
            }),
        }
    }

    pub fn process_event(&self, event: &TelemetryEvent) -> Result<DetectionOutcome> {
        let idx = self.shard_index_for_event(event);
        self.inner.shards[idx].process_event(event.clone())
    }

    pub fn scan_process_memory(
        &self,
        pid: u32,
        mode: detection::memory_scanner::ScanMode,
    ) -> Result<detection::memory_scanner::MemoryScanResult> {
        let idx = (pid as usize) % self.inner.shards.len();
        self.inner.shards[idx].scan_process_memory(pid, mode)
    }

    pub fn swap_engine(&self, version: String, next: DetectionEngine) -> Result<()> {
        self.swap_engine_with_builder(version, next, DetectionEngine::default_with_rules)
    }

    pub fn swap_engine_with_builder<F>(
        &self,
        version: String,
        next: DetectionEngine,
        mut shard_engine_builder: F,
    ) -> Result<()>
    where
        F: FnMut() -> DetectionEngine,
    {
        let shard_count = self.inner.shards.len();
        let mut engines = Vec::with_capacity(shard_count);
        engines.push(next);
        for _ in 1..shard_count {
            engines.push(shard_engine_builder());
        }

        self.swap_prebuilt_engines(version, engines)
    }

    pub fn swap_prebuilt_engines(
        &self,
        version: String,
        engines: Vec<DetectionEngine>,
    ) -> Result<()> {
        let shard_count = self.inner.shards.len();
        if engines.len() != shard_count {
            return Err(anyhow!(
                "swap detection engines failed: expected {} engines, got {}",
                shard_count,
                engines.len()
            ));
        }

        for (idx, (shard, shard_engine)) in self
            .inner
            .shards
            .iter()
            .zip(engines.into_iter())
            .enumerate()
        {
            shard
                .swap_engine(shard_engine)
                .map_err(|err| anyhow!("swap detection shard {idx} failed: {err}"))?;
        }

        self.inner.version.store(Arc::new(Some(version)));
        Ok(())
    }

    pub fn version(&self) -> Result<Option<String>> {
        let version = self.inner.version.load();
        Ok(version.as_ref().clone())
    }

    pub fn shard_count(&self) -> usize {
        self.inner.shards.len()
    }

    pub fn apply_emergency_rule(&self, rule: EmergencyRule) -> Result<()> {
        info!(rule_name = %rule.name, rule_type = ?rule.rule_type, "applying emergency rule to detection state");

        for (idx, shard) in self.inner.shards.iter().enumerate() {
            shard
                .apply_emergency_rule(rule.rule_type, rule.rule_content.clone())
                .map_err(|err| anyhow!("apply emergency rule on shard {idx} failed: {err}"))?;
        }
        Ok(())
    }

    pub fn update_allowlist(
        &self,
        processes: Vec<String>,
        path_prefixes: Vec<String>,
    ) -> Result<()> {
        for (idx, shard) in self.inner.shards.iter().enumerate() {
            shard
                .update_allowlist(processes.clone(), path_prefixes.clone())
                .map_err(|err| anyhow!("update allowlist on shard {idx} failed: {err}"))?;
        }
        Ok(())
    }

    pub fn set_anomaly_baseline(
        &self,
        process_key: String,
        distribution: HashMap<EventClass, f64>,
    ) -> Result<()> {
        for (idx, shard) in self.inner.shards.iter().enumerate() {
            shard
                .set_anomaly_baseline(process_key.clone(), distribution.clone())
                .map_err(|err| anyhow!("set anomaly baseline on shard {idx} failed: {err}"))?;
        }
        Ok(())
    }

    fn shard_index_for_event(&self, event: &TelemetryEvent) -> usize {
        event.session_id as usize % self.inner.shards.len()
    }
}

#[cfg(test)]
mod tests;
