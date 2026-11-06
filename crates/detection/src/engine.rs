use std::collections::HashSet;
use std::fmt;
use std::path::Path;

use crate::beaconing::BeaconingTracker;
use crate::behavioral::{BehavioralAlarm, BehavioralEngine};
use crate::exploit::detect_exploit_indicators;
use crate::kernel_integrity::detect_kernel_integrity_indicators;
use crate::layer1::{IocLayer1, Layer1EventHit, Layer1Result};
use crate::layer2::TemporalEngine;
use crate::layer3::{AnomalyDecision, AnomalyEngine};
use crate::layer4::Layer4Engine;
use crate::layer5::{MlEngine, MlExtraContext, MlFeatures, MlScore};
use crate::policy::confidence_policy;
use crate::tamper::detect_tamper_indicators;
use crate::types::{Confidence, DetectionSignals, EventClass, TelemetryEvent};
use crate::vulnerability::CveDatabase;
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

/// Allowlist for suppressing detection on known-good processes and paths.
pub struct DetectionAllowlist {
    processes: HashSet<String>,
    path_prefixes: Vec<String>,
}

impl DetectionAllowlist {
    pub fn new() -> Self {
        Self {
            processes: HashSet::new(),
            path_prefixes: Vec::new(),
        }
    }

    pub fn add_allowed_process(&mut self, name: String) {
        self.processes.insert(name);
    }

    pub fn add_allowed_path(&mut self, prefix: String) {
        self.path_prefixes.push(prefix);
    }

    /// Replace the allowlist contents from server-provided lists.
    /// Entries must identify full executable paths, never basenames.
    pub fn load_from_lists(&mut self, processes: Vec<String>, path_prefixes: Vec<String>) {
        self.processes.clear();
        self.path_prefixes.clear();
        for p in processes {
            self.processes.insert(p);
        }
        self.path_prefixes = path_prefixes;
        // Bare basenames are not identities; only explicit executable paths qualify.
    }

    pub fn is_allowed(&self, event: &TelemetryEvent) -> bool {
        if event.event_class != EventClass::ProcessExec { return false; }
        let Some(path) = event.file_path.as_deref() else { return false; };
        if !(path.starts_with('/') || path.as_bytes().get(1) == Some(&b':')) { return false; }
        self.processes.contains(path) || self.path_prefixes.iter().any(|prefix| {
            let prefix = prefix.trim_end_matches(['/', '\\']);
            !prefix.is_empty() && (path == prefix || path.strip_prefix(prefix).is_some_and(|suffix| suffix.starts_with(['/', '\\'])))
        })
    }
}

impl Default for DetectionAllowlist {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct DetectionOutcome {
    pub confidence: Confidence,
    pub signals: DetectionSignals,
    pub temporal_hits: Vec<String>,
    pub kill_chain_hits: Vec<String>,
    pub kill_chain_evidence: Vec<crate::layer4::KillChainEvidence>,
    pub observation_id: Option<String>,
    pub peer_is_configured_server: bool,
    pub exploit_indicators: Vec<String>,
    pub kernel_integrity_indicators: Vec<String>,
    pub tamper_indicators: Vec<String>,
    pub yara_hits: Vec<YaraHit>,
    pub anomaly: Option<AnomalyDecision>,
    pub layer1: Layer1EventHit,
    pub ml_score: Option<MlScore>,
    pub behavioral_alarms: Vec<BehavioralAlarm>,
}

impl Default for DetectionOutcome {
    fn default() -> Self {
        Self {
            confidence: Confidence::None,
            signals: DetectionSignals::default(),
            temporal_hits: Vec::new(),
            kill_chain_hits: Vec::new(),
            kill_chain_evidence: Vec::new(),
            observation_id: None,
            peer_is_configured_server: false,
            exploit_indicators: Vec::new(),
            kernel_integrity_indicators: Vec::new(),
            tamper_indicators: Vec::new(),
            yara_hits: Vec::new(),
            anomaly: None,
            layer1: Layer1EventHit::default(),
            ml_score: None,
            behavioral_alarms: Vec::new(),
        }
    }
}

pub struct DetectionEngine {
    pub layer1: IocLayer1,
    pub layer2: TemporalEngine,
    pub layer3: AnomalyEngine,
    pub layer4: Layer4Engine,
    pub layer5: MlEngine,
    pub behavioral: BehavioralEngine,
    pub beaconing: BeaconingTracker,
    pub yara: YaraEngine,
    pub allowlist: DetectionAllowlist,
    pub cve: CveDatabase,
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
            layer5: MlEngine::new(),
            behavioral: BehavioralEngine::new(),
            beaconing: BeaconingTracker::new(),
            yara: YaraEngine::new(),
            allowlist: DetectionAllowlist::new(),
            cve: CveDatabase::new(),
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
            layer5: MlEngine::new(),
            behavioral: BehavioralEngine::new(),
            beaconing: BeaconingTracker::new(),
            yara,
            allowlist: DetectionAllowlist::new(),
            cve: CveDatabase::new(),
        }
    }

    pub fn default_with_rules() -> Self {
        Self {
            layer1: IocLayer1::new(),
            layer2: TemporalEngine::with_default_rules(),
            layer3: AnomalyEngine::default(),
            layer4: Layer4Engine::with_default_templates(),
            layer5: MlEngine::new(),
            behavioral: BehavioralEngine::new(),
            beaconing: BeaconingTracker::new(),
            yara: YaraEngine::new(),
            allowlist: DetectionAllowlist::new(),
            cve: CveDatabase::new(),
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
            // RAFIX shared: one malformed pack file must not stop later rules.
            let source = match std::fs::read_to_string(&path) {
                Ok(source) => source,
                Err(_) => { eprintln!("skipping unreadable Sigma file: {}", path.display()); continue; }
            };
            match self.layer2.add_sigma_rule_yaml(&source) {
                Ok(_) => loaded += 1,
                Err(_) => eprintln!("skipping invalid Sigma file: {}", path.display()),
            }
        }

        Ok(loaded)
    }

    pub fn process_event(&mut self, event: &TelemetryEvent) -> DetectionOutcome {
        let allowed = self.allowlist.is_allowed(event);
        let layer1 = self.layer1.check_event(event);
        // RAFIX shared: discard non-curated substring hits before ML, telemetry or response.
        let mut yara_hits = self.yara.scan_event(event);
        // RAFIX-INTEGRATION: remove when APACKS fail-closed YARA loader lands.
        yara_hits.retain(|hit| matches!(hit.rule_name.as_str(), "eguard_eicar_test" | "eguard_eicar_test_file"));

        // ── Layer 2: Temporal pattern correlation ───────────────
        let temporal_hits = self.layer2.observe(event);

        // ── Layer 3: Statistical anomaly (KL-divergence) ────────
        let anomaly = self.layer3.observe(event);

        // ── Layer 4: Kill chain graph matching ──────────────────
        let kill_chain_hits = self.layer4.observe(event);

        // ── Behavioral engine: CUSUM + entropy + spectral ───────
        let behavioral_alarms = self.behavioral.observe(event);

        let behavioral_high = behavioral_alarms
            .iter()
            .any(|a| a.gated && a.magnitude > 2.0);
        let behavioral_med = behavioral_alarms
            .iter()
            .any(|a| a.gated && a.magnitude > 1.0);

        // ── Beaconing tracker: MI-based C2 detection ────────────
        let (c2_beaconing_detected, beacon_mi_score) = if matches!(
            event.event_class,
            EventClass::NetworkConnect | EventClass::DnsQuery
        ) {
            let dst_key = format!(
                "{}:{}",
                event.dst_ip.as_deref().unwrap_or(""),
                event.dst_port.unwrap_or(0)
            );
            let result =
                self.beaconing
                    .observe(&dst_key, event.ts_unix, event.event_size.unwrap_or(0));
            (result.detected, result.mi_score)
        } else {
            (false, 0.0)
        };

        // ── Process tree anomaly: derive from behavioral tree_branching ──
        let process_tree_anomaly = behavioral_alarms
            .iter()
            .any(|a| a.gated && a.dimension == "tree_branching");

        // ── CVE vulnerability check on ModuleLoad ───────────────
        let vulnerable_software = event.event_class == EventClass::ModuleLoad
            && event
                .file_path
                .as_deref()
                .is_some_and(|path| self.cve.check_module_path(path));

        let exploit_indicators = detect_exploit_indicators(event);
        let kernel_integrity_indicators = detect_kernel_integrity_indicators(event);
        let tamper_indicators = detect_tamper_indicators(event);
        let network_ioc_hit = has_network_ioc_field(&layer1);
        let signals = DetectionSignals {
            z1_exact_ioc: layer1.result == Layer1Result::ExactMatch,
            yara_hit: !yara_hits.is_empty(),
            z2_temporal: temporal_hits.iter().any(|name| self.layer2.rule_level(name) >= crate::RuleLevel::High),
            z2_temporal_medium: temporal_hits.iter().any(|name| self.layer2.rule_level(name) == crate::RuleLevel::Medium),
            z2_temporal_low: temporal_hits.iter().any(|name| self.layer2.rule_level(name) == crate::RuleLevel::Low),
            z3_anomaly_high: anomaly.as_ref().map(|a| a.high).unwrap_or(false) || behavioral_high,
            z3_anomaly_med: anomaly.as_ref().map(|a| a.medium).unwrap_or(false) || behavioral_med,
            z4_kill_chain: !kill_chain_hits.is_empty(),
            l1_prefilter_hit: layer1.prefilter_hit,
            l1_named_hit: !layer1.matched_signatures.is_empty() || !layer1.matched_fields.iter().all(|f| f == "command_line" || f == "file_path"),
            l1_strong_signature: layer1.strong,
            exploit_indicator: !exploit_indicators.is_empty(),
            kernel_integrity: !kernel_integrity_indicators.is_empty(),
            tamper_indicator: !tamper_indicators.is_empty(),
            c2_beaconing_detected,
            process_tree_anomaly,
            network_ioc_hit,
            vulnerable_software,
            ..Default::default()
        };

        // ── Layer 5: ML meta-scoring ────────────────────────────
        // Combines all signals + event metadata + information theory
        let extra = MlExtraContext { beacon_mi_score };
        let features = MlFeatures::extract(
            event,
            &signals,
            temporal_hits.len(),
            kill_chain_hits.len(),
            yara_hits.len(),
            layer1.matched_signatures.len(),
            behavioral_alarms.len(),
            &extra,
        );
        let ml_result = self.layer5.score(&features);

        // ── Confidence aggregation ──────────────────────────────
        // Deterministic confidence from L1–L4, then ML can escalate
        let base_confidence = confidence_policy(&signals);
        let confidence = if allowed && !signals.z1_exact_ioc && !signals.yara_hit {
            Confidence::None
        } else {
            ml_enhanced_confidence(base_confidence, &ml_result)
        };

        DetectionOutcome {
            confidence,
            signals,
            temporal_hits,
            kill_chain_hits,
            kill_chain_evidence: self.layer4.last_evidence().to_vec(),
            observation_id: Some(self.layer4.current_event_id().to_string()),
            peer_is_configured_server: self.layer4.peer_is_configured_server(event),
            exploit_indicators,
            kernel_integrity_indicators,
            tamper_indicators,
            yara_hits,
            anomaly,
            layer1,
            ml_score: Some(ml_result),
            behavioral_alarms,
        }
    }
}

/// Returns `true` if the Layer 1 hit matched on a network field (dst_domain or dst_ip).
fn has_network_ioc_field(layer1: &Layer1EventHit) -> bool {
    layer1
        .matched_fields
        .iter()
        .any(|f| f == "dst_domain" || f == "dst_ip")
}

/// ML can escalate confidence but never downgrade deterministic decisions.
/// This keeps CrowdStrike-style "ML overrules everything" from causing FPs
/// while letting ML catch things the rule layers miss.
fn ml_enhanced_confidence(base: Confidence, ml: &MlScore) -> Confidence {
    match base {
        // Deterministic decisions are authoritative — ML cannot override
        Confidence::Definite | Confidence::VeryHigh => base,
        // An anomaly also feeds ML features; that is not independent evidence
        // for High. Keep ML-only detections visible at Medium.
        Confidence::None if ml.positive && ml.score >= 0.85 => Confidence::Medium,
        Confidence::Low if ml.positive && ml.score >= 0.80 => Confidence::Medium,
        Confidence::High if ml.positive && ml.score >= 0.95 => Confidence::VeryHigh,
        _ => base,
    }
}

impl Default for DetectionEngine {
    fn default() -> Self {
        Self::default_with_rules()
    }
}
