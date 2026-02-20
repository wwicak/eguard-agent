use serde_json::json;
use tracing::info;

use detection::{Confidence, DetectionOutcome, TelemetryEvent};
use grpc_client::EventEnvelope;

use super::{AgentRuntime, TickEvaluation};

impl AgentRuntime {
    pub(super) fn build_event_envelope(
        &self,
        enriched: &crate::platform::EnrichedEvent,
        event: &TelemetryEvent,
        outcome: &DetectionOutcome,
        confidence: Confidence,
        now_unix: i64,
    ) -> EventEnvelope {
        let payload_json =
            self.telemetry_payload_json(enriched, event, outcome, confidence, now_unix);
        if std::env::var("EGUARD_DEBUG_AUDIT_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some()
        {
            info!(payload = %payload_json, "debug audit payload");
        }
        EventEnvelope {
            agent_id: self.config.agent_id.clone(),
            event_type: "process_exec".to_string(),
            severity: "info".to_string(),
            rule_name: String::new(),
            payload_json,
            created_at_unix: now_unix,
        }
    }

    pub(super) fn telemetry_payload_json(
        &self,
        enriched: &crate::platform::EnrichedEvent,
        event: &TelemetryEvent,
        outcome: &DetectionOutcome,
        confidence: Confidence,
        now_unix: i64,
    ) -> String {
        let rule_type = Self::detection_rule_type(outcome);
        let detection_layers = Self::detection_layers(outcome);
        let primary_rule_name = Self::detection_rule_name(outcome);
        let yara_hits = outcome
            .yara_hits
            .iter()
            .map(|hit| {
                json!({
                    "rule": hit.rule_name,
                    "source": hit.source,
                    "literal": hit.matched_literal,
                })
            })
            .collect::<Vec<_>>();
        let behavioral_alarms = outcome
            .behavioral_alarms
            .iter()
            .map(|alarm| {
                json!({
                    "dimension": alarm.dimension,
                    "magnitude": alarm.magnitude,
                    "wasserstein_distance": alarm.wasserstein_distance,
                    "current_entropy": alarm.current_entropy,
                    "p_value": alarm.p_value,
                    "gated": alarm.gated,
                })
            })
            .collect::<Vec<_>>();

        let ml_score = outcome.ml_score.as_ref().map(|score| {
            let top_features = score
                .top_features
                .iter()
                .map(|(name, contribution)| {
                    json!({
                        "name": name,
                        "contribution": contribution,
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "score": score.score,
                "positive": score.positive,
                "top_features": top_features,
            })
        });

        let anomaly = outcome.anomaly.as_ref().map(|decision| {
            json!({
                "high": decision.high,
                "medium": decision.medium,
                "kl_bits": decision.kl_bits,
                "tau_high": decision.tau_high,
                "tau_med": decision.tau_med,
                "entropy_bits": decision.entropy_bits,
                "entropy_z": decision.entropy_z,
            })
        });

        json!({
            "observed_at_unix": now_unix,
            "event": {
                "ts_unix": event.ts_unix,
                "event_class": event.event_class.as_str(),
                "pid": event.pid,
                "ppid": event.ppid,
                "uid": event.uid,
                "process": &event.process,
                "parent_process": &event.parent_process,
                "session_id": event.session_id,
                "file_path": event.file_path.as_deref(),
                "file_write": event.file_write,
                "file_hash": event.file_hash.as_deref(),
                "dst_port": event.dst_port,
                "dst_ip": event.dst_ip.as_deref(),
                "dst_domain": event.dst_domain.as_deref(),
                "command_line": event.command_line.as_deref(),
                "event_size": event.event_size,
            },
            "container": {
                "runtime": enriched.container_runtime.as_deref(),
                "id": enriched.container_id.as_deref(),
                "escape": enriched.container_escape,
                "privileged": enriched.container_privileged,
            },
            "detection": {
                "confidence": format!("{:?}", confidence).to_ascii_lowercase(),
                "rule_type": rule_type,
                "detection_layers": detection_layers,
                "temporal_hits": &outcome.temporal_hits,
                "kill_chain_hits": &outcome.kill_chain_hits,
                "exploit_indicators": &outcome.exploit_indicators,
                "kernel_integrity_indicators": &outcome.kernel_integrity_indicators,
                "tamper_indicators": &outcome.tamper_indicators,
                "ioc_matches": &outcome.layer1.matched_signatures,
                "yara_hits": yara_hits,
                "anomaly": anomaly,
                "ml_score": ml_score,
                "behavioral_alarms": behavioral_alarms,
                "signals": {
                    "z1_exact_ioc": outcome.signals.z1_exact_ioc,
                    "z2_temporal": outcome.signals.z2_temporal,
                    "z3_anomaly_high": outcome.signals.z3_anomaly_high,
                    "z3_anomaly_med": outcome.signals.z3_anomaly_med,
                    "z4_kill_chain": outcome.signals.z4_kill_chain,
                    "l1_prefilter_hit": outcome.signals.l1_prefilter_hit,
                    "exploit_indicator": outcome.signals.exploit_indicator,
                    "kernel_integrity": outcome.signals.kernel_integrity,
                    "tamper_indicator": outcome.signals.tamper_indicator,
                },
            },
            "audit": {
                "primary_rule_name": primary_rule_name,
                "rule_type": rule_type,
                "detection_layers": detection_layers,
                "signals": {
                    "z1_exact_ioc": outcome.signals.z1_exact_ioc,
                    "z2_temporal": outcome.signals.z2_temporal,
                    "z3_anomaly_high": outcome.signals.z3_anomaly_high,
                    "z3_anomaly_med": outcome.signals.z3_anomaly_med,
                    "z4_kill_chain": outcome.signals.z4_kill_chain,
                    "l1_prefilter_hit": outcome.signals.l1_prefilter_hit,
                    "exploit_indicator": outcome.signals.exploit_indicator,
                    "kernel_integrity": outcome.signals.kernel_integrity,
                    "tamper_indicator": outcome.signals.tamper_indicator,
                },
                "matched_fields": &outcome.layer1.matched_fields,
                "matched_signatures": &outcome.layer1.matched_signatures,
                "temporal_hits": &outcome.temporal_hits,
                "kill_chain_hits": &outcome.kill_chain_hits,
                "exploit_indicators": &outcome.exploit_indicators,
                "yara_hits": yara_hits,
                "anomaly": anomaly,
                "ml_score": ml_score,
                "behavioral_alarms": behavioral_alarms,
            }
        })
        .to_string()
    }

    fn detection_rule_type(outcome: &DetectionOutcome) -> &'static str {
        if !outcome.yara_hits.is_empty() {
            return "yara";
        }
        if !outcome.temporal_hits.is_empty() {
            return "sigma";
        }
        if outcome.signals.z1_exact_ioc {
            return "ioc";
        }
        if !outcome.kernel_integrity_indicators.is_empty() {
            return "kernel_integrity";
        }
        if !outcome.tamper_indicators.is_empty() {
            return "self_protect";
        }
        if !outcome.exploit_indicators.is_empty() {
            return "exploit";
        }
        if !outcome.kill_chain_hits.is_empty() {
            return "kill_chain";
        }
        if outcome.signals.z3_anomaly_high || outcome.signals.z3_anomaly_med {
            return "anomaly";
        }
        if outcome
            .ml_score
            .as_ref()
            .map(|score| score.positive)
            .unwrap_or(false)
        {
            return "ml";
        }
        ""
    }

    pub(super) fn detection_rule_name(outcome: &DetectionOutcome) -> Option<String> {
        if !outcome.temporal_hits.is_empty() {
            return Some(outcome.temporal_hits[0].clone());
        }
        if !outcome.kill_chain_hits.is_empty() {
            return Some(outcome.kill_chain_hits[0].clone());
        }
        if !outcome.kernel_integrity_indicators.is_empty() {
            return Some(format!("kernel:{}", outcome.kernel_integrity_indicators[0]));
        }
        if !outcome.tamper_indicators.is_empty() {
            return Some(format!("self_protect:{}", outcome.tamper_indicators[0]));
        }
        if !outcome.exploit_indicators.is_empty() {
            return Some(format!("exploit:{}", outcome.exploit_indicators[0]));
        }
        if !outcome.yara_hits.is_empty() {
            return Some(outcome.yara_hits[0].rule_name.clone());
        }
        if !outcome.layer1.matched_signatures.is_empty() {
            return Some(format!("ioc_sig:{}", outcome.layer1.matched_signatures[0]));
        }
        None
    }

    fn detection_layers(outcome: &DetectionOutcome) -> Vec<String> {
        let mut layers = Vec::new();
        if outcome.signals.z1_exact_ioc {
            layers.push("L1_ioc".to_string());
        }
        if !outcome.temporal_hits.is_empty() {
            layers.push("L2_sigma".to_string());
        }
        if outcome.signals.z3_anomaly_high || outcome.signals.z3_anomaly_med {
            layers.push("L3_anomaly".to_string());
        }
        if !outcome.kill_chain_hits.is_empty() {
            layers.push("L4_kill_chain".to_string());
        }
        if !outcome.kernel_integrity_indicators.is_empty() {
            layers.push("KRN_kernel_integrity".to_string());
        }
        if !outcome.tamper_indicators.is_empty() {
            layers.push("ATP_tamper".to_string());
        }
        if !outcome.exploit_indicators.is_empty() {
            layers.push("EXP_exploit".to_string());
        }
        if outcome
            .ml_score
            .as_ref()
            .map(|score| score.positive)
            .unwrap_or(false)
        {
            layers.push("L5_ml".to_string());
        }
        if !outcome.yara_hits.is_empty() {
            layers.push("yara".to_string());
        }
        layers
    }

    pub(super) fn log_detection_evaluation(&self, evaluation: &TickEvaluation) {
        info!(
            action = ?evaluation.action,
            confidence = ?evaluation.confidence,
            mode = ?self.runtime_mode,
            temporal_hits = evaluation.detection_outcome.temporal_hits.len(),
            killchain_hits = evaluation.detection_outcome.kill_chain_hits.len(),
            z1 = evaluation.detection_outcome.signals.z1_exact_ioc,
            z2 = evaluation.detection_outcome.signals.z2_temporal,
            z3h = evaluation.detection_outcome.signals.z3_anomaly_high,
            z4 = evaluation.detection_outcome.signals.z4_kill_chain,
            exploit = evaluation.detection_outcome.signals.exploit_indicator,
            yara_hits = evaluation.detection_outcome.yara_hits.len(),
            "event evaluated"
        );
    }
}
