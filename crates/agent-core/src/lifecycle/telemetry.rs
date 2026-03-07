use std::collections::BTreeSet;

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
        event_txn: &super::EventTxn,
        confidence: Confidence,
        now_unix: i64,
    ) -> EventEnvelope {
        let payload_json =
            self.telemetry_payload_json(enriched, event, outcome, event_txn, confidence, now_unix);
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
        event_txn: &super::EventTxn,
        confidence: Confidence,
        now_unix: i64,
    ) -> String {
        let rule_type = Self::detection_rule_type(outcome);
        let detection_layers = Self::detection_layers(outcome);
        let primary_rule_name = Self::detection_rule_name(outcome);
        let mitre_techniques = Self::mitre_techniques(event, outcome);
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
                "raw_positive": score.raw_positive,
                "conformal_gated": score.conformal_gated,
                "conformal_p_value": score.conformal_p_value,
                "decision_threshold": score.decision_threshold,
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
            "mitre_techniques": &mitre_techniques,
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
            "event_txn": {
                "event_class": &event_txn.event_class,
                "operation": &event_txn.operation,
                "subject": event_txn.subject.as_deref(),
                "object": event_txn.object.as_deref(),
                "pid": event_txn.pid,
                "uid": event_txn.uid,
                "session_id": event_txn.session_id,
                "ts_unix": event_txn.ts_unix,
                "key": &event_txn.key,
            },
            "container": {
                "runtime": enriched.container_runtime.as_deref(),
                "id": enriched.container_id.as_deref(),
                "escape": enriched.container_escape,
                "privileged": enriched.container_privileged,
            },
            "detection": {
                "confidence": super::confidence_label(confidence),
                "rule_type": rule_type,
                "detection_layers": detection_layers,
                "mitre_techniques": &mitre_techniques,
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
                    "campaign_correlated": outcome.signals.campaign_correlated,
                },
            },
            "audit": {
                "primary_rule_name": primary_rule_name,
                "rule_type": rule_type,
                "detection_layers": detection_layers,
                "mitre_techniques": &mitre_techniques,
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
                    "campaign_correlated": outcome.signals.campaign_correlated,
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

    pub(super) fn detection_rule_type(outcome: &DetectionOutcome) -> &'static str {
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

    pub(super) fn detection_layers(outcome: &DetectionOutcome) -> Vec<String> {
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

    pub(super) fn mitre_techniques(
        event: &TelemetryEvent,
        outcome: &DetectionOutcome,
    ) -> Vec<String> {
        let mut techniques = BTreeSet::new();

        for rule_name in &outcome.temporal_hits {
            for technique in Self::mitre_techniques_for_label(rule_name) {
                techniques.insert(technique.to_string());
            }
        }
        for hit in &outcome.kill_chain_hits {
            for technique in Self::mitre_techniques_for_label(hit) {
                techniques.insert(technique.to_string());
            }
        }
        for indicator in &outcome.exploit_indicators {
            for technique in Self::mitre_techniques_for_label(indicator) {
                techniques.insert(technique.to_string());
            }
        }
        for indicator in &outcome.kernel_integrity_indicators {
            for technique in Self::mitre_techniques_for_label(indicator) {
                techniques.insert(technique.to_string());
            }
        }
        for indicator in &outcome.tamper_indicators {
            for technique in Self::mitre_techniques_for_label(indicator) {
                techniques.insert(technique.to_string());
            }
        }

        if !outcome.yara_hits.is_empty() {
            techniques.insert("T1027".to_string());
        }

        let process = event.process.to_ascii_lowercase();
        let command_line = event
            .command_line
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let file_path = event
            .file_path
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();

        if process.contains("powershell") || command_line.contains("powershell") {
            techniques.insert("T1059.001".to_string());
        }
        if matches!(event.event_class, detection::EventClass::ProcessExec)
            && (process == "bash"
                || process == "sh"
                || process == "dash"
                || process == "zsh"
                || command_line.contains("/bin/sh")
                || command_line.contains("/bin/bash"))
        {
            techniques.insert("T1059.004".to_string());
        }
        if file_path.contains("hklm\\sam")
            || file_path.contains("security")
            || file_path.contains("system32\\config\\sam")
            || file_path.contains("/etc/shadow")
            || file_path.contains("/etc/master.passwd")
            || command_line.contains("reg save")
            || command_line.contains("minidump")
            || command_line.contains("lsass")
        {
            techniques.insert("T1003".to_string());
        }

        techniques.into_iter().collect()
    }

    fn mitre_techniques_for_label(label: &str) -> &'static [&'static str] {
        let normalized = label.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "eguard_builtin_webshell" | "killchain_webshell_network" => &["T1505.003", "T1190"],
            "eguard_builtin_reverse_shell" | "killchain_reverse_shell" => &["T1059.004", "T1071"],
            "eguard_builtin_download_exec" => &["T1105", "T1059"],
            "eguard_builtin_privesc" | "killchain_user_root_module" => &["T1548", "T1068"],
            "eguard_builtin_kernel_module" | "rootkit_load" => &["T1014"],
            "eguard_builtin_persistence" => &["T1053", "T1543"],
            "eguard_builtin_lateral_movement" | "killchain_lateral_ssh" => {
                &["T1021", "T1021.004", "T1570"]
            }
            "eguard_builtin_sensitive_file_access" | "killchain_credential_theft" => {
                &["T1003", "T1552"]
            }
            "eguard_builtin_data_exfil"
            | "killchain_data_theft"
            | "eguard_dns_tunneling_detected" => &["T1048", "T1041"],
            "eguard_c2_beaconing_detected" => &["T1071", "T1105"],
            "eguard_win_reg_save_sam" => &["T1003"],
            "eguard_win_ps_download_cradle" => &["T1059.001", "T1105"],
            "eguard_win_shadow_copy_delete" => &["T1490", "T1486"],
            "eguard_win_event_log_clear" => &["T1070"],
            "eguard_win_schtask_creation" => &["T1053"],
            "eguard_win_service_creation_suspicious" => &["T1543"],
            "killchain_ransomware_write_burst" => &["T1486"],
            "killchain_exploit_ptrace_fileless"
            | "killchain_exploit_userfaultfd_execveat"
            | "killchain_exploit_proc_mem_fileless" => &["T1055", "T1068"],
            _ => {
                if normalized.contains("powershell") {
                    &["T1059.001"]
                } else if normalized.contains("credential")
                    || normalized.contains("lsass")
                    || normalized.contains("sam")
                {
                    &["T1003"]
                } else if normalized.contains("lateral") || normalized.contains("ssh") {
                    &["T1021"]
                } else if normalized.contains("persist") || normalized.contains("autorun") {
                    &["T1053", "T1543"]
                } else if normalized.contains("exfil") || normalized.contains("dns") {
                    &["T1048", "T1041"]
                } else if normalized.contains("ransom") {
                    &["T1486"]
                } else if normalized.contains("tamper") || normalized.contains("defender") {
                    &["T1562", "T1070"]
                } else if normalized.contains("kernel") || normalized.contains("rootkit") {
                    &["T1014"]
                } else {
                    &[]
                }
            }
        }
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

#[cfg(test)]
mod tests {
    use super::AgentRuntime;
    use detection::{
        Confidence, DetectionOutcome, DetectionSignals, EventClass, Layer1EventHit, TelemetryEvent,
    };

    fn event(process: &str, cmdline: Option<&str>) -> TelemetryEvent {
        TelemetryEvent {
            ts_unix: 1_700_000_000,
            event_class: EventClass::ProcessExec,
            pid: 42,
            ppid: 1,
            uid: 0,
            process: process.to_string(),
            parent_process: "cmd.exe".to_string(),
            session_id: 1,
            file_path: None,
            file_write: false,
            file_hash: None,
            dst_port: None,
            dst_ip: None,
            dst_domain: None,
            command_line: cmdline.map(ToString::to_string),
            event_size: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        }
    }

    #[test]
    fn mitre_techniques_include_rule_and_process_context() {
        let outcome = DetectionOutcome {
            confidence: Confidence::High,
            signals: DetectionSignals {
                z2_temporal: true,
                ..DetectionSignals::default()
            },
            temporal_hits: vec!["eguard_builtin_sensitive_file_access".to_string()],
            kill_chain_hits: Vec::new(),
            exploit_indicators: Vec::new(),
            kernel_integrity_indicators: Vec::new(),
            tamper_indicators: Vec::new(),
            yara_hits: Vec::new(),
            anomaly: None,
            layer1: Layer1EventHit::default(),
            ml_score: None,
            behavioral_alarms: Vec::new(),
        };

        let techniques = AgentRuntime::mitre_techniques(
            &event("powershell.exe", Some("powershell -enc AAA")),
            &outcome,
        );

        assert!(techniques.iter().any(|value| value == "T1003"));
        assert!(techniques.iter().any(|value| value == "T1059.001"));
    }
}
