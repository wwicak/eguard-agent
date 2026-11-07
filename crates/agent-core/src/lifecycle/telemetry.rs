use std::collections::BTreeSet;

use serde_json::json;
use tracing::{debug, info};

use detection::{Confidence, DetectionOutcome, TelemetryEvent};
use grpc_client::EventEnvelope;

use super::{confidence_to_severity, AgentRuntime, TickEvaluation};

impl AgentRuntime {
    pub(super) fn buffer_completed_yara(&mut self, now_unix: i64) -> anyhow::Result<()> {
        for result in self.detection_state.take_yara_results() {
            let confidence = result
                .hits
                .iter()
                .map(|hit| hit.severity)
                .max()
                .unwrap_or(Confidence::None);
            let mut outcome = DetectionOutcome {
                confidence,
                observation_id: result.observation_id,
                yara_hits: result.hits,
                yara_scan_incomplete: result.incomplete,
                ..Default::default()
            };
            outcome.signals.yara_hit = !outcome.yara_hits.is_empty();
            self.buffer_yara_incomplete(&outcome, now_unix)?;
            if outcome.yara_hits.is_empty() {
                continue;
            }
            // Async YARA corroborates campaign hashes, never autonomous response or ML/temporal state.
            if !result.sha256.is_empty() {
                self.buffer_ioc_signal(
                    result.sha256.clone(),
                    "hash".into(),
                    &format!("{confidence:?}"),
                    result.event.ts_unix,
                );
            }
            let rule_name = Self::detection_rule_name(&outcome).unwrap_or_default();
            let severity = confidence_to_severity(confidence);
            if !self.telemetry_noise.should_send(
                cfg!(target_os = "linux") && self.config.telemetry_noise_filter,
                &result.event,
                &outcome,
                severity,
                &rule_name,
                now_unix,
            ) {
                continue;
            }
            let hits = outcome.yara_hits.iter().map(|hit| json!({"rule":hit.rule_name,
                "source":hit.source,"literal":hit.matched_literal,"severity":confidence_to_severity(hit.severity)})).collect::<Vec<_>>();
            let mut event_json = serde_json::to_value(&result.event)?;
            event_json["event_class"] = result.event.event_class.as_str().into();
            event_json["observation_id"] = serde_json::to_value(&outcome.observation_id)?;
            self.buffer.enqueue(EventEnvelope {
                agent_id: self.config.agent_id.clone(), event_type: "alert".into(),
                severity: severity.into(), rule_name: rule_name.clone(), created_at_unix: now_unix,
                payload_json: json!({"observed_at_unix":now_unix,"event":event_json,
                    "observation_id":outcome.observation_id,"scan_latency_ms":result.scan_latency_ms,
                    "active_pack_hash":result.pack_hash,"scanned_sha256":result.sha256,
                    "alert_only":true,"auto_response":false,
                    "detection":{"confidence":super::confidence_label(confidence),"rule_type":"yara",
                        "detection_layers":["YARA"],"yara_hits":hits,"signals":{"yara_hit":true}},
                    "audit":{"primary_rule_name":rule_name,"rule_type":"yara","detection_layers":["YARA"],"yara_hits":hits}
                }).to_string(),
            })?;
        }
        Ok(())
    }

    pub(super) fn buffer_yara_incomplete(
        &mut self,
        outcome: &DetectionOutcome,
        now_unix: i64,
    ) -> anyhow::Result<()> {
        for incomplete in &outcome.yara_scan_incomplete {
            self.buffer.enqueue(EventEnvelope {
                agent_id: self.config.agent_id.clone(), event_type: "alert".to_string(),
                severity: "low".to_string(), rule_name: "yara_scan_incomplete".to_string(),
                payload_json: json!({"rule_type":"yara_scan_incomplete", "rule_name":"yara_scan_incomplete",
                    "severity":"low", "alert_only":true, "auto_response":false,
                    "reason":incomplete.reason,"file_path":incomplete.path,"sha256":incomplete.sha256,
                    "active_pack_hash":incomplete.pack_hash}).to_string(),
                created_at_unix: now_unix,
            })?;
        }
        Ok(())
    }

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
                    "severity": confidence_to_severity(hit.severity),
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
                "observation_id": &outcome.observation_id,
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
                // RAFIX shared: preserve unlink and image identity at the telemetry boundary.
                "file_unlink": event.file_unlink,
                "process_exe": event.process_exe.as_deref(),
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
                "kill_chain_evidence": &outcome.kill_chain_evidence,
                "peer_is_configured_server": outcome.peer_is_configured_server,
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
                "kill_chain_evidence": &outcome.kill_chain_evidence,
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
        let mut without_yara = outcome.signals.clone();
        without_yara.yara_hit = false;
        if outcome.signals.yara_hit
            && !outcome.yara_hits.is_empty()
            && detection::confidence_policy(&outcome.signals) >= Confidence::High
            && detection::confidence_policy(&without_yara)
                < detection::confidence_policy(&outcome.signals)
        {
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
        if Self::detection_rule_type(outcome) == "yara" {
            return outcome.yara_hits.first().map(|hit| hit.rule_name.clone());
        }
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
        if outcome.signals.yara_hit {
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
        if ["\\config\\sam", "\\config\\security", "\\config\\system"]
            .iter()
            .any(|store| file_path.ends_with(store))
            || ["hklm\\sam", "hklm\\security"]
                .iter()
                .any(|hive| file_path == *hive || file_path.starts_with(&format!("{hive}\\")))
            || matches!(
                event.file_path.as_deref(),
                Some(
                    "/etc/shadow" | "/etc/gshadow" | "/etc/master.passwd" | "/etc/security/opasswd"
                )
            )
            || matches!(process.as_str(), "lsass" | "lsass.exe")
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
            "phi_webshell" | "eguard_builtin_webshell" | "killchain_webshell_network" => {
                &["T1505.003", "T1190"]
            }
            "phi_reverse_shell" | "eguard_builtin_reverse_shell" | "killchain_reverse_shell" => {
                &["T1059.004", "T1071"]
            }
            "phi_download_pipe_shell"
            | "phi_download_then_exec_file"
            | "phi_interpreter_download_exec"
            | "eguard_builtin_download_exec" => &["T1105", "T1059"],
            "phi_unbrokered_root_shell"
            | "eguard_builtin_privesc"
            | "killchain_user_root_module" => &["T1548", "T1068"],
            "eguard_builtin_kernel_module" | "rootkit_load" => &["T1014"],
            "phi_persistence_write" | "phi_persistence_install" | "eguard_builtin_persistence" => {
                &["T1053", "T1543"]
            }
            "eguard_builtin_lateral_movement" | "killchain_lateral_ssh" => {
                &["T1021", "T1021.004", "T1570"]
            }
            "eguard_builtin_shadow_read"
            | "eguard_win_credential_store_read"
            | "eguard_builtin_sensitive_file_access"
            | "killchain_credential_theft" => &["T1003", "T1552"],
            "phi_credential_exfil"
            | "phi_data_staging"
            | "eguard_builtin_data_exfil"
            | "killchain_data_theft"
            | "eguard_dns_tunneling_detected" => &["T1048", "T1041"],
            "eguard_c2_beaconing_detected" => &["T1071", "T1105"],
            "eguard_win_reg_save_sam" => &["T1003"],
            "eguard_win_ps_download_cradle" | "eguard_win_ps_download_cradle_office" => {
                &["T1059.001", "T1105"]
            }
            "tamper:agent_service_control" | "windows_taskkill_eguard_tamper" => &["T1562.001"],
            "eguard_win_shadow_copy_delete" => &["T1490", "T1486"],
            "eguard_win_event_log_clear" => &["T1070"],
            "eguard_win_schtask_creation" | "eguard_win_schtask_suspicious_action" => &["T1053"],
            "eguard_win_service_creation" | "eguard_win_service_creation_suspicious" => &["T1543"],
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
        debug!(
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
            // RAFIX shared: default optional image and unlink semantics in existing fixtures.
            process_exe: None,
            file_unlink: false,
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

    fn context_techniques(event: &TelemetryEvent) -> Vec<String> {
        let mut engine = detection::DetectionEngine::default_with_rules();
        let outcome = engine.process_event(&self::event("cron", None));
        AgentRuntime::mitre_techniques(event, &outcome)
    }

    #[test]
    fn verdict_a7_cron_security_config_is_not_credential_access() {
        for path in [
            "/etc/security/limits.conf",
            "/etc/security/pam_env.conf",
            "/etc/security/namespace.conf",
            "/tmp/security-report",
            "/etc/shadow.backup-not-a-store",
        ] {
            let mut event = event("cron", Some("cron"));
            event.event_class = EventClass::FileOpen;
            event.file_path = Some(path.to_string());
            assert!(
                !context_techniques(&event).iter().any(|t| t == "T1003"),
                "ordinary configuration read tagged as credentials: {path}"
            );
        }
    }

    #[test]
    fn verdict_a7_linux_credential_stores_keep_t1003() {
        for path in [
            "/etc/gshadow",
            "/etc/shadow",
            "/etc/master.passwd",
            "/etc/security/opasswd",
        ] {
            let mut event = event("cat", None);
            event.event_class = EventClass::FileOpen;
            event.file_path = Some(path.to_string());
            assert!(
                context_techniques(&event).iter().any(|t| t == "T1003"),
                "{path}"
            );
        }
    }

    #[test]
    fn verdict_a7_windows_credential_stores_keep_t1003() {
        for path in [
            r"C:\Windows\System32\config\SYSTEM",
            r"C:\Windows\System32\config\SAM",
            r"C:\Windows\System32\config\SECURITY",
            r"HKLM\SAM",
            r"HKLM\SECURITY",
        ] {
            let mut event = event("reg.exe", None);
            event.event_class = EventClass::FileOpen;
            event.file_path = Some(path.to_string());
            assert!(
                context_techniques(&event).iter().any(|t| t == "T1003"),
                "{path}"
            );
        }
        for cmd in [
            "reg save HKLM\\SAM backup",
            "rundll32 minidump",
            "dump lsass",
        ] {
            assert!(
                context_techniques(&event("reg.exe", Some(cmd)))
                    .iter()
                    .any(|t| t == "T1003"),
                "{cmd}"
            );
        }
    }

    #[test]
    fn mitre_techniques_include_rule_and_process_context() {
        let outcome = DetectionOutcome {
            // RAFIX shared: no suppression in unrelated outcome fixtures.
            pipe_alert_suppressed: false,
            confidence: Confidence::High,
            signals: DetectionSignals {
                z2_temporal: true,
                ..DetectionSignals::default()
            },
            temporal_hits: vec!["eguard_builtin_sensitive_file_access".to_string()],
            kill_chain_hits: Vec::new(),
            kill_chain_evidence: Vec::new(),
            observation_id: None,
            peer_is_configured_server: false,
            exploit_indicators: Vec::new(),
            kernel_integrity_indicators: Vec::new(),
            tamper_indicators: Vec::new(),
            yara_hits: Vec::new(),
            yara_scan_incomplete: Vec::new(),
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
    #[test]
    fn rafix_yara_type_requires_severity_driving_signal_not_raw_hits() {
        let mut outcome = DetectionOutcome::default();
        outcome.confidence = Confidence::High;
        outcome.temporal_hits.push("fixture_sigma".into());
        outcome.signals.z2_temporal = true;
        outcome.yara_hits.push(detection::YaraHit {
            rule_name: "uncurated_noise".into(),
            source: "synthetic".into(),
            matched_literal: "1.0".into(),
            severity: detection::Confidence::High,
        });
        assert_eq!(AgentRuntime::detection_rule_type(&outcome), "sigma");
        assert!(!AgentRuntime::detection_layers(&outcome)
            .iter()
            .any(|l| l == "yara"));
        assert!(
            !AgentRuntime::mitre_techniques(&event("fixture", None), &outcome)
                .iter()
                .any(|t| t == "T1027")
        );
        outcome.temporal_hits.clear();
        outcome.signals.z2_temporal = false;
        outcome.signals.yara_hit = true;
        outcome.yara_hits[0].rule_name = "eguard_eicar_test".into();
        assert_eq!(AgentRuntime::detection_rule_type(&outcome), "yara");
        assert_eq!(
            AgentRuntime::detection_rule_name(&outcome).as_deref(),
            Some("eguard_eicar_test")
        );
        outcome.signals.z1_exact_ioc = true;
        assert_eq!(
            AgentRuntime::detection_rule_type(&outcome),
            "ioc",
            "YARA did not cause the definite IOC severity"
        );
    }

    #[test]
    fn rafix_canonical_temporal_labels_keep_their_mitre_mapping() {
        for (label, expected) in [
            ("phi_webshell", "T1505.003"),
            ("phi_reverse_shell", "T1059.004"),
            ("phi_unbrokered_root_shell", "T1068"),
            ("phi_download_pipe_shell", "T1105"),
        ] {
            assert!(
                AgentRuntime::mitre_techniques_for_label(label).contains(&expected),
                "{label}"
            );
        }
    }
    #[test]
    fn agent_stop_is_medium_alert_only_with_subtechnique() {
        let mut engine = detection::DetectionEngine::default_with_rules();
        let event = event("systemctl", Some("systemctl stop eguard-agent"));
        let out = engine.process_event(&event);
        assert_eq!(out.confidence, Confidence::Medium);
        assert!(!AgentRuntime::has_concrete_response_evidence(&event, &out));
        assert!(AgentRuntime::mitre_techniques(&event, &out).contains(&"T1562.001".to_string()));
    }
}
