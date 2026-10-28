use std::path::Path;
use std::time::Instant;

use tracing::{info, warn};

use baseline::{BaselineStatus, BaselineTransition, ProcessKey};
use detection::{Confidence, TelemetryEvent};
use grpc_client::ResponseEnvelope;
use response::{
    capture_script_content, quarantine_file, KillReport, PlannedAction, ResponseConfig,
    ResponseError,
};

use crate::config::AgentMode;

use super::{
    circuit_breaker::{BreakerDecision, DestructiveKind, BREAKER_MAX_BLAST_UNITS},
    confidence_label, interval_due, now_unix,
    types::LocalActionStepResult,
    AgentRuntime, LocalActionResult, BASELINE_SAVE_INTERVAL_SECS,
};

impl AgentRuntime {
    pub(super) fn effective_response_config(&self) -> ResponseConfig {
        let mut cfg = self.config.response.clone();
        if matches!(self.runtime_mode, AgentMode::Learning)
            || matches!(self.baseline_store.status, BaselineStatus::Learning)
        {
            cfg.autonomous_response = false;
        }
        cfg
    }

    pub(super) fn observe_baseline(&mut self, event: &TelemetryEvent, now_unix: i64) {
        let process_key = ProcessKey {
            comm: event.process.clone(),
            parent_comm: event.parent_process.clone(),
        };
        self.baseline_store
            .learn_event(process_key.clone(), event.event_class.as_str());
        self.dirty_baseline_keys
            .insert(format!("{}:{}", process_key.comm, process_key.parent_comm));

        // Publish a mature local profile once, not on every observation: a
        // current attack window must not continually become its own baseline.
        if let Some(profile) = self.baseline_store.baselines.get_mut(&process_key) {
            if profile.sample_count == 1000 {
                let distribution = profile
                    .event_distribution
                    .iter()
                    .filter_map(|(name, count)| {
                        super::baseline::parse_event_class_name(name)
                            .map(|class| (class, *count as f64 / profile.sample_count as f64))
                    })
                    .collect();
                let key = format!("{}:{}", process_key.comm, process_key.parent_comm);
                match self
                    .detection_state
                    .set_anomaly_baselines_bulk(vec![(key, distribution)])
                {
                    Ok(()) => {
                        profile.entropy_threshold = 1.0 + (profile.sample_count as f64).log10()
                    }
                    Err(err) => {
                        warn!(error = %err, "failed publishing mature local anomaly baseline")
                    }
                }
            }
        }

        let now = now_unix.max(0) as u64;
        if let Some(transition) = self.baseline_store.check_transition_with_now(now) {
            match transition {
                BaselineTransition::LearningComplete => {
                    if let Err(err) =
                        super::seed_anomaly_baselines(&self.detection_state, &self.baseline_store)
                    {
                        warn!(error = %err, "failed publishing completed anomaly baselines");
                    }
                    info!(
                        agent_id = %self.config.agent_id,
                        baseline_status = "active",
                        "baseline learning completed; enabling active mode"
                    );
                    if !matches!(self.config.mode, AgentMode::Degraded) {
                        self.runtime_mode = AgentMode::Active;
                    }
                }
                BaselineTransition::BecameStale => {
                    self.metrics.baseline_stale_transition_total = self
                        .metrics
                        .baseline_stale_transition_total
                        .saturating_add(1);
                    warn!(
                        agent_id = %self.config.agent_id,
                        baseline_status = "stale",
                        stale_transition_total = self.metrics.baseline_stale_transition_total,
                        "baseline became stale; anomaly thresholds should be reviewed"
                    );
                }
            }

            if let Err(err) = self.baseline_store.save() {
                warn!(error = %err, "failed persisting baseline transition state");
            } else {
                let stats = self.baseline_store.storage_stats();
                info!(
                    agent_id = %self.config.agent_id,
                    baseline_status = ?self.baseline_store.status,
                    snapshot_size_bytes = stats.snapshot_size_bytes,
                    journal_size_bytes = stats.journal_size_bytes,
                    compaction_count = stats.compaction_count,
                    last_compaction_reclaimed_bytes = stats.last_compaction_reclaimed_bytes,
                    "persisted baseline transition state"
                );
            }
            self.last_baseline_save_unix = Some(now_unix);
        } else if interval_due(
            self.last_baseline_save_unix,
            now_unix,
            BASELINE_SAVE_INTERVAL_SECS,
        ) {
            self.last_baseline_save_unix = Some(now_unix);
            if let Err(err) = self.baseline_store.save() {
                warn!(error = %err, "failed persisting baseline store snapshot");
            } else {
                let stats = self.baseline_store.storage_stats();
                info!(
                    agent_id = %self.config.agent_id,
                    baseline_status = ?self.baseline_store.status,
                    snapshot_size_bytes = stats.snapshot_size_bytes,
                    journal_size_bytes = stats.journal_size_bytes,
                    compaction_count = stats.compaction_count,
                    last_compaction_reclaimed_bytes = stats.last_compaction_reclaimed_bytes,
                    "persisted baseline store snapshot"
                );
            }
        }
    }

    pub(super) async fn report_local_action_if_needed(
        &mut self,
        action: PlannedAction,
        confidence: Confidence,
        event: &TelemetryEvent,
        now_unix: i64,
        response_meta: (&[String], &str, &str),
    ) {
        if matches!(action, PlannedAction::AlertOnly | PlannedAction::None) {
            return;
        }

        let (detection_layers, rule_name, threat_category) = response_meta;
        let local = self.execute_planned_action(action, event, now_unix);
        if std::env::var("EGUARD_DEBUG_EVENT_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some()
        {
            info!(
                action = ?action,
                success = local.success,
                detail = %local.detail,
                "debug response execution"
            );
        }
        for response in build_local_action_response_reports(
            &self.config.agent_id,
            confidence,
            event,
            detection_layers,
            rule_name,
            threat_category,
            &local,
        ) {
            self.enqueue_response_report(response);
        }
    }

    fn execute_planned_action(
        &mut self,
        action: PlannedAction,
        event: &TelemetryEvent,
        _now_unix: i64,
    ) -> LocalActionResult {
        let mut success = true;
        let mut notes = Vec::new();
        let mut result = LocalActionResult {
            success: true,
            detail: String::new(),
            reports: Vec::new(),
        };

        self.execute_capture_step(action, event, &mut success, &mut notes, &mut result);
        self.execute_kill_step(action, event, &mut success, &mut notes, &mut result);
        self.execute_quarantine_step(action, event, &mut success, &mut notes, &mut result);

        if notes.is_empty() {
            notes.push("no_local_action".to_string());
        }

        result.success = success;
        result.detail = notes.join("; ");
        result
    }

    fn execute_capture_step(
        &self,
        action: PlannedAction,
        event: &TelemetryEvent,
        success: &mut bool,
        notes: &mut Vec<String>,
        result: &mut LocalActionResult,
    ) {
        if !should_capture_script(action, event) {
            return;
        }

        let mut step = new_local_action_step("capture_script");
        match capture_script_content(event.pid) {
            Ok(capture) => {
                let bytes = capture
                    .script_content
                    .as_ref()
                    .map(|buf| buf.len())
                    .or_else(|| capture.stdin_content.as_ref().map(|buf| buf.len()))
                    .unwrap_or(0);
                step.detail = format!("script_capture_bytes={}", bytes);
                notes.push(step.detail.clone());
            }
            Err(err) => {
                *success = false;
                step.success = false;
                step.detail = format!("capture_failed:{}", err);
                notes.push(step.detail.clone());
            }
        }
        result.reports.push(step);
    }

    fn execute_kill_step(
        &mut self,
        action: PlannedAction,
        event: &TelemetryEvent,
        success: &mut bool,
        notes: &mut Vec<String>,
        result: &mut LocalActionResult,
    ) {
        if !requires_kill(action) {
            return;
        }

        let mut step = new_local_action_step("kill_tree");
        if event.pid == std::process::id() {
            self.breaker.record_units(
                DestructiveKind::ProtectedGuardViolation,
                16,
                now_unix().max(0) as u64,
            );
            *success = false;
            step.success = false;
            step.detail = "kill_skipped:self_pid".to_string();
            notes.push(step.detail.clone());
            result.reports.push(step);
            return;
        }

        let mut circuit_open = false;
        let mut rate_limited = false;
        let kill_result = {
            let breaker = &mut self.breaker;
            let limiter = &mut self.limiter;
            let protected = &self.protected;
            KillReport::kill_process_tree_budgeted(event.pid, protected, |tree_size| {
                if matches!(
                    breaker.check_and_charge(
                        DestructiveKind::Kill,
                        tree_size as u64,
                        now_unix().max(0) as u64,
                    ),
                    BreakerDecision::Deny { .. }
                ) {
                    circuit_open = true;
                    return false;
                }
                if !limiter.allow(Instant::now()) {
                    rate_limited = true;
                    return false;
                }
                true
            })
        };
        if circuit_open {
            *success = false;
            step.success = false;
            step.detail = "kill_skipped:circuit_open".to_string();
            notes.push(step.detail.clone());
            result.reports.push(step);
            return;
        }
        if rate_limited {
            *success = false;
            step.success = false;
            step.detail = "kill_skipped:rate_limited".to_string();
            notes.push(step.detail.clone());
            result.reports.push(step);
            return;
        }

        match kill_result {
            Ok(kill_report) => {
                step.killed_pids = kill_report.killed_pids.clone();
                step.detail = format!("killed_pids={}", kill_report.killed_pids.len());
                notes.push(step.detail.clone());
            }
            Err(err) => {
                match &err {
                    ResponseError::ProtectedProcess(_) => self.breaker.record_units(
                        DestructiveKind::ProtectedGuardViolation,
                        16,
                        now_unix().max(0) as u64,
                    ),
                    ResponseError::Signal(message)
                        if message.contains("exceeds") && message.contains("descendants") =>
                    {
                        self.breaker.record_units(
                            DestructiveKind::Kill,
                            BREAKER_MAX_BLAST_UNITS,
                            now_unix().max(0) as u64,
                        )
                    }
                    _ => {}
                }
                *success = false;
                step.success = false;
                step.detail = format!("kill_failed:{}", err);
                notes.push(step.detail.clone());
            }
        }
        result.reports.push(step);
    }

    fn execute_quarantine_step(
        &mut self,
        action: PlannedAction,
        event: &TelemetryEvent,
        success: &mut bool,
        notes: &mut Vec<String>,
        result: &mut LocalActionResult,
    ) {
        if !requires_quarantine(action) {
            return;
        }

        let mut step = new_local_action_step("quarantine_file");

        let Some(path) = event.file_path.as_deref() else {
            *success = false;
            step.success = false;
            step.detail = "quarantine_failed:missing_file_path".to_string();
            notes.push(step.detail.clone());
            result.reports.push(step);
            return;
        };

        let file_bytes = std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0);
        let size_units = quarantine_size_units(file_bytes);
        let blast_units = 1u64.saturating_add(size_units);
        if matches!(
            self.breaker.check_and_charge(
                DestructiveKind::Quarantine,
                blast_units,
                now_unix().max(0) as u64,
            ),
            BreakerDecision::Deny { .. }
        ) {
            *success = false;
            step.success = false;
            step.detail = "quarantine_skipped:circuit_open".to_string();
            notes.push(step.detail.clone());
            result.reports.push(step);
            return;
        }

        // Consume quota before the attempt: failures count intentionally to cap incident blast radius.
        if !self.quarantine_limiter.allow(Instant::now()) {
            *success = false;
            step.success = false;
            step.detail = "quarantine_skipped:rate_limited".to_string();
            notes.push(step.detail.clone());
            result.reports.push(step);
            return;
        }

        let sha = event
            .file_hash
            .as_deref()
            .and_then(normalize_quarantine_sha256)
            .unwrap_or_default();
        match quarantine_file(Path::new(path), &sha, &self.protected) {
            Ok(quarantine_report) => {
                self.reconcile_quarantine_size_charge(
                    size_units,
                    quarantine_report.file_size,
                    now_unix().max(0) as u64,
                );
                step.file_path = Some(quarantine_report.original_path.display().to_string());
                step.quarantine_path =
                    Some(quarantine_report.quarantine_path.display().to_string());
                step.sha256 = Some(quarantine_report.sha256.clone());
                step.file_size = quarantine_report.file_size;
                step.detail = format!(
                    "quarantined:{}",
                    quarantine_report.quarantine_path.display()
                );
                notes.push(step.detail.clone());
            }
            Err(err) => {
                if matches!(err, ResponseError::ProtectedPath(_)) {
                    self.breaker.record_units(
                        DestructiveKind::ProtectedGuardViolation,
                        16,
                        now_unix().max(0) as u64,
                    );
                }
                *success = false;
                step.success = false;
                step.detail = format!("quarantine_failed:{}", err);
                notes.push(step.detail.clone());
            }
        }
        result.reports.push(step);
    }

    fn reconcile_quarantine_size_charge(
        &mut self,
        charged_size_units: u64,
        authoritative_file_size: u64,
        now_unix: u64,
    ) {
        let authoritative_units = quarantine_size_units(authoritative_file_size);
        if authoritative_units > charged_size_units {
            self.breaker.record_units(
                DestructiveKind::Quarantine,
                authoritative_units - charged_size_units,
                now_unix,
            );
        }
    }
}

fn quarantine_size_units(file_bytes: u64) -> u64 {
    file_bytes.saturating_add(8 * 1024 * 1024 - 1) / (8 * 1024 * 1024)
}

fn build_local_action_response_reports(
    agent_id: &str,
    confidence: Confidence,
    event: &TelemetryEvent,
    detection_layers: &[String],
    rule_name: &str,
    threat_category: &str,
    local: &LocalActionResult,
) -> Vec<ResponseEnvelope> {
    local
        .reports
        .iter()
        .map(|step| ResponseEnvelope {
            agent_id: agent_id.to_string(),
            action_type: step.action_type.clone(),
            confidence: confidence_label(confidence).to_string(),
            success: step.success,
            error_message: if step.success {
                String::new()
            } else {
                step.detail.clone()
            },
            detection_layers: detection_layers.to_vec(),
            target_process: event.process.clone(),
            target_pid: event.pid,
            rule_name: rule_name.to_string(),
            threat_category: threat_category.to_string(),
            file_path: step.file_path.clone().or_else(|| event.file_path.clone()),
            quarantine_path: step.quarantine_path.clone(),
            sha256: step.sha256.clone(),
            file_size: step.file_size,
            killed_pids: step.killed_pids.clone(),
        })
        .collect()
}

fn new_local_action_step(action_type: &str) -> LocalActionStepResult {
    LocalActionStepResult {
        action_type: action_type.to_string(),
        success: true,
        detail: String::new(),
        file_path: None,
        quarantine_path: None,
        sha256: None,
        file_size: 0,
        killed_pids: Vec::new(),
    }
}

fn should_capture_script(action: PlannedAction, event: &TelemetryEvent) -> bool {
    matches!(action, PlannedAction::CaptureScript)
        || (requires_kill(action) && is_script_interpreter(&event.process))
}

pub(super) fn remediation_check_type(action_id: &str) -> Option<String> {
    if action_id == "enable_firewall" {
        return Some("firewall_required".to_string());
    }
    if action_id == "disable_ssh_root_login" {
        return Some("ssh_root_login".to_string());
    }
    if let Some(rest) = action_id.strip_prefix("install_package:") {
        return Some(format!("package_installed:{}", rest));
    }
    if let Some(rest) = action_id.strip_prefix("remove_package:") {
        return Some(format!("package_absent:{}", rest));
    }
    None
}

fn requires_kill(action: PlannedAction) -> bool {
    matches!(
        action,
        PlannedAction::KillOnly | PlannedAction::KillAndQuarantine
    )
}

fn requires_quarantine(action: PlannedAction) -> bool {
    matches!(
        action,
        PlannedAction::QuarantineOnly | PlannedAction::KillAndQuarantine
    )
}

fn is_script_interpreter(process: &str) -> bool {
    matches!(
        process,
        "bash" | "sh" | "python" | "python3" | "perl" | "ruby"
    )
}

fn normalize_quarantine_sha256(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.len() != 64 || !trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AgentConfig;
    use detection::EventClass;
    use std::fs;

    fn sample_event() -> TelemetryEvent {
        TelemetryEvent {
            ts_unix: 123,
            event_class: EventClass::FileOpen,
            pid: 4242,
            ppid: 1,
            uid: 0,
            process: "bash".to_string(),
            parent_process: "sshd".to_string(),
            session_id: 7,
            file_path: Some("/tmp/payload.sh".to_string()),
            file_write: true,
            file_hash: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
            dst_port: None,
            dst_ip: None,
            dst_domain: None,
            command_line: None,
            event_size: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        }
    }

    #[test]
    fn r2_mature_local_profile_is_published_in_learning_and_forced_active_modes() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        for force_active in [false, true] {
            let base = unique_temp_dir("r2-mature-baseline");
            let mut runtime = runtime_with_response_limits(2, 1);
            runtime.baseline_store =
                baseline::BaselineStore::new(base.join("baselines.bin")).unwrap();
            let mut event = sample_event();
            event.process = "stable-worker".into();
            event.parent_process = "supervisor".into();
            event.file_hash = None;
            event.file_write = false;
            let key = ProcessKey {
                comm: event.process.clone(),
                parent_comm: event.parent_process.clone(),
            };
            for _ in 0..999 {
                runtime.baseline_store.learn_event(key.clone(), "file_open");
            }
            let now = runtime.baseline_store.learning_started_unix as i64;
            if force_active {
                runtime.baseline_store.force_active(now as u64);
            }
            runtime.observe_baseline(&event, now);
            assert_eq!(
                runtime.baseline_store.status,
                if force_active {
                    BaselineStatus::Active
                } else {
                    BaselineStatus::Learning
                }
            );
            assert!(runtime.baseline_store.baselines[&key].entropy_threshold > 0.0);
            for i in 0..256 {
                event.ts_unix = now + i;
                assert!(runtime
                    .detection_state
                    .process_event(&event)
                    .unwrap()
                    .anomaly
                    .is_none());
            }
            drop(runtime);
            fs::remove_dir_all(base).unwrap();
        }
    }

    #[test]
    fn r2_learning_completion_publishes_local_baseline_without_restart() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let base = unique_temp_dir("r2-baseline");
        let mut runtime = runtime_with_response_limits(2, 1);
        runtime.baseline_store = baseline::BaselineStore::new(base.join("baselines.bin")).unwrap();
        let mut event = sample_event();
        event.process = "recurring-worker".into();
        event.parent_process = "supervisor".into();
        event.file_hash = None;
        event.file_write = false;
        let key = ProcessKey {
            comm: event.process.clone(),
            parent_comm: event.parent_process.clone(),
        };
        for _ in 0..1024 {
            runtime.baseline_store.learn_event(key.clone(), "file_open");
        }
        let completion = runtime.baseline_store.learning_started_unix as i64 + 8 * 24 * 3600;
        runtime.observe_baseline(&event, completion);
        assert_eq!(runtime.baseline_store.status, BaselineStatus::Active);
        for i in 0..256 {
            event.ts_unix = completion + i;
            let out = runtime.detection_state.process_event(&event).unwrap();
            assert!(
                out.anomaly.is_none(),
                "learned behavior still anomalous: {:?}",
                out.anomaly
            );
        }
        // Active scoring must not follow the current window and normalize a new attack.
        event.event_class = EventClass::NetworkConnect;
        event.file_path = None;
        let mut anomalous = false;
        for i in 256..384 {
            event.ts_unix = completion + i;
            runtime.observe_baseline(&event, completion + i);
            anomalous |= runtime
                .detection_state
                .process_event(&event)
                .unwrap()
                .anomaly
                .is_some_and(|d| d.high);
        }
        assert!(anomalous, "new behavior was absorbed into the baseline");
        drop(runtime);
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly supplied local event export"]
    fn r2_replay_exported_events() {
        use std::collections::BTreeMap;
        use std::io::{BufRead, BufReader};
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let input = std::env::var("EGUARD_REPLAY_INPUT").expect("local input path");
        let output = std::env::var("EGUARD_REPLAY_OUTPUT").expect("local output path");
        let base = unique_temp_dir("r2-replay");
        let mut runtime = runtime_with_response_limits(2, 1);
        runtime.baseline_store = baseline::BaselineStore::new(base.join("baselines.bin")).unwrap();
        runtime.baseline_store.seed_with_defaults_if_empty();
        let sources = super::super::detection_bootstrap::DetectionSourcePaths {
            sigma_dir: base.join("sigma"),
            yara_dir: base.join("yara"),
            ioc_dir: base.join("ioc"),
        };
        let engine =
            super::super::detection_bootstrap::build_detection_engine_with_ransomware_policy(
                detection::RansomwarePolicy::default(),
                &sources,
            );
        runtime.detection_state = crate::detection_state::SharedDetectionState::new(engine, None);
        super::super::seed_anomaly_baselines(&runtime.detection_state, &runtime.baseline_store)
            .unwrap();
        let mut confidences = BTreeMap::<String, usize>::new();
        let mut rules = BTreeMap::<String, usize>::new();
        let mut total = 0usize;
        for line in BufReader::new(fs::File::open(input).unwrap()).lines() {
            let row: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
            let mut event = row["event"].clone();
            let class = match event["event_class"].as_str().unwrap() {
                "process_exec" => EventClass::ProcessExec,
                "process_exit" => EventClass::ProcessExit,
                "file_open" => EventClass::FileOpen,
                "network_connect" | "tcp_connect" => EventClass::NetworkConnect,
                "dns_query" => EventClass::DnsQuery,
                "module_load" => EventClass::ModuleLoad,
                "login" => EventClass::Login,
                "alert" => EventClass::Alert,
                other => panic!("unsupported event class: {other}"),
            };
            event["event_class"] = serde_json::to_value(class).unwrap();
            event["container_runtime"] = serde_json::Value::Null;
            event["container_id"] = serde_json::Value::Null;
            event["container_escape"] = false.into();
            event["container_privileged"] = false.into();
            let event: TelemetryEvent = serde_json::from_value(event).unwrap();
            runtime.observe_baseline(&event, event.ts_unix);
            let outcome = runtime.detection_state.process_event(&event).unwrap();
            *confidences
                .entry(confidence_label(outcome.confidence).into())
                .or_default() += 1;
            let mut hits = outcome.temporal_hits;
            hits.extend(outcome.kill_chain_hits);
            hits.extend(
                outcome
                    .layer1
                    .matched_signatures
                    .into_iter()
                    .map(|s| format!("ioc_sig:{s}")),
            );
            hits.extend(
                outcome
                    .yara_hits
                    .into_iter()
                    .map(|h| format!("yara:{}", h.rule_name)),
            );
            if let Some(a) = outcome.anomaly {
                hits.push(format!(
                    "anomaly:{}",
                    if a.high {
                        "high"
                    } else if a.medium {
                        "medium"
                    } else {
                        "drift"
                    }
                ));
            }
            if outcome.ml_score.is_some_and(|m| m.positive) {
                hits.push("ml_positive".into());
            }
            hits.sort();
            hits.dedup();
            for hit in hits {
                *rules.entry(hit).or_default() += 1;
            }
            total += 1;
        }
        let result =
            serde_json::json!({"total": total, "confidence": confidences, "rule_hits": rules});
        fs::write(output, serde_json::to_vec_pretty(&result).unwrap()).unwrap();
        drop(runtime);
        fs::remove_dir_all(base).unwrap();
    }

    fn runtime_with_response_limits(
        max_kills_per_minute: usize,
        max_quarantines_per_minute: usize,
    ) -> AgentRuntime {
        let mut cfg = AgentConfig::default();
        cfg.offline_buffer_backend = "memory".to_string();
        cfg.server_addr = "127.0.0.1:1".to_string();
        cfg.self_protection_integrity_check_interval_secs = 0;
        cfg.response.max_kills_per_minute = max_kills_per_minute;
        cfg.response.max_quarantines_per_minute = max_quarantines_per_minute;
        AgentRuntime::new(cfg).expect("runtime")
    }

    fn unique_temp_dir(label: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("eguard-{label}-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn quarantine_rate_limiter_skips_second_file_without_consuming_kill_quota() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let base = unique_temp_dir("quarantine-rate-limit");
        let quarantine_dir = base.join("quarantine");
        let data_dir = base.join("data");
        fs::create_dir_all(&quarantine_dir).expect("create quarantine dir");
        fs::create_dir_all(&data_dir).expect("create data dir");
        std::env::set_var("EGUARD_TEST_QUARANTINE_DIR", &quarantine_dir);
        std::env::set_var("EGUARD_AGENT_DATA_DIR", &data_dir);

        let mut runtime = runtime_with_response_limits(2, 1);
        let first_path = base.join("first.bin");
        let second_path = base.join("second.bin");
        fs::write(&first_path, b"first").expect("write first file");
        fs::write(&second_path, b"second").expect("write second file");

        let mut first_event = sample_event();
        first_event.file_path = Some(first_path.display().to_string());
        first_event.file_hash = None;
        let first = runtime.execute_planned_action(PlannedAction::QuarantineOnly, &first_event, 1);
        assert!(first.success, "{}", first.detail);
        assert_eq!(first.reports.len(), 1);
        assert_eq!(first.reports[0].action_type, "quarantine_file");
        assert!(first.reports[0].success);

        let mut second_event = sample_event();
        second_event.file_path = Some(second_path.display().to_string());
        second_event.file_hash = None;
        let second =
            runtime.execute_planned_action(PlannedAction::QuarantineOnly, &second_event, 2);
        assert!(!second.success);
        assert_eq!(second.reports.len(), 1);
        assert_eq!(second.reports[0].action_type, "quarantine_file");
        assert_eq!(second.reports[0].detail, "quarantine_skipped:rate_limited");
        assert!(second_path.exists(), "rate-limited file remains untouched");

        let now = Instant::now();
        assert!(runtime.limiter.allow(now));
        assert!(runtime.limiter.allow(now));
        assert!(!runtime.limiter.allow(now));

        std::env::remove_var("EGUARD_TEST_QUARANTINE_DIR");
        std::env::remove_var("EGUARD_AGENT_DATA_DIR");
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn circuit_breaker_denies_local_quarantine_before_file_change() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let base = unique_temp_dir("quarantine-circuit-open");
        let quarantine_dir = base.join("quarantine");
        let data_dir = base.join("data");
        fs::create_dir_all(&quarantine_dir).expect("create quarantine dir");
        fs::create_dir_all(&data_dir).expect("create data dir");
        std::env::set_var("EGUARD_TEST_QUARANTINE_DIR", &quarantine_dir);
        std::env::set_var("EGUARD_AGENT_DATA_DIR", &data_dir);

        let mut runtime = runtime_with_response_limits(1, 1);
        let now = now_unix().max(0) as u64;
        assert!(matches!(
            runtime.breaker.check_and_charge(
                DestructiveKind::Kill,
                super::super::circuit_breaker::BREAKER_MAX_BLAST_UNITS,
                now,
            ),
            BreakerDecision::Allow
        ));
        assert!(matches!(
            runtime
                .breaker
                .check_and_charge(DestructiveKind::Kill, 1, now),
            BreakerDecision::Deny { .. }
        ));

        let path = base.join("payload.bin");
        fs::write(&path, b"payload").expect("write payload");
        let mut event = sample_event();
        event.file_path = Some(path.display().to_string());
        event.file_hash = None;
        let result = runtime.execute_planned_action(PlannedAction::QuarantineOnly, &event, 1);

        assert!(!result.success);
        assert_eq!(result.reports[0].detail, "quarantine_skipped:circuit_open");
        assert!(
            path.exists(),
            "circuit-open quarantine must not move the file"
        );

        std::env::remove_var("EGUARD_TEST_QUARANTINE_DIR");
        std::env::remove_var("EGUARD_AGENT_DATA_DIR");
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn circuit_breaker_quarantine_post_action_size_reconciliation_charges_growth_delta() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let base = unique_temp_dir("quarantine-size-reconcile");
        fs::create_dir_all(&base).expect("create data dir");
        std::env::set_var("EGUARD_AGENT_DATA_DIR", &base);

        let mut runtime = runtime_with_response_limits(1, 1);
        let now = now_unix().max(0) as u64;
        assert_eq!(
            runtime
                .breaker
                .check_and_charge(DestructiveKind::Quarantine, 2, now),
            BreakerDecision::Allow
        );
        runtime.reconcile_quarantine_size_charge(1, 16 * 1024 * 1024, now);
        assert_eq!(
            runtime
                .breaker
                .check_and_charge(DestructiveKind::Kill, 125, now),
            BreakerDecision::Allow
        );
        assert!(matches!(
            runtime
                .breaker
                .check_and_charge(DestructiveKind::Kill, 1, now),
            BreakerDecision::Deny { .. }
        ));

        std::env::remove_var("EGUARD_AGENT_DATA_DIR");
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn local_action_reports_split_kill_and_quarantine_results() {
        let event = sample_event();
        let local = LocalActionResult {
            success: false,
            detail: "killed_pids=1; quarantine_failed:missing_file_path".to_string(),
            reports: vec![
                LocalActionStepResult {
                    action_type: "kill_tree".to_string(),
                    success: true,
                    detail: "killed_pids=1".to_string(),
                    file_path: None,
                    quarantine_path: None,
                    sha256: None,
                    file_size: 0,
                    killed_pids: vec![4242],
                },
                LocalActionStepResult {
                    action_type: "quarantine_file".to_string(),
                    success: false,
                    detail: "quarantine_failed:missing_file_path".to_string(),
                    file_path: None,
                    quarantine_path: None,
                    sha256: None,
                    file_size: 0,
                    killed_pids: Vec::new(),
                },
            ],
        };

        let reports = build_local_action_response_reports(
            "agent-1",
            Confidence::Definite,
            &event,
            &["L2_sigma".to_string()],
            "test_rule",
            "malware",
            &local,
        );

        assert_eq!(reports.len(), 2);
        assert_eq!(reports[0].action_type, "kill_tree");
        assert!(reports[0].success);
        assert_eq!(reports[0].killed_pids, vec![4242]);
        assert_eq!(reports[1].action_type, "quarantine_file");
        assert!(!reports[1].success);
        assert_eq!(
            reports[1].error_message,
            "quarantine_failed:missing_file_path"
        );
        assert_eq!(reports[1].file_path.as_deref(), Some("/tmp/payload.sh"));
    }

    #[test]
    fn local_action_reports_preserve_capture_script_action_type() {
        let mut event = sample_event();
        event.event_class = EventClass::ProcessExec;
        event.file_path = None;
        event.file_hash = None;
        event.process = "python3".to_string();

        let local = LocalActionResult {
            success: true,
            detail: "script_capture_bytes=128".to_string(),
            reports: vec![LocalActionStepResult {
                action_type: "capture_script".to_string(),
                success: true,
                detail: "script_capture_bytes=128".to_string(),
                file_path: None,
                quarantine_path: None,
                sha256: None,
                file_size: 0,
                killed_pids: Vec::new(),
            }],
        };

        let reports = build_local_action_response_reports(
            "agent-2",
            Confidence::High,
            &event,
            &[],
            "script_rule",
            "behavioral",
            &local,
        );

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].action_type, "capture_script");
        assert!(reports[0].success);
    }
}
