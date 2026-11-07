use std::path::Path;

use detection::DetectionOutcome;
use tracing::{info, warn};

use super::{AgentRuntime, PendingResponseAction, TickEvaluation, RESPONSE_QUEUE_CAPACITY};

// Well below half-queue drain headroom, even with primary/local response reports.
const MAX_PLAYBOOK_REPORTS_PER_EVALUATION: usize = 16;

impl AgentRuntime {
    pub(super) async fn run_connected_response_stage(
        &mut self,
        now_unix: i64,
        evaluation: Option<&TickEvaluation>,
    ) {
        if std::env::var("EGUARD_DEBUG_EVENT_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some()
        {
            tracing::info!(
                pending_actions = self.pending_response_actions.len(),
                "debug response stage"
            );
        }

        self.maybe_apply_auto_isolation(now_unix, evaluation);
        self.enqueue_response_action_if_present(now_unix, evaluation);
        self.enqueue_playbook_actions_if_present(now_unix, evaluation);
        let executed = self.execute_response_backlog_budget(now_unix).await;
        let oldest_age_secs = self.response_queue_oldest_age_secs(now_unix);

        self.metrics.last_response_execute_count += executed;
        self.metrics.last_response_queue_depth = self.pending_response_actions.len();
        self.metrics.max_response_queue_depth = self
            .metrics
            .max_response_queue_depth
            .max(self.pending_response_actions.len());
        self.metrics.last_response_oldest_age_secs = oldest_age_secs;
        self.metrics.max_response_oldest_age_secs = self
            .metrics
            .max_response_oldest_age_secs
            .max(oldest_age_secs);
    }

    pub(super) fn maybe_apply_auto_isolation(
        &mut self,
        now_unix: i64,
        evaluation: Option<&TickEvaluation>,
    ) {
        let Some(evaluation) = evaluation else {
            return;
        };

        if self.host_control.isolated
            || !Self::has_concrete_response_evidence(&evaluation.detection_outcome)
        {
            return;
        }

        let response_cfg = self.effective_response_config();
        let should_isolate = super::evaluate_auto_isolation(
            evaluation.confidence,
            now_unix,
            &response_cfg,
            &mut self.auto_isolation_state,
        );
        if !should_isolate {
            return;
        }

        let outcome = super::execute_server_command_with_state(
            super::ServerCommand::Isolate,
            now_unix,
            &mut self.host_control,
        );

        self.enqueue_response_report(super::ResponseEnvelope {
            agent_id: self.config.agent_id.clone(),
            action_type: "auto_isolate".to_string(),
            confidence: super::confidence_label(evaluation.confidence).to_string(),
            success: outcome.status == "completed",
            error_message: outcome.detail,
            detection_layers: Vec::new(),
            target_process: String::new(),
            target_pid: 0,
            rule_name: String::new(),
            threat_category: String::new(),
            file_path: None,
            quarantine_path: None,
            sha256: None,
            file_size: 0,
            killed_pids: Vec::new(),
        });
    }

    fn enqueue_response_action_if_present(
        &mut self,
        now_unix: i64,
        evaluation: Option<&TickEvaluation>,
    ) {
        let Some(evaluation) = evaluation else {
            return;
        };

        let action = self.sanitize_planned_action_for_event(
            evaluation.action,
            &evaluation.detection_event,
            &evaluation.detection_outcome,
        );
        if matches!(
            action,
            super::PlannedAction::AlertOnly | super::PlannedAction::None
        ) {
            return;
        }

        if !self.should_enqueue_response_action(
            now_unix,
            action,
            &evaluation.event_txn.key,
            "primary",
        ) {
            return;
        }

        if self.pending_response_actions.len() >= RESPONSE_QUEUE_CAPACITY {
            warn!(
                queue_depth = self.pending_response_actions.len(),
                capacity = RESPONSE_QUEUE_CAPACITY,
                "response queue reached capacity; dropping oldest pending response"
            );
            self.pending_response_actions.pop_front();
        }

        let detection_layers = super::AgentRuntime::detection_layers(&evaluation.detection_outcome);
        let rule_name = super::AgentRuntime::detection_rule_name(&evaluation.detection_outcome)
            .unwrap_or_default();
        let threat_category =
            super::AgentRuntime::detection_rule_type(&evaluation.detection_outcome).to_string();

        self.pending_response_actions
            .push_back(PendingResponseAction {
                action,
                confidence: evaluation.confidence,
                event: evaluation.detection_event.clone(),
                txn_key: evaluation.event_txn.key.clone(),
                enqueued_at_unix: now_unix,
                detection_layers,
                rule_name,
                threat_category,
            });
    }

    /// Evaluate the playbook engine and enqueue any resulting actions.
    ///
    /// Playbook actions augment (not replace) the standard confidence-based
    /// response. Each playbook action string is mapped to the closest
    /// [`PlannedAction`] variant. Actions like "alert" and "log" produce
    /// response reports but no local kill/quarantine.
    fn enqueue_playbook_actions_if_present(
        &mut self,
        now_unix: i64,
        evaluation: Option<&TickEvaluation>,
    ) {
        let Some(evaluation) = evaluation else {
            return;
        };

        let playbook_actions = self
            .playbook_engine
            .evaluate(&evaluation.detection_outcome, &evaluation.detection_event);

        if playbook_actions.is_empty() {
            return;
        }

        let detection_layers = super::AgentRuntime::detection_layers(&evaluation.detection_outcome);
        let rule_name = super::AgentRuntime::detection_rule_name(&evaluation.detection_outcome)
            .unwrap_or_default();
        let threat_category =
            super::AgentRuntime::detection_rule_type(&evaluation.detection_outcome).to_string();

        let mut reports = 0usize;
        let mut truncated = 0u64;
        for pb_action in &playbook_actions {
            let produces_report = matches!(pb_action.action.as_str(), "alert" | "log")
                || (pb_action.action == "isolate" && !self.host_control.isolated);
            let emit_report = !produces_report || reports < MAX_PLAYBOOK_REPORTS_PER_EVALUATION;
            if produces_report {
                if emit_report {
                    reports += 1;
                } else {
                    truncated += 1;
                }
            }
            match pb_action.action.as_str() {
                "kill" => {
                    self.push_playbook_response(
                        super::PlannedAction::KillOnly,
                        evaluation,
                        now_unix,
                        &detection_layers,
                        &rule_name,
                        &threat_category,
                    );
                }
                "quarantine" => {
                    self.push_playbook_response(
                        super::PlannedAction::QuarantineOnly,
                        evaluation,
                        now_unix,
                        &detection_layers,
                        &rule_name,
                        &threat_category,
                    );
                }
                "capture" => {
                    self.push_playbook_response(
                        super::PlannedAction::CaptureScript,
                        evaluation,
                        now_unix,
                        &detection_layers,
                        &rule_name,
                        &threat_category,
                    );
                }
                "isolate" => {
                    self.execute_playbook_isolate(evaluation, now_unix, emit_report);
                }
                "alert" | "log" => {
                    if !emit_report {
                        continue;
                    }
                    self.enqueue_playbook_alert_report(
                        &pb_action.action,
                        evaluation,
                        &detection_layers,
                        &rule_name,
                        &threat_category,
                    );
                }
                unknown => {
                    warn!(action = unknown, "unknown playbook action type; skipping");
                }
            }
        }
        if truncated > 0 {
            self.metrics.playbook_reports_truncated_total = self
                .metrics
                .playbook_reports_truncated_total
                .saturating_add(truncated);
            warn!(
                truncated,
                limit = MAX_PLAYBOOK_REPORTS_PER_EVALUATION,
                "per-evaluation playbook report fanout truncated"
            );
        }
    }

    fn push_playbook_response(
        &mut self,
        action: super::PlannedAction,
        evaluation: &TickEvaluation,
        now_unix: i64,
        detection_layers: &[String],
        rule_name: &str,
        threat_category: &str,
    ) {
        let cfg = self.effective_response_config();
        if action != super::PlannedAction::CaptureScript
            && (!cfg.autonomous_response || cfg.dry_run)
        {
            return;
        }
        let action = self.sanitize_planned_action_for_event(
            action,
            &evaluation.detection_event,
            &evaluation.detection_outcome,
        );
        if matches!(
            action,
            super::PlannedAction::AlertOnly | super::PlannedAction::None
        ) {
            return;
        }

        if !self.should_enqueue_response_action(
            now_unix,
            action,
            &evaluation.event_txn.key,
            "playbook",
        ) {
            return;
        }

        if self.pending_response_actions.len() >= RESPONSE_QUEUE_CAPACITY {
            warn!(
                queue_depth = self.pending_response_actions.len(),
                capacity = RESPONSE_QUEUE_CAPACITY,
                "response queue reached capacity; dropping oldest for playbook action"
            );
            self.pending_response_actions.pop_front();
        }

        self.pending_response_actions
            .push_back(PendingResponseAction {
                action,
                confidence: evaluation.confidence,
                event: evaluation.detection_event.clone(),
                txn_key: evaluation.event_txn.key.clone(),
                enqueued_at_unix: now_unix,
                detection_layers: detection_layers.to_vec(),
                rule_name: rule_name.to_string(),
                threat_category: threat_category.to_string(),
            });
    }

    pub(super) fn has_concrete_response_evidence(outcome: &DetectionOutcome) -> bool {
        if outcome.confidence < detection::Confidence::VeryHigh {
            return false;
        }
        if outcome.signals.deception_triggered {
            return true;
        }
        if outcome.signals.z1_exact_ioc
            && outcome.layer1.result == detection::Layer1Result::ExactMatch
            && outcome
                .layer1
                .matched_fields
                .iter()
                .any(|field| matches!(field.as_str(), "file_hash" | "dst_ip" | "dst_domain"))
        {
            return true;
        }
        // YARA is alert-only, even when corroborated; independent hash/deception above are unchanged.
        if !outcome.yara_hits.is_empty() {
            return false;
        }
        // Anomaly/ML and prefilter text are not independent attack evidence.
        [
            !outcome.temporal_hits.is_empty(),
            !outcome.kill_chain_hits.is_empty(),
            !outcome.exploit_indicators.is_empty(),
            !outcome.tamper_indicators.is_empty(),
        ]
        .into_iter()
        .filter(|active| *active)
        .count()
            >= 2
    }

    pub(super) fn sanitize_planned_action_for_event(
        &self,
        action: super::PlannedAction,
        event: &detection::TelemetryEvent,
        outcome: &DetectionOutcome,
    ) -> super::PlannedAction {
        if !outcome.yara_hits.is_empty() && !Self::has_concrete_response_evidence(outcome) {
            return super::PlannedAction::AlertOnly;
        }
        if matches!(
            action,
            super::PlannedAction::KillOnly
                | super::PlannedAction::QuarantineOnly
                | super::PlannedAction::KillAndQuarantine
        ) && !Self::has_concrete_response_evidence(outcome)
        {
            return super::PlannedAction::AlertOnly;
        }
        if self.event_supports_quarantine(event, outcome) {
            return action;
        }

        match action {
            super::PlannedAction::QuarantineOnly => super::PlannedAction::AlertOnly,
            super::PlannedAction::KillAndQuarantine => super::PlannedAction::KillOnly,
            other => other,
        }
    }

    fn event_supports_quarantine(
        &self,
        event: &detection::TelemetryEvent,
        outcome: &DetectionOutcome,
    ) -> bool {
        let Some(path) = event.file_path.as_deref() else {
            return false;
        };

        let path = Path::new(path);
        if !path.is_absolute() || self.protected.is_protected_path(path) {
            return false;
        }

        if is_linux_runtime_or_pseudo_path(path) {
            return false;
        }

        event.file_write || outcome.signals.z1_exact_ioc || outcome.signals.yara_hit
    }

    fn execute_playbook_isolate(
        &mut self,
        evaluation: &TickEvaluation,
        now_unix: i64,
        emit_report: bool,
    ) {
        let cfg = self.effective_response_config();
        if !cfg.autonomous_response
            || cfg.dry_run
            || !Self::has_concrete_response_evidence(&evaluation.detection_outcome)
        {
            return;
        }
        if self.host_control.isolated {
            info!("playbook isolate skipped: host already isolated");
            return;
        }

        let outcome = super::execute_server_command_with_state(
            super::ServerCommand::Isolate,
            now_unix,
            &mut self.host_control,
        );

        // Preserve the local isolation action even when its side report is capped.
        if !emit_report {
            return;
        }
        self.enqueue_response_report(super::ResponseEnvelope {
            agent_id: self.config.agent_id.clone(),
            action_type: "playbook_isolate".to_string(),
            confidence: super::confidence_label(evaluation.confidence).to_string(),
            success: outcome.status == "completed",
            error_message: outcome.detail,
            detection_layers: Vec::new(),
            target_process: evaluation.detection_event.process.clone(),
            target_pid: evaluation.detection_event.pid,
            rule_name: String::new(),
            threat_category: String::new(),
            file_path: evaluation.detection_event.file_path.clone(),
            quarantine_path: None,
            sha256: None,
            file_size: 0,
            killed_pids: Vec::new(),
        });
    }

    fn enqueue_playbook_alert_report(
        &mut self,
        action_label: &str,
        evaluation: &TickEvaluation,
        detection_layers: &[String],
        rule_name: &str,
        threat_category: &str,
    ) {
        self.enqueue_response_report(super::ResponseEnvelope {
            agent_id: self.config.agent_id.clone(),
            action_type: format!("playbook_{}", action_label),
            confidence: super::confidence_label(evaluation.confidence).to_string(),
            success: true,
            error_message: String::new(),
            detection_layers: detection_layers.to_vec(),
            target_process: evaluation.detection_event.process.clone(),
            target_pid: evaluation.detection_event.pid,
            rule_name: rule_name.to_string(),
            threat_category: threat_category.to_string(),
            file_path: evaluation.detection_event.file_path.clone(),
            quarantine_path: None,
            sha256: None,
            file_size: 0,
            killed_pids: Vec::new(),
        });
    }

    async fn execute_response_backlog_budget(&mut self, now_unix: i64) -> usize {
        let mut executed = 0usize;

        while self.response_execution_remaining > 0 {
            let Some(pending) = self.pending_response_actions.pop_front() else {
                break;
            };

            if std::env::var("EGUARD_DEBUG_EVENT_TXN_LOG")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .is_some()
            {
                info!(
                    txn_key = %pending.txn_key,
                    action = ?pending.action,
                    "executing response action for event transaction"
                );
            }

            self.report_local_action_if_needed(
                pending.action,
                pending.confidence,
                &pending.event,
                now_unix,
                (
                    &pending.detection_layers,
                    &pending.rule_name,
                    &pending.threat_category,
                ),
            )
            .await;

            self.response_execution_remaining -= 1;
            executed = executed.saturating_add(1);
        }

        executed
    }

    fn should_enqueue_response_action(
        &mut self,
        now_unix: i64,
        action: super::PlannedAction,
        txn_key: &str,
        source: &str,
    ) -> bool {
        if self.response_action_dedupe_window_secs <= 0 {
            return true;
        }

        self.prune_response_action_dedupe_state(now_unix);
        let policy_context = self.compliance_policy_hash.as_str();
        let bundle_context = self.latest_custom_rule_hash.as_deref().unwrap_or_default();
        let dedupe_key = format!(
            "{}|{:?}|{}|policy:{}|bundle:{}",
            source, action, txn_key, policy_context, bundle_context
        );

        if let Some(last_seen_unix) = self.recent_response_action_keys.get(&dedupe_key) {
            let age_secs = now_unix.saturating_sub(*last_seen_unix);
            if age_secs <= self.response_action_dedupe_window_secs {
                self.metrics.response_action_deduped_total =
                    self.metrics.response_action_deduped_total.saturating_add(1);
                info!(
                    source,
                    action = ?action,
                    txn_key,
                    age_secs,
                    dedupe_window_secs = self.response_action_dedupe_window_secs,
                    deduped_total = self.metrics.response_action_deduped_total,
                    "skipping duplicate response action inside dedupe window"
                );
                return false;
            }
        }

        self.recent_response_action_keys
            .insert(dedupe_key, now_unix);
        true
    }

    fn prune_response_action_dedupe_state(&mut self, now_unix: i64) {
        if self.recent_response_action_keys.is_empty() {
            return;
        }

        let retention = self
            .response_action_dedupe_window_secs
            .max(1)
            .saturating_mul(4);
        self.recent_response_action_keys
            .retain(|_, ts| now_unix.saturating_sub(*ts) <= retention);

        if self.recent_response_action_keys.len()
            > self.response_action_dedupe_key_limit.saturating_mul(2)
        {
            self.recent_response_action_keys.clear();
        }
    }

    fn response_queue_oldest_age_secs(&self, now_unix: i64) -> u64 {
        let Some(item) = self.pending_response_actions.front() else {
            return 0;
        };

        now_unix.saturating_sub(item.enqueued_at_unix).max(0) as u64
    }
}

fn is_linux_runtime_or_pseudo_path(path: &Path) -> bool {
    path == Path::new("/proc")
        || path.starts_with("/proc/")
        || path == Path::new("/sys")
        || path.starts_with("/sys/")
        || path == Path::new("/dev")
        || path.starts_with("/dev/")
        || path == Path::new("/run")
        || path.starts_with("/run/")
        || path == Path::new("/var/run")
        || path.starts_with("/var/run/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AgentConfig;
    use detection::{DetectionOutcome, EventClass, TelemetryEvent};

    fn runtime() -> AgentRuntime {
        let mut cfg = AgentConfig::default();
        cfg.offline_buffer_backend = "memory".to_string();
        cfg.server_addr = "127.0.0.1:1".to_string();
        cfg.self_protection_integrity_check_interval_secs = 0;
        AgentRuntime::new(cfg).expect("runtime")
    }

    #[test]
    fn response_action_dedupe_window_suppresses_duplicate_actions() {
        let mut runtime = runtime();
        runtime.response_action_dedupe_window_secs = 60;

        assert!(runtime.should_enqueue_response_action(
            1_700_000_000,
            super::super::PlannedAction::KillOnly,
            "txn-key-1",
            "primary"
        ));
        assert!(!runtime.should_enqueue_response_action(
            1_700_000_010,
            super::super::PlannedAction::KillOnly,
            "txn-key-1",
            "primary"
        ));
        assert_eq!(runtime.metrics.response_action_deduped_total, 1);

        assert!(runtime.should_enqueue_response_action(
            1_700_000_061,
            super::super::PlannedAction::KillOnly,
            "txn-key-1",
            "primary"
        ));
    }

    #[test]
    fn response_action_dedupe_key_distinguishes_sources_and_actions() {
        let mut runtime = runtime();
        runtime.response_action_dedupe_window_secs = 60;

        assert!(runtime.should_enqueue_response_action(
            1_700_000_100,
            super::super::PlannedAction::KillOnly,
            "txn-key-2",
            "primary"
        ));
        assert!(runtime.should_enqueue_response_action(
            1_700_000_101,
            super::super::PlannedAction::QuarantineOnly,
            "txn-key-2",
            "primary"
        ));
        assert!(runtime.should_enqueue_response_action(
            1_700_000_102,
            super::super::PlannedAction::KillOnly,
            "txn-key-2",
            "playbook"
        ));

        assert_eq!(runtime.metrics.response_action_deduped_total, 0);
    }

    #[test]
    fn response_action_dedupe_key_includes_policy_and_bundle_context() {
        let mut runtime = runtime();
        runtime.response_action_dedupe_window_secs = 60;
        runtime.compliance_policy_hash = "policy-hash-a".to_string();
        runtime.latest_custom_rule_hash = Some("bundle-hash-a".to_string());

        assert!(runtime.should_enqueue_response_action(
            1_700_000_200,
            super::super::PlannedAction::KillOnly,
            "txn-key-3",
            "primary"
        ));
        assert!(!runtime.should_enqueue_response_action(
            1_700_000_201,
            super::super::PlannedAction::KillOnly,
            "txn-key-3",
            "primary"
        ));

        runtime.compliance_policy_hash = "policy-hash-b".to_string();
        assert!(runtime.should_enqueue_response_action(
            1_700_000_202,
            super::super::PlannedAction::KillOnly,
            "txn-key-3",
            "primary"
        ));

        runtime.latest_custom_rule_hash = Some("bundle-hash-b".to_string());
        assert!(runtime.should_enqueue_response_action(
            1_700_000_203,
            super::super::PlannedAction::KillOnly,
            "txn-key-3",
            "primary"
        ));
    }

    #[test]
    fn response_action_dedupe_pruning_respects_configured_key_limit() {
        let mut runtime = runtime();
        runtime.response_action_dedupe_window_secs = 60;
        runtime.response_action_dedupe_key_limit = 4;

        for i in 0..10 {
            runtime
                .recent_response_action_keys
                .insert(format!("k-{i}"), 1_600_000_000);
        }

        assert!(runtime.should_enqueue_response_action(
            1_700_000_000,
            super::super::PlannedAction::KillOnly,
            "txn-key-prune",
            "primary"
        ));
        assert!(runtime.recent_response_action_keys.len() <= 2);
    }

    fn windows_evaluation() -> TickEvaluation {
        let fixtures: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../detection/src/testdata/windows_discovery.json"
        ))
        .unwrap();
        let event: TelemetryEvent = serde_json::from_value(fixtures[0]["event"].clone()).unwrap();
        TickEvaluation {
            event_txn: super::super::EventTxn {
                event_class: "network_connect".into(),
                operation: "network_connect".into(),
                subject: Some(event.process.clone()),
                object: event.dst_ip.clone(),
                pid: event.pid,
                uid: event.uid,
                session_id: event.session_id,
                ts_unix: event.ts_unix,
                key: "windows-discovery".into(),
            },
            event_envelope: grpc_client::EventEnvelope::info(
                "fixture".into(),
                "network_connect".into(),
                "{}".into(),
                event.ts_unix,
            ),
            detection_event: event,
            detection_outcome: DetectionOutcome::default(),
            confidence: detection::Confidence::VeryHigh,
            action: response::PlannedAction::KillAndQuarantine,
            compliance: compliance::ComplianceResult {
                status: "ok".into(),
                detail: "ok".into(),
                checks: vec![],
            },
        }
    }

    #[test]
    fn windows_fp_local_destructive_actions_reject_weak_evidence() {
        let _guard = crate::test_support::TestEnvGuard::new(&[]);
        let mut runtime = runtime();
        runtime.runtime_mode = crate::config::AgentMode::Active;
        runtime.baseline_store.status = baseline::BaselineStatus::Active;
        runtime.config.response.autonomous_response = true;
        runtime.config.response.auto_isolation.enabled = true;
        runtime
            .config
            .response
            .auto_isolation
            .min_incidents_in_window = 1;
        runtime
            .playbook_engine
            .load_from_policy(&serde_json::json!({
                "response_playbooks": [{"name":"test", "enabled":true, "priority":1,
                    "conditions":{"require_signals":[]},
                    "actions":[{"action":"kill"},{"action":"quarantine"},{"action":"isolate"},
                        {"action":"capture"},{"action":"alert"}]}]
            }));
        for one_pattern in [false, true] {
            let mut evaluation = windows_evaluation();
            evaluation.detection_outcome.confidence = detection::Confidence::VeryHigh;
            evaluation.detection_outcome.signals.z3_anomaly_high = true;
            if one_pattern {
                evaluation
                    .detection_outcome
                    .temporal_hits
                    .push("one_pattern".into());
                evaluation.detection_outcome.signals.z2_temporal = true;
                evaluation.detection_outcome.signals.l1_prefilter_hit = true;
            }
            runtime.enqueue_response_action_if_present(10, Some(&evaluation));
            assert!(runtime
                .pending_response_actions
                .iter()
                .all(|pending| { pending.action == response::PlannedAction::CaptureScript }));
            runtime.enqueue_playbook_actions_if_present(10, Some(&evaluation));
            runtime.maybe_apply_auto_isolation(10, Some(&evaluation));
            assert!(!runtime.host_control.isolated);
            assert!(runtime
                .pending_response_actions
                .iter()
                .all(|pending| { pending.action == response::PlannedAction::CaptureScript }));
            assert!(runtime
                .pending_response_reports
                .iter()
                .all(|report| { report.envelope.action_type == "playbook_alert" }));
        }
        assert!(
            !runtime.pending_response_actions.is_empty(),
            "capture remains available"
        );
        assert!(
            !runtime.pending_response_reports.is_empty(),
            "alerts remain available"
        );
    }

    #[test]
    fn windows_fp_verified_malware_hash_still_queues_destructive_response() {
        let _guard = crate::test_support::TestEnvGuard::new(&[]);
        let mut runtime = runtime();
        let mut evaluation = windows_evaluation();
        evaluation.detection_event.file_hash = Some("known-malware-sha256".into());
        let mut layer1 = detection::IocLayer1::new();
        layer1.load_hashes(["known-malware-sha256".into()]);
        let mut engine = detection::DetectionEngine::new(
            layer1,
            detection::TemporalEngine::with_default_rules(),
            detection::AnomalyEngine::default(),
            detection::Layer4Engine::with_default_templates(),
        );
        evaluation.detection_outcome = engine.process_event(&evaluation.detection_event);
        evaluation.confidence = evaluation.detection_outcome.confidence;
        runtime.enqueue_response_action_if_present(10, Some(&evaluation));
        assert_eq!(evaluation.confidence, detection::Confidence::Definite);
        assert_eq!(runtime.pending_response_actions.len(), 1);
        assert_eq!(
            runtime.pending_response_actions[0].action,
            response::PlannedAction::KillOnly
        );
    }

    fn quarantine_event(path: &str, file_write: bool, event_class: EventClass) -> TelemetryEvent {
        TelemetryEvent {
            ts_unix: 1_700_000_000,
            event_class,
            pid: 4242,
            ppid: 1,
            uid: 1000,
            process: "bash".to_string(),
            parent_process: "sshd".to_string(),
            session_id: 1,
            file_path: Some(path.to_string()),
            file_write,
            file_hash: None,
            dst_port: None,
            dst_ip: None,
            dst_domain: None,
            command_line: Some("bash proof".to_string()),
            event_size: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        }
    }

    fn concrete_outcome() -> DetectionOutcome {
        DetectionOutcome {
            confidence: detection::Confidence::VeryHigh,
            temporal_hits: vec!["credential_dump_sequence".into()],
            exploit_indicators: vec!["process_injection".into()],
            ..Default::default()
        }
    }

    #[test]
    fn quarantine_only_is_downgraded_for_non_write_process_paths() {
        let runtime = runtime();
        let event = quarantine_event(
            "/usr/libexec/openssh/sshd-session",
            false,
            EventClass::ProcessExec,
        );

        assert_eq!(
            runtime.sanitize_planned_action_for_event(
                super::super::PlannedAction::QuarantineOnly,
                &event,
                &concrete_outcome(),
            ),
            super::super::PlannedAction::AlertOnly
        );
    }

    #[test]
    fn kill_and_quarantine_downgrades_to_kill_only_for_non_quarantinable_paths() {
        let runtime = runtime();
        let event = quarantine_event(
            "/usr/lib/systemd/systemd-nsresourcework",
            false,
            EventClass::ProcessExec,
        );

        assert_eq!(
            runtime.sanitize_planned_action_for_event(
                super::super::PlannedAction::KillAndQuarantine,
                &event,
                &concrete_outcome(),
            ),
            super::super::PlannedAction::KillOnly
        );
    }

    #[test]
    fn quarantine_only_is_retained_for_writable_tmp_file() {
        let runtime = runtime();
        let event = quarantine_event(
            "/tmp/platinum_sigma_file_quarantine_test.txt",
            true,
            EventClass::FileOpen,
        );

        assert_eq!(
            runtime.sanitize_planned_action_for_event(
                super::super::PlannedAction::QuarantineOnly,
                &event,
                &concrete_outcome(),
            ),
            super::super::PlannedAction::QuarantineOnly
        );
    }

    #[test]
    fn quarantine_only_is_downgraded_for_protected_write_path() {
        let runtime = runtime();
        let event = quarantine_event("/usr/bin/ls", true, EventClass::FileOpen);

        assert_eq!(
            runtime.sanitize_planned_action_for_event(
                super::super::PlannedAction::QuarantineOnly,
                &event,
                &concrete_outcome(),
            ),
            super::super::PlannedAction::AlertOnly
        );
    }

    #[test]
    fn quarantine_only_is_retained_for_read_only_exact_ioc_file() {
        let runtime = runtime();
        let event = quarantine_event(
            "/tmp/platinum_exact_ioc_read_quarantine_test.txt",
            false,
            EventClass::FileOpen,
        );
        let mut outcome = concrete_outcome();
        outcome.signals.z1_exact_ioc = true;

        assert_eq!(
            runtime.sanitize_planned_action_for_event(
                super::super::PlannedAction::QuarantineOnly,
                &event,
                &outcome,
            ),
            super::super::PlannedAction::QuarantineOnly
        );
    }

    #[test]
    fn quarantine_only_is_downgraded_for_uncorroborated_yara_file() {
        let runtime = runtime();
        let event = quarantine_event(
            "/tmp/platinum_yara_read_quarantine_test.txt",
            false,
            EventClass::FileOpen,
        );
        let mut outcome = DetectionOutcome::default();
        outcome.signals.yara_hit = true;

        assert_eq!(
            runtime.sanitize_planned_action_for_event(
                super::super::PlannedAction::QuarantineOnly,
                &event,
                &outcome,
            ),
            super::super::PlannedAction::AlertOnly
        );
    }
}
