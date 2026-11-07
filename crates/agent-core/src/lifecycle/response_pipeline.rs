use std::path::Path;

use detection::DetectionOutcome;
use tracing::{info, warn};

use super::{AgentRuntime, PendingResponseAction, TickEvaluation, RESPONSE_QUEUE_CAPACITY};

// Well below half-queue drain headroom, even with primary/local response reports.
const MAX_PLAYBOOK_REPORTS_PER_EVALUATION: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ResponseOrigin {
    Telemetry,
    OperatorScan,
}

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
            || !Self::has_concrete_response_evidence(
                &evaluation.detection_event,
                &evaluation.detection_outcome,
            )
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

    pub(super) fn has_concrete_response_evidence(
        event: &detection::TelemetryEvent,
        outcome: &DetectionOutcome,
    ) -> bool {
        Self::has_concrete_response_evidence_for_origin(event, outcome, ResponseOrigin::Telemetry)
    }

    fn has_concrete_response_evidence_for_origin(
        event: &detection::TelemetryEvent,
        outcome: &DetectionOutcome,
        origin: ResponseOrigin,
    ) -> bool {
        if outcome.confidence < detection::Confidence::VeryHigh || event.file_unlink {
            return false;
        }
        let file_event = event.event_class == detection::EventClass::ProcessExec
            || (event.event_class == detection::EventClass::FileOpen
                && (event.file_write || origin == ResponseOrigin::OperatorScan));
        if !file_event {
            return false;
        }
        // Shared hosting and dirty IP/domain feeds are alert-only. Only an exact
        // hash of the executed image or written file supports the IOC path.
        if outcome.signals.z1_exact_ioc
            && outcome.layer1.result == detection::Layer1Result::ExactMatch
            && outcome
                .layer1
                .exact_matched_fields
                .iter()
                .any(|f| f == "file_hash")
            && event
                .file_hash
                .as_deref()
                .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return true;
        }
        let Some(path) = event.file_path.as_deref().filter(|p| !p.is_empty()) else {
            return false;
        };
        // Operator scans hash the current file bytes; passive telemetry keeps the same-file chain gate.
        if origin == ResponseOrigin::OperatorScan {
            return outcome.signals.yara_hit
                && outcome
                    .yara_hits
                    .iter()
                    .any(|hit| !hit.rule_name.is_empty() && hit.source == path);
        }
        let Some(id) = outcome
            .observation_id
            .as_deref()
            .filter(|id| !id.is_empty())
        else {
            return false;
        };
        // Substring YARA, heuristics, deception and broad chains are not enough
        // alone. Both sources must witness this exact file event, pid and session.
        event.pid != 0
            && event.session_id != 0
            && outcome
                .yara_hits
                .iter()
                .any(|hit| !hit.rule_name.is_empty() && hit.source == path)
            && outcome.kill_chain_evidence.iter().any(|chain| {
                !chain.template.is_empty()
                    && outcome.kill_chain_hits.contains(&chain.template)
                    && chain.witnesses.iter().any(|w| {
                        w.event_id == id
                            && w.pid == event.pid
                            && w.session_id == event.session_id
                            && w.ts_unix == event.ts_unix
                            && w.file_path.as_deref() == Some(path)
                    })
            })
    }

    pub(super) fn sanitize_planned_action_for_event(
        &self,
        action: super::PlannedAction,
        event: &detection::TelemetryEvent,
        outcome: &DetectionOutcome,
    ) -> super::PlannedAction {
        self.sanitize_planned_action_for_origin(action, event, outcome, ResponseOrigin::Telemetry)
    }

    pub(super) fn sanitize_operator_scan_action(
        &self,
        action: super::PlannedAction,
        event: &detection::TelemetryEvent,
        outcome: &DetectionOutcome,
    ) -> super::PlannedAction {
        self.sanitize_planned_action_for_origin(
            action,
            event,
            outcome,
            ResponseOrigin::OperatorScan,
        )
    }

    fn sanitize_planned_action_for_origin(
        &self,
        action: super::PlannedAction,
        event: &detection::TelemetryEvent,
        outcome: &DetectionOutcome,
        origin: ResponseOrigin,
    ) -> super::PlannedAction {
        if matches!(
            action,
            super::PlannedAction::KillOnly
                | super::PlannedAction::QuarantineOnly
                | super::PlannedAction::KillAndQuarantine
        ) && !Self::has_concrete_response_evidence_for_origin(event, outcome, origin)
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
            || !Self::has_concrete_response_evidence(
                &evaluation.detection_event,
                &evaluation.detection_outcome,
            )
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
        evaluation.detection_event.event_class = EventClass::ProcessExec;
        evaluation.detection_event.file_hash = Some("ab".repeat(32));
        let mut layer1 = detection::IocLayer1::new();
        layer1.load_hashes(["ab".repeat(32)]);
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

    fn assert_weak_path_alert_only(requested: &str) {
        let e = quarantine_event("/tmp/rafix-synthetic", true, EventClass::FileOpen);
        let mut cases = Vec::new();
        let mut a1 = DetectionOutcome::default();
        a1.temporal_hits.push("prefilter_sequence".into());
        a1.signals.l1_prefilter_hit = true;
        cases.push(("A1-prefilter-temporal", a1));
        let mut a2 = DetectionOutcome::default();
        a2.temporal_hits.push("download_exec".into());
        a2.kill_chain_hits.push("generic_shell_network".into());
        cases.push(("A2-broad-chain", a2));
        let mut a4 = DetectionOutcome::default();
        a4.exploit_indicators.push("fileless_devfd".into());
        a4.tamper_indicators.push("tamper:/proc/self/exe".into());
        cases.push(("A4-runc-clone", a4));
        let mut a6 = DetectionOutcome::default();
        a6.temporal_hits.push("download_exec".into());
        a6.yara_hits.push(detection::YaraHit {
            rule_name: "broad_literal".into(),
            source: "/tmp/rafix-synthetic".into(),
            matched_literal: "bash".into(),
        });
        cases.push(("A6-substring-yara", a6));
        let mut deception = DetectionOutcome::default();
        deception.signals.deception_triggered = true;
        cases.push(("deception-real-user-file", deception));
        let mut memory = DetectionOutcome::default();
        memory.signals.yara_hit = true;
        cases.push(("memory-scan", memory));
        for field in ["dst_domain", "dst_ip"] {
            let mut ioc = DetectionOutcome::default();
            ioc.signals.z1_exact_ioc = true;
            ioc.layer1.result = detection::Layer1Result::ExactMatch;
            ioc.layer1.matched_fields.push(field.into());
            cases.push((field, ioc));
        }
        let (name, mut o) = cases
            .into_iter()
            .find(|(name, _)| *name == requested)
            .expect("case exists");
        o.confidence = detection::Confidence::Definite;
        assert!(
            !AgentRuntime::has_concrete_response_evidence(&e, &o),
            "{name}"
        );
    }
    #[test]
    fn rafix_response_a1_prefilter_temporal_is_alert_only() {
        assert_weak_path_alert_only("A1-prefilter-temporal");
    }
    #[test]
    fn rafix_response_a2_broad_chain_is_alert_only() {
        assert_weak_path_alert_only("A2-broad-chain");
    }
    #[test]
    fn rafix_response_a4_runc_clone_is_alert_only() {
        assert_weak_path_alert_only("A4-runc-clone");
    }
    #[test]
    fn rafix_response_a6_substring_yara_is_alert_only() {
        assert_weak_path_alert_only("A6-substring-yara");
    }
    #[test]
    fn rafix_response_deception_alone_is_alert_only() {
        assert_weak_path_alert_only("deception-real-user-file");
    }
    #[test]
    fn rafix_response_memory_scan_is_alert_only() {
        assert_weak_path_alert_only("memory-scan");
    }
    #[test]
    fn rafix_response_domain_ioc_is_alert_only() {
        assert_weak_path_alert_only("dst_domain");
    }
    #[test]
    fn rafix_response_ip_ioc_is_alert_only() {
        assert_weak_path_alert_only("dst_ip");
    }

    #[test]
    fn rafix_response_domain_ioc_remains_a_definite_alert_not_kill_evidence() {
        let mut engine = detection::DetectionEngine::default_with_rules();
        engine.layer1.load_domains(["shared.fixture.test".into()]);
        let mut e = quarantine_event("/tmp/rafix-domain", false, EventClass::ProcessExec);
        e.file_hash = None;
        e.dst_domain = Some("shared.fixture.test".into());
        let o = engine.process_event(&e);
        assert_eq!(o.confidence, detection::Confidence::Definite);
        assert!(!AgentRuntime::has_concrete_response_evidence(&e, &o));
    }

    fn bound_file_evidence() -> (TelemetryEvent, DetectionOutcome) {
        let e = quarantine_event("/tmp/rafix-payload", true, EventClass::FileOpen);
        let mut o = DetectionOutcome::default();
        o.confidence = detection::Confidence::VeryHigh;
        o.observation_id = Some("current-file-event".into());
        o.kill_chain_hits.push("named-file-chain".into());
        o.kill_chain_evidence.push(detection::KillChainEvidence {
            template: "named-file-chain".into(),
            witnesses: vec![detection::KillChainWitness {
                event_id: "current-file-event".into(),
                ts_unix: e.ts_unix,
                pid: e.pid,
                process: e.process.clone(),
                exec_generation: 1,
                file_path: e.file_path.clone(),
                session_id: e.session_id,
            }],
            peer_ip: None,
            peer_port: None,
            peer_is_configured_server: false,
        });
        o.yara_hits.push(detection::YaraHit {
            rule_name: "file-signature".into(),
            source: e.file_path.clone().unwrap(),
            matched_literal: "synthetic".into(),
        });
        (e, o)
    }

    #[test]
    fn rafix_response_exact_hash_only_for_executed_image_or_written_file() {
        let mut e = quarantine_event("/tmp/rafix-payload", true, EventClass::FileOpen);
        e.file_hash = Some("ab".repeat(32));
        let mut o = DetectionOutcome::default();
        o.confidence = detection::Confidence::Definite;
        o.signals.z1_exact_ioc = true;
        o.layer1.result = detection::Layer1Result::ExactMatch;
        o.layer1.matched_fields.push("file_hash".into());
        assert!(
            !AgentRuntime::has_concrete_response_evidence(&e, &o),
            "prefilter is not exact hash"
        );
        o.layer1.exact_matched_fields.push("file_hash".into());
        assert!(AgentRuntime::has_concrete_response_evidence(&e, &o));
        e.file_write = false;
        assert!(
            !AgentRuntime::has_concrete_response_evidence(&e, &o),
            "read of a file is not the running image"
        );
        e.event_class = EventClass::ProcessExec;
        assert!(AgentRuntime::has_concrete_response_evidence(&e, &o));
        e.event_class = EventClass::NetworkConnect;
        assert!(!AgentRuntime::has_concrete_response_evidence(&e, &o));
        e.event_class = EventClass::ProcessExec;
        e.file_hash = None;
        assert!(!AgentRuntime::has_concrete_response_evidence(&e, &o));
        e.file_hash = Some("invalid-hash".into());
        assert!(!AgentRuntime::has_concrete_response_evidence(&e, &o));
    }

    #[test]
    fn rafix_response_yara_and_chain_must_bind_same_file_event() {
        let (e, o) = bound_file_evidence();
        assert!(AgentRuntime::has_concrete_response_evidence(&e, &o));
        let mut deleted = e.clone();
        deleted.file_unlink = true;
        assert!(!AgentRuntime::has_concrete_response_evidence(&deleted, &o));
        for change in 0..13 {
            let mut bad = o.clone();
            match change {
                0 => bad.kill_chain_evidence[0].witnesses[0].file_path = Some("/tmp/other".into()),
                1 => bad.kill_chain_evidence[0].witnesses[0].pid += 1,
                2 => bad.kill_chain_evidence[0].witnesses[0].session_id += 1,
                3 => bad.kill_chain_evidence[0].witnesses[0].event_id = "older-event".into(),
                4 => bad.kill_chain_evidence[0].witnesses[0].ts_unix -= 1,
                5 => bad.yara_hits[0].source = "/tmp/other".into(),
                6 => bad.kill_chain_evidence[0].template = "other-template".into(),
                7 => bad.kill_chain_hits.clear(),
                8 => bad.yara_hits.clear(),
                9 => bad.confidence = detection::Confidence::High,
                10 => bad.observation_id = None,
                11 => bad.yara_hits[0].rule_name.clear(),
                _ => {
                    bad.kill_chain_evidence[0].template.clear();
                    bad.kill_chain_hits = vec![String::new()];
                }
            }
            assert!(
                !AgentRuntime::has_concrete_response_evidence(&e, &bad),
                "condition {change}"
            );
        }
    }

    #[test]
    fn rafix_response_deception_requires_the_same_strong_corroboration() {
        let (e, mut o) = bound_file_evidence();
        o.signals.deception_triggered = true;
        assert!(AgentRuntime::has_concrete_response_evidence(&e, &o));
        o.yara_hits.clear();
        assert!(!AgentRuntime::has_concrete_response_evidence(&e, &o));
        o.kill_chain_evidence.clear();
        assert!(!AgentRuntime::has_concrete_response_evidence(&e, &o));
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
            // RAFIX shared: default optional image and unlink semantics in existing fixtures.
            process_exe: None,
            file_unlink: false,
            file_write,
            file_hash: Some("ab".repeat(32)),
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
        let mut outcome = DetectionOutcome::default();
        outcome.confidence = detection::Confidence::VeryHigh;
        outcome.signals.z1_exact_ioc = true;
        outcome.layer1.result = detection::Layer1Result::ExactMatch;
        outcome.layer1.exact_matched_fields.push("file_hash".into());
        outcome
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
    fn quarantine_only_is_rejected_for_read_only_exact_ioc_file() {
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
            super::super::PlannedAction::AlertOnly
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
    #[test]
    fn operator_scan_origin_cannot_be_spoofed_by_telemetry_labels() {
        let runtime = runtime();
        let path = std::env::temp_dir().join(format!("rafix-spoof-{}", std::process::id()));
        std::fs::write(&path, b"synthetic").unwrap();
        let mut event = quarantine_event(path.to_str().unwrap(), false, EventClass::FileOpen);
        event.process = "on_demand_scan".into();
        event.command_line = Some("on_demand_scan".into());
        assert_eq!(
            runtime.sanitize_planned_action_for_event(
                super::super::PlannedAction::QuarantineOnly,
                &event,
                &concrete_outcome()
            ),
            super::super::PlannedAction::AlertOnly
        );
        assert!(path.exists());
        assert!(
            !AgentRuntime::has_concrete_response_evidence(&event, &concrete_outcome()),
            "a process label cannot grant auto-isolation authority either"
        );
        assert_eq!(
            runtime.sanitize_operator_scan_action(
                super::super::PlannedAction::QuarantineOnly,
                &event,
                &concrete_outcome()
            ),
            super::super::PlannedAction::QuarantineOnly
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn operator_scan_preserves_protected_and_runtime_path_guards() {
        let runtime = runtime();
        for path in ["/usr/bin/ls", "/proc/self/exe", "/dev/fd/3", "relative.bin"] {
            let event = quarantine_event(path, false, EventClass::FileOpen);
            assert_eq!(
                runtime.sanitize_operator_scan_action(
                    super::super::PlannedAction::QuarantineOnly,
                    &event,
                    &concrete_outcome()
                ),
                super::super::PlannedAction::AlertOnly,
                "{path}"
            );
        }
        let mut event = quarantine_event("/tmp/rafix-operator-safe", false, EventClass::FileOpen);
        event.file_unlink = true;
        assert_eq!(
            runtime.sanitize_operator_scan_action(
                super::super::PlannedAction::QuarantineOnly,
                &event,
                &concrete_outcome()
            ),
            super::super::PlannedAction::AlertOnly
        );
        event.file_unlink = false;
        let mut outcome = concrete_outcome();
        outcome.confidence = detection::Confidence::High;
        assert_eq!(
            runtime.sanitize_operator_scan_action(
                super::super::PlannedAction::QuarantineOnly,
                &event,
                &outcome
            ),
            super::super::PlannedAction::AlertOnly
        );
    }
}
