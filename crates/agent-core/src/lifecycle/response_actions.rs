use std::path::Path;
use std::time::Instant;

use tracing::{info, warn};

use baseline::{BaselineStatus, BaselineTransition, ProcessKey};
use detection::{Confidence, TelemetryEvent};
use grpc_client::ResponseEnvelope;
use response::{
    capture_script_content, kill_process_tree, quarantine_file, PlannedAction, ResponseConfig,
};

use crate::config::AgentMode;

use super::{
    confidence_label, interval_due, AgentRuntime, LocalActionResult, BASELINE_SAVE_INTERVAL_SECS,
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

        let now = now_unix.max(0) as u64;
        if let Some(transition) = self.baseline_store.check_transition_with_now(now) {
            match transition {
                BaselineTransition::LearningComplete => {
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
        let response = ResponseEnvelope {
            agent_id: self.config.agent_id.clone(),
            action_type: format!("{:?}", action).to_ascii_lowercase(),
            confidence: confidence_label(confidence).to_string(),
            success: local.success,
            error_message: local.detail,
            detection_layers: detection_layers.to_vec(),
            target_process: event.process.clone(),
            target_pid: event.pid,
            rule_name: rule_name.to_string(),
            threat_category: threat_category.to_string(),
            file_path: event.file_path.clone(),
        };
        self.enqueue_response_report(response);
    }

    fn execute_planned_action(
        &mut self,
        action: PlannedAction,
        event: &TelemetryEvent,
        _now_unix: i64,
    ) -> LocalActionResult {
        let mut success = true;
        let mut notes = Vec::new();

        self.execute_capture_step(action, event, &mut success, &mut notes);
        self.execute_kill_step(action, event, &mut success, &mut notes);
        self.execute_quarantine_step(action, event, &mut success, &mut notes);

        if notes.is_empty() {
            notes.push("no_local_action".to_string());
        }

        LocalActionResult {
            success,
            detail: notes.join("; "),
        }
    }

    fn execute_capture_step(
        &self,
        action: PlannedAction,
        event: &TelemetryEvent,
        success: &mut bool,
        notes: &mut Vec<String>,
    ) {
        if !should_capture_script(action, event) {
            return;
        }

        match capture_script_content(event.pid) {
            Ok(capture) => {
                let bytes = capture
                    .script_content
                    .as_ref()
                    .map(|buf| buf.len())
                    .or_else(|| capture.stdin_content.as_ref().map(|buf| buf.len()))
                    .unwrap_or(0);
                notes.push(format!("script_capture_bytes={}", bytes));
            }
            Err(err) => {
                *success = false;
                notes.push(format!("capture_failed:{}", err));
            }
        }
    }

    fn execute_kill_step(
        &mut self,
        action: PlannedAction,
        event: &TelemetryEvent,
        success: &mut bool,
        notes: &mut Vec<String>,
    ) {
        if !requires_kill(action) {
            return;
        }

        if event.pid == std::process::id() {
            *success = false;
            notes.push("kill_skipped:self_pid".to_string());
            return;
        }

        if !self.limiter.allow(Instant::now()) {
            *success = false;
            notes.push("kill_skipped:rate_limited".to_string());
            return;
        }

        match kill_process_tree(event.pid, &self.protected) {
            Ok(report) => notes.push(format!("killed_pids={}", report.killed_pids.len())),
            Err(err) => {
                *success = false;
                notes.push(format!("kill_failed:{}", err));
            }
        }
    }

    fn execute_quarantine_step(
        &self,
        action: PlannedAction,
        event: &TelemetryEvent,
        success: &mut bool,
        notes: &mut Vec<String>,
    ) {
        if !requires_quarantine(action) {
            return;
        }

        let Some(path) = event.file_path.as_deref() else {
            *success = false;
            notes.push("quarantine_failed:missing_file_path".to_string());
            return;
        };

        let sha = event
            .file_hash
            .clone()
            .unwrap_or_else(|| synthetic_quarantine_id(event));
        match quarantine_file(Path::new(path), &sha, &self.protected) {
            Ok(report) => notes.push(format!("quarantined:{}", report.quarantine_path.display())),
            Err(err) => {
                *success = false;
                notes.push(format!("quarantine_failed:{}", err));
            }
        }
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

fn synthetic_quarantine_id(event: &TelemetryEvent) -> String {
    format!("pid:{}:{}", event.pid, event.ts_unix)
}
