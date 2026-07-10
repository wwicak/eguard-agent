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
    confidence_label, interval_due, types::LocalActionStepResult, AgentRuntime, LocalActionResult,
    BASELINE_SAVE_INTERVAL_SECS,
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
            *success = false;
            step.success = false;
            step.detail = "kill_skipped:self_pid".to_string();
            notes.push(step.detail.clone());
            result.reports.push(step);
            return;
        }

        if !self.limiter.allow(Instant::now()) {
            *success = false;
            step.success = false;
            step.detail = "kill_skipped:rate_limited".to_string();
            notes.push(step.detail.clone());
            result.reports.push(step);
            return;
        }

        match kill_process_tree(event.pid, &self.protected) {
            Ok(kill_report) => {
                step.killed_pids = kill_report.killed_pids.clone();
                step.detail = format!("killed_pids={}", kill_report.killed_pids.len());
                notes.push(step.detail.clone());
            }
            Err(err) => {
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
                *success = false;
                step.success = false;
                step.detail = format!("quarantine_failed:{}", err);
                notes.push(step.detail.clone());
            }
        }
        result.reports.push(step);
    }
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
        fs::create_dir_all(&quarantine_dir).expect("create quarantine dir");
        std::env::set_var("EGUARD_TEST_QUARANTINE_DIR", &quarantine_dir);

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
