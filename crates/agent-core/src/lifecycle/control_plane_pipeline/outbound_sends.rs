use baseline::BaselineStatus;
use grpc_client::{
    ComplianceCheckEnvelope, HeartbeatAgentStatusEnvelope, HeartbeatResourceUsageEnvelope,
    HeartbeatRuntimeEnvelope, InventoryEnvelope,
};
use tracing::debug;

use super::super::{
    interval_due, AgentRuntime, ComplianceResult, PendingControlPlaneSend,
    COMMAND_BACKLOG_CAPACITY, CONTROL_PLANE_SEND_QUEUE_CAPACITY, CONTROL_PLANE_TASK_QUEUE_CAPACITY,
    HEARTBEAT_INTERVAL_SECS, RESPONSE_QUEUE_CAPACITY, RESPONSE_REPORT_QUEUE_CAPACITY,
};

impl AgentRuntime {
    pub(super) fn send_heartbeat_if_due(
        &mut self,
        now_unix: i64,
        compliance_status: &str,
        baseline_status: &str,
    ) {
        if !interval_due(
            self.last_heartbeat_attempt_unix,
            now_unix,
            HEARTBEAT_INTERVAL_SECS,
        ) {
            return;
        }
        self.last_heartbeat_attempt_unix = Some(now_unix);
        debug!(
            now_unix,
            compliance_status, baseline_status, "enqueueing heartbeat send"
        );

        let config_version = self.heartbeat_config_version();
        let runtime = self.build_heartbeat_runtime_payload(baseline_status);

        self.enqueue_control_plane_send(PendingControlPlaneSend::Heartbeat {
            agent_id: self.config.agent_id.clone(),
            compliance_status: compliance_status.to_string(),
            config_version,
            baseline_status: baseline_status.to_string(),
            runtime,
        });
    }

    pub(crate) fn baseline_status_label(&self) -> &'static str {
        match self.baseline_store.status {
            BaselineStatus::Learning => "learning",
            BaselineStatus::Active => "active",
            BaselineStatus::Stale => "stale",
        }
    }

    pub(crate) fn build_heartbeat_runtime_payload(
        &self,
        baseline_status: &str,
    ) -> HeartbeatRuntimeEnvelope {
        let snapshot = self.observability_snapshot();
        let response_cfg = self.effective_response_config();
        let report = self.last_reload_report.as_ref();

        let command_pressure_grade =
            queue_pressure_grade(snapshot.pending_command_count, COMMAND_BACKLOG_CAPACITY);
        let task_pressure_grade = queue_pressure_grade(
            snapshot.pending_control_plane_task_count,
            CONTROL_PLANE_TASK_QUEUE_CAPACITY,
        );
        let send_pressure_grade = queue_pressure_grade(
            snapshot.pending_control_plane_send_count,
            CONTROL_PLANE_SEND_QUEUE_CAPACITY,
        );
        let control_plane_pressure = queue_pressure_label(
            command_pressure_grade
                .max(task_pressure_grade)
                .max(send_pressure_grade),
        );

        let response_queue_pressure_grade =
            queue_pressure_grade(snapshot.pending_response_count, RESPONSE_QUEUE_CAPACITY);
        let report_queue_pressure_grade = queue_pressure_grade(
            snapshot.pending_response_report_count,
            RESPONSE_REPORT_QUEUE_CAPACITY,
        );
        let response_pressure =
            queue_pressure_label(response_queue_pressure_grade.max(report_queue_pressure_grade));

        HeartbeatRuntimeEnvelope {
            status: HeartbeatAgentStatusEnvelope {
                mode: snapshot.runtime_mode.clone(),
                autonomous_response_enabled: response_cfg.autonomous_response,
                active_sigma_rules: report.map(|r| r.sigma_rules as i64).unwrap_or_default(),
                active_yara_rules: report.map(|r| r.yara_rules as i64).unwrap_or_default(),
                active_ioc_entries: report.map(|r| r.ioc_entries as i64).unwrap_or_default(),
                last_detection: format!(
                    "tick={} strict_budget={} backlog={} txn_keys={} baseline={} task_replaced={} send_replaced={} task_dropped={} send_dropped={} queue_pressure={} command_pressure={} task_pressure={} send_pressure={} command_queue={}/{} task_queue={}/{} send_queue={}/{} telemetry_backend={}",
                    snapshot.tick_count,
                    snapshot.strict_budget_mode,
                    snapshot.raw_event_backlog_depth,
                    snapshot.event_txn_coalesce_key_count,
                    baseline_status,
                    snapshot.control_plane_task_replaced_total,
                    snapshot.control_plane_send_replaced_total,
                    snapshot.control_plane_task_dropped_total,
                    snapshot.control_plane_send_dropped_total,
                    control_plane_pressure,
                    queue_pressure_label(command_pressure_grade),
                    queue_pressure_label(task_pressure_grade),
                    queue_pressure_label(send_pressure_grade),
                    snapshot.pending_command_count,
                    COMMAND_BACKLOG_CAPACITY,
                    snapshot.pending_control_plane_task_count,
                    CONTROL_PLANE_TASK_QUEUE_CAPACITY,
                    snapshot.pending_control_plane_send_count,
                    CONTROL_PLANE_SEND_QUEUE_CAPACITY,
                    self.ebpf_engine.backend_label(),
                ),
                last_response_action: format!(
                    "last_response_exec={} queue_depth={}/{} deduped={} dedupe_keys={} report_dropped={} response_pressure={} response_queue_pressure={} report_queue_pressure={} report_queue={}/{}",
                    snapshot.last_response_execute_count,
                    snapshot.pending_response_count,
                    RESPONSE_QUEUE_CAPACITY,
                    snapshot.response_action_deduped_total,
                    snapshot.response_action_dedupe_key_count,
                    snapshot.response_report_dropped_total,
                    response_pressure,
                    queue_pressure_label(response_queue_pressure_grade),
                    queue_pressure_label(report_queue_pressure_grade),
                    snapshot.pending_response_report_count,
                    RESPONSE_REPORT_QUEUE_CAPACITY,
                ),
            },
            resource_usage: HeartbeatResourceUsageEnvelope {
                cpu_percent: 0.0,
                memory_rss_bytes: current_process_rss_bytes(),
                disk_usage_bytes: snapshot.pending_event_bytes as i64,
                events_per_second: 0.0,
            },
            buffered_events: snapshot.pending_event_count as i64,
        }
    }

    pub(super) fn send_compliance_if_due(&mut self, now_unix: i64, compliance: &ComplianceResult) {
        if !interval_due(
            self.last_compliance_attempt_unix,
            now_unix,
            self.compliance_interval_secs(),
        ) {
            return;
        }
        self.last_compliance_attempt_unix = Some(now_unix);

        let checks = compliance
            .checks
            .iter()
            .map(|check| {
                let remediation = self
                    .last_compliance_remediations
                    .get(&check.check_id)
                    .or_else(|| self.last_compliance_remediations.get(&check.check_type));
                ComplianceCheckEnvelope {
                    check_type: check.check_type.clone(),
                    status: check.status.clone(),
                    actual_value: check.actual_value.clone(),
                    expected_value: check.expected_value.clone(),
                    detail: check.detail.clone(),
                    auto_remediated: remediation
                        .map(|r| r.success)
                        .unwrap_or(check.auto_remediated),
                    remediation_detail: remediation
                        .map(|r| r.detail.clone())
                        .unwrap_or_else(|| check.remediation_detail.clone()),
                    check_id: check.check_id.clone(),
                    severity: check.severity.clone(),
                    evidence_json: check.evidence_json.clone(),
                    evidence_source: check.evidence_source.clone(),
                    collected_at_unix: check.collected_at_unix,
                    grace_expires_at_unix: check.grace_expires_at_unix,
                    remediation_action_id: check.remediation_action_id.clone(),
                }
            })
            .collect::<Vec<_>>();

        let summary_check_type = compliance
            .checks
            .first()
            .map(|check| check.check_type.clone())
            .unwrap_or_else(|| "policy_summary".to_string());

        let envelope = super::super::ComplianceEnvelope {
            agent_id: self.config.agent_id.clone(),
            policy_id: self.compliance_policy_id.clone(),
            policy_version: self.compliance_policy_version.clone(),
            checked_at_unix: now_unix,
            overall_status: compliance.status.clone(),
            checks,
            policy_hash: self.compliance_policy_hash.clone(),
            schema_version: self.compliance_policy_schema_version.clone(),
            check_type: summary_check_type,
            status: compliance.status.clone(),
            detail: compliance.detail.clone(),
            expected_value: String::new(),
            actual_value: String::new(),
        };

        self.enqueue_control_plane_send(PendingControlPlaneSend::Compliance { envelope });
    }

    pub(super) fn send_inventory_if_due(&mut self, now_unix: i64, inventory: &InventoryEnvelope) {
        if !interval_due(
            self.last_inventory_attempt_unix,
            now_unix,
            self.inventory_interval_secs(),
        ) {
            return;
        }
        self.last_inventory_attempt_unix = Some(now_unix);

        let mut envelope = inventory.clone();
        if envelope.collected_at_unix == 0 {
            envelope.collected_at_unix = now_unix;
        }

        self.enqueue_control_plane_send(PendingControlPlaneSend::Inventory { envelope });
    }
}

fn queue_pressure_grade(depth: usize, capacity: usize) -> u8 {
    let capacity = capacity.max(1);
    let usage_percent = depth.saturating_mul(100) / capacity;
    if usage_percent >= 90 {
        2
    } else if usage_percent >= 70 {
        1
    } else {
        0
    }
}

fn queue_pressure_label(grade: u8) -> &'static str {
    match grade {
        2 => "critical",
        1 => "elevated",
        _ => "normal",
    }
}

#[cfg(target_os = "linux")]
fn current_process_rss_bytes() -> i64 {
    let Ok(contents) = std::fs::read_to_string("/proc/self/statm") else {
        return 0;
    };
    let mut parts = contents.split_whitespace();
    let _total_pages = parts.next();
    let Some(rss_pages) = parts.next().and_then(|raw| raw.parse::<i64>().ok()) else {
        return 0;
    };
    rss_pages.saturating_mul(4096)
}

#[cfg(not(target_os = "linux"))]
fn current_process_rss_bytes() -> i64 {
    0
}
