use serde::Deserialize;

use compliance::ComplianceResult;
use detection::{Confidence, DetectionOutcome, TelemetryEvent};
use grpc_client::{
    CommandEnvelope, ComplianceEnvelope, EventEnvelope, InventoryEnvelope, ResponseEnvelope,
};
use response::PlannedAction;

#[derive(Debug)]
pub(super) struct TickEvaluation {
    pub(super) detection_event: TelemetryEvent,
    pub(super) detection_outcome: DetectionOutcome,
    pub(super) confidence: Confidence,
    pub(super) action: PlannedAction,
    pub(super) compliance: ComplianceResult,
    pub(super) event_envelope: EventEnvelope,
}

#[derive(Debug, Clone)]
pub(super) struct PendingCommand {
    pub(super) envelope: CommandEnvelope,
    pub(super) enqueued_at_unix: i64,
}

#[derive(Debug, Clone)]
pub(super) enum ControlPlaneTaskKind {
    Heartbeat {
        compliance_status: String,
        baseline_status: String,
    },
    Compliance { compliance: ComplianceResult },
    Inventory { inventory: InventoryEnvelope },
    PolicySync,
    ThreatIntelRefresh,
    CommandSync,
}

#[derive(Debug, Clone)]
pub(super) struct PendingControlPlaneTask {
    pub(super) kind: ControlPlaneTaskKind,
    pub(super) enqueued_at_unix: i64,
}

#[derive(Debug, Clone)]
pub(super) struct PendingResponseAction {
    pub(super) action: PlannedAction,
    pub(super) confidence: Confidence,
    pub(super) event: TelemetryEvent,
    pub(super) enqueued_at_unix: i64,
    pub(super) detection_layers: Vec<String>,
    pub(super) rule_name: String,
    pub(super) threat_category: String,
}

#[derive(Debug, Clone)]
pub(super) enum PendingControlPlaneSend {
    Heartbeat {
        agent_id: String,
        compliance_status: String,
        config_version: String,
        baseline_status: String,
    },
    Compliance {
        envelope: ComplianceEnvelope,
    },
    Inventory {
        envelope: InventoryEnvelope,
    },
}

#[derive(Debug, Clone)]
pub(super) struct PendingResponseReport {
    pub(super) envelope: ResponseEnvelope,
}

#[derive(Debug)]
pub(super) enum AsyncWorkerResult {
    ControlPlaneSend {
        kind: &'static str,
        error: Option<String>,
    },
    ResponseReport {
        action_type: String,
        error: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ReloadReport {
    pub(super) old_version: String,
    pub(super) new_version: String,
    pub(super) sigma_rules: usize,
    pub(super) yara_rules: usize,
    pub(super) ioc_entries: usize,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RuntimeObservabilitySnapshot {
    pub tick_count: u64,
    pub runtime_mode: String,
    pub pending_event_count: usize,
    pub pending_event_bytes: usize,
    pub consecutive_send_failures: u32,
    pub recent_ebpf_drops: u64,
    pub ebpf_failed_probe_count: usize,
    pub ebpf_attach_degraded: bool,
    pub ebpf_btf_available: bool,
    pub ebpf_lsm_available: bool,
    pub ebpf_kernel_version: String,
    pub degraded_due_to_send_failures: u64,
    pub degraded_due_to_self_protection: u64,
    pub last_degraded_cause: Option<String>,
    pub last_tick_total_micros: u64,
    pub max_tick_total_micros: u64,
    pub last_evaluate_micros: u64,
    pub last_connected_tick_micros: u64,
    pub last_degraded_tick_micros: u64,
    pub last_send_event_batch_micros: u64,
    pub last_heartbeat_micros: u64,
    pub last_compliance_micros: u64,
    pub last_threat_intel_refresh_micros: u64,
    pub last_control_plane_sync_micros: u64,
    pub pending_control_plane_task_count: usize,
    pub last_control_plane_execute_count: usize,
    pub last_control_plane_queue_depth: usize,
    pub max_control_plane_queue_depth: usize,
    pub last_control_plane_oldest_age_secs: u64,
    pub max_control_plane_oldest_age_secs: u64,
    pub last_command_sync_micros: u64,
    pub pending_command_count: usize,
    pub last_command_fetch_count: usize,
    pub last_command_execute_count: usize,
    pub last_command_backlog_depth: usize,
    pub max_command_backlog_depth: usize,
    pub last_command_backlog_oldest_age_secs: u64,
    pub max_command_backlog_oldest_age_secs: u64,
    pub pending_response_count: usize,
    pub last_response_execute_count: usize,
    pub last_response_queue_depth: usize,
    pub max_response_queue_depth: usize,
    pub last_response_oldest_age_secs: u64,
    pub max_response_oldest_age_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DegradedCause {
    SendFailures,
    SelfProtection,
}

impl DegradedCause {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::SendFailures => "send_failures",
            Self::SelfProtection => "self_protection",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct RuntimeMetrics {
    pub(super) degraded_due_to_send_failures: u64,
    pub(super) degraded_due_to_self_protection: u64,
    pub(super) last_degraded_cause: Option<DegradedCause>,
    pub(super) last_tick_total_micros: u64,
    pub(super) max_tick_total_micros: u64,
    pub(super) last_evaluate_micros: u64,
    pub(super) last_connected_tick_micros: u64,
    pub(super) last_degraded_tick_micros: u64,
    pub(super) last_send_event_batch_micros: u64,
    pub(super) last_heartbeat_micros: u64,
    pub(super) last_compliance_micros: u64,
    pub(super) last_threat_intel_refresh_micros: u64,
    pub(super) last_control_plane_sync_micros: u64,
    pub(super) last_control_plane_execute_count: usize,
    pub(super) last_control_plane_queue_depth: usize,
    pub(super) max_control_plane_queue_depth: usize,
    pub(super) last_control_plane_oldest_age_secs: u64,
    pub(super) max_control_plane_oldest_age_secs: u64,
    pub(super) last_command_sync_micros: u64,
    pub(super) last_command_fetch_count: usize,
    pub(super) last_command_execute_count: usize,
    pub(super) last_command_backlog_depth: usize,
    pub(super) max_command_backlog_depth: usize,
    pub(super) last_command_backlog_oldest_age_secs: u64,
    pub(super) max_command_backlog_oldest_age_secs: u64,
    pub(super) last_response_execute_count: usize,
    pub(super) last_response_queue_depth: usize,
    pub(super) max_response_queue_depth: usize,
    pub(super) last_response_oldest_age_secs: u64,
    pub(super) max_response_oldest_age_secs: u64,
}

pub(super) struct LocalActionResult {
    pub(super) success: bool,
    pub(super) detail: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct EmergencyRulePayload {
    #[serde(default)]
    pub(super) rule_name: String,
    #[serde(default)]
    pub(super) rule_type: String,
    #[serde(default)]
    pub(super) rule_content: String,
    #[serde(default)]
    pub(super) content: String,
    #[serde(default)]
    pub(super) severity: String,
}
