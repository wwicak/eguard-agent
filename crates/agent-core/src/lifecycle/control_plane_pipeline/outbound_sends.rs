use grpc_client::{ComplianceCheckEnvelope, InventoryEnvelope};

use super::super::{
    interval_due, AgentRuntime, ComplianceResult, PendingControlPlaneSend, HEARTBEAT_INTERVAL_SECS,
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

        let config_version = self.heartbeat_config_version();
        self.enqueue_control_plane_send(PendingControlPlaneSend::Heartbeat {
            agent_id: self.config.agent_id.clone(),
            compliance_status: compliance_status.to_string(),
            config_version,
            baseline_status: baseline_status.to_string(),
        });
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
