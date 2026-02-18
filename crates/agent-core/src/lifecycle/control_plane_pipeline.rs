use std::time::Instant;

use anyhow::Result;
use tracing::warn;

use compliance::parse_policy_json;
use grpc_client::{ComplianceCheckEnvelope, InventoryEnvelope, PolicyEnvelope, TlsConfig};

use super::{
    elapsed_micros, interval_due, update_tls_policy_from_server, AgentRuntime, ComplianceResult,
    ControlPlaneTaskKind, PendingControlPlaneSend, PendingControlPlaneTask, TickEvaluation,
    CONTROL_PLANE_TASK_EXECUTION_BUDGET_PER_TICK, CONTROL_PLANE_TASK_QUEUE_CAPACITY,
    HEARTBEAT_INTERVAL_SECS,
};

impl AgentRuntime {
    pub(super) async fn run_connected_control_plane_stage(
        &mut self,
        now_unix: i64,
        evaluation: Option<&TickEvaluation>,
    ) -> Result<()> {
        let control_started = Instant::now();
        self.enqueue_due_control_plane_tasks(now_unix, evaluation);
        let executed = self.execute_control_plane_task_budget(now_unix).await?;
        let oldest_age_secs = self.control_plane_queue_oldest_age_secs(now_unix);

        self.metrics.last_control_plane_sync_micros = elapsed_micros(control_started);
        self.metrics.last_control_plane_execute_count = executed;
        self.metrics.last_control_plane_queue_depth = self.pending_control_plane_tasks.len();
        self.metrics.max_control_plane_queue_depth = self
            .metrics
            .max_control_plane_queue_depth
            .max(self.pending_control_plane_tasks.len());
        self.metrics.last_control_plane_oldest_age_secs = oldest_age_secs;
        self.metrics.max_control_plane_oldest_age_secs = self
            .metrics
            .max_control_plane_oldest_age_secs
            .max(oldest_age_secs);

        Ok(())
    }

    fn enqueue_due_control_plane_tasks(
        &mut self,
        now_unix: i64,
        evaluation: Option<&TickEvaluation>,
    ) {
        let heartbeat_due = interval_due(
            self.last_heartbeat_attempt_unix,
            now_unix,
            HEARTBEAT_INTERVAL_SECS,
        );
        if heartbeat_due {
            let status = evaluation
                .map(|eval| eval.compliance.status.clone())
                .unwrap_or_else(|| self.evaluate_compliance().status);
            self.try_enqueue_control_plane_task(
                ControlPlaneTaskKind::Heartbeat {
                    compliance_status: status,
                },
                now_unix,
            );
        }

        let compliance_due = interval_due(
            self.last_compliance_attempt_unix,
            now_unix,
            self.compliance_interval_secs(),
        );
        if compliance_due {
            let compliance = evaluation
                .map(|eval| eval.compliance.clone())
                .unwrap_or_else(|| self.evaluate_compliance());
            self.try_enqueue_control_plane_task(
                ControlPlaneTaskKind::Compliance { compliance },
                now_unix,
            );
        }

        let inventory_due = interval_due(
            self.last_inventory_attempt_unix,
            now_unix,
            self.inventory_interval_secs(),
        );
        if inventory_due {
            let inventory = self.collect_inventory(now_unix);
            self.try_enqueue_control_plane_task(
                ControlPlaneTaskKind::Inventory { inventory },
                now_unix,
            );
        }

        if self.policy_refresh_due(now_unix) {
            self.try_enqueue_control_plane_task(ControlPlaneTaskKind::PolicySync, now_unix);
        }

        if self.threat_intel_refresh_due(now_unix) {
            self.try_enqueue_control_plane_task(ControlPlaneTaskKind::ThreatIntelRefresh, now_unix);
        }

        self.try_enqueue_control_plane_task(ControlPlaneTaskKind::CommandSync, now_unix);
    }

    fn try_enqueue_control_plane_task(&mut self, kind: ControlPlaneTaskKind, now_unix: i64) {
        if self.has_pending_control_plane_task(&kind) {
            return;
        }

        if self.pending_control_plane_tasks.len() >= CONTROL_PLANE_TASK_QUEUE_CAPACITY {
            warn!(
                queue_depth = self.pending_control_plane_tasks.len(),
                capacity = CONTROL_PLANE_TASK_QUEUE_CAPACITY,
                "control-plane queue reached capacity; dropping oldest task"
            );
            self.pending_control_plane_tasks.pop_front();
        }

        self.pending_control_plane_tasks
            .push_back(PendingControlPlaneTask {
                kind,
                enqueued_at_unix: now_unix,
            });
    }

    fn has_pending_control_plane_task(&self, kind: &ControlPlaneTaskKind) -> bool {
        self.pending_control_plane_tasks
            .iter()
            .any(|task| task.kind.kind_name() == kind.kind_name())
    }

    async fn execute_control_plane_task_budget(&mut self, now_unix: i64) -> Result<usize> {
        let mut executed = 0usize;

        while executed < CONTROL_PLANE_TASK_EXECUTION_BUDGET_PER_TICK {
            let Some(task) = self.pending_control_plane_tasks.pop_front() else {
                break;
            };

            match task.kind {
                ControlPlaneTaskKind::Heartbeat { compliance_status } => {
                    let heartbeat_started = Instant::now();
                    self.send_heartbeat_if_due(now_unix, &compliance_status);
                    self.metrics.last_heartbeat_micros = elapsed_micros(heartbeat_started);
                }
                ControlPlaneTaskKind::Compliance { compliance } => {
                    let compliance_started = Instant::now();
                    self.send_compliance_if_due(now_unix, &compliance);
                    self.metrics.last_compliance_micros = elapsed_micros(compliance_started);
                }
                ControlPlaneTaskKind::Inventory { inventory } => {
                    let inventory_started = Instant::now();
                    self.send_inventory_if_due(now_unix, &inventory);
                    self.metrics.last_compliance_micros = elapsed_micros(inventory_started);
                }
                ControlPlaneTaskKind::PolicySync => {
                    self.refresh_policy_if_due(now_unix).await?;
                }
                ControlPlaneTaskKind::ThreatIntelRefresh => {
                    let threat_refresh_started = Instant::now();
                    if let Err(err) = self.refresh_threat_intel_if_due(now_unix).await {
                        warn!(error = %err, "threat intel refresh failed");
                    }
                    self.metrics.last_threat_intel_refresh_micros =
                        elapsed_micros(threat_refresh_started);
                }
                ControlPlaneTaskKind::CommandSync => {
                    self.run_connected_command_stage(now_unix).await;
                }
            }

            executed = executed.saturating_add(1);
        }

        Ok(executed)
    }

    fn control_plane_queue_oldest_age_secs(&self, now_unix: i64) -> u64 {
        let Some(task) = self.pending_control_plane_tasks.front() else {
            return 0;
        };

        now_unix.saturating_sub(task.enqueued_at_unix).max(0) as u64
    }

    fn threat_intel_refresh_due(&self, now_unix: i64) -> bool {
        interval_due(
            self.last_threat_intel_refresh_unix,
            now_unix,
            super::THREAT_INTEL_INTERVAL_SECS,
        )
    }

    fn policy_refresh_due(&self, now_unix: i64) -> bool {
        let interval_secs = if self.config.policy_refresh_interval_secs == 0 {
            super::POLICY_REFRESH_INTERVAL_SECS
        } else {
            self.config.policy_refresh_interval_secs as i64
        };

        interval_due(self.last_policy_fetch_unix, now_unix, interval_secs)
    }

    async fn refresh_policy_if_due(&mut self, now_unix: i64) -> Result<()> {
        if !self.policy_refresh_due(now_unix) {
            return Ok(());
        }
        self.last_policy_fetch_unix = Some(now_unix);
        match self.client.fetch_policy(&self.config.agent_id).await {
            Ok(Some(policy)) => {
                self.apply_policy_from_server(policy);
            }
            Ok(None) => {}
            Err(err) => {
                warn!(error = %err, "failed to refresh policy from server");
            }
        }
        Ok(())
    }

    fn apply_policy_from_server(&mut self, policy: PolicyEnvelope) {
        let mut policy_changed = false;
        if !policy.policy_id.trim().is_empty() && self.compliance_policy_id != policy.policy_id {
            self.compliance_policy_id = policy.policy_id.clone();
            policy_changed = true;
        }
        if !policy.policy_version.trim().is_empty()
            && self.compliance_policy_version != policy.policy_version
        {
            self.compliance_policy_version = policy.policy_version.clone();
            policy_changed = true;
        } else if !policy.config_version.trim().is_empty()
            && self.compliance_policy_version != policy.config_version
        {
            self.compliance_policy_version = policy.config_version.clone();
            policy_changed = true;
        }

        if !policy.policy_hash.trim().is_empty()
            && self.compliance_policy_hash != policy.policy_hash
        {
            self.compliance_policy_hash = policy.policy_hash.clone();
            policy_changed = true;
        }
        if !policy.policy_signature.trim().is_empty()
            && self.compliance_policy_signature != policy.policy_signature
        {
            self.compliance_policy_signature = policy.policy_signature.clone();
            policy_changed = true;
        }
        if !policy.schema_version.trim().is_empty()
            && self.compliance_policy_schema_version != policy.schema_version
        {
            self.compliance_policy_schema_version = policy.schema_version.clone();
            policy_changed = true;
        }

        if !policy.policy_json.trim().is_empty() {
            if !super::policy::verify_policy_envelope(&policy) {
                warn!("policy verification failed; keeping current policy");
            } else {
                match parse_policy_json(&policy.policy_json) {
                    Ok(parsed) => {
                        self.compliance_policy = parsed;
                        policy_changed = true;
                    }
                    Err(err) => {
                        warn!(error = %err, "invalid compliance policy JSON from server; keeping current");
                    }
                }
            }
        }

        if policy_changed {
            self.last_compliance_checked_unix = None;
            self.last_compliance_result = None;
        }

        if update_tls_policy_from_server(&mut self.config, &policy)
            && self.client.is_tls_configured()
        {
            if let (Some(cert), Some(key), Some(ca)) = (
                self.config.tls_cert_path.clone(),
                self.config.tls_key_path.clone(),
                self.config.tls_ca_path.clone(),
            ) {
                if let Err(err) = self.client.configure_tls(TlsConfig {
                    cert_path: cert,
                    key_path: key,
                    ca_path: ca,
                    pinned_ca_sha256: self.config.tls_pinned_ca_sha256.clone(),
                    ca_pin_path: self.config.tls_ca_pin_path.clone(),
                }) {
                    warn!(error = %err, "failed to apply updated TLS policy");
                }
            }
        }
    }

    fn send_heartbeat_if_due(&mut self, now_unix: i64, compliance_status: &str) {
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
        });
    }

    fn send_compliance_if_due(&mut self, now_unix: i64, compliance: &ComplianceResult) {
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

        let envelope = super::ComplianceEnvelope {
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

    fn send_inventory_if_due(&mut self, now_unix: i64, inventory: &InventoryEnvelope) {
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

impl ControlPlaneTaskKind {
    fn kind_name(&self) -> &'static str {
        match self {
            Self::Heartbeat { .. } => "heartbeat",
            Self::Compliance { .. } => "compliance",
            Self::Inventory { .. } => "inventory",
            Self::PolicySync => "policy_sync",
            Self::ThreatIntelRefresh => "threat_intel",
            Self::CommandSync => "command_sync",
        }
    }
}
