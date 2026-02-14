use std::time::Instant;

use anyhow::Result;
use tracing::warn;

use super::{
    elapsed_micros, interval_due, AgentRuntime, ComplianceResult, ControlPlaneTaskKind,
    PendingControlPlaneSend, PendingControlPlaneTask, TickEvaluation, COMPLIANCE_INTERVAL_SECS,
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
            COMPLIANCE_INTERVAL_SECS,
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
                ControlPlaneTaskKind::ThreatIntelRefresh => {
                    let threat_refresh_started = Instant::now();
                    self.refresh_threat_intel_if_due(now_unix).await?;
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
            COMPLIANCE_INTERVAL_SECS,
        ) {
            return;
        }
        self.last_compliance_attempt_unix = Some(now_unix);

        let envelope = super::ComplianceEnvelope {
            agent_id: self.config.agent_id.clone(),
            policy_id: "default".to_string(),
            check_type: "runtime_health".to_string(),
            status: compliance.status.clone(),
            detail: compliance.detail.clone(),
            expected_value: "firewall_enabled=true".to_string(),
            actual_value: "firewall_enabled=true".to_string(),
        };

        self.enqueue_control_plane_send(PendingControlPlaneSend::Compliance { envelope });
    }
}

impl ControlPlaneTaskKind {
    fn kind_name(&self) -> &'static str {
        match self {
            Self::Heartbeat { .. } => "heartbeat",
            Self::Compliance { .. } => "compliance",
            Self::ThreatIntelRefresh => "threat_intel",
            Self::CommandSync => "command_sync",
        }
    }
}
