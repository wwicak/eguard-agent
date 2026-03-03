use std::time::Instant;

use anyhow::Result;
use tracing::warn;

use super::super::{
    elapsed_micros, AgentRuntime, ControlPlaneTaskKind, PendingControlPlaneTask,
    CONTROL_PLANE_TASK_EXECUTION_BUDGET_PER_TICK,
};

impl AgentRuntime {
    pub(super) async fn execute_control_plane_task_budget(
        &mut self,
        now_unix: i64,
    ) -> Result<usize> {
        let mut executed = 0usize;

        while executed < CONTROL_PLANE_TASK_EXECUTION_BUDGET_PER_TICK {
            let Some(task) = self.pending_control_plane_tasks.pop_front() else {
                break;
            };

            match task.kind {
                ControlPlaneTaskKind::Heartbeat {
                    compliance_status,
                    baseline_status,
                } => {
                    let heartbeat_started = Instant::now();
                    self.send_heartbeat_if_due(now_unix, &compliance_status, &baseline_status);
                    self.metrics.last_heartbeat_micros = elapsed_micros(heartbeat_started);
                }
                ControlPlaneTaskKind::Compliance { compliance } => {
                    let compliance_started = Instant::now();
                    self.send_compliance_if_due(now_unix, &compliance);
                    self.metrics.last_compliance_micros = elapsed_micros(compliance_started);
                }
                ControlPlaneTaskKind::Inventory { inventory } => {
                    let inventory_started = Instant::now();
                    self.send_inventory_if_due(now_unix, inventory.as_ref());
                    self.metrics.last_inventory_micros = elapsed_micros(inventory_started);
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
                ControlPlaneTaskKind::BaselineUpload => {
                    if let Err(err) = self.upload_baseline_profiles_if_due(now_unix).await {
                        warn!(error = %err, "baseline upload sync failed");
                    }
                }
                ControlPlaneTaskKind::FleetBaselineFetch => {
                    if let Err(err) = self.fetch_and_apply_fleet_baselines_if_due(now_unix).await {
                        warn!(error = %err, "fleet baseline fetch/apply failed");
                    }
                }
                ControlPlaneTaskKind::IocSignalUpload => {
                    if let Err(err) = self.upload_ioc_signals_if_due(now_unix).await {
                        warn!(error = %err, "IOC signal upload failed");
                    }
                }
                ControlPlaneTaskKind::CampaignFetch => {
                    if let Err(err) = self.fetch_and_apply_campaigns_if_due(now_unix).await {
                        warn!(error = %err, "campaign fetch failed");
                    }
                }
                ControlPlaneTaskKind::FimUpload
                | ControlPlaneTaskKind::UsbUpload
                | ControlPlaneTaskKind::DeceptionUpload
                | ControlPlaneTaskKind::VulnerabilityUpload
                | ControlPlaneTaskKind::HuntingUpload
                | ControlPlaneTaskKind::ZeroTrustUpload => {
                    // Placeholder — feature upload handlers will be wired in
                    // when the corresponding scan/detection loops are implemented.
                }
            }

            executed = executed.saturating_add(1);
        }

        Ok(executed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AgentConfig;
    use compliance::ComplianceResult;

    fn new_runtime() -> AgentRuntime {
        let mut cfg = AgentConfig::default();
        cfg.offline_buffer_backend = "memory".to_string();
        cfg.server_addr = "127.0.0.1:1".to_string();
        cfg.self_protection_integrity_check_interval_secs = 0;
        AgentRuntime::new(cfg).expect("runtime")
    }

    #[tokio::test]
    async fn inventory_task_updates_inventory_metric_without_touching_compliance_metric() {
        let mut runtime = new_runtime();
        let now = 1_700_000_000;
        let inventory = runtime.collect_inventory(now);
        runtime.metrics.last_compliance_micros = 777;
        runtime.metrics.last_inventory_micros = u64::MAX;
        runtime
            .pending_control_plane_tasks
            .push_back(PendingControlPlaneTask {
                kind: ControlPlaneTaskKind::Inventory {
                    inventory: Box::new(inventory),
                },
                enqueued_at_unix: now,
            });

        let executed = runtime
            .execute_control_plane_task_budget(now)
            .await
            .expect("execute inventory task");

        assert_eq!(executed, 1);
        assert_eq!(runtime.metrics.last_compliance_micros, 777);
        assert_ne!(runtime.metrics.last_inventory_micros, u64::MAX);
    }

    #[tokio::test]
    async fn compliance_task_updates_compliance_metric_without_touching_inventory_metric() {
        let mut runtime = new_runtime();
        let now = 1_700_000_000;
        runtime.metrics.last_compliance_micros = u64::MAX;
        runtime.metrics.last_inventory_micros = 888;
        runtime
            .pending_control_plane_tasks
            .push_back(PendingControlPlaneTask {
                kind: ControlPlaneTaskKind::Compliance {
                    compliance: ComplianceResult {
                        status: "ok".to_string(),
                        detail: "ok".to_string(),
                        checks: Vec::new(),
                    },
                },
                enqueued_at_unix: now,
            });

        let executed = runtime
            .execute_control_plane_task_budget(now)
            .await
            .expect("execute compliance task");

        assert_eq!(executed, 1);
        assert_ne!(runtime.metrics.last_compliance_micros, u64::MAX);
        assert_eq!(runtime.metrics.last_inventory_micros, 888);
    }
}
