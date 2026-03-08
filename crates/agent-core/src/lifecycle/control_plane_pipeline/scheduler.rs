use baseline::BaselineStatus;
use tracing::{debug, warn};

use super::super::{
    interval_due, AgentRuntime, ControlPlaneTaskKind, PendingControlPlaneTask, TickEvaluation,
    BASELINE_UPLOAD_BATCH_SIZE, BASELINE_UPLOAD_INTERVAL_SECS, CAMPAIGN_FETCH_INTERVAL_SECS,
    CONTROL_PLANE_TASK_QUEUE_CAPACITY, FLEET_BASELINE_FETCH_INTERVAL_SECS, HEARTBEAT_INTERVAL_SECS,
    IOC_SIGNAL_UPLOAD_INTERVAL_SECS, POLICY_REFRESH_INTERVAL_SECS, THREAT_INTEL_INTERVAL_SECS,
};
use super::rollout::rollout_allows;

impl AgentRuntime {
    pub(super) fn enqueue_due_control_plane_tasks(
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
            debug!(
                now_unix,
                last_heartbeat_attempt_unix = ?self.last_heartbeat_attempt_unix,
                "heartbeat task due"
            );
            let status = evaluation
                .map(|eval| eval.compliance.status.clone())
                .unwrap_or_else(|| self.evaluate_compliance().status);
            self.try_enqueue_control_plane_task(
                ControlPlaneTaskKind::Heartbeat {
                    compliance_status: status,
                    baseline_status: self.baseline_status_label().to_string(),
                },
                now_unix,
            );
        }

        // PolicySync must run before Compliance so the first tick fetches
        // the server policy before evaluating/sending compliance results.
        if self.policy_refresh_due(now_unix) {
            self.try_enqueue_control_plane_task(ControlPlaneTaskKind::PolicySync, now_unix);
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
                ControlPlaneTaskKind::Inventory {
                    inventory: Box::new(inventory),
                },
                now_unix,
            );
        }

        if self.threat_intel_refresh_due(now_unix) {
            self.try_enqueue_control_plane_task(ControlPlaneTaskKind::ThreatIntelRefresh, now_unix);
        }

        if self.baseline_upload_due(now_unix) {
            self.try_enqueue_control_plane_task(ControlPlaneTaskKind::BaselineUpload, now_unix);
        }

        if self.fleet_baseline_fetch_due(now_unix) {
            self.try_enqueue_control_plane_task(ControlPlaneTaskKind::FleetBaselineFetch, now_unix);
        }

        if self.ioc_signal_upload_due(now_unix) {
            self.try_enqueue_control_plane_task(ControlPlaneTaskKind::IocSignalUpload, now_unix);
        }

        if self.campaign_fetch_due(now_unix) {
            self.try_enqueue_control_plane_task(ControlPlaneTaskKind::CampaignFetch, now_unix);
        }

        self.try_enqueue_control_plane_task(ControlPlaneTaskKind::CommandSync, now_unix);
    }

    pub(super) fn try_enqueue_control_plane_task(
        &mut self,
        kind: ControlPlaneTaskKind,
        now_unix: i64,
    ) {
        if let Some(existing) = self
            .pending_control_plane_tasks
            .iter_mut()
            .find(|task| task.kind.kind_name() == kind.kind_name())
        {
            match kind {
                ControlPlaneTaskKind::Heartbeat { .. }
                | ControlPlaneTaskKind::Compliance { .. }
                | ControlPlaneTaskKind::Inventory { .. } => {
                    if existing.kind == kind {
                        return;
                    }
                    existing.kind = kind;
                    self.metrics.control_plane_task_replaced_total = self
                        .metrics
                        .control_plane_task_replaced_total
                        .saturating_add(1);
                }
                _ => {
                    // Payloadless tasks are already deduped by kind; keep the original queue entry
                    // and avoid counting synthetic replacement churn.
                }
            }
            return;
        }

        if self.pending_control_plane_tasks.len() >= CONTROL_PLANE_TASK_QUEUE_CAPACITY {
            warn!(
                queue_depth = self.pending_control_plane_tasks.len(),
                capacity = CONTROL_PLANE_TASK_QUEUE_CAPACITY,
                "control-plane queue reached capacity; dropping oldest task"
            );
            self.pending_control_plane_tasks.pop_front();
            self.metrics.control_plane_task_dropped_total = self
                .metrics
                .control_plane_task_dropped_total
                .saturating_add(1);
        }

        self.pending_control_plane_tasks
            .push_back(PendingControlPlaneTask {
                kind,
                enqueued_at_unix: now_unix,
            });
    }

    pub(super) fn control_plane_queue_oldest_age_secs(&self, now_unix: i64) -> u64 {
        let Some(task) = self.pending_control_plane_tasks.front() else {
            return 0;
        };

        now_unix.saturating_sub(task.enqueued_at_unix).max(0) as u64
    }

    fn threat_intel_refresh_due(&self, now_unix: i64) -> bool {
        interval_due(
            self.last_threat_intel_refresh_unix,
            now_unix,
            THREAT_INTEL_INTERVAL_SECS,
        )
    }

    pub(super) fn baseline_upload_due(&self, now_unix: i64) -> bool {
        if !self.baseline_upload_enabled
            || self.dirty_baseline_keys.is_empty()
            || !rollout_allows(&self.config.agent_id, self.baseline_upload_canary_percent)
        {
            return false;
        }

        if self.dirty_baseline_keys.len() >= BASELINE_UPLOAD_BATCH_SIZE {
            return true;
        }

        interval_due(
            self.last_baseline_upload_unix,
            now_unix,
            BASELINE_UPLOAD_INTERVAL_SECS,
        )
    }

    pub(super) fn fleet_baseline_fetch_due(&self, now_unix: i64) -> bool {
        self.fleet_seed_enabled
            && rollout_allows(&self.config.agent_id, self.fleet_seed_canary_percent)
            && matches!(
                self.baseline_store.status,
                BaselineStatus::Learning | BaselineStatus::Stale
            )
            && interval_due(
                self.last_fleet_baseline_fetch_unix,
                now_unix,
                FLEET_BASELINE_FETCH_INTERVAL_SECS,
            )
    }

    pub(super) fn ioc_signal_upload_due(&self, now_unix: i64) -> bool {
        !self.ioc_signal_buffer.is_empty()
            && interval_due(
                self.last_ioc_signal_upload_unix,
                now_unix,
                IOC_SIGNAL_UPLOAD_INTERVAL_SECS,
            )
    }

    pub(super) fn campaign_fetch_due(&self, now_unix: i64) -> bool {
        interval_due(
            self.last_campaign_fetch_unix,
            now_unix,
            CAMPAIGN_FETCH_INTERVAL_SECS,
        )
    }

    pub(super) fn policy_refresh_due(&self, now_unix: i64) -> bool {
        let interval_secs = if self.config.policy_refresh_interval_secs == 0 {
            POLICY_REFRESH_INTERVAL_SECS
        } else {
            self.config.policy_refresh_interval_secs as i64
        };

        interval_due(self.last_policy_fetch_unix, now_unix, interval_secs)
    }
}

impl ControlPlaneTaskKind {
    pub(super) fn kind_name(&self) -> &'static str {
        match self {
            Self::Heartbeat { .. } => "heartbeat",
            Self::Compliance { .. } => "compliance",
            Self::Inventory { .. } => "inventory",
            Self::PolicySync => "policy_sync",
            Self::ThreatIntelRefresh => "threat_intel",
            Self::CommandSync => "command_sync",
            Self::BaselineUpload => "baseline_upload",
            Self::FleetBaselineFetch => "fleet_baseline_fetch",
            Self::IocSignalUpload => "ioc_signal_upload",
            Self::CampaignFetch => "campaign_fetch",
            Self::FimUpload => "fim_upload",
            Self::UsbUpload => "usb_upload",
            Self::DeceptionUpload => "deception_upload",
            Self::VulnerabilityUpload => "vulnerability_upload",
            Self::HuntingUpload => "hunting_upload",
            Self::ZeroTrustUpload => "zero_trust_upload",
        }
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

    #[test]
    fn reenqueue_heartbeat_replaces_payload_but_preserves_queue_age_anchor() {
        let mut runtime = new_runtime();

        runtime.try_enqueue_control_plane_task(
            ControlPlaneTaskKind::Heartbeat {
                compliance_status: "warn".to_string(),
                baseline_status: "learning".to_string(),
            },
            1_700_000_000,
        );
        runtime.try_enqueue_control_plane_task(
            ControlPlaneTaskKind::Heartbeat {
                compliance_status: "ok".to_string(),
                baseline_status: "active".to_string(),
            },
            1_700_000_120,
        );

        assert_eq!(runtime.pending_control_plane_tasks.len(), 1);
        assert_eq!(runtime.metrics.control_plane_task_replaced_total, 1);
        let task = runtime
            .pending_control_plane_tasks
            .front()
            .expect("queued heartbeat");
        assert_eq!(task.enqueued_at_unix, 1_700_000_000);
        match &task.kind {
            ControlPlaneTaskKind::Heartbeat {
                compliance_status,
                baseline_status,
            } => {
                assert_eq!(compliance_status, "ok");
                assert_eq!(baseline_status, "active");
            }
            other => panic!("expected heartbeat task, got {}", other.kind_name()),
        }
    }

    #[test]
    fn reenqueue_heartbeat_same_payload_is_noop_for_replacement_counter() {
        let mut runtime = new_runtime();

        runtime.try_enqueue_control_plane_task(
            ControlPlaneTaskKind::Heartbeat {
                compliance_status: "ok".to_string(),
                baseline_status: "active".to_string(),
            },
            1_700_000_000,
        );
        runtime.try_enqueue_control_plane_task(
            ControlPlaneTaskKind::Heartbeat {
                compliance_status: "ok".to_string(),
                baseline_status: "active".to_string(),
            },
            1_700_000_120,
        );

        assert_eq!(runtime.pending_control_plane_tasks.len(), 1);
        assert_eq!(runtime.metrics.control_plane_task_replaced_total, 0);
    }

    #[test]
    fn reenqueue_inventory_replaces_payload_without_queue_growth() {
        let mut runtime = new_runtime();

        let first = runtime.collect_inventory(1_700_000_000);
        let second = runtime.collect_inventory(1_700_000_060);

        runtime.try_enqueue_control_plane_task(
            ControlPlaneTaskKind::Inventory {
                inventory: Box::new(first),
            },
            1_700_000_000,
        );
        runtime.try_enqueue_control_plane_task(
            ControlPlaneTaskKind::Inventory {
                inventory: Box::new(second),
            },
            1_700_000_060,
        );

        assert_eq!(runtime.pending_control_plane_tasks.len(), 1);
        assert_eq!(runtime.metrics.control_plane_task_replaced_total, 1);
        let task = runtime
            .pending_control_plane_tasks
            .front()
            .expect("queued inventory");
        assert_eq!(task.enqueued_at_unix, 1_700_000_000);
        match &task.kind {
            ControlPlaneTaskKind::Inventory { inventory } => {
                assert_eq!(inventory.collected_at_unix, 1_700_000_060);
            }
            other => panic!("expected inventory task, got {}", other.kind_name()),
        }
    }

    #[test]
    fn queue_capacity_drop_increments_task_dropped_counter() {
        let mut runtime = new_runtime();
        runtime.pending_control_plane_tasks.clear();
        runtime.metrics.control_plane_task_dropped_total = 0;

        for i in 0..CONTROL_PLANE_TASK_QUEUE_CAPACITY {
            runtime
                .pending_control_plane_tasks
                .push_back(PendingControlPlaneTask {
                    kind: ControlPlaneTaskKind::Heartbeat {
                        compliance_status: format!("status-{i}"),
                        baseline_status: "learning".to_string(),
                    },
                    enqueued_at_unix: 1_700_000_000 + i as i64,
                });
        }

        runtime.try_enqueue_control_plane_task(
            ControlPlaneTaskKind::Compliance {
                compliance: ComplianceResult {
                    status: "ok".to_string(),
                    detail: "ok".to_string(),
                    checks: Vec::new(),
                },
            },
            1_700_000_500,
        );

        assert_eq!(
            runtime.pending_control_plane_tasks.len(),
            CONTROL_PLANE_TASK_QUEUE_CAPACITY
        );
        assert_eq!(runtime.metrics.control_plane_task_dropped_total, 1);
        assert!(matches!(
            runtime.pending_control_plane_tasks.back(),
            Some(PendingControlPlaneTask {
                kind: ControlPlaneTaskKind::Compliance { .. },
                ..
            })
        ));
    }

    #[test]
    fn reenqueue_payloadless_task_does_not_increment_replacement_counter() {
        let mut runtime = new_runtime();

        runtime.try_enqueue_control_plane_task(ControlPlaneTaskKind::CommandSync, 1_700_000_000);
        runtime.try_enqueue_control_plane_task(ControlPlaneTaskKind::CommandSync, 1_700_000_120);

        assert_eq!(runtime.pending_control_plane_tasks.len(), 1);
        assert_eq!(runtime.metrics.control_plane_task_replaced_total, 0);
        let task = runtime
            .pending_control_plane_tasks
            .front()
            .expect("queued command sync");
        assert_eq!(task.enqueued_at_unix, 1_700_000_000);
        assert!(matches!(task.kind, ControlPlaneTaskKind::CommandSync));
    }
}
