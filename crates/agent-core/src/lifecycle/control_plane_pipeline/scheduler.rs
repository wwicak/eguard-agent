use baseline::BaselineStatus;
use tracing::warn;

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
            let status = evaluation
                .map(|eval| eval.compliance.status.clone())
                .unwrap_or_else(|| self.evaluate_compliance().status);
            let baseline_label = match self.baseline_store.status {
                BaselineStatus::Learning => "learning",
                BaselineStatus::Active => "active",
                BaselineStatus::Stale => "stale",
            };
            self.try_enqueue_control_plane_task(
                ControlPlaneTaskKind::Heartbeat {
                    compliance_status: status,
                    baseline_status: baseline_label.to_string(),
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
