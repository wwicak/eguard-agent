use std::time::Instant;

use anyhow::Result;
use tracing::{info, warn};

use baseline::BaselineStatus;
use compliance::parse_policy_json;
use grpc_client::{
    BaselineProfileEnvelope, ComplianceCheckEnvelope, InventoryEnvelope, IocSignalBatch,
    PolicyEnvelope, TlsConfig,
};

use crate::config::AgentMode;

use super::{
    elapsed_micros, interval_due, update_tls_policy_from_server, AgentRuntime, ComplianceResult,
    ControlPlaneTaskKind, PendingControlPlaneSend, PendingControlPlaneTask, TickEvaluation,
    BASELINE_UPLOAD_BATCH_SIZE, BASELINE_UPLOAD_INTERVAL_SECS, BASELINE_UPLOAD_MAX_BYTES,
    CAMPAIGN_FETCH_INTERVAL_SECS, CONTROL_PLANE_TASK_EXECUTION_BUDGET_PER_TICK,
    CONTROL_PLANE_TASK_QUEUE_CAPACITY, FLEET_BASELINE_FETCH_INTERVAL_SECS,
    HEARTBEAT_INTERVAL_SECS, IOC_SIGNAL_BUFFER_CAP, IOC_SIGNAL_UPLOAD_INTERVAL_SECS,
};

fn baseline_upload_max_bytes() -> usize {
    std::env::var("EGUARD_BASELINE_UPLOAD_MAX_BYTES")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(BASELINE_UPLOAD_MAX_BYTES)
}

fn rollout_bucket(agent_id: &str) -> u8 {
    let mut hash = 0xcbf29ce484222325u64;
    for b in agent_id.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    (hash % 100) as u8
}

fn rollout_allows(agent_id: &str, canary_percent: u8) -> bool {
    if canary_percent >= 100 {
        return true;
    }
    if canary_percent == 0 {
        return false;
    }
    rollout_bucket(agent_id) < canary_percent
}

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
                ControlPlaneTaskKind::Inventory { inventory },
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

    fn baseline_upload_due(&self, now_unix: i64) -> bool {
        if !self.baseline_upload_enabled
            || self.dirty_baseline_keys.is_empty()
            || !rollout_allows(
                &self.config.agent_id,
                self.baseline_upload_canary_percent,
            )
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

    fn fleet_baseline_fetch_due(&self, now_unix: i64) -> bool {
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

    fn ioc_signal_upload_due(&self, now_unix: i64) -> bool {
        !self.ioc_signal_buffer.is_empty()
            && interval_due(
                self.last_ioc_signal_upload_unix,
                now_unix,
                IOC_SIGNAL_UPLOAD_INTERVAL_SECS,
            )
    }

    fn campaign_fetch_due(&self, now_unix: i64) -> bool {
        interval_due(
            self.last_campaign_fetch_unix,
            now_unix,
            CAMPAIGN_FETCH_INTERVAL_SECS,
        )
    }

    /// Buffer an IOC signal from a detection hit for later batch upload.
    pub(super) fn buffer_ioc_signal(
        &mut self,
        ioc_value: String,
        ioc_type: String,
        confidence: &str,
        now_unix: i64,
    ) {
        if self.ioc_signal_buffer.len() >= IOC_SIGNAL_BUFFER_CAP {
            // Drop oldest to make room — ring-buffer behavior.
            self.ioc_signal_buffer.remove(0);
        }

        // Coalesce: if the same IOC is already buffered, bump its event_count.
        if let Some(existing) = self
            .ioc_signal_buffer
            .iter_mut()
            .find(|s| s.ioc_value == ioc_value)
        {
            existing.event_count = existing.event_count.saturating_add(1);
            return;
        }

        self.ioc_signal_buffer.push(grpc_client::IocSignal {
            ioc_value,
            ioc_type,
            confidence: confidence.to_string(),
            first_seen_unix: now_unix,
            event_count: 1,
        });
    }

    async fn upload_ioc_signals_if_due(&mut self, now_unix: i64) -> Result<()> {
        if !self.ioc_signal_upload_due(now_unix) {
            return Ok(());
        }
        self.last_ioc_signal_upload_unix = Some(now_unix);

        let signals = std::mem::take(&mut self.ioc_signal_buffer);
        if signals.is_empty() {
            return Ok(());
        }

        let batch = IocSignalBatch {
            agent_id: self.config.agent_id.clone(),
            signals,
        };

        self.client.send_ioc_signals(&batch).await?;
        info!(
            agent_id = %self.config.agent_id,
            signal_count = batch.signals.len(),
            "uploaded IOC signal batch for campaign correlation"
        );
        Ok(())
    }

    async fn fetch_and_apply_campaigns_if_due(&mut self, now_unix: i64) -> Result<()> {
        if !self.campaign_fetch_due(now_unix) {
            return Ok(());
        }
        self.last_campaign_fetch_unix = Some(now_unix);

        let campaigns = self.client.fetch_campaigns(&self.config.agent_id).await?;
        if campaigns.is_empty() {
            self.active_campaign_iocs.clear();
            return Ok(());
        }

        let mut new_campaign_iocs = std::collections::HashSet::with_capacity(campaigns.len());
        for campaign in &campaigns {
            new_campaign_iocs.insert(campaign.ioc_value.clone());
        }

        info!(
            agent_id = %self.config.agent_id,
            active_campaigns = campaigns.len(),
            "fetched active campaign alerts"
        );
        self.active_campaign_iocs = new_campaign_iocs;
        Ok(())
    }

    /// Check if the given IOC values include any active campaign IOCs.
    /// If so, mark the detection as campaign-correlated.
    pub(super) fn is_campaign_correlated(&self, ioc_values: &[String]) -> bool {
        ioc_values
            .iter()
            .any(|ioc| self.active_campaign_iocs.contains(ioc))
    }

    pub(super) async fn upload_baseline_profiles_if_due(&mut self, now_unix: i64) -> Result<()> {
        if !self.baseline_upload_due(now_unix) {
            return Ok(());
        }
        self.last_baseline_upload_unix = Some(now_unix);

        let candidate_keys = self
            .dirty_baseline_keys
            .iter()
            .take(BASELINE_UPLOAD_BATCH_SIZE)
            .cloned()
            .collect::<Vec<_>>();
        if candidate_keys.is_empty() {
            return Ok(());
        }

        let mut profiles = self.collect_baseline_profiles(&candidate_keys);
        if profiles.is_empty() {
            for key in candidate_keys {
                self.dirty_baseline_keys.remove(&key);
            }
            return Ok(());
        }

        let max_payload_bytes = baseline_upload_max_bytes();

        let mut selected_count = profiles.len();
        let mut payload_bytes = serde_json::to_vec(&profiles)
            .map(|buf| buf.len())
            .unwrap_or(0);
        while payload_bytes > max_payload_bytes && selected_count > 1 {
            selected_count -= 1;
            profiles.truncate(selected_count);
            payload_bytes = serde_json::to_vec(&profiles)
                .map(|buf| buf.len())
                .unwrap_or(0);
        }

        if payload_bytes > max_payload_bytes {
            self.metrics.baseline_upload_payload_reject_total = self
                .metrics
                .baseline_upload_payload_reject_total
                .saturating_add(1);
            warn!(
                agent_id = %self.config.agent_id,
                baseline_status = ?self.baseline_store.status,
                payload_bytes,
                max_payload_bytes,
                payload_reject_total = self.metrics.baseline_upload_payload_reject_total,
                "single baseline profile exceeds upload payload cap; skipping until distribution shrinks"
            );
            return Ok(());
        }

        self.client
            .send_baseline_profiles(&self.config.agent_id, &profiles)
            .await?;

        let uploaded_keys = profiles
            .iter()
            .map(|profile| profile.process_key.clone())
            .collect::<Vec<_>>();
        for key in uploaded_keys {
            self.dirty_baseline_keys.remove(&key);
        }

        self.metrics.baseline_rows_uploaded_total = self
            .metrics
            .baseline_rows_uploaded_total
            .saturating_add(profiles.len() as u64);

        info!(
            agent_id = %self.config.agent_id,
            baseline_status = ?self.baseline_store.status,
            uploaded_profiles = profiles.len(),
            payload_bytes,
            uploaded_rows_total = self.metrics.baseline_rows_uploaded_total,
            remaining_dirty_profiles = self.dirty_baseline_keys.len(),
            "uploaded baseline profile batch"
        );
        Ok(())
    }

    fn collect_baseline_profiles(&self, keys: &[String]) -> Vec<BaselineProfileEnvelope> {
        if keys.is_empty() {
            return Vec::new();
        }

        let wanted = keys
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        let learned_at_unix = self.baseline_store.last_refresh_unix.min(i64::MAX as u64) as i64;

        let mut out = Vec::with_capacity(keys.len());
        for (process_key, profile) in &self.baseline_store.baselines {
            let process_key_str = format!("{}:{}", process_key.comm, process_key.parent_comm);
            if !wanted.contains(&process_key_str) {
                continue;
            }

            let observed_total = profile.event_distribution.values().copied().sum::<u64>();
            let total = profile.sample_count.max(observed_total);
            if total == 0 {
                continue;
            }

            let mut distribution = std::collections::HashMap::new();
            for (event_name, count) in &profile.event_distribution {
                if *count == 0 {
                    continue;
                }
                distribution.insert(event_name.clone(), (*count as f64) / (total as f64));
            }
            if distribution.is_empty() {
                continue;
            }

            out.push(BaselineProfileEnvelope {
                process_key: process_key_str,
                event_distribution: distribution,
                sample_count: total.min(i64::MAX as u64) as i64,
                entropy_threshold: profile.entropy_threshold,
                learned_at_unix,
            });
        }

        out
    }

    pub(super) async fn fetch_and_apply_fleet_baselines_if_due(
        &mut self,
        now_unix: i64,
    ) -> Result<()> {
        if !self.fleet_baseline_fetch_due(now_unix) {
            return Ok(());
        }
        self.last_fleet_baseline_fetch_unix = Some(now_unix);

        let fleet_baselines = self.client.fetch_fleet_baselines(512).await?;
        if fleet_baselines.is_empty() {
            return Ok(());
        }

        let seeded = super::apply_fleet_baseline_seeds(&mut self.baseline_store, &fleet_baselines);
        if seeded == 0 {
            return Ok(());
        }

        super::seed_anomaly_baselines(&self.detection_state, &self.baseline_store)?;
        if let Err(err) = self.baseline_store.save() {
            warn!(error = %err, "failed persisting baseline store after fleet seed apply");
        }

        for baseline in fleet_baselines {
            self.dirty_baseline_keys.insert(baseline.process_key);
        }

        self.metrics.baseline_seed_rows_applied_total = self
            .metrics
            .baseline_seed_rows_applied_total
            .saturating_add(seeded as u64);

        info!(
            agent_id = %self.config.agent_id,
            baseline_status = ?self.baseline_store.status,
            seeded_profiles = seeded,
            seeded_rows_total = self.metrics.baseline_seed_rows_applied_total,
            "applied fleet baseline seed profiles"
        );
        Ok(())
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
                        info!(
                            firewall = parsed.firewall_required,
                            kernel_prefix = ?parsed.min_kernel_prefix,
                            disk_enc = parsed.disk_encryption_required,
                            ssh_root = parsed.require_ssh_root_login_disabled,
                            password_policy = parsed.password_policy_required,
                            screen_lock = parsed.screen_lock_required,
                            auto_updates = parsed.auto_updates_required,
                            antivirus = parsed.antivirus_required,
                            "compliance policy updated from server"
                        );
                        self.compliance_policy = parsed;
                        policy_changed = true;
                    }
                    Err(err) => {
                        warn!(error = %err, "invalid compliance policy JSON from server; keeping current");
                    }
                }
            }
        }

        // Parse structured fields from policy JSON.
        if !policy.policy_json.trim().is_empty() {
            if let Ok(raw) = serde_json::from_str::<serde_json::Value>(&policy.policy_json) {
                // Detection allowlist — push to shards.
                if let Some(allowlist_obj) = raw.get("detection_allowlist") {
                    let processes: Vec<String> = allowlist_obj
                        .get("processes")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_default();
                    let path_prefixes: Vec<String> = allowlist_obj
                        .get("path_prefixes")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_default();

                    info!(
                        processes_count = processes.len(),
                        path_prefixes_count = path_prefixes.len(),
                        "applying detection allowlist from policy"
                    );
                    if let Err(err) = self
                        .detection_state
                        .update_allowlist(processes, path_prefixes)
                    {
                        warn!(error = %err, "failed to update detection allowlist");
                    }
                }

                // Baseline mode — server can force-skip the learning window.
                if let Some(mode) = raw.get("baseline_mode").and_then(|v| v.as_str()) {
                    match mode {
                        "force_active" | "skip_learning" => {
                            if matches!(self.baseline_store.status, BaselineStatus::Learning) {
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();
                                self.baseline_store.force_active(now);
                                if !matches!(self.runtime_mode, AgentMode::Degraded) {
                                    self.runtime_mode = AgentMode::Active;
                                }
                                info!(
                                    baseline_mode = mode,
                                    "baseline forced to Active via server policy"
                                );
                                if let Err(err) = self.baseline_store.save() {
                                    warn!(error = %err, "failed to persist baseline after force_active");
                                }
                            }
                        }
                        "default" | "" => {} // natural progression
                        other => warn!(baseline_mode = other, "unknown baseline_mode in policy"),
                    }
                }

                if let Some(upload_enabled) =
                    raw.get("baseline_upload_enabled").and_then(|v| v.as_bool())
                {
                    self.baseline_upload_enabled = upload_enabled;
                    info!(
                        baseline_upload_enabled = upload_enabled,
                        "updated baseline upload flag from policy"
                    );
                }

                if let Some(seed_enabled) = raw.get("fleet_seed_enabled").and_then(|v| v.as_bool())
                {
                    self.fleet_seed_enabled = seed_enabled;
                    info!(
                        fleet_seed_enabled = seed_enabled,
                        "updated fleet-seed flag from policy"
                    );
                }

                if let Some(upload_canary) = raw
                    .get("baseline_upload_canary_percent")
                    .and_then(|v| v.as_u64())
                {
                    self.baseline_upload_canary_percent = upload_canary.min(100) as u8;
                    info!(
                        baseline_upload_canary_percent = self.baseline_upload_canary_percent,
                        "updated baseline upload canary percent from policy"
                    );
                }

                if let Some(seed_canary) = raw
                    .get("fleet_seed_canary_percent")
                    .and_then(|v| v.as_u64())
                {
                    self.fleet_seed_canary_percent = seed_canary.min(100) as u8;
                    info!(
                        fleet_seed_canary_percent = self.fleet_seed_canary_percent,
                        "updated fleet-seed canary percent from policy"
                    );
                }

                // Bundle public key — server distributes Ed25519 key via policy.
                if let Some(key_hex) = raw.get("bundle_public_key").and_then(|v| v.as_str()) {
                    let key_hex = key_hex.trim();
                    if !key_hex.is_empty() && key_hex.len() == 64 {
                        // SAFETY: set_var is acceptable here because this runs on the single
                        // runtime tick thread and the key is validated by the bundle verifier.
                        #[allow(unused_unsafe)]
                        unsafe {
                            std::env::set_var("EGUARD_RULE_BUNDLE_PUBKEY", key_hex);
                        }
                        info!("bundle public key updated from server policy");
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

    fn send_heartbeat_if_due(
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
            Self::BaselineUpload => "baseline_upload",
            Self::FleetBaselineFetch => "fleet_baseline_fetch",
            Self::IocSignalUpload => "ioc_signal_upload",
            Self::CampaignFetch => "campaign_fetch",
        }
    }
}
