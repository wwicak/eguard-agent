use anyhow::Result;
use grpc_client::BaselineProfileEnvelope;
use tracing::{info, warn};

use super::super::AgentRuntime;
use super::rollout::baseline_upload_max_bytes;

impl AgentRuntime {
    pub(in super::super) async fn upload_baseline_profiles_if_due(
        &mut self,
        now_unix: i64,
    ) -> Result<()> {
        if !self.baseline_upload_due(now_unix) {
            return Ok(());
        }
        self.last_baseline_upload_unix = Some(now_unix);

        let candidate_keys = self
            .dirty_baseline_keys
            .iter()
            .take(super::super::BASELINE_UPLOAD_BATCH_SIZE)
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

    pub(in super::super) async fn fetch_and_apply_fleet_baselines_if_due(
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

        let seeded =
            super::super::apply_fleet_baseline_seeds(&mut self.baseline_store, &fleet_baselines);
        if seeded == 0 {
            return Ok(());
        }

        super::super::seed_anomaly_baselines(&self.detection_state, &self.baseline_store)?;
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
}
