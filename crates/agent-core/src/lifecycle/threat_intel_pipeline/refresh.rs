use anyhow::Result;
use grpc_client::ThreatIntelVersionEnvelope;
use tracing::info;

use super::state::persist_threat_intel_replay_floor_state;
use super::version::{ensure_publish_timestamp_floor, ensure_version_monotonicity};
use super::super::{interval_due, AgentRuntime, THREAT_INTEL_INTERVAL_SECS};

impl AgentRuntime {
    pub(crate) async fn refresh_threat_intel_if_due(&mut self, now_unix: i64) -> Result<()> {
        if !interval_due(
            self.last_threat_intel_refresh_unix,
            now_unix,
            THREAT_INTEL_INTERVAL_SECS,
        ) {
            return Ok(());
        }
        self.last_threat_intel_refresh_unix = Some(now_unix);

        if let Some(intel) = self.client.fetch_latest_threat_intel().await? {
            self.ensure_threat_intel_freshness(&intel)?;
            let changed = self.threat_intel_changed(&intel)?;
            let latest_hash = intel.custom_rule_version_hash.clone();
            if changed {
                info!(
                    version = %intel.version,
                    bundle = %intel.bundle_path,
                    bundle_signature = %intel.bundle_signature_path,
                    bundle_sha256 = %intel.bundle_sha256,
                    published_at_unix = intel.published_at_unix,
                    custom_rule_count = intel.custom_rule_count,
                    custom_rule_hash = %latest_hash,
                    "new threat intel version available"
                );
                let local_bundle_path = self.prepare_bundle_for_reload(&intel).await?;
                self.reload_detection_state(&intel.version, &local_bundle_path, Some(&intel))?;
            }

            self.update_threat_intel_freshness_state(&intel, latest_hash);
        }

        Ok(())
    }

    fn threat_intel_changed(&self, intel: &ThreatIntelVersionEnvelope) -> Result<bool> {
        let known_version = self.current_threat_version()?;
        let latest_hash = intel.custom_rule_version_hash.as_str();

        Ok(known_version.as_deref() != Some(intel.version.as_str())
            || self.latest_custom_rule_hash.as_deref() != Some(latest_hash))
    }

    fn current_threat_version(&self) -> Result<Option<String>> {
        Ok(self
            .latest_threat_version
            .clone()
            .or(self.detection_state.version()?))
    }

    fn ensure_threat_intel_freshness(&self, intel: &ThreatIntelVersionEnvelope) -> Result<()> {
        let known_version = self.current_threat_version()?;
        ensure_version_monotonicity(known_version.as_deref(), &intel.version)?;
        ensure_version_monotonicity(self.threat_intel_version_floor.as_deref(), &intel.version)?;
        ensure_publish_timestamp_floor(
            self.latest_threat_published_at_unix,
            intel.published_at_unix,
        )?;
        Ok(())
    }

    fn update_threat_intel_freshness_state(
        &mut self,
        intel: &ThreatIntelVersionEnvelope,
        latest_hash: String,
    ) {
        self.latest_threat_version = Some(intel.version.clone());
        self.latest_custom_rule_hash = Some(latest_hash);

        let version_floor = intel.version.trim();
        if !version_floor.is_empty() {
            self.threat_intel_version_floor = Some(version_floor.to_string());
        }

        let published_at_unix = intel.published_at_unix;
        if published_at_unix > 0 {
            self.latest_threat_published_at_unix = Some(
                self.latest_threat_published_at_unix
                    .map(|floor| floor.max(published_at_unix))
                    .unwrap_or(published_at_unix),
            );
        }

        if let Err(err) = persist_threat_intel_replay_floor_state(
            self.threat_intel_version_floor
                .as_deref()
                .unwrap_or_default(),
            self.latest_threat_published_at_unix.unwrap_or_default(),
        ) {
            tracing::warn!(error = %err, "failed persisting threat-intel replay floor state");
        }

    }
}
