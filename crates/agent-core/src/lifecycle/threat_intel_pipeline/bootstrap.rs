use tracing::{info, warn};

use super::state::{
    load_threat_intel_last_known_good_state, load_threat_intel_replay_floor_state,
    persist_threat_intel_replay_floor_state,
};
use super::version::ensure_version_monotonicity;
use super::super::bundle_path::is_remote_bundle_reference;
use super::super::AgentRuntime;

impl AgentRuntime {
    pub(crate) fn bootstrap_threat_intel_replay_floor(&mut self) {
        let Some(state) = load_threat_intel_replay_floor_state() else {
            return;
        };

        let version_floor = state.version_floor.trim();
        if !version_floor.is_empty() {
            self.threat_intel_version_floor = Some(version_floor.to_string());
        }

        if state.published_at_unix_floor > 0 {
            self.latest_threat_published_at_unix = Some(state.published_at_unix_floor);
        }

        info!(
            version_floor = version_floor,
            published_at_unix_floor = state.published_at_unix_floor,
            "loaded persisted threat-intel replay floor state"
        );
    }

    pub(crate) fn bootstrap_last_known_good_bundle(&mut self) {
        let Some(state) = load_threat_intel_last_known_good_state() else {
            return;
        };

        let version = state.version.trim();
        let bundle_path = state.bundle_path.trim();
        if version.is_empty() || bundle_path.is_empty() || is_remote_bundle_reference(bundle_path) {
            return;
        }

        if let Err(err) =
            ensure_version_monotonicity(self.threat_intel_version_floor.as_deref(), version)
        {
            warn!(
                error = %err,
                version = version,
                bundle_path = bundle_path,
                "skipping persisted last-known-good bundle due to version floor violation"
            );
            return;
        }

        if let Err(err) = self.reload_detection_state(version, bundle_path, None) {
            warn!(
                error = %err,
                version = version,
                bundle_path = bundle_path,
                "failed loading persisted last-known-good threat-intel bundle"
            );
            return;
        }

        self.latest_threat_version = Some(version.to_string());
        self.threat_intel_version_floor = Some(version.to_string());
        if let Err(err) = persist_threat_intel_replay_floor_state(
            self.threat_intel_version_floor
                .as_deref()
                .unwrap_or_default(),
            self.latest_threat_published_at_unix.unwrap_or_default(),
        ) {
            warn!(error = %err, "failed persisting replay floor after last-known-good bootstrap");
        }

        info!(
            version = version,
            bundle_path = bundle_path,
            "bootstrapped detection state from persisted last-known-good threat-intel bundle"
        );
    }
}
