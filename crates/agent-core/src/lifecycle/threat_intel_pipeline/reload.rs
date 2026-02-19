use anyhow::{anyhow, Result};
use grpc_client::ThreatIntelVersionEnvelope;
use tracing::{info, warn};

use super::super::{
    build_ransomware_policy, detection_bootstrap, load_bundle_full, AgentRuntime, ReloadReport,
};
use super::bundle_guard::{
    bundle_ioc_total, enforce_bundle_signature_database_floor, enforce_signature_drop_guard,
    ensure_shard_bundle_summary_matches, push_count_mismatch, signature_database_total,
};
use super::state::persist_threat_intel_last_known_good_state;

impl AgentRuntime {
    pub(crate) fn reload_detection_state(
        &mut self,
        version: &str,
        bundle_path: &str,
        expected_intel: Option<&ThreatIntelVersionEnvelope>,
    ) -> Result<()> {
        let old_version = self.detection_state.version()?.unwrap_or_default();
        let previous_signature_total = self
            .last_reload_report
            .as_ref()
            .map(|report| report.sigma_rules + report.yara_rules + report.ioc_entries);

        let mut next_engine = detection_bootstrap::build_detection_engine_with_ransomware_policy(
            build_ransomware_policy(&self.config),
        );
        let summary = load_bundle_full(&mut next_engine, bundle_path);
        let ioc_entries = bundle_ioc_total(&summary);
        let signature_total = signature_database_total(&summary);

        self.corroborate_threat_intel_update(version, expected_intel, &summary)?;
        enforce_bundle_signature_database_floor(bundle_path, &summary)?;
        enforce_signature_drop_guard(bundle_path, previous_signature_total, signature_total)?;

        let shard_count = self.detection_state.shard_count();
        if shard_count <= 1 {
            self.detection_state
                .swap_engine(version.to_string(), next_engine)?;
        } else {
            let mut shard_engines = Vec::with_capacity(shard_count);
            shard_engines.push(next_engine);

            for shard_idx in 1..shard_count {
                let mut shard_engine =
                    detection_bootstrap::build_detection_engine_with_ransomware_policy(
                        build_ransomware_policy(&self.config),
                    );
                let shard_summary = load_bundle_full(&mut shard_engine, bundle_path);

                self.corroborate_threat_intel_update(version, expected_intel, &shard_summary)?;
                enforce_bundle_signature_database_floor(bundle_path, &shard_summary)?;
                ensure_shard_bundle_summary_matches(shard_idx, &summary, &shard_summary)?;

                shard_engines.push(shard_engine);
            }

            self.detection_state
                .swap_prebuilt_engines(version.to_string(), shard_engines)?;
        }

        let database_total = summary.total_rules();
        let report = ReloadReport {
            old_version,
            new_version: version.to_string(),
            sigma_rules: summary.sigma_loaded,
            yara_rules: summary.yara_loaded,
            ioc_entries,
        };
        self.last_reload_report = Some(report.clone());
        info!(
            old_version = %report.old_version,
            new_version = %report.new_version,
            bundle = %bundle_path,
            sigma_rules = report.sigma_rules,
            yara_rules = report.yara_rules,
            ioc_entries = report.ioc_entries,
            signature_total,
            database_total,
            "detection state hot-reloaded"
        );

        if let Err(err) = persist_threat_intel_last_known_good_state(version, bundle_path) {
            tracing::warn!(
                error = %err,
                version = version,
                bundle_path = bundle_path,
                "failed persisting last-known-good threat-intel bundle state"
            );
        }

        Ok(())
    }

    fn corroborate_threat_intel_update(
        &self,
        version: &str,
        expected_intel: Option<&ThreatIntelVersionEnvelope>,
        summary: &super::super::rule_bundle_loader::BundleLoadSummary,
    ) -> Result<()> {
        let Some(expected) = expected_intel else {
            return Ok(());
        };

        if !expected.version.trim().is_empty() && expected.version.trim() != version.trim() {
            return Err(anyhow!(
                "threat-intel version mismatch: expected '{}' but applying '{}'",
                expected.version,
                version
            ));
        }

        let mut mismatches = Vec::new();
        push_count_mismatch(
            &mut mismatches,
            "sigma_count",
            expected.sigma_count,
            summary.sigma_loaded,
        );
        push_count_mismatch(
            &mut mismatches,
            "yara_count",
            expected.yara_count,
            summary.yara_loaded,
        );
        push_count_mismatch(
            &mut mismatches,
            "ioc_count",
            expected.ioc_count,
            bundle_ioc_total(summary),
        );
        push_count_mismatch(
            &mut mismatches,
            "cve_count",
            expected.cve_count,
            summary.cve_entries,
        );

        if !mismatches.is_empty() {
            warn!(
                version = version,
                mismatches = %mismatches.join(", "),
                "threat-intel bundle corroboration mismatch (warn-only)"
            );
        }

        Ok(())
    }
}
