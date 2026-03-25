use anyhow::{anyhow, Result};
use grpc_client::ThreatIntelVersionEnvelope;
use tracing::{info, warn};

use super::super::{
    build_ransomware_policy, detection_bootstrap, load_bundle_full, AgentRuntime, ReloadReport,
};
use super::bundle_guard::{
    bundle_ioc_total, enforce_bundle_signature_database_floor, enforce_signature_drop_guard,
    ensure_shard_bundle_summary_matches, push_count_lower_bound_mismatch, push_count_mismatch,
    signature_database_total,
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
        let previous_layer5_model = self.capture_previous_layer5_model();

        let detection_sources =
            detection_bootstrap::DetectionSourcePaths::from_config(&self.config);
        let mut next_engine = detection_bootstrap::build_detection_engine_with_ransomware_policy(
            build_ransomware_policy(&self.config),
            &detection_sources,
        );
        apply_previous_layer5_model_fallback(&mut next_engine, previous_layer5_model.as_ref());
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
                        &detection_sources,
                    );
                apply_previous_layer5_model_fallback(
                    &mut shard_engine,
                    previous_layer5_model.as_ref(),
                );
                let shard_summary = load_bundle_full(&mut shard_engine, bundle_path);

                // Corroboration against expected intel is done on the primary shard summary.
                // For additional shards we only enforce deterministic parity with shard 0.
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

    fn capture_previous_layer5_model(&self) -> Option<detection::MlModel> {
        match self.detection_state.layer5_model_snapshot() {
            Ok(model) => Some(model),
            Err(err) => {
                warn!(
                    error = %err,
                    "failed capturing active layer5 model snapshot; reload will use default fallback"
                );
                None
            }
        }
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

        // SIGMA count semantics currently diverge between upstream manifest files and
        // runtime-loadable rules. Keep strict corroboration on families with stable
        // semantics (IOC/CVE) and use lower-bound corroboration for YARA.
        push_count_lower_bound_mismatch(
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

impl AgentRuntime {
    /// Spawn a background OS thread for the heavy bundle loading work.
    /// The tick loop calls `poll_background_reload` to check for completion
    /// and apply the lightweight engine swap.  This keeps heartbeat and
    /// telemetry running while sigma/YARA/IOC rules compile.
    pub(crate) fn start_background_reload(
        &mut self,
        version: &str,
        bundle_path: &str,
    ) {
        if self.background_reload_rx.is_some() {
            warn!("background reload already in progress, skipping");
            return;
        }

        let version = version.to_string();
        let bundle_path_str = bundle_path.to_string();
        let config = self.config.clone();
        let shard_count = self.detection_state.shard_count();
        let previous_layer5_model = self.capture_previous_layer5_model();

        let (tx, rx) = std::sync::mpsc::channel();
        self.background_reload_rx = Some(rx);

        info!(
            version = %version,
            bundle_path = %bundle_path_str,
            shard_count,
            "starting background bundle reload (non-blocking)"
        );

        let spawn_result = std::thread::Builder::new()
            .name("eguard-bundle-reload".to_string())
            .spawn(move || {
                // Lower thread priority so heartbeat/telemetry get CPU time.
                // On Unix, set nice level to 19 (lowest priority).
                #[cfg(unix)]
                unsafe {
                    // setpriority(PRIO_PROCESS=0, 0=self, 19=lowest priority)
                    extern "C" { fn setpriority(which: i32, who: u32, prio: i32) -> i32; }
                    let _ = setpriority(0, 0, 19);
                }

                let detection_sources =
                    super::super::detection_bootstrap::DetectionSourcePaths::from_config(&config);

                let build_engine = || {
                    let mut engine =
                        super::super::detection_bootstrap::build_detection_engine_with_ransomware_policy(
                            super::super::build_ransomware_policy(&config),
                            &detection_sources,
                        );
                    apply_previous_layer5_model_fallback(
                        &mut engine,
                        previous_layer5_model.as_ref(),
                    );
                    let summary = super::super::load_bundle_full(&mut engine, &bundle_path_str);
                    (engine, summary)
                };

                let (primary_engine, primary_summary) = build_engine();
                let report = super::super::ReloadReport {
                    old_version: String::new(),
                    new_version: version.clone(),
                    sigma_rules: primary_summary.sigma_loaded,
                    yara_rules: primary_summary.yara_loaded,
                    ioc_entries: super::bundle_guard::bundle_ioc_total(&primary_summary),
                };

                let mut engines = Vec::with_capacity(shard_count);
                engines.push(primary_engine);
                for _ in 1..shard_count {
                    let (engine, _) = build_engine();
                    engines.push(engine);
                }

                info!(
                    version = %version,
                    sigma = report.sigma_rules,
                    yara = report.yara_rules,
                    ioc = report.ioc_entries,
                    "background bundle reload complete, sending to main loop"
                );

                let _ = tx.send(super::super::BackgroundReloadResult {
                    version,
                    bundle_path: bundle_path_str,
                    engines,
                    report,
                });
            });

        match spawn_result {
            Ok(_handle) => { /* thread is detached — result arrives via channel */ }
            Err(err) => {
                warn!(error = %err, "failed to spawn background bundle reload thread");
                self.background_reload_rx = None;
            }
        }
    }

    /// Check if a background bundle reload has completed.  Called from the
    /// tick loop — returns immediately if nothing is ready.
    pub(crate) fn poll_background_reload(&mut self) {
        let Some(rx) = self.background_reload_rx.as_ref() else {
            return;
        };

        let result = match rx.try_recv() {
            Ok(result) => result,
            Err(std::sync::mpsc::TryRecvError::Empty) => return,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                warn!("background reload thread terminated without sending result");
                self.background_reload_rx = None;
                return;
            }
        };

        self.background_reload_rx = None;

        let version = result.version;
        let bundle_path = result.bundle_path;
        info!(
            version = %version,
            sigma = result.report.sigma_rules,
            yara = result.report.yara_rules,
            ioc = result.report.ioc_entries,
            "applying background-loaded detection engines"
        );

        if let Err(err) = self
            .detection_state
            .swap_prebuilt_engines(version.clone(), result.engines)
        {
            warn!(error = %err, "failed swapping background-loaded detection engines");
            return;
        }

        self.last_reload_report = Some(result.report.clone());
        self.latest_threat_version = Some(version.clone());
        self.threat_intel_version_floor = Some(version.clone());

        if let Err(err) = super::state::persist_threat_intel_last_known_good_state(
            &version,
            &bundle_path,
        ) {
            warn!(error = %err, "failed persisting last-known-good after background reload");
        }

        info!(
            version = %version,
            "detection state hot-reloaded from background thread"
        );
    }
}

fn apply_previous_layer5_model_fallback(
    engine: &mut detection::DetectionEngine,
    previous_model: Option<&detection::MlModel>,
) {
    let Some(previous_model) = previous_model else {
        return;
    };

    if let Err(err) = engine.layer5.reload_model(previous_model.clone()) {
        warn!(
            error = %err,
            "failed applying previous layer5 model fallback; using default model"
        );
    }
}
