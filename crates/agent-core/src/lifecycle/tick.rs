use std::time::{Duration, Instant};

use anyhow::Result;
use tracing::{debug, info, warn};

use nac::posture_from_compliance;
use response::plan_action;
use tokio::time::timeout;

use crate::platform::enrich_event_with_cache;

use crate::config::AgentMode;

use super::{
    confidence_to_severity, elapsed_micros, interval_due, run_periodic_storage_hygiene,
    should_drop_low_value_linux_event, should_drop_low_value_windows_event, to_detection_event,
    AgentRuntime, TickEvaluation, ACTIVE_CAMPAIGN_IOC_LIMIT, COMPLIANCE_ALERT_STATE_LIMIT,
    COMPLIANCE_GRACE_STATE_LIMIT, DISK_CHECK_INTERVAL_SECS, HEARTBEAT_INTERVAL_SECS,
    ISOLATION_FAILSAFE_CHECK_INTERVAL_SECS, MEMORY_PRESSURE_CHECK_INTERVAL_TICKS,
    STORAGE_HYGIENE_INTERVAL_SECS,
};

impl AgentRuntime {
    const DEGRADED_RECOVERY_PROBE_TIMEOUT_MS: u64 = 750;
    const EXTRA_TELEMETRY_EVAL_TIME_BUDGET_MS: u64 = 35;
    pub(super) const MAX_EXTRA_TELEMETRY_EVALS_PER_TICK: usize = 7;

    pub async fn tick(&mut self, now_unix: i64) -> Result<()> {
        let tick_started = Instant::now();
        self.reset_tick_stage_metrics();
        self.tick_count = self.tick_count.saturating_add(1);
        if std::env::var("EGUARD_DEBUG_TICK_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some()
        {
            info!(tick = self.tick_count, "debug tick");
        }

        // Prioritize tray/user-driven ZTNA work ahead of heavier maintenance,
        // telemetry polling, and background control-plane activity so launches
        // remain responsive even when the service is busy.
        if std::env::var("EGUARD_DEBUG_TICK_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some()
        {
            info!(tick = self.tick_count, "tick pre-tray command phase start");
        }
        self.apply_pending_tray_commands().await?;
        if std::env::var("EGUARD_DEBUG_TICK_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some()
        {
            info!(tick = self.tick_count, "tick pre-tray command phase complete");
            info!(tick = self.tick_count, "tick pre-ztna ensure phase start");
        }
        self.ensure_ztna_tunnel_if_due(now_unix).await?;
        if std::env::var("EGUARD_DEBUG_TICK_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some()
        {
            info!(tick = self.tick_count, "tick pre-ztna ensure phase complete");
        }
        self.teardown_idle_ztna_session_if_needed(now_unix).await;
        self.write_tray_session_state(now_unix)?;

        // Delay bundle bootstrap much longer on startup so post-restart
        // heartbeat + telemetry stay healthy before background rule/model
        // loading begins.  This avoids a blind spot right after tamper/
        // crash recovery, where the agent must prioritize connectivity.
        #[cfg(target_os = "macos")]
        let bundle_bootstrap_delay_ticks: u64 = 30;
        #[cfg(not(target_os = "macos"))]
        let bundle_bootstrap_delay_ticks: u64 = 5;

        if self.deferred_bundle_bootstrap_pending && self.tick_count >= bundle_bootstrap_delay_ticks
        {
            self.run_deferred_bundle_bootstrap();
        }

        // Check if a background bundle reload has completed and apply
        // the engine swap.  This is a non-blocking poll.
        self.poll_background_reload();

        self.run_self_protection_if_due(now_unix).await?;
        self.enforce_config_permissions_if_due(now_unix);
        self.run_storage_hygiene_if_due(now_unix);
        self.check_isolation_failsafe(now_unix);
        self.check_memory_pressure();
        self.check_disk_pressure(now_unix);

        let evaluate_started = Instant::now();
        let evaluation = self.evaluate_tick(now_unix)?;
        self.metrics.last_evaluate_micros = elapsed_micros(evaluate_started);
        if std::env::var("EGUARD_DEBUG_LATENCY_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some()
        {
            if let Some(evaluation) = evaluation.as_ref() {
                info!(
                    evaluate_micros = self.metrics.last_evaluate_micros,
                    event_class = ?evaluation.detection_event.event_class,
                    confidence = ?evaluation.confidence,
                    "debug detection latency"
                );
            }
        }
        self.run_kernel_integrity_scan_if_due(now_unix);
        // Log detection evaluation BEFORE the connected/degraded tick
        // handlers so that transport errors (which propagate via `?`)
        // cannot suppress the log.
        if let Some(evaluation) = evaluation.as_ref() {
            self.log_detection_evaluation(evaluation);
        }
        if matches!(self.runtime_mode, AgentMode::Degraded) {
            self.handle_degraded_tick(now_unix, evaluation.as_ref())
                .await?;
        } else {
            self.handle_connected_tick(now_unix, evaluation.as_ref())
                .await?;
        }
        self.sync_tray_state(now_unix).await?;
        self.run_additional_telemetry_evaluations(now_unix).await?;

        self.metrics.last_tick_total_micros = elapsed_micros(tick_started);
        self.metrics.max_tick_total_micros = self
            .metrics
            .max_tick_total_micros
            .max(self.metrics.last_tick_total_micros);
        let _ = self.protected.is_protected_process("systemd");
        Ok(())
    }

    async fn run_additional_telemetry_evaluations(&mut self, now_unix: i64) -> Result<()> {
        let extra_budget = self.additional_telemetry_eval_budget();
        if extra_budget == 0 {
            return Ok(());
        }

        let started = Instant::now();
        let mut processed = 0usize;
        while processed < extra_budget {
            if started.elapsed() >= Duration::from_millis(Self::EXTRA_TELEMETRY_EVAL_TIME_BUDGET_MS)
            {
                break;
            }

            let Some(evaluation) = self.evaluate_tick(now_unix)? else {
                break;
            };

            self.log_detection_evaluation(&evaluation);
            if matches!(self.runtime_mode, AgentMode::Degraded) {
                self.run_connected_response_stage(now_unix, Some(&evaluation))
                    .await;
                self.buffer_degraded_telemetry_if_present(Some(&evaluation))?;
            } else {
                self.run_connected_response_stage(now_unix, Some(&evaluation))
                    .await;
                self.run_connected_telemetry_stage(Some(&evaluation))
                    .await?;
            }

            processed = processed.saturating_add(1);
        }

        if processed > 0 {
            info!(
                processed,
                backlog = self.telemetry_backlog_depth(),
                budget = extra_budget,
                time_budget_ms = Self::EXTRA_TELEMETRY_EVAL_TIME_BUDGET_MS,
                "processed additional telemetry evaluations under backlog pressure"
            );
        }

        Ok(())
    }

    pub(super) fn additional_telemetry_eval_budget(&self) -> usize {
        if !self.strict_budget_mode {
            return 0;
        }

        let backlog = self.telemetry_backlog_depth();
        if backlog >= 4_096 {
            return Self::MAX_EXTRA_TELEMETRY_EVALS_PER_TICK;
        }
        if backlog >= 2_048 {
            return 3;
        }
        if backlog >= 1_024 {
            return 1;
        }

        0
    }

    fn run_storage_hygiene_if_due(&mut self, now_unix: i64) {
        if !interval_due(
            self.last_storage_hygiene_unix,
            now_unix,
            STORAGE_HYGIENE_INTERVAL_SECS,
        ) {
            return;
        }
        self.last_storage_hygiene_unix = Some(now_unix);
        self.run_storage_hygiene();
    }

    pub(super) fn run_storage_hygiene(&mut self) {
        let _ = run_periodic_storage_hygiene();
        if let Err(err) = self.buffer.run_maintenance() {
            warn!(error = %err, "offline buffer maintenance failed");
        }
    }

    pub(super) fn evaluate_tick(&mut self, now_unix: i64) -> Result<Option<TickEvaluation>> {
        let Some(raw) = self.next_raw_event() else {
            return Ok(None);
        };

        self.enrichment_cache
            .set_budget_mode(self.strict_budget_mode);
        let enriched = enrich_event_with_cache(raw, &mut self.enrichment_cache);

        let detection_event = to_detection_event(&enriched, now_unix);
        if should_drop_low_value_windows_event(&enriched, &detection_event)
            || should_drop_low_value_linux_event(&enriched, &detection_event)
        {
            return Ok(None);
        }

        self.observe_baseline(&detection_event, now_unix);

        let mut detection_outcome = self.detection_state.process_event(&detection_event)?;

        // Buffer IOC signals for cross-endpoint campaign correlation.
        if detection_outcome.signals.z1_exact_ioc || detection_outcome.signals.yara_hit {
            for sig in &detection_outcome.layer1.matched_signatures {
                let ioc_type = Self::classify_ioc_type(sig);
                self.buffer_ioc_signal(
                    sig.clone(),
                    ioc_type.to_string(),
                    &format!("{:?}", detection_outcome.confidence),
                    now_unix,
                );
            }
        }

        // Escalate confidence for campaign-correlated IOCs.
        if self.is_campaign_correlated(&detection_outcome.layer1.matched_signatures) {
            detection_outcome.signals.campaign_correlated = true;
            if detection_outcome.signals.z1_exact_ioc
                && detection_outcome.confidence < detection::Confidence::VeryHigh
            {
                detection_outcome.confidence = detection::Confidence::VeryHigh;
            }
        }

        let confidence = detection_outcome.confidence;
        let response_cfg = self.effective_response_config();
        let action = plan_action(confidence, &response_cfg);

        if std::env::var("EGUARD_DEBUG_EVENT_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some()
        {
            info!(
                event_class = ?detection_event.event_class,
                pid = detection_event.pid,
                session_id = detection_event.session_id,
                process = %detection_event.process,
                parent_process = %detection_event.parent_process,
                file_path = ?detection_event.file_path,
                file_hash = ?detection_event.file_hash,
                container_runtime = ?detection_event.container_runtime,
                container_id = ?detection_event.container_id,
                container_escape = detection_event.container_escape,
                container_privileged = detection_event.container_privileged,
                kill_chain_hits = ?detection_outcome.kill_chain_hits,
                exploit_indicators = ?detection_outcome.exploit_indicators,
                kernel_integrity_indicators = ?detection_outcome.kernel_integrity_indicators,
                tamper_indicators = ?detection_outcome.tamper_indicators,
                confidence = ?confidence,
                action = ?action,
                mode = ?self.runtime_mode,
                "debug event evaluation"
            );
        }

        let compliance = self.evaluate_compliance();
        let posture = posture_from_compliance(&compliance.status);
        self.log_posture(posture);

        let event_txn = super::EventTxn::from_enriched(&enriched, &detection_event, now_unix);
        self.metrics.telemetry_event_txn_total =
            self.metrics.telemetry_event_txn_total.saturating_add(1);

        let mut event_envelope = self.build_event_envelope(
            &enriched,
            &detection_event,
            &detection_outcome,
            &event_txn,
            confidence,
            now_unix,
        );

        // Enrich envelope with detection results
        event_envelope.event_type = detection_event.event_class.as_str().to_string();
        event_envelope.severity = confidence_to_severity(confidence).to_string();
        if let Some(rule_name) = Self::detection_rule_name(&detection_outcome) {
            event_envelope.rule_name = rule_name;
        }

        Ok(Some(TickEvaluation {
            detection_event,
            detection_outcome,
            confidence,
            action,
            compliance,
            event_txn,
            event_envelope,
        }))
    }

    async fn handle_degraded_tick(
        &mut self,
        now_unix: i64,
        evaluation: Option<&TickEvaluation>,
    ) -> Result<()> {
        let degraded_started = Instant::now();
        self.client.set_online(false);

        // Local containment must continue even when delivery to the server is degraded.
        self.run_connected_response_stage(now_unix, evaluation)
            .await;
        self.buffer_degraded_telemetry_if_present(evaluation)?;
        self.drive_async_workers();
        self.run_degraded_control_plane_stage(now_unix, evaluation)
            .await;
        self.drive_async_workers();

        self.metrics.last_degraded_tick_micros = elapsed_micros(degraded_started);
        Ok(())
    }

    fn buffer_degraded_telemetry_if_present(
        &mut self,
        evaluation: Option<&TickEvaluation>,
    ) -> Result<()> {
        let Some(evaluation) = evaluation else {
            return Ok(());
        };

        self.buffer.enqueue(evaluation.event_envelope.clone())?;
        warn!(
            pending = self.buffer.pending_count(),
            "server unavailable, buffered event"
        );
        Ok(())
    }

    async fn run_degraded_control_plane_stage(
        &mut self,
        now_unix: i64,
        evaluation: Option<&TickEvaluation>,
    ) {
        if !self.should_probe_server_recovery(now_unix) {
            return;
        }

        self.last_recovery_probe_unix = Some(now_unix);
        let compliance_status = evaluation
            .map(|eval| eval.compliance.status.as_str())
            .unwrap_or("unknown");
        if timeout(
            Duration::from_millis(Self::DEGRADED_RECOVERY_PROBE_TIMEOUT_MS),
            self.probe_server_recovery(compliance_status),
        )
        .await
        .is_err()
        {
            self.client.set_online(false);
            warn!(
                timeout_ms = Self::DEGRADED_RECOVERY_PROBE_TIMEOUT_MS,
                "degraded probe timed out"
            );
        }
    }

    fn should_probe_server_recovery(&self, now_unix: i64) -> bool {
        !self.is_forced_degraded()
            && interval_due(
                self.last_recovery_probe_unix,
                now_unix,
                HEARTBEAT_INTERVAL_SECS,
            )
    }

    pub(super) fn is_forced_degraded(&self) -> bool {
        matches!(self.config.mode, AgentMode::Degraded) || self.tamper_forced_degraded
    }

    async fn probe_server_recovery(&mut self, compliance_status: &str) {
        self.client.set_online(true);
        match self.client.check_server_state().await {
            Ok(Some(_)) => {
                let config_version = self.heartbeat_config_version();
                let baseline_status = self.baseline_status_label().to_string();
                let runtime = self.build_heartbeat_runtime_payload(&baseline_status);
                match self
                    .client
                    .send_heartbeat_with_runtime_config(
                        &self.config.agent_id,
                        compliance_status,
                        &config_version,
                        &baseline_status,
                        Some(&runtime),
                    )
                    .await
                {
                    Ok(_) => {
                        self.runtime_mode = self.config.mode.clone();
                        self.consecutive_send_failures = 0;
                        self.last_recovery_probe_unix = None;
                        info!(mode = ?self.runtime_mode, "server reachable again, leaving degraded mode");
                        self.run_deferred_bundle_bootstrap();
                    }
                    Err(err) => {
                        self.client.set_online(false);
                        warn!(error = %err, "degraded probe heartbeat failed");
                    }
                }
            }
            Ok(None) => {
                self.client.set_online(false);
                warn!("degraded probe state check returned no data");
            }
            Err(err) => {
                self.client.set_online(false);
                warn!(error = %err, "degraded probe failed");
            }
        }
    }

    async fn handle_connected_tick(
        &mut self,
        now_unix: i64,
        evaluation: Option<&TickEvaluation>,
    ) -> Result<()> {
        let connected_started = Instant::now();
        debug!(now_unix, "connected tick start");
        self.client.set_online(true);
        self.run_connected_response_stage(now_unix, evaluation)
            .await;
        self.ensure_enrolled().await;

        self.run_connected_telemetry_stage(evaluation).await?;
        debug!(now_unix, "connected telemetry stage complete");
        self.run_connected_control_plane_stage(now_unix, evaluation)
            .await?;
        debug!(now_unix, "connected control-plane stage complete");
        self.run_memory_scan_if_due(now_unix).await;
        debug!(now_unix, "connected memory scan complete");
        self.drive_async_workers();
        debug!(now_unix, "connected async worker drive complete");

        self.metrics.last_connected_tick_micros = elapsed_micros(connected_started);
        debug!(
            now_unix,
            tick_micros = self.metrics.last_connected_tick_micros,
            "connected tick complete"
        );
        Ok(())
    }

    /// Periodically check whether the isolation failsafe timeout has expired.
    /// If the host has been isolated longer than the configured timeout, force
    /// unisolation to prevent permanent user lockout.
    fn check_isolation_failsafe(&mut self, now_unix: i64) {
        if !self.host_control.isolated {
            return;
        }
        if let Some(last) = self.last_isolation_failsafe_check_unix {
            if now_unix - last < ISOLATION_FAILSAFE_CHECK_INTERVAL_SECS {
                return;
            }
        }
        self.last_isolation_failsafe_check_unix = Some(now_unix);

        if let Some(state) = super::command_pipeline::isolation_state::read_isolation_state() {
            if super::command_pipeline::isolation_state::is_failsafe_expired(&state, now_unix) {
                tracing::error!(
                    elapsed_secs = now_unix - state.isolated_at_unix,
                    "isolation failsafe expired - auto-unisolating host"
                );
                super::command_pipeline::isolation_state::force_remove_isolation();
                super::command_pipeline::isolation_state::clear_isolation_state();
                self.host_control.isolated = false;
            }
        }
    }

    /// Shed in-memory load when RSS exceeds the configured threshold.
    fn check_memory_pressure(&mut self) {
        if self.tick_count % MEMORY_PRESSURE_CHECK_INTERVAL_TICKS != 0 {
            return;
        }

        let threshold = std::env::var("EGUARD_MEMORY_PRESSURE_THRESHOLD_BYTES")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(512 * 1024 * 1024); // 512MB default

        let rss = read_process_rss_bytes();
        if rss > threshold {
            tracing::error!(
                rss_mb = rss / (1024 * 1024),
                threshold_mb = threshold / (1024 * 1024),
                "memory pressure detected - shedding load"
            );
            self.recent_file_event_keys.clear();
            self.recent_event_txn_keys.clear();
            self.suppressed_internal_process_pids.clear();
            self.compliance_alert_state.clear();
            self.compliance_grace_state.clear();
            self.active_campaign_iocs.clear();
            self.recent_response_action_keys.clear();
            if self.raw_event_backlog_cap > 256 {
                self.raw_event_backlog_cap = 256;
            }
            self.strict_budget_mode = true;
        }
    }

    /// Check disk free space and enable strict budget mode if disk space is low.
    fn check_disk_pressure(&mut self, now_unix: i64) {
        if let Some(last) = self.last_storage_hygiene_unix {
            if now_unix - last < DISK_CHECK_INTERVAL_SECS {
                return;
            }
        }

        #[cfg(target_os = "linux")]
        {
            let data_dir = std::env::var("EGUARD_AGENT_DATA_DIR")
                .unwrap_or_else(|_| "/var/lib/eguard-agent".to_string());
            let min_free = std::env::var("EGUARD_MIN_FREE_DISK_BYTES")
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(100 * 1024 * 1024); // 100MB

            if let Some(free) = get_free_disk_bytes_via_df(&data_dir) {
                if free < min_free {
                    tracing::error!(
                        free_mb = free / (1024 * 1024),
                        min_mb = min_free / (1024 * 1024),
                        path = %data_dir,
                        "disk pressure detected - disabling disk writes"
                    );
                    self.strict_budget_mode = true;
                }
            }
        }
    }

    /// Cap compliance_alert_state, compliance_grace_state, and active_campaign_iocs
    /// after insertion to prevent unbounded growth.
    pub(super) fn enforce_collection_caps(&mut self) {
        if self.compliance_alert_state.len() > COMPLIANCE_ALERT_STATE_LIMIT * 2 {
            warn!(
                entries = self.compliance_alert_state.len(),
                limit = COMPLIANCE_ALERT_STATE_LIMIT,
                "compliance_alert_state exceeded limit, clearing"
            );
            self.compliance_alert_state.clear();
        }
        if self.compliance_grace_state.len() > COMPLIANCE_GRACE_STATE_LIMIT * 2 {
            warn!(
                entries = self.compliance_grace_state.len(),
                limit = COMPLIANCE_GRACE_STATE_LIMIT,
                "compliance_grace_state exceeded limit, clearing"
            );
            self.compliance_grace_state.clear();
        }
        if self.active_campaign_iocs.len() > ACTIVE_CAMPAIGN_IOC_LIMIT * 2 {
            warn!(
                entries = self.active_campaign_iocs.len(),
                limit = ACTIVE_CAMPAIGN_IOC_LIMIT,
                "active_campaign_iocs exceeded limit, clearing"
            );
            self.active_campaign_iocs.clear();
        }
    }

    /// Classify an IOC value by its format (hash, ip, domain).
    fn classify_ioc_type(ioc: &str) -> &'static str {
        let trimmed = ioc.trim();
        // SHA-256
        if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
            return "hash";
        }
        // MD5
        if trimmed.len() == 32 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
            return "hash";
        }
        // IPv4/IPv6
        if trimmed.parse::<std::net::IpAddr>().is_ok() {
            return "ip";
        }
        "domain"
    }
}

#[cfg(target_os = "linux")]
fn read_process_rss_bytes() -> u64 {
    // Read from /proc/self/statm - second field is RSS in pages
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|content| {
            content
                .split_whitespace()
                .nth(1)
                .and_then(|rss_pages| rss_pages.parse::<u64>().ok())
        })
        .map(|pages| pages * 4096) // page size typically 4096
        .unwrap_or(0)
}

#[cfg(target_os = "windows")]
fn read_process_rss_bytes() -> u64 {
    0
}

#[cfg(target_os = "macos")]
fn read_process_rss_bytes() -> u64 {
    0
}

/// Get free disk bytes by parsing `df` output.
/// This avoids requiring a `libc` dependency in agent-core.
#[cfg(target_os = "linux")]
fn get_free_disk_bytes_via_df(path: &str) -> Option<u64> {
    let output = std::process::Command::new("df")
        .arg("-B1") // block size = 1 byte
        .arg("--output=avail")
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Output has a header line then the value
    stdout
        .lines()
        .nth(1)
        .and_then(|line| line.trim().parse::<u64>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AgentConfig, AgentMode};
    use crate::lifecycle::shared_env_var_lock;
    use compliance::ComplianceResult;
    use detection::{Confidence, DetectionOutcome, DetectionSignals, EventClass, TelemetryEvent};
    use grpc_client::EventEnvelope;
    use response::PlannedAction;

    fn new_runtime() -> AgentRuntime {
        let mut cfg = AgentConfig::default();
        cfg.offline_buffer_backend = "memory".to_string();
        cfg.server_addr = "127.0.0.1:1".to_string();
        cfg.self_protection_integrity_check_interval_secs = 0;
        AgentRuntime::new(cfg).expect("runtime")
    }

    fn degraded_kill_evaluation(pid: u32, now_unix: i64) -> TickEvaluation {
        let detection_event = TelemetryEvent {
            ts_unix: now_unix,
            event_class: EventClass::ProcessExec,
            pid,
            ppid: 42_000,
            uid: 1000,
            process: "sleep".to_string(),
            parent_process: "bash".to_string(),
            session_id: 42_000,
            file_path: Some("/usr/bin/sleep".to_string()),
            file_write: false,
            file_hash: None,
            dst_port: None,
            dst_ip: None,
            dst_domain: None,
            command_line: Some("sleep 30".to_string()),
            event_size: None,
            container_runtime: Some("host".to_string()),
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };
        let mut detection_outcome = DetectionOutcome::default();
        detection_outcome.confidence = Confidence::High;
        detection_outcome.signals = DetectionSignals::default();
        TickEvaluation {
            detection_event: detection_event.clone(),
            detection_outcome,
            confidence: Confidence::High,
            action: PlannedAction::KillOnly,
            compliance: ComplianceResult {
                status: "ok".to_string(),
                detail: "ok".to_string(),
                checks: Vec::new(),
            },
            event_txn: super::super::EventTxn {
                event_class: detection_event.event_class.as_str().to_string(),
                operation: "process_exec".to_string(),
                subject: detection_event.file_path.clone(),
                object: None,
                pid: detection_event.pid,
                uid: detection_event.uid,
                session_id: detection_event.session_id,
                ts_unix: now_unix,
                key: format!(
                    "process_exec|process_exec|{}|-|pid:{}|sid:{}",
                    detection_event.file_path.as_deref().unwrap_or_default(),
                    detection_event.pid,
                    detection_event.session_id
                ),
            },
            event_envelope: EventEnvelope {
                agent_id: "agent-test".to_string(),
                event_type: "process_exec".to_string(),
                severity: "high".to_string(),
                rule_name: "offline_kill_test".to_string(),
                payload_json: "{}".to_string(),
                created_at_unix: now_unix,
            },
        }
    }

    #[tokio::test]
    async fn degraded_tick_executes_local_response_and_preserves_response_report_queue() {
        let _env_guard = shared_env_var_lock().lock().expect("env var lock");
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn disposable child");

        let mut runtime = new_runtime();
        let now_unix = 1_700_000_100;
        runtime.runtime_mode = AgentMode::Degraded;
        runtime.last_recovery_probe_unix = Some(now_unix);

        let evaluation = degraded_kill_evaluation(child.id(), now_unix);
        runtime
            .handle_degraded_tick(now_unix, Some(&evaluation))
            .await
            .expect("degraded tick");

        let exit_status = child.wait().expect("wait for child");
        assert!(
            !exit_status.success(),
            "child should be terminated by local degraded response"
        );
        assert_eq!(
            runtime.pending_response_reports.len(),
            1,
            "offline response report should stay queued until connectivity returns"
        );
        assert_eq!(runtime.buffer.pending_count(), 1);
    }

    #[tokio::test]
    async fn degraded_recovery_probe_timeout_does_not_wedge_tick_progress() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind hanging server");
        let addr = listener.local_addr().expect("listener addr");
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept client");
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let mut cfg = AgentConfig::default();
        cfg.transport_mode = "http".to_string();
        cfg.server_addr = addr.to_string();
        cfg.offline_buffer_backend = "memory".to_string();
        cfg.self_protection_integrity_check_interval_secs = 0;

        let mut runtime = AgentRuntime::new(cfg).expect("runtime");
        let now_unix = 1_700_000_200;
        runtime.runtime_mode = AgentMode::Degraded;

        let started = Instant::now();
        runtime
            .handle_degraded_tick(now_unix, None)
            .await
            .expect("degraded tick");
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_secs(2),
            "degraded recovery probe should stay bounded, elapsed={elapsed:?}"
        );
        assert!(matches!(runtime.runtime_mode, AgentMode::Degraded));
        assert_eq!(runtime.last_recovery_probe_unix, Some(now_unix));

        server.abort();
    }
}
