use std::time::Instant;

use anyhow::Result;
use tracing::{info, warn};

use nac::posture_from_compliance;
use response::plan_action;

use crate::platform::enrich_event_with_cache;

use crate::config::AgentMode;

use super::{
    confidence_to_severity, elapsed_micros, interval_due, to_detection_event, AgentRuntime,
    TickEvaluation, HEARTBEAT_INTERVAL_SECS,
};

impl AgentRuntime {
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
        self.run_self_protection_if_due(now_unix).await?;

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

        self.metrics.last_tick_total_micros = elapsed_micros(tick_started);
        self.metrics.max_tick_total_micros = self
            .metrics
            .max_tick_total_micros
            .max(self.metrics.last_tick_total_micros);
        let _ = self.protected.is_protected_process("systemd");
        Ok(())
    }

    pub(super) fn evaluate_tick(&mut self, now_unix: i64) -> Result<Option<TickEvaluation>> {
        let Some(raw) = self.next_raw_event() else {
            return Ok(None);
        };

        self.enrichment_cache
            .set_budget_mode(self.strict_budget_mode);
        let enriched = enrich_event_with_cache(raw, &mut self.enrichment_cache);

        let detection_event = to_detection_event(&enriched, now_unix);

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

        let mut event_envelope = self.build_event_envelope(
            &enriched,
            &detection_event,
            &detection_outcome,
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

        self.buffer_degraded_telemetry_if_present(evaluation)?;
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
        self.probe_server_recovery(compliance_status).await;
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
                match self
                    .client
                    .send_heartbeat(&self.config.agent_id, compliance_status)
                    .await
                {
                    Ok(_) => {
                        self.runtime_mode = self.config.mode.clone();
                        self.consecutive_send_failures = 0;
                        self.last_recovery_probe_unix = None;
                        info!(mode = ?self.runtime_mode, "server reachable again, leaving degraded mode");
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
        self.client.set_online(true);
        self.run_connected_response_stage(now_unix, evaluation)
            .await;
        self.ensure_enrolled().await;

        self.run_connected_telemetry_stage(evaluation).await?;
        self.run_connected_control_plane_stage(now_unix, evaluation)
            .await?;
        self.run_memory_scan_if_due(now_unix).await;
        self.drive_async_workers();

        self.metrics.last_connected_tick_micros = elapsed_micros(connected_started);
        Ok(())
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
