use std::collections::HashMap;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{anyhow, Result};
use serde::Deserialize;
use serde_json::json;
use tracing::{info, warn};

use baseline::{BaselineStatus, BaselineStore, BaselineTransition, ProcessKey};
use compliance::{evaluate, evaluate_linux, parse_policy_json, CompliancePolicy, ComplianceResult};
use detection::{Confidence, DetectionEngine, DetectionOutcome, EventClass, TelemetryEvent};
use grpc_client::{
    Client as GrpcClient, CommandEnvelope, ComplianceEnvelope, EnrollmentEnvelope, EventBuffer,
    EventEnvelope, ResponseEnvelope, TlsConfig, TransportMode,
};
use nac::{posture_from_compliance, Posture};
use platform_linux::{
    enrich_event_with_cache, EbpfEngine, EbpfStats, EnrichmentCache, EventType, RawEvent,
};
use response::{
    capture_script_content, kill_process_tree, plan_action, quarantine_file, HostControlState,
    KillRateLimiter, PlannedAction, ProtectedList, ResponseConfig,
};
use self_protect::{
    apply_linux_hardening, LinuxHardeningConfig, SelfProtectEngine, SelfProtectReport,
};

use crate::config::{AgentConfig, AgentMode};
use crate::detection_state::{EmergencyRuleType, SharedDetectionState};

mod bundle_path;
mod command_pipeline;
mod detection_bootstrap;
mod ebpf_bootstrap;
mod rule_bundle_loader;
mod rule_bundle_verify;
use bundle_path::{
    is_remote_bundle_reference, resolve_rules_staging_root, staging_bundle_archive_path,
};

const DEFAULT_RULES_STAGING_DIR: &str = "/var/lib/eguard-agent/rules-staging";
const MAX_SIGNED_RULE_BUNDLE_BYTES: u64 = 256 * 1024 * 1024;
const HEARTBEAT_INTERVAL_SECS: i64 = 30;
const COMPLIANCE_INTERVAL_SECS: i64 = 60;
const THREAT_INTEL_INTERVAL_SECS: i64 = 150;
const BASELINE_SAVE_INTERVAL_SECS: i64 = 300;
const EVENT_BATCH_SIZE: usize = 256;
const COMMAND_FETCH_LIMIT: usize = 10;
const DEGRADE_AFTER_SEND_FAILURES: u32 = 3;

struct TickEvaluation {
    detection_event: TelemetryEvent,
    detection_outcome: DetectionOutcome,
    confidence: Confidence,
    action: PlannedAction,
    compliance: ComplianceResult,
    event_envelope: EventEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReloadReport {
    old_version: String,
    new_version: String,
    sigma_rules: usize,
    yara_rules: usize,
    ioc_entries: usize,
}

pub struct AgentRuntime {
    config: AgentConfig,
    buffer: EventBuffer,
    detection_state: SharedDetectionState,
    protected: ProtectedList,
    limiter: KillRateLimiter,
    compliance_policy: CompliancePolicy,
    baseline_store: BaselineStore,
    ebpf_engine: EbpfEngine,
    enrichment_cache: EnrichmentCache,
    client: GrpcClient,
    self_protect_engine: SelfProtectEngine,
    tick_count: u64,
    runtime_mode: AgentMode,
    last_ebpf_stats: EbpfStats,
    recent_ebpf_drops: u64,
    consecutive_send_failures: u32,
    last_self_protect_check_unix: Option<i64>,
    last_heartbeat_attempt_unix: Option<i64>,
    last_compliance_attempt_unix: Option<i64>,
    last_threat_intel_refresh_unix: Option<i64>,
    last_baseline_save_unix: Option<i64>,
    last_recovery_probe_unix: Option<i64>,
    tamper_forced_degraded: bool,
    enrolled: bool,
    latest_threat_version: Option<String>,
    latest_custom_rule_hash: Option<String>,
    last_reload_report: Option<ReloadReport>,
    host_control: HostControlState,
    completed_command_ids: VecDeque<String>,
}

impl AgentRuntime {
    pub fn new(config: AgentConfig) -> Result<Self> {
        let detection_shards = resolve_detection_shard_count();
        let detection_state = SharedDetectionState::new_with_shards(
            build_detection_engine(),
            None,
            detection_shards,
            build_detection_engine,
        );
        info!(detection_shards, "initialized detection shard pool");
        let baseline_store = load_baseline_store()?;
        seed_anomaly_baselines(&detection_state, &baseline_store)?;
        let compliance_policy = load_compliance_policy();
        let ebpf_engine = init_ebpf_engine();
        let enrichment_cache = EnrichmentCache::default();

        let buffer = if config.offline_buffer_backend.eq_ignore_ascii_case("memory") {
            EventBuffer::memory(config.offline_buffer_cap_bytes)
        } else {
            match EventBuffer::sqlite(&config.offline_buffer_path, config.offline_buffer_cap_bytes)
            {
                Ok(buf) => buf,
                Err(err) => {
                    warn!(
                        error = %err,
                        backend = %config.offline_buffer_backend,
                        path = %config.offline_buffer_path,
                        "failed to initialize sqlite buffer, falling back to memory"
                    );
                    EventBuffer::memory(config.offline_buffer_cap_bytes)
                }
            }
        };

        let mut client = GrpcClient::with_mode(
            config.server_addr.clone(),
            TransportMode::from_str(&config.transport_mode),
        );
        let self_protect_engine = SelfProtectEngine::from_env();
        if let (Some(cert), Some(key), Some(ca)) = (
            config.tls_cert_path.clone(),
            config.tls_key_path.clone(),
            config.tls_ca_path.clone(),
        ) {
            if let Err(err) = client.configure_tls(TlsConfig {
                cert_path: cert,
                key_path: key,
                ca_path: ca,
            }) {
                warn!(error = %err, "failed to configure TLS; continuing without TLS");
            }
        }

        client.enqueue_mock_command(CommandEnvelope {
            command_id: "bootstrap-isolate-check".to_string(),
            command_type: "scan".to_string(),
            payload_json: "{\"scope\":\"quick\"}".to_string(),
        });

        let mut hardening_config = LinuxHardeningConfig::default();
        hardening_config.drop_capability_bounding_set = config.self_protection_prevent_uninstall;
        let hardening_report = apply_linux_hardening(&hardening_config);
        if hardening_report.has_failures() {
            warn!(
                failed_steps = ?hardening_report.failed_step_names(),
                dropped_capabilities = hardening_report.dropped_capability_count,
                "linux hardening applied with failures"
            );
        } else {
            info!(
                dropped_capabilities = hardening_report.dropped_capability_count,
                "linux hardening applied"
            );
        }

        let initial_mode = derive_runtime_mode(&config.mode, baseline_store.status);

        Ok(Self {
            limiter: KillRateLimiter::new(config.response.max_kills_per_minute),
            protected: ProtectedList::default_linux(),
            compliance_policy,
            baseline_store,
            ebpf_engine,
            enrichment_cache,
            buffer,
            detection_state,
            client,
            self_protect_engine,
            config,
            tick_count: 0,
            runtime_mode: initial_mode,
            last_ebpf_stats: EbpfStats::default(),
            recent_ebpf_drops: 0,
            consecutive_send_failures: 0,
            last_self_protect_check_unix: None,
            last_heartbeat_attempt_unix: None,
            last_compliance_attempt_unix: None,
            last_threat_intel_refresh_unix: None,
            last_baseline_save_unix: None,
            last_recovery_probe_unix: None,
            tamper_forced_degraded: false,
            enrolled: false,
            latest_threat_version: None,
            latest_custom_rule_hash: None,
            last_reload_report: None,
            host_control: HostControlState::default(),
            completed_command_ids: VecDeque::new(),
        })
    }

    pub async fn tick(&mut self, now_unix: i64) -> Result<()> {
        self.tick_count = self.tick_count.saturating_add(1);
        self.run_self_protection_if_due(now_unix).await?;

        let evaluation = self.evaluate_tick(now_unix)?;
        if matches!(self.runtime_mode, AgentMode::Degraded) {
            self.handle_degraded_tick(now_unix, &evaluation).await?;
        } else {
            self.handle_connected_tick(now_unix, &evaluation).await?;
            self.log_detection_evaluation(&evaluation);
        }

        let _ = self.protected.is_protected_process("systemd");
        Ok(())
    }

    fn evaluate_tick(&mut self, now_unix: i64) -> Result<TickEvaluation> {
        let raw = self.next_raw_event(now_unix);
        let enriched = enrich_event_with_cache(raw, &mut self.enrichment_cache);

        let detection_event = to_detection_event(&enriched, now_unix);
        self.observe_baseline(&detection_event, now_unix);

        let detection_outcome = self.detection_state.process_event(&detection_event)?;
        let confidence = detection_outcome.confidence;
        let response_cfg = self.effective_response_config();
        let action = plan_action(confidence, &response_cfg);

        let compliance = self.evaluate_compliance();
        let posture = posture_from_compliance(&compliance.status);
        self.log_posture(posture);

        let event_envelope = self.build_event_envelope(enriched.process_exe.as_deref(), now_unix);

        Ok(TickEvaluation {
            detection_event,
            detection_outcome,
            confidence,
            action,
            compliance,
            event_envelope,
        })
    }

    async fn handle_degraded_tick(
        &mut self,
        now_unix: i64,
        evaluation: &TickEvaluation,
    ) -> Result<()> {
        self.client.set_online(false);
        self.buffer.enqueue(evaluation.event_envelope.clone())?;
        warn!(
            pending = self.buffer.pending_count(),
            "server unavailable, buffered event"
        );

        if self.should_probe_server_recovery(now_unix) {
            self.last_recovery_probe_unix = Some(now_unix);
            self.probe_server_recovery(&evaluation.compliance.status)
                .await;
        }

        Ok(())
    }

    fn should_probe_server_recovery(&self, now_unix: i64) -> bool {
        !self.is_forced_degraded()
            && interval_due(
                self.last_recovery_probe_unix,
                now_unix,
                HEARTBEAT_INTERVAL_SECS,
            )
    }

    fn is_forced_degraded(&self) -> bool {
        matches!(self.config.mode, AgentMode::Degraded) || self.tamper_forced_degraded
    }

    async fn run_self_protection_if_due(&mut self, now_unix: i64) -> Result<()> {
        if self.tamper_forced_degraded {
            return Ok(());
        }

        let interval = self.config.self_protection_integrity_check_interval_secs;
        if interval == 0 {
            return Ok(());
        }

        if let Some(last) = self.last_self_protect_check_unix {
            if now_unix.saturating_sub(last) < interval as i64 {
                return Ok(());
            }
        }
        self.last_self_protect_check_unix = Some(now_unix);

        let report = self.self_protect_engine.evaluate();
        if report.is_clean() {
            return Ok(());
        }

        self.handle_self_protection_violation(now_unix, &report)
            .await
    }

    async fn handle_self_protection_violation(
        &mut self,
        now_unix: i64,
        report: &SelfProtectReport,
    ) -> Result<()> {
        if self.tamper_forced_degraded {
            return Ok(());
        }

        let alert = EventEnvelope {
            agent_id: self.config.agent_id.clone(),
            event_type: "alert".to_string(),
            payload_json: self.self_protect_alert_payload(report, now_unix),
            created_at_unix: now_unix,
        };

        if self.client.is_online() {
            if let Err(err) = self.client.send_events(&[alert.clone()]).await {
                warn!(
                    error = %err,
                    pending = self.buffer.pending_count(),
                    "failed sending self-protect alert; buffering locally"
                );
                self.buffer.enqueue(alert)?;
            }
        } else {
            self.buffer.enqueue(alert)?;
        }

        self.tamper_forced_degraded = true;
        self.runtime_mode = AgentMode::Degraded;
        warn!(
            violations = ?report.violation_codes(),
            summary = %report.summary(),
            "self-protection violation detected; forcing degraded mode"
        );

        Ok(())
    }

    fn self_protect_alert_payload(&self, report: &SelfProtectReport, now_unix: i64) -> String {
        json!({
            "rule_name": "agent_tamper",
            "severity": "critical",
            "timestamp": now_unix,
            "violations": report.violation_codes(),
            "detail": report.summary(),
        })
        .to_string()
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
        evaluation: &TickEvaluation,
    ) -> Result<()> {
        self.client.set_online(true);
        self.ensure_enrolled().await;

        self.send_event_batch(evaluation.event_envelope.clone())
            .await?;
        self.send_heartbeat_if_due(now_unix, &evaluation.compliance.status)
            .await;
        self.send_compliance_if_due(now_unix, &evaluation.compliance)
            .await;
        self.refresh_threat_intel_if_due(now_unix).await?;
        self.sync_pending_commands(now_unix).await;
        self.report_local_action_if_needed(
            evaluation.action,
            evaluation.confidence,
            &evaluation.detection_event,
            now_unix,
        )
        .await;

        Ok(())
    }

    async fn ensure_enrolled(&mut self) {
        if self.enrolled {
            return;
        }

        let enroll = self.build_enrollment_envelope();
        if let Err(err) = self.client.enroll(&enroll).await {
            warn!(error = %err, "enrollment failed");
            return;
        }

        self.enrolled = true;
        self.consume_bootstrap_config();
    }

    fn build_enrollment_envelope(&self) -> EnrollmentEnvelope {
        let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| self.config.agent_id.clone());
        EnrollmentEnvelope {
            agent_id: self.config.agent_id.clone(),
            mac: self.config.mac.clone(),
            hostname,
            enrollment_token: self.config.enrollment_token.clone(),
            tenant_id: self.config.tenant_id.clone(),
        }
    }

    async fn send_event_batch(&mut self, envelope: EventEnvelope) -> Result<()> {
        let mut batch = self.buffer.drain_batch(EVENT_BATCH_SIZE)?;
        batch.push(envelope);

        if let Err(err) = self.client.send_events(&batch).await {
            for ev in batch {
                self.buffer.enqueue(ev)?;
            }

            self.consecutive_send_failures = self.consecutive_send_failures.saturating_add(1);
            if self.consecutive_send_failures >= DEGRADE_AFTER_SEND_FAILURES {
                self.runtime_mode = AgentMode::Degraded;
            }

            warn!(
                error = %err,
                pending = self.buffer.pending_count(),
                "send failed, events re-buffered"
            );
        } else {
            self.consecutive_send_failures = 0;
        }

        Ok(())
    }

    async fn send_heartbeat_if_due(&mut self, now_unix: i64, compliance_status: &str) {
        if !interval_due(
            self.last_heartbeat_attempt_unix,
            now_unix,
            HEARTBEAT_INTERVAL_SECS,
        ) {
            return;
        }
        self.last_heartbeat_attempt_unix = Some(now_unix);

        let config_version = self.heartbeat_config_version();
        if let Err(err) = self
            .client
            .send_heartbeat_with_config(&self.config.agent_id, compliance_status, &config_version)
            .await
        {
            warn!(error = %err, "heartbeat failed");
        }
    }

    async fn send_compliance_if_due(&mut self, now_unix: i64, compliance: &ComplianceResult) {
        if !interval_due(
            self.last_compliance_attempt_unix,
            now_unix,
            COMPLIANCE_INTERVAL_SECS,
        ) {
            return;
        }
        self.last_compliance_attempt_unix = Some(now_unix);

        let envelope = ComplianceEnvelope {
            agent_id: self.config.agent_id.clone(),
            policy_id: "default".to_string(),
            check_type: "runtime_health".to_string(),
            status: compliance.status.clone(),
            detail: compliance.detail.clone(),
            expected_value: "firewall_enabled=true".to_string(),
            actual_value: "firewall_enabled=true".to_string(),
        };

        if let Err(err) = self.client.send_compliance(&envelope).await {
            warn!(error = %err, "compliance send failed");
        }
    }

    async fn refresh_threat_intel_if_due(&mut self, now_unix: i64) -> Result<()> {
        if !interval_due(
            self.last_threat_intel_refresh_unix,
            now_unix,
            THREAT_INTEL_INTERVAL_SECS,
        ) {
            return Ok(());
        }
        self.last_threat_intel_refresh_unix = Some(now_unix);

        if let Some(v) = self.client.fetch_latest_threat_intel().await? {
            let latest_hash = v.custom_rule_version_hash.clone();
            let known_version = self
                .latest_threat_version
                .clone()
                .or(self.detection_state.version()?);
            let changed = known_version.as_deref() != Some(v.version.as_str())
                || self.latest_custom_rule_hash.as_deref() != Some(latest_hash.as_str());
            if changed {
                info!(
                    version = %v.version,
                    bundle = %v.bundle_path,
                    custom_rule_count = v.custom_rule_count,
                    custom_rule_hash = %latest_hash,
                    "new threat intel version available"
                );
                let local_bundle_path = self
                    .prepare_bundle_for_reload(&v.version, &v.bundle_path)
                    .await?;
                self.reload_detection_state(&v.version, &local_bundle_path)?;
            }
            self.latest_threat_version = Some(v.version);
            self.latest_custom_rule_hash = Some(latest_hash);
        }

        Ok(())
    }

    async fn sync_pending_commands(&mut self, now_unix: i64) {
        let completed_cursor = self.completed_command_cursor();
        match self
            .client
            .fetch_commands(
                &self.config.agent_id,
                &completed_cursor,
                COMMAND_FETCH_LIMIT,
            )
            .await
        {
            Ok(commands) => {
                for command in commands {
                    self.handle_command(command, now_unix).await;
                }
            }
            Err(err) => {
                warn!(error = %err, "command fetch failed");
            }
        }
    }

    async fn report_local_action_if_needed(
        &mut self,
        action: PlannedAction,
        confidence: Confidence,
        event: &TelemetryEvent,
        now_unix: i64,
    ) {
        if matches!(action, PlannedAction::AlertOnly | PlannedAction::None) {
            return;
        }

        let local = self.execute_planned_action(action, event, now_unix);
        let response = ResponseEnvelope {
            agent_id: self.config.agent_id.clone(),
            action_type: format!("{:?}", action).to_ascii_lowercase(),
            confidence: confidence_label(confidence),
            success: local.success,
            error_message: local.detail,
        };
        if let Err(err) = self.client.send_response(&response).await {
            warn!(error = %err, "response report send failed");
        }
    }

    fn build_event_envelope(&self, process_exe: Option<&str>, now_unix: i64) -> EventEnvelope {
        EventEnvelope {
            agent_id: self.config.agent_id.clone(),
            event_type: "process_exec".to_string(),
            payload_json: format!("{{\"exe\":\"{}\"}}", process_exe.unwrap_or_default()),
            created_at_unix: now_unix,
        }
    }

    fn log_detection_evaluation(&self, evaluation: &TickEvaluation) {
        info!(
            action = ?evaluation.action,
            confidence = ?evaluation.confidence,
            mode = ?self.runtime_mode,
            temporal_hits = evaluation.detection_outcome.temporal_hits.len(),
            killchain_hits = evaluation.detection_outcome.kill_chain_hits.len(),
            z1 = evaluation.detection_outcome.signals.z1_exact_ioc,
            z2 = evaluation.detection_outcome.signals.z2_temporal,
            z3h = evaluation.detection_outcome.signals.z3_anomaly_high,
            z4 = evaluation.detection_outcome.signals.z4_kill_chain,
            yara_hits = evaluation.detection_outcome.yara_hits.len(),
            "event evaluated"
        );
    }

    fn log_posture(&self, posture: Posture) {
        info!(?posture, "computed nac posture");
    }

    fn evaluate_compliance(&self) -> ComplianceResult {
        match evaluate_linux(&self.compliance_policy) {
            Ok(result) => result,
            Err(err) => {
                warn!(error = %err, "linux compliance probe failed, using minimal fallback checks");
                evaluate(&self.compliance_policy, true, "unknown")
            }
        }
    }

    fn consume_bootstrap_config(&self) {
        let Some(path) = self.config.bootstrap_config_path.as_ref() else {
            return;
        };
        match std::fs::remove_file(path) {
            Ok(()) => info!(path = %path.display(), "consumed bootstrap config after enrollment"),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                warn!(error = %err, path = %path.display(), "failed consuming bootstrap config")
            }
        }
    }

    fn next_raw_event(&mut self, now_unix: i64) -> RawEvent {
        let timeout = self.adaptive_poll_timeout();
        let sampling_stride =
            compute_sampling_stride(self.buffer.pending_count(), self.recent_ebpf_drops);
        let polled = self.ebpf_engine.poll_once(timeout);
        self.observe_ebpf_stats();

        match polled {
            Ok(events) => {
                if sampling_stride > 1 {
                    info!(
                        sampling_stride,
                        backlog = self.buffer.pending_count(),
                        recent_ebpf_drops = self.recent_ebpf_drops,
                        "applying statistical sampling due to backpressure"
                    );
                }
                if let Some(event) = events.into_iter().step_by(sampling_stride).next() {
                    return event;
                }
            }
            Err(err) => {
                warn!(error = %err, "eBPF poll failed, falling back to synthetic event");
            }
        }

        synthetic_raw_event(now_unix)
    }

    fn adaptive_poll_timeout(&self) -> std::time::Duration {
        compute_poll_timeout(self.buffer.pending_count(), self.recent_ebpf_drops)
    }

    fn observe_ebpf_stats(&mut self) {
        let stats = self.ebpf_engine.stats();
        self.recent_ebpf_drops = stats
            .events_dropped
            .saturating_sub(self.last_ebpf_stats.events_dropped);
        self.last_ebpf_stats = stats;
    }

    fn effective_response_config(&self) -> ResponseConfig {
        let mut cfg = self.config.response.clone();
        if matches!(self.runtime_mode, AgentMode::Learning)
            || matches!(self.baseline_store.status, BaselineStatus::Learning)
        {
            cfg.autonomous_response = false;
        }
        cfg
    }

    fn observe_baseline(&mut self, event: &TelemetryEvent, now_unix: i64) {
        let process_key = ProcessKey {
            comm: event.process.clone(),
            parent_comm: event.parent_process.clone(),
        };
        self.baseline_store
            .learn_event(process_key, event.event_class.as_str());

        let now = now_unix.max(0) as u64;
        if let Some(transition) = self.baseline_store.check_transition_with_now(now) {
            match transition {
                BaselineTransition::LearningComplete => {
                    info!("baseline learning completed; enabling active mode");
                    if !matches!(self.config.mode, AgentMode::Degraded) {
                        self.runtime_mode = AgentMode::Active;
                    }
                }
                BaselineTransition::BecameStale => {
                    warn!("baseline became stale; anomaly thresholds should be reviewed");
                }
            }

            if let Err(err) = self.baseline_store.save() {
                warn!(error = %err, "failed persisting baseline transition state");
            }
            self.last_baseline_save_unix = Some(now_unix);
        } else if interval_due(
            self.last_baseline_save_unix,
            now_unix,
            BASELINE_SAVE_INTERVAL_SECS,
        ) {
            self.last_baseline_save_unix = Some(now_unix);
            if let Err(err) = self.baseline_store.save() {
                warn!(error = %err, "failed persisting baseline store snapshot");
            }
        }
    }

    fn execute_planned_action(
        &mut self,
        action: PlannedAction,
        event: &TelemetryEvent,
        _now_unix: i64,
    ) -> LocalActionResult {
        let mut success = true;
        let mut notes = Vec::new();

        self.execute_capture_step(action, event, &mut success, &mut notes);
        self.execute_kill_step(action, event, &mut success, &mut notes);
        self.execute_quarantine_step(action, event, &mut success, &mut notes);

        if notes.is_empty() {
            notes.push("no_local_action".to_string());
        }

        LocalActionResult {
            success,
            detail: notes.join("; "),
        }
    }

    fn execute_capture_step(
        &self,
        action: PlannedAction,
        event: &TelemetryEvent,
        success: &mut bool,
        notes: &mut Vec<String>,
    ) {
        if !should_capture_script(action, event) {
            return;
        }

        match capture_script_content(event.pid) {
            Ok(capture) => {
                let bytes = capture
                    .script_content
                    .as_ref()
                    .map(|buf| buf.len())
                    .or_else(|| capture.stdin_content.as_ref().map(|buf| buf.len()))
                    .unwrap_or(0);
                notes.push(format!("script_capture_bytes={}", bytes));
            }
            Err(err) => {
                *success = false;
                notes.push(format!("capture_failed:{}", err));
            }
        }
    }

    fn execute_kill_step(
        &mut self,
        action: PlannedAction,
        event: &TelemetryEvent,
        success: &mut bool,
        notes: &mut Vec<String>,
    ) {
        if !requires_kill(action) {
            return;
        }

        if event.pid == std::process::id() {
            *success = false;
            notes.push("kill_skipped:self_pid".to_string());
            return;
        }

        if !self.limiter.allow(Instant::now()) {
            *success = false;
            notes.push("kill_skipped:rate_limited".to_string());
            return;
        }

        match kill_process_tree(event.pid, &self.protected) {
            Ok(report) => notes.push(format!("killed_pids={}", report.killed_pids.len())),
            Err(err) => {
                *success = false;
                notes.push(format!("kill_failed:{}", err));
            }
        }
    }

    fn execute_quarantine_step(
        &self,
        action: PlannedAction,
        event: &TelemetryEvent,
        success: &mut bool,
        notes: &mut Vec<String>,
    ) {
        if !requires_quarantine(action) {
            return;
        }

        let Some(path) = event.file_path.as_deref() else {
            *success = false;
            notes.push("quarantine_failed:missing_file_path".to_string());
            return;
        };

        let sha = event
            .file_hash
            .clone()
            .unwrap_or_else(|| synthetic_quarantine_id(event));
        match quarantine_file(Path::new(path), &sha, &self.protected) {
            Ok(report) => notes.push(format!("quarantined:{}", report.quarantine_path.display())),
            Err(err) => {
                *success = false;
                notes.push(format!("quarantine_failed:{}", err));
            }
        }
    }

    fn reload_detection_state(&mut self, version: &str, bundle_path: &str) -> Result<()> {
        let old_version = self.detection_state.version()?.unwrap_or_default();
        let mut next_engine = build_detection_engine();
        let (sigma_loaded, yara_loaded) = load_bundle_rules(&mut next_engine, bundle_path);
        let ioc_entries = next_engine.layer1.ioc_entry_count();
        let shard_count = self.detection_state.shard_count();
        if shard_count <= 1 {
            self.detection_state
                .swap_engine(version.to_string(), next_engine)?;
        } else {
            let bundle_path = bundle_path.to_string();
            self.detection_state.swap_engine_with_builder(
                version.to_string(),
                next_engine,
                move || {
                    let mut shard_engine = build_detection_engine();
                    let _ = load_bundle_rules(&mut shard_engine, &bundle_path);
                    shard_engine
                },
            )?;
        }
        let report = ReloadReport {
            old_version,
            new_version: version.to_string(),
            sigma_rules: sigma_loaded,
            yara_rules: yara_loaded,
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
            "detection state hot-reloaded"
        );
        Ok(())
    }

    fn heartbeat_config_version(&self) -> String {
        if let Some(version) = &self.latest_threat_version {
            return version.clone();
        }
        self.detection_state
            .version()
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    async fn prepare_bundle_for_reload(&self, version: &str, bundle_path: &str) -> Result<String> {
        let bundle_path = bundle_path.trim();
        if bundle_path.is_empty() {
            return Ok(String::new());
        }

        if !is_remote_bundle_reference(bundle_path) {
            return Ok(bundle_path.to_string());
        }

        let local_bundle = self
            .download_remote_bundle_archive(version, bundle_path)
            .await?;
        self.download_remote_bundle_signature_if_needed(bundle_path, &local_bundle)
            .await?;

        Ok(local_bundle.to_string_lossy().into_owned())
    }

    async fn download_remote_bundle_archive(
        &self,
        version: &str,
        bundle_url: &str,
    ) -> Result<PathBuf> {
        let local_bundle = staging_bundle_archive_path(version, bundle_url)?;
        self.client
            .download_bundle(bundle_url, &local_bundle)
            .await
            .map_err(|err| anyhow!("download threat-intel bundle '{}': {}", bundle_url, err))?;
        Ok(local_bundle)
    }

    async fn download_remote_bundle_signature_if_needed(
        &self,
        bundle_url: &str,
        local_bundle: &Path,
    ) -> Result<()> {
        if !is_signed_bundle_archive(local_bundle) {
            return Ok(());
        }

        let signature_url = format!("{}.sig", bundle_url);
        let signature_dst = PathBuf::from(format!("{}.sig", local_bundle.to_string_lossy()));
        self.client
            .download_bundle(&signature_url, &signature_dst)
            .await
            .map_err(|err| {
                anyhow!(
                    "download threat-intel bundle signature '{}': {}",
                    signature_url,
                    err
                )
            })?;
        Ok(())
    }
}

fn load_compliance_policy() -> CompliancePolicy {
    if let Ok(path) = std::env::var("EGUARD_COMPLIANCE_POLICY_PATH") {
        let path = path.trim();
        if !path.is_empty() {
            match std::fs::read_to_string(path) {
                Ok(raw) => match parse_policy_json(&raw) {
                    Ok(policy) => return policy,
                    Err(err) => {
                        warn!(error = %err, path = %path, "invalid compliance policy file; using fallback")
                    }
                },
                Err(err) => {
                    warn!(error = %err, path = %path, "failed reading compliance policy file; using fallback")
                }
            }
        }
    }

    if let Ok(raw) = std::env::var("EGUARD_COMPLIANCE_POLICY_JSON") {
        let raw = raw.trim();
        if !raw.is_empty() {
            match parse_policy_json(raw) {
                Ok(policy) => return policy,
                Err(err) => {
                    warn!(error = %err, "invalid EGUARD_COMPLIANCE_POLICY_JSON; using fallback")
                }
            }
        }
    }

    CompliancePolicy {
        firewall_required: true,
        min_kernel_prefix: None,
        ..CompliancePolicy::default()
    }
}

fn compute_poll_timeout(pending: usize, recent_ebpf_drops: u64) -> std::time::Duration {
    if recent_ebpf_drops > 0 {
        std::time::Duration::from_millis(1)
    } else if pending > 4096 {
        std::time::Duration::from_millis(5)
    } else if pending > 1024 {
        std::time::Duration::from_millis(20)
    } else {
        std::time::Duration::from_millis(100)
    }
}

fn compute_sampling_stride(pending: usize, recent_ebpf_drops: u64) -> usize {
    if recent_ebpf_drops == 0 {
        return 1;
    }
    if pending > 8_192 {
        8
    } else if pending > 4_096 {
        4
    } else if pending > 1_024 {
        2
    } else {
        1
    }
}

fn resolve_detection_shard_count() -> usize {
    const MAX_DETECTION_SHARDS: usize = 16;
    if let Ok(raw) = std::env::var("EGUARD_DETECTION_SHARDS") {
        match raw.trim().parse::<usize>() {
            Ok(value) if value > 0 => return value.min(MAX_DETECTION_SHARDS),
            _ => warn!(
                value = %raw,
                "invalid EGUARD_DETECTION_SHARDS value; falling back to CPU-based default"
            ),
        }
    }

    std::thread::available_parallelism()
        .map(|n| n.get().clamp(1, MAX_DETECTION_SHARDS))
        .unwrap_or(1)
}

fn interval_due(last_run_unix: Option<i64>, now_unix: i64, interval_secs: i64) -> bool {
    match last_run_unix {
        None => true,
        Some(last) => now_unix < last || now_unix.saturating_sub(last) >= interval_secs,
    }
}

struct LocalActionResult {
    success: bool,
    detail: String,
}

fn should_capture_script(action: PlannedAction, event: &TelemetryEvent) -> bool {
    matches!(action, PlannedAction::CaptureScript)
        || (requires_kill(action) && is_script_interpreter(&event.process))
}

fn requires_kill(action: PlannedAction) -> bool {
    matches!(
        action,
        PlannedAction::KillOnly | PlannedAction::KillAndQuarantine
    )
}

fn requires_quarantine(action: PlannedAction) -> bool {
    matches!(
        action,
        PlannedAction::QuarantineOnly | PlannedAction::KillAndQuarantine
    )
}

fn is_script_interpreter(process: &str) -> bool {
    matches!(
        process,
        "bash" | "sh" | "dash" | "zsh" | "ksh" | "python" | "python3" | "perl"
    )
}

fn synthetic_quarantine_id(event: &TelemetryEvent) -> String {
    format!("pid{}-ts{}", event.pid, event.ts_unix)
}

fn load_baseline_store() -> Result<BaselineStore> {
    let default_path = "/var/lib/eguard-agent/baselines.bin".to_string();
    let configured_path = std::env::var("EGUARD_BASELINE_PATH")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or(default_path);
    let path = PathBuf::from(configured_path);

    match BaselineStore::load_or_new(path.clone()) {
        Ok(mut store) => {
            seed_default_baselines_if_needed(&mut store, &path);
            Ok(store)
        }
        Err(err) => {
            warn!(error = %err, path = %path.display(), "failed loading baseline store, using temp fallback");
            let fallback = std::env::temp_dir().join("eguard-agent-baselines.bin");
            let mut store =
                BaselineStore::load_or_new(fallback.clone()).map_err(|fallback_err| {
                    anyhow!(
                        "failed to initialize baseline store at {} and fallback {}: {} / {}",
                        path.display(),
                        fallback.display(),
                        err,
                        fallback_err
                    )
                })?;
            seed_default_baselines_if_needed(&mut store, &fallback);
            Ok(store)
        }
    }
}

fn seed_default_baselines_if_needed(store: &mut BaselineStore, path: &Path) {
    let seeded = store.seed_with_defaults_if_empty();
    if seeded == 0 {
        return;
    }

    info!(
        seeded_profiles = seeded,
        path = %path.display(),
        "initialized baseline store with built-in seed baselines"
    );
    if let Err(err) = store.save() {
        warn!(
            error = %err,
            path = %path.display(),
            "failed to persist seeded baseline store"
        );
    }
}

fn seed_anomaly_baselines(
    detection_state: &SharedDetectionState,
    baseline_store: &BaselineStore,
) -> Result<()> {
    let mut seeded = 0usize;
    for ((comm, parent), distribution) in baseline_store.init_entropy_baselines() {
        let mut parsed = HashMap::new();
        for (event_name, probability) in distribution {
            if let Some(event_class) = parse_event_class_name(&event_name) {
                parsed.insert(event_class, probability);
            }
        }
        if parsed.is_empty() {
            continue;
        }

        detection_state.set_anomaly_baseline(format!("{}:{}", comm, parent), parsed)?;
        seeded += 1;
    }

    if seeded > 0 {
        info!(
            seeded_baselines = seeded,
            "initialized anomaly baselines from baseline store"
        );
    }
    Ok(())
}

fn parse_event_class_name(raw: &str) -> Option<EventClass> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "process_exec" => Some(EventClass::ProcessExec),
        "file_open" => Some(EventClass::FileOpen),
        "network_connect" | "tcp_connect" => Some(EventClass::NetworkConnect),
        "dns_query" => Some(EventClass::DnsQuery),
        "module_load" => Some(EventClass::ModuleLoad),
        "login" => Some(EventClass::Login),
        "alert" => Some(EventClass::Alert),
        _ => None,
    }
}

fn derive_runtime_mode(config_mode: &AgentMode, baseline_status: BaselineStatus) -> AgentMode {
    match config_mode {
        AgentMode::Degraded => AgentMode::Degraded,
        AgentMode::Active => AgentMode::Active,
        AgentMode::Learning => {
            if matches!(baseline_status, BaselineStatus::Learning) {
                AgentMode::Learning
            } else {
                AgentMode::Active
            }
        }
    }
}

fn init_ebpf_engine() -> EbpfEngine {
    ebpf_bootstrap::init_ebpf_engine()
}

fn default_ebpf_objects_dirs() -> Vec<PathBuf> {
    ebpf_bootstrap::default_ebpf_objects_dirs()
}

fn candidate_ebpf_object_paths(objects_dir: &Path) -> Vec<PathBuf> {
    ebpf_bootstrap::candidate_ebpf_object_paths(objects_dir)
}

fn synthetic_raw_event(now_unix: i64) -> RawEvent {
    RawEvent {
        event_type: EventType::ProcessExec,
        pid: std::process::id(),
        uid: 0,
        ts_ns: (now_unix.max(0) as u64) * 1_000_000_000,
        payload: "simulated_event".to_string(),
    }
}

#[derive(Debug, Deserialize)]
struct EmergencyRulePayload {
    #[serde(default)]
    rule_name: String,
    #[serde(default)]
    rule_type: String,
    #[serde(default)]
    rule_content: String,
    #[serde(default)]
    content: String,
    #[serde(default)]
    severity: String,
}

fn parse_emergency_rule_type(raw: &str) -> Result<EmergencyRuleType> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "ioc_hash" => Ok(EmergencyRuleType::IocHash),
        "ioc_domain" => Ok(EmergencyRuleType::IocDomain),
        "ioc_ip" => Ok(EmergencyRuleType::IocIP),
        "sigma" | "yara" | "signature" => Ok(EmergencyRuleType::Signature),
        other => Err(anyhow!("unsupported emergency rule type: {}", other)),
    }
}

fn confidence_label(c: Confidence) -> String {
    format!("{:?}", c).to_ascii_lowercase()
}

fn to_detection_event(enriched: &platform_linux::EnrichedEvent, now_unix: i64) -> TelemetryEvent {
    let process = enriched
        .process_exe
        .as_deref()
        .and_then(|p| p.rsplit('/').next())
        .unwrap_or("unknown")
        .to_string();

    TelemetryEvent {
        ts_unix: now_unix,
        event_class: map_event_class(&enriched.event.event_type),
        pid: enriched.event.pid,
        ppid: enriched.parent_chain.first().copied().unwrap_or_default(),
        uid: enriched.event.uid,
        process,
        parent_process: enriched
            .parent_process
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        file_path: enriched
            .file_path
            .clone()
            .or_else(|| enriched.process_exe.clone()),
        file_hash: enriched
            .file_sha256
            .clone()
            .or_else(|| enriched.process_exe_sha256.clone()),
        dst_port: enriched.dst_port,
        dst_ip: enriched.dst_ip.clone(),
        dst_domain: enriched.dst_domain.clone(),
        command_line: enriched.process_cmdline.clone(),
    }
}

fn map_event_class(event_type: &platform_linux::EventType) -> EventClass {
    match event_type {
        platform_linux::EventType::ProcessExec => EventClass::ProcessExec,
        platform_linux::EventType::ProcessExit => EventClass::ProcessExec,
        platform_linux::EventType::FileOpen => EventClass::FileOpen,
        platform_linux::EventType::TcpConnect => EventClass::NetworkConnect,
        platform_linux::EventType::DnsQuery => EventClass::DnsQuery,
        platform_linux::EventType::ModuleLoad => EventClass::ModuleLoad,
        platform_linux::EventType::LsmBlock => EventClass::Alert,
    }
}

fn load_bundle_rules(detection: &mut DetectionEngine, bundle_path: &str) -> (usize, usize) {
    rule_bundle_loader::load_bundle_rules(detection, bundle_path)
}

fn is_signed_bundle_archive(path: &Path) -> bool {
    rule_bundle_loader::is_signed_bundle_archive(path)
}

fn sanitize_archive_relative_path(path: &Path) -> Option<PathBuf> {
    rule_bundle_loader::sanitize_archive_relative_path(path)
}

fn verify_bundle_signature(bundle_path: &Path) -> bool {
    rule_bundle_verify::verify_bundle_signature(bundle_path)
}

fn resolve_rule_bundle_public_key() -> Option<[u8; 32]> {
    rule_bundle_verify::resolve_rule_bundle_public_key()
}

fn resolve_bundle_signature_path(bundle_path: &Path) -> Option<PathBuf> {
    rule_bundle_verify::resolve_bundle_signature_path(bundle_path)
}

fn verify_bundle_signature_with_material(
    bundle_path: &Path,
    signature_path: &Path,
    public_key: [u8; 32],
) -> std::result::Result<(), String> {
    rule_bundle_verify::verify_bundle_signature_with_material(
        bundle_path,
        signature_path,
        public_key,
    )
}

fn read_file_limited(path: &Path, max_bytes: u64) -> std::result::Result<Vec<u8>, String> {
    rule_bundle_verify::read_file_limited(path, max_bytes)
}

fn parse_ed25519_key_material(raw: &[u8]) -> Option<[u8; 32]> {
    rule_bundle_verify::parse_ed25519_key_material(raw)
}

fn decode_hex_bytes(raw: &str) -> Option<Vec<u8>> {
    rule_bundle_verify::decode_hex_bytes(raw)
}

fn push_unique_dir(out: &mut Vec<PathBuf>, path: PathBuf) {
    rule_bundle_loader::push_unique_dir(out, path)
}

fn build_detection_engine() -> DetectionEngine {
    detection_bootstrap::build_detection_engine()
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod tests_ebpf_policy;

#[cfg(test)]
mod tests_baseline_seed_policy;

#[cfg(test)]
mod tests_det_stub_completion;
#[cfg(test)]
mod tests_ebpf_memory;
#[cfg(test)]
mod tests_pkg_contract;
#[cfg(test)]
mod tests_resource_policy;
#[cfg(test)]
mod tests_self_protect_hardening;
#[cfg(test)]
mod tests_self_protect_policy;
