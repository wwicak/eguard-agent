use std::collections::HashMap;
use std::collections::VecDeque;
#[cfg(test)]
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{anyhow, Result};
use serde::Deserialize;
use serde_json::json;
use tokio::task::JoinSet;
use tracing::{info, warn};

use baseline::{BaselineStatus, BaselineStore, BaselineTransition, ProcessKey};
use compliance::{evaluate, evaluate_linux, parse_policy_json, CompliancePolicy, ComplianceResult};
use detection::{
    Confidence,
    DetectionEngine,
    DetectionOutcome,
    EventClass,
    RansomwarePolicy,
    TelemetryEvent,
};
use detection::memory_scanner::{find_suspicious_pids, MemoryScanResult, ScanMode};
#[cfg(test)]
use grpc_client::PolicyEnvelope;
use grpc_client::{
    Client as GrpcClient, CommandEnvelope, ComplianceEnvelope, EnrollmentEnvelope, EventBuffer,
    EventEnvelope, ResponseEnvelope, TlsConfig, TransportMode,
};
use nac::{posture_from_compliance, Posture};
use platform_linux::{enrich_event_with_cache, EbpfEngine, EbpfStats, EnrichmentCache, RawEvent};
use response::{
    capture_script_content, evaluate_auto_isolation, execute_server_command_with_state,
    kill_process_tree, plan_action, quarantine_file, AutoIsolationState, HostControlState,
    KillRateLimiter, PlannedAction, ProtectedList, ResponseConfig, ServerCommand,
};
use self_protect::{
    apply_linux_hardening, LinuxHardeningConfig, SelfProtectEngine, SelfProtectReport,
};
#[cfg(test)]
use x509_parser::pem::parse_x509_pem;
#[cfg(test)]
use x509_parser::prelude::parse_x509_certificate;

use crate::config::{AgentConfig, AgentMode};
use crate::detection_state::{EmergencyRuleType, SharedDetectionState};

mod bundle_path;
mod command_control_pipeline;
mod command_pipeline;
mod control_plane_pipeline;
mod detection_bootstrap;
mod ebpf_bootstrap;
mod response_pipeline;
mod rule_bundle_loader;
mod rule_bundle_verify;
mod telemetry_pipeline;
mod threat_intel_pipeline;
use bundle_path::resolve_rules_staging_root;

const DEFAULT_RULES_STAGING_DIR: &str = "/var/lib/eguard-agent/rules-staging";
const MAX_SIGNED_RULE_BUNDLE_BYTES: u64 = 256 * 1024 * 1024;
const HEARTBEAT_INTERVAL_SECS: i64 = 30;
const COMPLIANCE_INTERVAL_SECS: i64 = 60;
const THREAT_INTEL_INTERVAL_SECS: i64 = 150;
const BASELINE_SAVE_INTERVAL_SECS: i64 = 300;
#[cfg(test)]
const SECONDS_PER_DAY: i64 = 86_400;
const EVENT_BATCH_SIZE: usize = 256;
const COMMAND_FETCH_LIMIT: usize = 10;
const COMMAND_FETCH_INTERVAL_SECS: i64 = 5;
const COMMAND_EXECUTION_BUDGET_PER_TICK: usize = 4;
const COMMAND_BACKLOG_CAPACITY: usize = 256;
const CONTROL_PLANE_TASK_EXECUTION_BUDGET_PER_TICK: usize = 6;
const CONTROL_PLANE_TASK_QUEUE_CAPACITY: usize = 64;
const CONTROL_PLANE_SEND_QUEUE_CAPACITY: usize = 128;
const CONTROL_PLANE_SEND_CONCURRENCY: usize = 4;
const RESPONSE_EXECUTION_BUDGET_PER_TICK: usize = 4;
const RESPONSE_QUEUE_CAPACITY: usize = 128;
const RESPONSE_REPORT_QUEUE_CAPACITY: usize = 256;
const RESPONSE_REPORT_CONCURRENCY: usize = 8;
const DEGRADE_AFTER_SEND_FAILURES: u32 = 3;

struct TickEvaluation {
    detection_event: TelemetryEvent,
    detection_outcome: DetectionOutcome,
    confidence: Confidence,
    action: PlannedAction,
    compliance: ComplianceResult,
    event_envelope: EventEnvelope,
}

#[derive(Debug, Clone)]
struct PendingCommand {
    envelope: CommandEnvelope,
    enqueued_at_unix: i64,
}

#[derive(Debug, Clone)]
enum ControlPlaneTaskKind {
    Heartbeat { compliance_status: String },
    Compliance { compliance: ComplianceResult },
    ThreatIntelRefresh,
    CommandSync,
}

#[derive(Debug, Clone)]
struct PendingControlPlaneTask {
    kind: ControlPlaneTaskKind,
    enqueued_at_unix: i64,
}

#[derive(Debug, Clone)]
struct PendingResponseAction {
    action: PlannedAction,
    confidence: Confidence,
    event: TelemetryEvent,
    enqueued_at_unix: i64,
}

#[derive(Debug, Clone)]
enum PendingControlPlaneSend {
    Heartbeat {
        agent_id: String,
        compliance_status: String,
        config_version: String,
    },
    Compliance {
        envelope: ComplianceEnvelope,
    },
}

#[derive(Debug, Clone)]
struct PendingResponseReport {
    envelope: ResponseEnvelope,
}

#[derive(Debug)]
enum AsyncWorkerResult {
    ControlPlaneSend {
        kind: &'static str,
        error: Option<String>,
    },
    ResponseReport {
        action_type: String,
        error: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReloadReport {
    old_version: String,
    new_version: String,
    sigma_rules: usize,
    yara_rules: usize,
    ioc_entries: usize,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RuntimeObservabilitySnapshot {
    pub tick_count: u64,
    pub runtime_mode: String,
    pub pending_event_count: usize,
    pub pending_event_bytes: usize,
    pub consecutive_send_failures: u32,
    pub recent_ebpf_drops: u64,
    pub ebpf_failed_probe_count: usize,
    pub ebpf_attach_degraded: bool,
    pub ebpf_btf_available: bool,
    pub ebpf_lsm_available: bool,
    pub ebpf_kernel_version: String,
    pub degraded_due_to_send_failures: u64,
    pub degraded_due_to_self_protection: u64,
    pub last_degraded_cause: Option<String>,
    pub last_tick_total_micros: u64,
    pub max_tick_total_micros: u64,
    pub last_evaluate_micros: u64,
    pub last_connected_tick_micros: u64,
    pub last_degraded_tick_micros: u64,
    pub last_send_event_batch_micros: u64,
    pub last_heartbeat_micros: u64,
    pub last_compliance_micros: u64,
    pub last_threat_intel_refresh_micros: u64,
    pub last_control_plane_sync_micros: u64,
    pub pending_control_plane_task_count: usize,
    pub last_control_plane_execute_count: usize,
    pub last_control_plane_queue_depth: usize,
    pub max_control_plane_queue_depth: usize,
    pub last_control_plane_oldest_age_secs: u64,
    pub max_control_plane_oldest_age_secs: u64,
    pub last_command_sync_micros: u64,
    pub pending_command_count: usize,
    pub last_command_fetch_count: usize,
    pub last_command_execute_count: usize,
    pub last_command_backlog_depth: usize,
    pub max_command_backlog_depth: usize,
    pub last_command_backlog_oldest_age_secs: u64,
    pub max_command_backlog_oldest_age_secs: u64,
    pub pending_response_count: usize,
    pub last_response_execute_count: usize,
    pub last_response_queue_depth: usize,
    pub max_response_queue_depth: usize,
    pub last_response_oldest_age_secs: u64,
    pub max_response_oldest_age_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DegradedCause {
    SendFailures,
    SelfProtection,
}

impl DegradedCause {
    #[cfg_attr(not(test), allow(dead_code))]
    fn label(self) -> &'static str {
        match self {
            Self::SendFailures => "send_failures",
            Self::SelfProtection => "self_protection",
        }
    }
}

#[derive(Debug, Clone, Default)]
struct RuntimeMetrics {
    degraded_due_to_send_failures: u64,
    degraded_due_to_self_protection: u64,
    last_degraded_cause: Option<DegradedCause>,
    last_tick_total_micros: u64,
    max_tick_total_micros: u64,
    last_evaluate_micros: u64,
    last_connected_tick_micros: u64,
    last_degraded_tick_micros: u64,
    last_send_event_batch_micros: u64,
    last_heartbeat_micros: u64,
    last_compliance_micros: u64,
    last_threat_intel_refresh_micros: u64,
    last_control_plane_sync_micros: u64,
    last_control_plane_execute_count: usize,
    last_control_plane_queue_depth: usize,
    max_control_plane_queue_depth: usize,
    last_control_plane_oldest_age_secs: u64,
    max_control_plane_oldest_age_secs: u64,
    last_command_sync_micros: u64,
    last_command_fetch_count: usize,
    last_command_execute_count: usize,
    last_command_backlog_depth: usize,
    max_command_backlog_depth: usize,
    last_command_backlog_oldest_age_secs: u64,
    max_command_backlog_oldest_age_secs: u64,
    last_response_execute_count: usize,
    last_response_queue_depth: usize,
    max_response_queue_depth: usize,
    last_response_oldest_age_secs: u64,
    max_response_oldest_age_secs: u64,
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
    last_command_fetch_attempt_unix: Option<i64>,
    last_threat_intel_refresh_unix: Option<i64>,
    last_baseline_save_unix: Option<i64>,
    last_recovery_probe_unix: Option<i64>,
    last_memory_scan_unix: Option<i64>,
    tamper_forced_degraded: bool,
    enrolled: bool,
    latest_threat_version: Option<String>,
    threat_intel_version_floor: Option<String>,
    latest_threat_published_at_unix: Option<i64>,
    latest_custom_rule_hash: Option<String>,
    last_reload_report: Option<ReloadReport>,
    metrics: RuntimeMetrics,
    host_control: HostControlState,
    auto_isolation_state: AutoIsolationState,
    pending_control_plane_tasks: VecDeque<PendingControlPlaneTask>,
    pending_control_plane_sends: VecDeque<PendingControlPlaneSend>,
    completed_command_ids: VecDeque<String>,
    pending_commands: VecDeque<PendingCommand>,
    pending_response_actions: VecDeque<PendingResponseAction>,
    pending_response_reports: VecDeque<PendingResponseReport>,
    control_plane_send_tasks: JoinSet<AsyncWorkerResult>,
    response_report_tasks: JoinSet<AsyncWorkerResult>,
}

impl AgentRuntime {
    pub fn new(config: AgentConfig) -> Result<Self> {
        let detection_shards = resolve_detection_shard_count();
        let bundle_path = config.detection_bundle_path.clone();
        let ransomware_policy = build_ransomware_policy(&config);
        let shard_builder = move || {
            let mut engine = detection_bootstrap::build_detection_engine_with_ransomware_policy(
                ransomware_policy.clone(),
            );
            if !bundle_path.is_empty() {
                load_bundle_full(&mut engine, &bundle_path);
            }
            engine
        };
        let detection_state = SharedDetectionState::new_with_shards(
            shard_builder(),
            None,
            detection_shards,
            shard_builder,
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
            TransportMode::parse(&config.transport_mode),
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
                pinned_ca_sha256: config.tls_pinned_ca_sha256.clone(),
                ca_pin_path: config.tls_ca_pin_path.clone(),
            }) {
                warn!(error = %err, "failed to configure TLS; continuing without TLS");
            }
        }

        client.enqueue_mock_command(CommandEnvelope {
            command_id: "bootstrap-isolate-check".to_string(),
            command_type: "scan".to_string(),
            payload_json: "{\"scope\":\"quick\"}".to_string(),
        });

        let hardening_config = LinuxHardeningConfig {
            drop_capability_bounding_set: config.self_protection_prevent_uninstall,
            ..LinuxHardeningConfig::default()
        };
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

        let mut runtime = Self {
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
            last_command_fetch_attempt_unix: None,
            last_threat_intel_refresh_unix: None,
            last_baseline_save_unix: None,
            last_recovery_probe_unix: None,
            last_memory_scan_unix: None,
            tamper_forced_degraded: false,
            enrolled: false,
            latest_threat_version: None,
            threat_intel_version_floor: None,
            latest_threat_published_at_unix: None,
            latest_custom_rule_hash: None,
            last_reload_report: None,
            metrics: RuntimeMetrics::default(),
            host_control: HostControlState::default(),
            auto_isolation_state: AutoIsolationState::default(),
            pending_control_plane_tasks: VecDeque::new(),
            pending_control_plane_sends: VecDeque::new(),
            completed_command_ids: VecDeque::new(),
            pending_commands: VecDeque::new(),
            pending_response_actions: VecDeque::new(),
            pending_response_reports: VecDeque::new(),
            control_plane_send_tasks: JoinSet::new(),
            response_report_tasks: JoinSet::new(),
        };
        runtime.bootstrap_threat_intel_replay_floor();
        runtime.bootstrap_last_known_good_bundle();
        Ok(runtime)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn observability_snapshot(&self) -> RuntimeObservabilitySnapshot {
        RuntimeObservabilitySnapshot {
            tick_count: self.tick_count,
            runtime_mode: runtime_mode_label(&self.runtime_mode).to_string(),
            pending_event_count: self.buffer.pending_count(),
            pending_event_bytes: self.buffer.pending_bytes(),
            consecutive_send_failures: self.consecutive_send_failures,
            recent_ebpf_drops: self.recent_ebpf_drops,
            ebpf_failed_probe_count: self.last_ebpf_stats.failed_probes.len(),
            ebpf_attach_degraded: !self.last_ebpf_stats.failed_probes.is_empty(),
            ebpf_btf_available: self.last_ebpf_stats.btf_available,
            ebpf_lsm_available: self.last_ebpf_stats.lsm_available,
            ebpf_kernel_version: self.last_ebpf_stats.kernel_version.clone(),
            degraded_due_to_send_failures: self.metrics.degraded_due_to_send_failures,
            degraded_due_to_self_protection: self.metrics.degraded_due_to_self_protection,
            last_degraded_cause: self
                .metrics
                .last_degraded_cause
                .map(|cause| cause.label().to_string()),
            last_tick_total_micros: self.metrics.last_tick_total_micros,
            max_tick_total_micros: self.metrics.max_tick_total_micros,
            last_evaluate_micros: self.metrics.last_evaluate_micros,
            last_connected_tick_micros: self.metrics.last_connected_tick_micros,
            last_degraded_tick_micros: self.metrics.last_degraded_tick_micros,
            last_send_event_batch_micros: self.metrics.last_send_event_batch_micros,
            last_heartbeat_micros: self.metrics.last_heartbeat_micros,
            last_compliance_micros: self.metrics.last_compliance_micros,
            last_threat_intel_refresh_micros: self.metrics.last_threat_intel_refresh_micros,
            last_control_plane_sync_micros: self.metrics.last_control_plane_sync_micros,
            pending_control_plane_task_count: self.pending_control_plane_tasks.len(),
            last_control_plane_execute_count: self.metrics.last_control_plane_execute_count,
            last_control_plane_queue_depth: self.metrics.last_control_plane_queue_depth,
            max_control_plane_queue_depth: self.metrics.max_control_plane_queue_depth,
            last_control_plane_oldest_age_secs: self.metrics.last_control_plane_oldest_age_secs,
            max_control_plane_oldest_age_secs: self.metrics.max_control_plane_oldest_age_secs,
            last_command_sync_micros: self.metrics.last_command_sync_micros,
            pending_command_count: self.pending_commands.len(),
            last_command_fetch_count: self.metrics.last_command_fetch_count,
            last_command_execute_count: self.metrics.last_command_execute_count,
            last_command_backlog_depth: self.metrics.last_command_backlog_depth,
            max_command_backlog_depth: self.metrics.max_command_backlog_depth,
            last_command_backlog_oldest_age_secs: self.metrics.last_command_backlog_oldest_age_secs,
            max_command_backlog_oldest_age_secs: self.metrics.max_command_backlog_oldest_age_secs,
            pending_response_count: self.pending_response_actions.len(),
            last_response_execute_count: self.metrics.last_response_execute_count,
            last_response_queue_depth: self.metrics.last_response_queue_depth,
            max_response_queue_depth: self.metrics.max_response_queue_depth,
            last_response_oldest_age_secs: self.metrics.last_response_oldest_age_secs,
            max_response_oldest_age_secs: self.metrics.max_response_oldest_age_secs,
        }
    }

    fn transition_to_degraded(&mut self, cause: DegradedCause) {
        let was_degraded = matches!(self.runtime_mode, AgentMode::Degraded);
        self.runtime_mode = AgentMode::Degraded;
        self.metrics.last_degraded_cause = Some(cause);
        if was_degraded {
            return;
        }

        match cause {
            DegradedCause::SendFailures => {
                self.metrics.degraded_due_to_send_failures =
                    self.metrics.degraded_due_to_send_failures.saturating_add(1);
            }
            DegradedCause::SelfProtection => {
                self.metrics.degraded_due_to_self_protection = self
                    .metrics
                    .degraded_due_to_self_protection
                    .saturating_add(1);
            }
        }
    }

    fn reset_tick_stage_metrics(&mut self) {
        self.metrics.last_connected_tick_micros = 0;
        self.metrics.last_degraded_tick_micros = 0;
        self.metrics.last_send_event_batch_micros = 0;
        self.metrics.last_heartbeat_micros = 0;
        self.metrics.last_compliance_micros = 0;
        self.metrics.last_threat_intel_refresh_micros = 0;
        self.metrics.last_control_plane_sync_micros = 0;
        self.metrics.last_control_plane_execute_count = 0;
        self.metrics.last_control_plane_queue_depth = self.pending_control_plane_tasks.len();
        self.metrics.last_control_plane_oldest_age_secs = 0;
        self.metrics.max_control_plane_queue_depth = self
            .metrics
            .max_control_plane_queue_depth
            .max(self.pending_control_plane_tasks.len());
        self.metrics.last_command_sync_micros = 0;
        self.metrics.last_command_fetch_count = 0;
        self.metrics.last_command_execute_count = 0;
        self.metrics.last_command_backlog_depth = self.pending_commands.len();
        self.metrics.last_command_backlog_oldest_age_secs = 0;
        self.metrics.max_command_backlog_depth = self
            .metrics
            .max_command_backlog_depth
            .max(self.pending_commands.len());
        self.metrics.last_response_execute_count = 0;
        self.metrics.last_response_queue_depth = self.pending_response_actions.len();
        self.metrics.last_response_oldest_age_secs = 0;
        self.metrics.max_response_queue_depth = self
            .metrics
            .max_response_queue_depth
            .max(self.pending_response_actions.len());
    }

    pub async fn tick(&mut self, now_unix: i64) -> Result<()> {
        let tick_started = Instant::now();
        self.reset_tick_stage_metrics();
        self.tick_count = self.tick_count.saturating_add(1);
        self.run_self_protection_if_due(now_unix).await?;

        let evaluate_started = Instant::now();
        let evaluation = self.evaluate_tick(now_unix)?;
        self.metrics.last_evaluate_micros = elapsed_micros(evaluate_started);
        if matches!(self.runtime_mode, AgentMode::Degraded) {
            self.handle_degraded_tick(now_unix, evaluation.as_ref())
                .await?;
        } else {
            self.handle_connected_tick(now_unix, evaluation.as_ref())
                .await?;
            if let Some(evaluation) = evaluation.as_ref() {
                self.log_detection_evaluation(evaluation);
            }
        }

        self.metrics.last_tick_total_micros = elapsed_micros(tick_started);
        self.metrics.max_tick_total_micros = self
            .metrics
            .max_tick_total_micros
            .max(self.metrics.last_tick_total_micros);
        let _ = self.protected.is_protected_process("systemd");
        Ok(())
    }

    fn evaluate_tick(&mut self, now_unix: i64) -> Result<Option<TickEvaluation>> {
        let Some(raw) = self.next_raw_event() else {
            return Ok(None);
        };

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

        let mut event_envelope = self.build_event_envelope(enriched.process_exe.as_deref(), now_unix);

        // Enrich envelope with detection results
        event_envelope.event_type = detection_event.event_class.as_str().to_string();
        event_envelope.severity = confidence_to_severity(confidence).to_string();
        if !detection_outcome.temporal_hits.is_empty() {
            event_envelope.rule_name = detection_outcome.temporal_hits[0].clone();
        } else if !detection_outcome.kill_chain_hits.is_empty() {
            event_envelope.rule_name = detection_outcome.kill_chain_hits[0].clone();
        } else if !detection_outcome.yara_hits.is_empty() {
            event_envelope.rule_name = detection_outcome.yara_hits[0].rule_name.clone();
        } else if !detection_outcome.layer1.matched_signatures.is_empty() {
            event_envelope.rule_name = format!("ioc_sig:{}", detection_outcome.layer1.matched_signatures[0]);
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
            severity: "critical".to_string(),
            rule_name: "agent_tamper".to_string(),
            payload_json: self.self_protect_alert_payload(report, now_unix),
            created_at_unix: now_unix,
        };

        if self.client.is_online() {
            if let Err(err) = self.client.send_events(std::slice::from_ref(&alert)).await {
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
        self.transition_to_degraded(DegradedCause::SelfProtection);
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
        evaluation: Option<&TickEvaluation>,
    ) -> Result<()> {
        let connected_started = Instant::now();
        self.client.set_online(true);
        self.ensure_enrolled().await;

        self.run_connected_telemetry_stage(evaluation).await?;
        self.run_connected_control_plane_stage(now_unix, evaluation)
            .await?;
        self.run_connected_response_stage(now_unix, evaluation)
            .await;
        self.run_memory_scan_if_due(now_unix);
        self.drive_async_workers();

        self.metrics.last_connected_tick_micros = elapsed_micros(connected_started);
        Ok(())
    }

    fn run_memory_scan_if_due(&mut self, now_unix: i64) {
        if !self.config.detection_memory_scan_enabled {
            return;
        }
        if !interval_due(
            self.last_memory_scan_unix,
            now_unix,
            self.config.detection_memory_scan_interval_secs as i64,
        ) {
            return;
        }
        self.last_memory_scan_unix = Some(now_unix);

        let mode = match self.config.detection_memory_scan_mode.as_str() {
            "all" => ScanMode::AllReadable,
            "exec+anon" => ScanMode::ExecutableAndAnonymous,
            _ => ScanMode::ExecutableOnly,
        };

        let mut pids = match find_suspicious_pids() {
            Ok(list) => list,
            Err(err) => {
                warn!(error = %err, "memory scan failed to enumerate pids");
                return;
            }
        };

        if pids.len() > self.config.detection_memory_scan_max_pids {
            pids.truncate(self.config.detection_memory_scan_max_pids);
        }

        let detections = self.scan_memory_pids(&pids, mode);
        for detection in detections {
            self.handle_memory_scan_detection(&detection, now_unix);
        }
    }

    fn scan_memory_pids(&self, pids: &[u32], mode: ScanMode) -> Vec<MemoryScanResult> {
        let mut results = Vec::new();
        for pid in pids {
            match self.detection_state.scan_process_memory(*pid, mode) {
                Ok(res) => {
                    if !res.hits.is_empty() {
                        results.push(res);
                    }
                }
                Err(err) => {
                    warn!(pid = *pid, error = %err, "memory scan failed on shard");
                }
            }
        }
        results
    }

    fn handle_memory_scan_detection(&mut self, detection: &MemoryScanResult, now_unix: i64) {
        let mut notes = Vec::new();
        notes.push(format!("memory_hits={}", detection.hits.len()));
        notes.push(format!("bytes_scanned={}", detection.bytes_scanned));
        if let Some(first) = detection.hits.first() {
            notes.push(format!("rule_name={}", first.rule_name));
            notes.push(format!("region_perms={}", first.region_perms));
        }
        if !detection.errors.is_empty() {
            notes.push(format!("scan_errors={}", detection.errors.len()));
        }

        let event = TelemetryEvent {
            ts_unix: now_unix,
            event_class: EventClass::Alert,
            pid: detection.pid,
            ppid: 0,
            uid: 0,
            process: "memory_scan".to_string(),
            parent_process: String::new(),
            session_id: detection.pid,
            file_path: None,
            file_write: false,
            file_hash: None,
            dst_port: None,
            dst_ip: None,
            dst_domain: None,
            command_line: Some(notes.join(";")),
            event_size: Some(detection.bytes_scanned as u64),
        };

        let detection_outcome = match self.detection_state.process_event(&event) {
            Ok(outcome) => outcome,
            Err(err) => {
                warn!(error = %err, "memory scan event processing failed");
                return;
            }
        };

        let confidence = detection_outcome.confidence.max(Confidence::VeryHigh);
        let response_cfg = self.effective_response_config();
        let action = plan_action(confidence, &response_cfg);
        let _ = self.report_local_action_if_needed(action, confidence, &event, now_unix);
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
        self.enqueue_response_report(response);
    }

    fn enqueue_control_plane_send(&mut self, send: PendingControlPlaneSend) {
        if self.pending_control_plane_sends.len() >= CONTROL_PLANE_SEND_QUEUE_CAPACITY {
            warn!(
                queue_depth = self.pending_control_plane_sends.len(),
                capacity = CONTROL_PLANE_SEND_QUEUE_CAPACITY,
                "control-plane send queue reached capacity; dropping oldest pending send"
            );
            self.pending_control_plane_sends.pop_front();
        }

        self.pending_control_plane_sends.push_back(send);
    }

    fn enqueue_response_report(&mut self, envelope: ResponseEnvelope) {
        if self.pending_response_reports.len() >= RESPONSE_REPORT_QUEUE_CAPACITY {
            warn!(
                queue_depth = self.pending_response_reports.len(),
                capacity = RESPONSE_REPORT_QUEUE_CAPACITY,
                "response report queue reached capacity; dropping oldest pending report"
            );
            self.pending_response_reports.pop_front();
        }

        self.pending_response_reports
            .push_back(PendingResponseReport { envelope });
    }

    fn drive_async_workers(&mut self) {
        self.collect_control_plane_send_results();
        self.collect_response_report_results();
        self.dispatch_control_plane_send_tasks();
        self.dispatch_response_report_tasks();
    }

    fn collect_control_plane_send_results(&mut self) {
        while let Some(joined) = self.control_plane_send_tasks.try_join_next() {
            match joined {
                Ok(AsyncWorkerResult::ControlPlaneSend { kind, error }) => {
                    if let Some(err) = error {
                        warn!(kind, error = %err, "control-plane async send failed");
                    }
                }
                Ok(AsyncWorkerResult::ResponseReport { .. }) => {}
                Err(err) => {
                    warn!(error = %err, "control-plane async worker task join failed");
                }
            }
        }
    }

    fn collect_response_report_results(&mut self) {
        while let Some(joined) = self.response_report_tasks.try_join_next() {
            match joined {
                Ok(AsyncWorkerResult::ResponseReport { action_type, error }) => {
                    if let Some(err) = error {
                        warn!(action_type = %action_type, error = %err, "response report async send failed");
                    }
                }
                Ok(AsyncWorkerResult::ControlPlaneSend { .. }) => {}
                Err(err) => {
                    warn!(error = %err, "response report async worker task join failed");
                }
            }
        }
    }

    fn dispatch_control_plane_send_tasks(&mut self) {
        while self.control_plane_send_tasks.len() < CONTROL_PLANE_SEND_CONCURRENCY {
            let Some(send) = self.pending_control_plane_sends.pop_front() else {
                break;
            };

            let client = self.client.clone();
            self.control_plane_send_tasks.spawn(async move {
                match send {
                    PendingControlPlaneSend::Heartbeat {
                        agent_id,
                        compliance_status,
                        config_version,
                    } => {
                        let error = client
                            .send_heartbeat_with_config(
                                &agent_id,
                                &compliance_status,
                                &config_version,
                            )
                            .await
                            .err()
                            .map(|err| err.to_string());
                        AsyncWorkerResult::ControlPlaneSend {
                            kind: "heartbeat",
                            error,
                        }
                    }
                    PendingControlPlaneSend::Compliance { envelope } => {
                        let error = client
                            .send_compliance(&envelope)
                            .await
                            .err()
                            .map(|err| err.to_string());
                        AsyncWorkerResult::ControlPlaneSend {
                            kind: "compliance",
                            error,
                        }
                    }
                }
            });
        }
    }

    fn dispatch_response_report_tasks(&mut self) {
        while self.response_report_tasks.len() < RESPONSE_REPORT_CONCURRENCY {
            let Some(report) = self.pending_response_reports.pop_front() else {
                break;
            };

            let client = self.client.clone();
            self.response_report_tasks.spawn(async move {
                let action_type = report.envelope.action_type.clone();
                let error = client
                    .send_response(&report.envelope)
                    .await
                    .err()
                    .map(|err| err.to_string());
                AsyncWorkerResult::ResponseReport { action_type, error }
            });
        }
    }

    fn build_event_envelope(&self, process_exe: Option<&str>, now_unix: i64) -> EventEnvelope {
        EventEnvelope {
            agent_id: self.config.agent_id.clone(),
            event_type: "process_exec".to_string(),
            severity: "info".to_string(),
            rule_name: String::new(),
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

#[cfg(test)]
fn update_tls_policy_from_server(config: &mut AgentConfig, policy: &PolicyEnvelope) -> bool {
    let Some(cert_policy) = policy.certificate_policy.as_ref() else {
        return false;
    };

    let mut changed = false;

    let pinned = cert_policy.pinned_ca_sha256.trim();
    if !pinned.is_empty() && config.tls_pinned_ca_sha256.as_deref() != Some(pinned) {
        config.tls_pinned_ca_sha256 = Some(pinned.to_string());
        changed = true;
    }

    if cert_policy.rotate_before_expiry_days > 0 {
        let days = cert_policy.rotate_before_expiry_days as u64;
        if config.tls_rotate_before_expiry_days != days {
            config.tls_rotate_before_expiry_days = days;
            changed = true;
        }
    }

    changed
}

#[cfg(test)]
fn days_until_certificate_expiry(cert_path: &str, now_unix: i64) -> Result<i64> {
    let cert_bytes =
        fs::read(cert_path).map_err(|err| anyhow!("read certificate '{}': {}", cert_path, err))?;
    let not_after_unix = parse_certificate_not_after_unix(&cert_bytes)?;
    Ok((not_after_unix - now_unix) / SECONDS_PER_DAY)
}

#[cfg(test)]
fn parse_certificate_not_after_unix(cert_bytes: &[u8]) -> Result<i64> {
    let der = if cert_bytes.starts_with(b"-----BEGIN") {
        let (_, pem) =
            parse_x509_pem(cert_bytes).map_err(|err| anyhow!("parse certificate PEM: {}", err))?;
        pem.contents
    } else {
        cert_bytes.to_vec()
    };

    let (_, cert) = parse_x509_certificate(&der)
        .map_err(|err| anyhow!("parse X509 certificate DER payload: {}", err))?;
    Ok(cert.validity().not_after.timestamp())
}

fn load_baseline_store() -> Result<BaselineStore> {
    let default_path = "/var/lib/eguard-agent/baselines.bin".to_string();
    let configured_path = std::env::var("EGUARD_BASELINE_PATH")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or(default_path);
    let path = PathBuf::from(configured_path);

    let skip_learning = std::env::var("EGUARD_BASELINE_SKIP_LEARNING")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    match BaselineStore::load_or_new(path.clone()) {
        Ok(mut store) => {
            seed_default_baselines_if_needed(&mut store, &path);
            if skip_learning && matches!(store.status, baseline::BaselineStatus::Learning) {
                store.status = baseline::BaselineStatus::Active;
                info!("baseline learning skipped via EGUARD_BASELINE_SKIP_LEARNING");
            }
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

#[cfg(test)]
fn apply_fleet_baseline_seeds(
    baseline_store: &mut BaselineStore,
    fleet_baselines: &[grpc_client::FleetBaselineEnvelope],
) -> usize {
    let mut seeded = 0usize;
    for baseline in fleet_baselines {
        let sample_hint = (baseline.agent_count.max(1) as u64).saturating_mul(100);
        if baseline_store.seed_from_fleet_baseline(
            &baseline.process_key,
            &baseline.median_distribution,
            sample_hint,
        ) {
            seeded = seeded.saturating_add(1);
        }
    }
    seeded
}

fn parse_event_class_name(raw: &str) -> Option<EventClass> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "process_exec" => Some(EventClass::ProcessExec),
        "process_exit" => Some(EventClass::ProcessExit),
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

#[cfg_attr(not(test), allow(dead_code))]
fn runtime_mode_label(mode: &AgentMode) -> &'static str {
    match mode {
        AgentMode::Learning => "learning",
        AgentMode::Active => "active",
        AgentMode::Degraded => "degraded",
    }
}

fn elapsed_micros(started: Instant) -> u64 {
    let micros = started.elapsed().as_micros();
    let bounded = micros.min(u64::MAX as u128) as u64;
    bounded.max(1)
}

fn init_ebpf_engine() -> EbpfEngine {
    ebpf_bootstrap::init_ebpf_engine()
}

#[cfg(test)]
fn default_ebpf_objects_dirs() -> Vec<PathBuf> {
    ebpf_bootstrap::default_ebpf_objects_dirs()
}

#[cfg(test)]
fn candidate_ebpf_object_paths(objects_dir: &Path) -> Vec<PathBuf> {
    ebpf_bootstrap::candidate_ebpf_object_paths(objects_dir)
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

fn confidence_to_severity(c: Confidence) -> &'static str {
    match c {
        Confidence::Definite => "critical",
        Confidence::VeryHigh => "high",
        Confidence::High => "high",
        Confidence::Medium => "medium",
        Confidence::Low => "low",
        Confidence::None => "info",
    }
}

fn to_detection_event(enriched: &platform_linux::EnrichedEvent, now_unix: i64) -> TelemetryEvent {
    let process = enriched
        .process_exe
        .as_deref()
        .and_then(|p| p.rsplit('/').next())
        .unwrap_or("unknown")
        .to_string();

    let session_id = enriched
        .parent_chain
        .last()
        .copied()
        .unwrap_or(enriched.event.pid);

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
        session_id,
        file_path: enriched
            .file_path
            .clone()
            .or_else(|| enriched.process_exe.clone()),
        file_write: enriched.file_write,
        file_hash: enriched
            .file_sha256
            .clone()
            .or_else(|| enriched.process_exe_sha256.clone()),
        dst_port: enriched.dst_port,
        dst_ip: enriched.dst_ip.clone(),
        dst_domain: enriched.dst_domain.clone(),
        command_line: enriched.process_cmdline.clone(),
        event_size: enriched.event_size,
    }
}

fn map_event_class(event_type: &platform_linux::EventType) -> EventClass {
    match event_type {
        platform_linux::EventType::ProcessExec => EventClass::ProcessExec,
        platform_linux::EventType::ProcessExit => EventClass::ProcessExit,
        platform_linux::EventType::FileOpen => EventClass::FileOpen,
        platform_linux::EventType::FileWrite => EventClass::FileOpen,
        platform_linux::EventType::FileRename => EventClass::FileOpen,
        platform_linux::EventType::FileUnlink => EventClass::FileOpen,
        platform_linux::EventType::TcpConnect => EventClass::NetworkConnect,
        platform_linux::EventType::DnsQuery => EventClass::DnsQuery,
        platform_linux::EventType::ModuleLoad => EventClass::ModuleLoad,
        platform_linux::EventType::LsmBlock => EventClass::Alert,
    }
}

#[cfg(test)]
fn load_bundle_rules(detection: &mut DetectionEngine, bundle_path: &str) -> (usize, usize) {
    rule_bundle_loader::load_bundle_rules(detection, bundle_path)
}

fn load_bundle_full(
    detection: &mut DetectionEngine,
    bundle_path: &str,
) -> rule_bundle_loader::BundleLoadSummary {
    rule_bundle_loader::load_bundle_full(detection, bundle_path)
}

fn is_signed_bundle_archive(path: &Path) -> bool {
    rule_bundle_loader::is_signed_bundle_archive(path)
}

#[cfg(test)]
fn sanitize_archive_relative_path(path: &Path) -> Option<PathBuf> {
    rule_bundle_loader::sanitize_archive_relative_path(path)
}

fn verify_bundle_signature(bundle_path: &Path) -> bool {
    rule_bundle_verify::verify_bundle_signature(bundle_path)
}

#[cfg(test)]
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

fn build_ransomware_policy(config: &AgentConfig) -> RansomwarePolicy {
    let mut policy = RansomwarePolicy::default();
    policy.write_threshold = config.detection_ransomware_write_threshold;
    policy.write_window_secs = config.detection_ransomware_write_window_secs as i64;
    policy.adaptive_delta = config.detection_ransomware_adaptive_delta;
    policy.adaptive_min_samples = config.detection_ransomware_adaptive_min_samples;
    policy.adaptive_floor = config.detection_ransomware_adaptive_floor;
    policy.learned_root_min_hits = config.detection_ransomware_learned_root_min_hits;
    policy.learned_root_max = config.detection_ransomware_learned_root_max;
    if !config.detection_ransomware_user_path_prefixes.is_empty() {
        policy.user_path_prefixes = config.detection_ransomware_user_path_prefixes.clone();
    }
    if !config.detection_ransomware_system_path_prefixes.is_empty() {
        policy.system_path_prefixes = config.detection_ransomware_system_path_prefixes.clone();
    }
    if !config.detection_ransomware_temp_path_tokens.is_empty() {
        policy.temp_path_tokens = config.detection_ransomware_temp_path_tokens.clone();
    }
    policy.sanitized()
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests;

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests_ebpf_policy;

#[cfg(test)]
mod tests_baseline_seed_policy;

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests_det_stub_completion;
#[cfg(test)]
mod tests_ebpf_memory;
#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests_observability;
#[cfg(test)]
mod tests_pkg_contract;
#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests_resource_policy;
#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests_self_protect_hardening;
#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests_self_protect_policy;
