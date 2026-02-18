use std::collections::{HashMap, VecDeque};

use anyhow::Result;
use tracing::{info, warn};

use baseline::BaselineStore;
use compliance::{CompliancePolicy, ComplianceResult, RemediationOutcome};
use grpc_client::{Client as GrpcClient, CommandEnvelope, EventBuffer, TlsConfig, TransportMode};
use platform_linux::{EbpfEngine, EbpfStats, EnrichmentCache};
use response::{AutoIsolationState, HostControlState, KillRateLimiter, ProtectedList};
use self_protect::{apply_linux_hardening, LinuxHardeningConfig, SelfProtectEngine};
use tokio::task::JoinSet;

use crate::config::{AgentConfig, AgentMode};
use crate::detection_state::SharedDetectionState;

use super::{
    build_ransomware_policy, derive_runtime_mode, init_ebpf_engine, load_baseline_store,
    load_bundle_full, load_compliance_policy, resolve_detection_shard_count, runtime_mode_label,
    seed_anomaly_baselines, AsyncWorkerResult, DegradedCause, PendingCommand,
    PendingControlPlaneSend, PendingControlPlaneTask, PendingResponseAction, PendingResponseReport,
    ReloadReport, RuntimeMetrics, RuntimeObservabilitySnapshot,
};

pub struct AgentRuntime {
    pub(super) config: AgentConfig,
    pub(super) buffer: EventBuffer,
    pub(super) detection_state: SharedDetectionState,
    pub(super) protected: ProtectedList,
    pub(super) limiter: KillRateLimiter,
    pub(super) compliance_policy: CompliancePolicy,
    pub(super) compliance_policy_id: String,
    pub(super) compliance_policy_version: String,
    pub(super) compliance_policy_hash: String,
    pub(super) compliance_policy_schema_version: String,
    pub(super) compliance_policy_signature: String,
    pub(super) compliance_grace_state: HashMap<String, i64>,
    pub(super) baseline_store: BaselineStore,
    pub(super) ebpf_engine: EbpfEngine,
    pub(super) enrichment_cache: EnrichmentCache,
    pub(super) client: GrpcClient,
    pub(super) self_protect_engine: SelfProtectEngine,
    pub(super) tick_count: u64,
    pub(super) runtime_mode: AgentMode,
    pub(super) last_ebpf_stats: EbpfStats,
    pub(super) recent_ebpf_drops: u64,
    pub(super) consecutive_send_failures: u32,
    pub(super) last_self_protect_check_unix: Option<i64>,
    pub(super) last_heartbeat_attempt_unix: Option<i64>,
    pub(super) last_compliance_attempt_unix: Option<i64>,
    pub(super) last_compliance_checked_unix: Option<i64>,
    pub(super) last_compliance_result: Option<ComplianceResult>,
    pub(super) last_compliance_remediations: HashMap<String, RemediationOutcome>,
    pub(super) compliance_alert_state: HashMap<String, i64>,
    pub(super) last_policy_fetch_unix: Option<i64>,
    pub(super) last_inventory_attempt_unix: Option<i64>,
    pub(super) last_inventory_sent_unix: Option<i64>,
    pub(super) last_inventory_hash: Option<String>,
    pub(super) last_command_fetch_attempt_unix: Option<i64>,
    pub(super) last_threat_intel_refresh_unix: Option<i64>,
    pub(super) last_baseline_save_unix: Option<i64>,
    pub(super) last_recovery_probe_unix: Option<i64>,
    pub(super) last_memory_scan_unix: Option<i64>,
    pub(super) last_kernel_integrity_scan_unix: Option<i64>,
    pub(super) tamper_forced_degraded: bool,
    pub(super) enrolled: bool,
    pub(super) latest_threat_version: Option<String>,
    pub(super) threat_intel_version_floor: Option<String>,
    pub(super) latest_threat_published_at_unix: Option<i64>,
    pub(super) latest_custom_rule_hash: Option<String>,
    pub(super) last_reload_report: Option<ReloadReport>,
    pub(super) metrics: RuntimeMetrics,
    pub(super) host_control: HostControlState,
    pub(super) auto_isolation_state: AutoIsolationState,
    pub(super) pending_control_plane_tasks: VecDeque<PendingControlPlaneTask>,
    pub(super) pending_control_plane_sends: VecDeque<PendingControlPlaneSend>,
    pub(super) completed_command_ids: VecDeque<String>,
    pub(super) pending_commands: VecDeque<PendingCommand>,
    pub(super) pending_response_actions: VecDeque<PendingResponseAction>,
    pub(super) pending_response_reports: VecDeque<PendingResponseReport>,
    pub(super) control_plane_send_tasks: JoinSet<AsyncWorkerResult>,
    pub(super) response_report_tasks: JoinSet<AsyncWorkerResult>,
}

impl AgentRuntime {
    pub fn new(config: AgentConfig) -> Result<Self> {
        let detection_shards = resolve_detection_shard_count();
        let bundle_path = config.detection_bundle_path.clone();
        let ransomware_policy = build_ransomware_policy(&config);
        let shard_builder = move || {
            let mut engine = super::detection_bootstrap::build_detection_engine_with_ransomware_policy(
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
        let compliance_policy_id = compliance_policy
            .policy_id
            .clone()
            .filter(|val| !val.trim().is_empty())
            .or_else(|| {
                std::env::var("EGUARD_POLICY_ID")
                    .ok()
                    .filter(|val| !val.trim().is_empty())
            })
            .unwrap_or_else(|| "default".to_string());
        let compliance_policy_version = compliance_policy
            .version
            .clone()
            .unwrap_or_default();
        let compliance_policy_hash = compliance_policy
            .policy_hash
            .clone()
            .unwrap_or_default();
        let compliance_policy_schema_version = compliance_policy
            .schema_version
            .clone()
            .unwrap_or_default();
        let compliance_policy_signature = compliance_policy
            .policy_signature
            .clone()
            .unwrap_or_default();
        let compliance_grace_state = HashMap::new();
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

        if std::env::var("EGUARD_ENABLE_BOOTSTRAP_TEST_COMMAND")
            .ok()
            .as_deref()
            == Some("1")
        {
            client.enqueue_mock_command(CommandEnvelope {
                command_id: "bootstrap-isolate-check".to_string(),
                command_type: "scan".to_string(),
                payload_json: "{\"scope\":\"quick\"}".to_string(),
            });
        }

        let mut hardening_config = LinuxHardeningConfig {
            drop_capability_bounding_set: config.self_protection_prevent_uninstall,
            ..LinuxHardeningConfig::default()
        };
        if config.detection_memory_scan_enabled
            && !hardening_config
                .retained_capability_names
                .iter()
                .any(|cap| cap == "CAP_SYS_PTRACE")
        {
            hardening_config
                .retained_capability_names
                .push("CAP_SYS_PTRACE".to_string());
        }
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
            compliance_policy_id,
            compliance_policy_version,
            compliance_policy_hash,
            compliance_policy_schema_version,
            compliance_policy_signature,
            compliance_grace_state,
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
            last_compliance_checked_unix: None,
            last_compliance_result: None,
            last_compliance_remediations: HashMap::new(),
            compliance_alert_state: HashMap::new(),
            last_policy_fetch_unix: None,
            last_inventory_attempt_unix: None,
            last_inventory_sent_unix: None,
            last_inventory_hash: None,
            last_command_fetch_attempt_unix: None,
            last_threat_intel_refresh_unix: None,
            last_baseline_save_unix: None,
            last_recovery_probe_unix: None,
            last_memory_scan_unix: None,
            last_kernel_integrity_scan_unix: None,
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

    pub(super) fn transition_to_degraded(&mut self, cause: DegradedCause) {
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

    pub(super) fn reset_tick_stage_metrics(&mut self) {
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

    pub(super) fn heartbeat_config_version(&self) -> String {
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
