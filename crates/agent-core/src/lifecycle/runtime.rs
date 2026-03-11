use std::collections::{BTreeSet, HashMap, VecDeque};

use anyhow::Result;
use tracing::{info, warn};

use crate::platform::{EbpfEngine, EbpfStats, EnrichmentCache, RawEvent};
use baseline::BaselineStore;
use compliance::{CompliancePolicy, ComplianceResult, RemediationOutcome};
use grpc_client::{
    Client as GrpcClient, CommandEnvelope, EventBuffer, IocSignal, TlsConfig, TransportMode,
};
use response::{AutoIsolationState, HostControlState, KillRateLimiter, ProtectedList};

use super::feature_policy::{
    DeceptionPolicyConfig, FimPolicyConfig, HuntingPolicyConfig, UsbPolicyConfig,
    ZeroTrustPolicyConfig,
};
use super::response_playbook::PlaybookEngine;
use self_protect::SelfProtectEngine;
#[cfg(target_os = "linux")]
use self_protect::{apply_linux_hardening, LinuxHardeningConfig};
use tokio::task::JoinSet;

use crate::config::{AgentConfig, AgentMode};
use crate::detection_state::SharedDetectionState;

use super::{
    build_ransomware_policy, derive_runtime_mode, host_is_low_memory, init_ebpf_engine,
    linux_host_mem_total_bytes, load_baseline_store, load_bundle_full, load_compliance_policy,
    resolve_detection_shard_count, runtime_mode_label, seed_anomaly_baselines, AsyncWorkerResult,
    DegradedCause, PendingCommand, PendingControlPlaneSend, PendingControlPlaneTask,
    PendingResponseAction, PendingResponseReport, ReloadReport, RuntimeMetrics,
    RuntimeObservabilitySnapshot,
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
    pub(super) raw_event_backlog: VecDeque<RawEvent>,
    pub(super) raw_event_backlog_cap: usize,
    pub(super) raw_event_ingest_cap: usize,
    pub(super) recent_file_event_keys: HashMap<String, u64>,
    pub(super) file_event_coalesce_window_ns: u64,
    pub(super) event_txn_coalesce_window_ns: u64,
    pub(super) recent_event_txn_keys: HashMap<String, u64>,
    pub(super) suppressed_internal_process_pids: HashMap<u32, u64>,
    pub(super) file_event_coalesce_key_limit: usize,
    pub(super) event_txn_coalesce_key_limit: usize,
    pub(super) strict_budget_mode: bool,
    pub(super) strict_budget_pending_threshold: usize,
    pub(super) strict_budget_raw_backlog_threshold: usize,
    pub(super) expensive_check_excluded_paths: Vec<String>,
    pub(super) expensive_check_excluded_processes: Vec<String>,
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
    pub(super) last_command_fetch_attempt_unix: Option<i64>,
    pub(super) last_threat_intel_refresh_unix: Option<i64>,
    pub(super) last_baseline_save_unix: Option<i64>,
    pub(super) last_baseline_upload_unix: Option<i64>,
    pub(super) last_fleet_baseline_fetch_unix: Option<i64>,
    pub(super) baseline_upload_enabled: bool,
    pub(super) fim_policy: FimPolicyConfig,
    pub(super) usb_policy: UsbPolicyConfig,
    pub(super) deception_policy: DeceptionPolicyConfig,
    pub(super) hunting_policy: HuntingPolicyConfig,
    pub(super) zero_trust_policy: ZeroTrustPolicyConfig,
    pub(super) fleet_seed_enabled: bool,
    pub(super) baseline_upload_canary_percent: u8,
    pub(super) fleet_seed_canary_percent: u8,
    pub(super) last_recovery_probe_unix: Option<i64>,
    pub(super) last_memory_scan_unix: Option<i64>,
    pub(super) last_kernel_integrity_scan_unix: Option<i64>,
    pub(super) tamper_forced_degraded: bool,
    pub(super) last_logged_posture: Option<nac::Posture>,
    pub(super) enrolled: bool,
    pub(super) last_enrollment_attempt_unix: Option<i64>,
    pub(super) enrollment_backoff_secs: i64,
    pub(super) latest_threat_version: Option<String>,
    pub(super) threat_intel_version_floor: Option<String>,
    pub(super) latest_threat_published_at_unix: Option<i64>,
    pub(super) latest_custom_rule_hash: Option<String>,
    pub(super) last_reload_report: Option<ReloadReport>,
    pub(super) metrics: RuntimeMetrics,
    pub(super) host_control: HostControlState,
    pub(super) auto_isolation_state: AutoIsolationState,
    pub(super) ioc_signal_buffer: Vec<IocSignal>,
    pub(super) last_ioc_signal_upload_unix: Option<i64>,
    pub(super) last_campaign_fetch_unix: Option<i64>,
    pub(super) active_campaign_iocs: std::collections::HashSet<String>,
    pub(super) playbook_engine: PlaybookEngine,
    pub(super) dirty_baseline_keys: BTreeSet<String>,
    pub(super) pending_control_plane_tasks: VecDeque<PendingControlPlaneTask>,
    pub(super) pending_control_plane_sends: VecDeque<PendingControlPlaneSend>,
    pub(super) completed_command_ids: VecDeque<String>,
    pub(super) pending_commands: VecDeque<PendingCommand>,
    pub(super) pending_response_actions: VecDeque<PendingResponseAction>,
    pub(super) response_action_dedupe_window_secs: i64,
    pub(super) response_action_dedupe_key_limit: usize,
    pub(super) recent_response_action_keys: HashMap<String, i64>,
    pub(super) pending_response_reports: VecDeque<PendingResponseReport>,
    pub(super) control_plane_send_tasks: JoinSet<AsyncWorkerResult>,
    pub(super) response_report_tasks: JoinSet<AsyncWorkerResult>,
}

impl AgentRuntime {
    pub fn new(config: AgentConfig) -> Result<Self> {
        if let Some(bundle_public_key) = config
            .detection_bundle_public_key
            .as_deref()
            .map(str::trim)
            .filter(|key| key.len() == 64)
        {
            #[allow(unused_unsafe)]
            unsafe {
                std::env::set_var("EGUARD_RULE_BUNDLE_PUBKEY", bundle_public_key);
            }
        }

        let host_mem_total_bytes = linux_host_mem_total_bytes();
        let low_memory_host = host_is_low_memory(host_mem_total_bytes);
        let detection_shards = resolve_detection_shard_count();
        let bundle_path = config.detection_bundle_path.clone();
        let ransomware_policy = build_ransomware_policy(&config);
        let detection_sources =
            super::detection_bootstrap::DetectionSourcePaths::from_config(&config);
        let shard_builder = move || {
            let mut engine =
                super::detection_bootstrap::build_detection_engine_with_ransomware_policy(
                    ransomware_policy.clone(),
                    &detection_sources,
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
        let mut baseline_store = load_baseline_store()?;
        baseline_store.configure_windows(
            config.baseline_learning_period_days,
            config.baseline_stale_after_days,
        );
        let max_baseline_profiles = std::env::var("EGUARD_BASELINE_MAX_PROFILES")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .unwrap_or(4096);
        baseline_store.configure_limits(max_baseline_profiles);

        let baseline_upload_enabled = parse_runtime_flag("EGUARD_BASELINE_UPLOAD_ENABLED", true);
        let fleet_seed_enabled = parse_runtime_flag("EGUARD_FLEET_SEED_ENABLED", true);
        let baseline_upload_canary_percent =
            parse_percentage_env("EGUARD_BASELINE_UPLOAD_CANARY_PERCENT", 100);
        let fleet_seed_canary_percent =
            parse_percentage_env("EGUARD_FLEET_SEED_CANARY_PERCENT", 100);

        let dirty_baseline_keys = baseline_store
            .baselines
            .keys()
            .map(|key| format!("{}:{}", key.comm, key.parent_comm))
            .collect::<BTreeSet<_>>();
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
        let compliance_policy_version = compliance_policy.version.clone().unwrap_or_default();
        let compliance_policy_hash = compliance_policy.policy_hash.clone().unwrap_or_default();
        let compliance_policy_schema_version =
            compliance_policy.schema_version.clone().unwrap_or_default();
        let compliance_policy_signature = compliance_policy
            .policy_signature
            .clone()
            .unwrap_or_default();
        let compliance_grace_state = HashMap::new();
        let ebpf_engine = init_ebpf_engine();
        let mut enrichment_cache = build_enrichment_cache(low_memory_host);

        let file_event_coalesce_window_ms = std::env::var("EGUARD_FILE_EVENT_COALESCE_WINDOW_MS")
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .unwrap_or(1_200);
        let event_txn_coalesce_window_ms = std::env::var("EGUARD_EVENT_TXN_COALESCE_WINDOW_MS")
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let mut file_event_coalesce_key_limit =
            std::env::var("EGUARD_FILE_EVENT_COALESCE_KEY_LIMIT")
                .ok()
                .and_then(|raw| raw.trim().parse::<usize>().ok())
                .unwrap_or(16_384)
                .max(512);
        let mut event_txn_coalesce_key_limit = std::env::var("EGUARD_EVENT_TXN_COALESCE_KEY_LIMIT")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .unwrap_or(16_384)
            .max(512);
        let mut strict_budget_pending_threshold =
            std::env::var("EGUARD_STRICT_BUDGET_PENDING_THRESHOLD")
                .ok()
                .and_then(|raw| raw.trim().parse::<usize>().ok())
                .unwrap_or(512)
                .max(64);
        let mut strict_budget_raw_backlog_threshold =
            std::env::var("EGUARD_STRICT_BUDGET_RAW_BACKLOG_THRESHOLD")
                .ok()
                .and_then(|raw| raw.trim().parse::<usize>().ok())
                .unwrap_or(128)
                .max(32);
        let mut raw_event_backlog_cap = std::env::var("EGUARD_RAW_EVENT_BACKLOG_CAP")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .unwrap_or(4_096)
            .max(256);
        let mut raw_event_ingest_cap = std::env::var("EGUARD_RAW_EVENT_INGEST_CAP")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .unwrap_or(1_024)
            .clamp(128, raw_event_backlog_cap);
        apply_low_memory_runtime_budget(
            low_memory_host,
            &mut file_event_coalesce_key_limit,
            &mut event_txn_coalesce_key_limit,
            &mut strict_budget_pending_threshold,
            &mut strict_budget_raw_backlog_threshold,
            &mut raw_event_backlog_cap,
            &mut raw_event_ingest_cap,
        );
        let response_action_dedupe_window_secs =
            std::env::var("EGUARD_RESPONSE_ACTION_DEDUPE_WINDOW_SECS")
                .ok()
                .and_then(|raw| raw.trim().parse::<i64>().ok())
                .unwrap_or(30)
                .max(0);
        let response_action_dedupe_key_limit =
            std::env::var("EGUARD_RESPONSE_ACTION_DEDUPE_KEY_LIMIT")
                .ok()
                .and_then(|raw| raw.trim().parse::<usize>().ok())
                .unwrap_or(32_768)
                .max(1_024);
        let expensive_check_excluded_paths = parse_csv_env("EGUARD_EXPENSIVE_CHECK_EXCLUDED_PATHS");
        let expensive_check_excluded_processes =
            parse_csv_env("EGUARD_EXPENSIVE_CHECK_EXCLUDED_PROCESSES");
        let hash_finalize_delay_ms = std::env::var("EGUARD_FILE_HASH_FINALIZE_DELAY_MS")
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .unwrap_or(1_200);
        if low_memory_host {
            info!(
                mem_total_bytes = host_mem_total_bytes.unwrap_or_default(),
                detection_shards,
                raw_event_backlog_cap,
                raw_event_ingest_cap,
                strict_budget_pending_threshold,
                strict_budget_raw_backlog_threshold,
                file_event_coalesce_key_limit,
                event_txn_coalesce_key_limit,
                "applying low-memory runtime budget profile"
            );
        }
        enrichment_cache.set_hash_finalize_delay_ms(hash_finalize_delay_ms);
        enrichment_cache.set_expensive_check_exclusions(
            expensive_check_excluded_paths.clone(),
            expensive_check_excluded_processes.clone(),
        );

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

        if cfg!(debug_assertions)
            && std::env::var("EGUARD_ENABLE_BOOTSTRAP_TEST_COMMAND")
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

        #[cfg(target_os = "linux")]
        {
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
        }

        #[cfg(target_os = "macos")]
        {
            use self_protect::{apply_macos_hardening, MacosHardeningConfig};
            let mac_config = MacosHardeningConfig {
                deny_attach: true,
                verify_code_signature: false, // requires signing identity
                set_dumpable_zero: true,
            };
            let report = apply_macos_hardening(&mac_config);
            if report.has_failures() {
                warn!(
                    failed_steps = ?report.failed_step_names(),
                    "macOS hardening applied with failures"
                );
            } else {
                info!("macOS hardening applied");
            }
        }

        let initial_mode = derive_runtime_mode(&config.mode, baseline_store.status);

        let mut playbook_engine = PlaybookEngine::new();
        playbook_engine.load_default_playbooks();

        let mut runtime = Self {
            limiter: KillRateLimiter::new(config.response.max_kills_per_minute),
            protected: {
                #[cfg(target_os = "linux")]
                {
                    ProtectedList::default_linux()
                }
                #[cfg(target_os = "macos")]
                {
                    ProtectedList::default_macos()
                }
                #[cfg(target_os = "windows")]
                {
                    ProtectedList::default_windows()
                }
            },
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
            enrolled: config.enrollment_token.is_none() && config.bootstrap_config_path.is_none(),
            last_enrollment_attempt_unix: None,
            enrollment_backoff_secs: 5,
            config,
            tick_count: 0,
            runtime_mode: initial_mode,
            last_ebpf_stats: EbpfStats::default(),
            recent_ebpf_drops: 0,
            raw_event_backlog: VecDeque::new(),
            raw_event_backlog_cap,
            raw_event_ingest_cap,
            recent_file_event_keys: HashMap::new(),
            file_event_coalesce_window_ns: file_event_coalesce_window_ms.saturating_mul(1_000_000),
            event_txn_coalesce_window_ns: event_txn_coalesce_window_ms.saturating_mul(1_000_000),
            recent_event_txn_keys: HashMap::new(),
            suppressed_internal_process_pids: HashMap::new(),
            file_event_coalesce_key_limit,
            event_txn_coalesce_key_limit,
            strict_budget_mode: false,
            strict_budget_pending_threshold,
            strict_budget_raw_backlog_threshold,
            expensive_check_excluded_paths,
            expensive_check_excluded_processes,
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
            last_command_fetch_attempt_unix: None,
            last_threat_intel_refresh_unix: None,
            last_baseline_save_unix: None,
            last_baseline_upload_unix: None,
            last_fleet_baseline_fetch_unix: None,
            baseline_upload_enabled,
            fim_policy: FimPolicyConfig::default(),
            usb_policy: UsbPolicyConfig::default(),
            deception_policy: DeceptionPolicyConfig::default(),
            hunting_policy: HuntingPolicyConfig::default(),
            zero_trust_policy: ZeroTrustPolicyConfig::default(),
            fleet_seed_enabled,
            baseline_upload_canary_percent,
            fleet_seed_canary_percent,
            last_recovery_probe_unix: None,
            last_memory_scan_unix: None,
            last_kernel_integrity_scan_unix: None,
            tamper_forced_degraded: false,
            last_logged_posture: None,
            latest_threat_version: None,
            threat_intel_version_floor: None,
            latest_threat_published_at_unix: None,
            latest_custom_rule_hash: None,
            last_reload_report: None,
            metrics: RuntimeMetrics::default(),
            host_control: HostControlState::default(),
            auto_isolation_state: AutoIsolationState::default(),
            ioc_signal_buffer: Vec::new(),
            last_ioc_signal_upload_unix: None,
            last_campaign_fetch_unix: None,
            active_campaign_iocs: std::collections::HashSet::new(),
            playbook_engine,
            dirty_baseline_keys,
            pending_control_plane_tasks: VecDeque::new(),
            pending_control_plane_sends: VecDeque::new(),
            completed_command_ids: VecDeque::new(),
            pending_commands: VecDeque::new(),
            pending_response_actions: VecDeque::new(),
            response_action_dedupe_window_secs,
            response_action_dedupe_key_limit,
            recent_response_action_keys: HashMap::new(),
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
            strict_budget_mode: self.strict_budget_mode,
            raw_event_backlog_depth: self.raw_event_backlog.len(),
            raw_event_backlog_cap: self.raw_event_backlog_cap,
            event_txn_coalesce_key_count: self.recent_event_txn_keys.len(),
            response_action_dedupe_key_count: self.recent_response_action_keys.len(),
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
            last_inventory_micros: self.metrics.last_inventory_micros,
            last_threat_intel_refresh_micros: self.metrics.last_threat_intel_refresh_micros,
            last_control_plane_sync_micros: self.metrics.last_control_plane_sync_micros,
            pending_control_plane_task_count: self.pending_control_plane_tasks.len(),
            pending_control_plane_send_count: self.pending_control_plane_sends.len(),
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
            pending_response_report_count: self.pending_response_reports.len(),
            last_response_execute_count: self.metrics.last_response_execute_count,
            last_response_queue_depth: self.metrics.last_response_queue_depth,
            max_response_queue_depth: self.metrics.max_response_queue_depth,
            last_response_oldest_age_secs: self.metrics.last_response_oldest_age_secs,
            max_response_oldest_age_secs: self.metrics.max_response_oldest_age_secs,
            baseline_rows_uploaded_total: self.metrics.baseline_rows_uploaded_total,
            baseline_seed_rows_applied_total: self.metrics.baseline_seed_rows_applied_total,
            baseline_upload_payload_reject_total: self.metrics.baseline_upload_payload_reject_total,
            baseline_stale_transition_total: self.metrics.baseline_stale_transition_total,
            telemetry_coalesced_events_total: self.metrics.telemetry_coalesced_events_total,
            telemetry_raw_backlog_dropped_total: self.metrics.telemetry_raw_backlog_dropped_total,
            telemetry_event_txn_total: self.metrics.telemetry_event_txn_total,
            telemetry_event_txn_coalesced_total: self.metrics.telemetry_event_txn_coalesced_total,
            response_action_deduped_total: self.metrics.response_action_deduped_total,
            strict_budget_mode_transition_total: self.metrics.strict_budget_mode_transition_total,
            control_plane_task_replaced_total: self.metrics.control_plane_task_replaced_total,
            control_plane_send_replaced_total: self.metrics.control_plane_send_replaced_total,
            control_plane_task_dropped_total: self.metrics.control_plane_task_dropped_total,
            control_plane_send_dropped_total: self.metrics.control_plane_send_dropped_total,
            response_report_dropped_total: self.metrics.response_report_dropped_total,
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
        self.metrics.last_inventory_micros = 0;
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

fn parse_runtime_flag(name: &str, default_value: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|raw| {
            let raw = raw.trim();
            raw.eq_ignore_ascii_case("1")
                || raw.eq_ignore_ascii_case("true")
                || raw.eq_ignore_ascii_case("yes")
                || raw.eq_ignore_ascii_case("on")
        })
        .unwrap_or(default_value)
}

fn parse_percentage_env(name: &str, default_value: u8) -> u8 {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.trim().parse::<u16>().ok())
        .map(|value| value.min(100) as u8)
        .unwrap_or(default_value.min(100))
}

fn parse_csv_env(name: &str) -> Vec<String> {
    std::env::var(name)
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

const LOW_MEMORY_ENRICHMENT_PROCESS_CACHE_ENTRIES: usize = 256;
const LOW_MEMORY_ENRICHMENT_FILE_HASH_ENTRIES: usize = 2_048;
const LOW_MEMORY_FILE_EVENT_COALESCE_KEY_LIMIT: usize = 4_096;
const LOW_MEMORY_EVENT_TXN_COALESCE_KEY_LIMIT: usize = 4_096;
const LOW_MEMORY_STRICT_BUDGET_PENDING_THRESHOLD: usize = 256;
const LOW_MEMORY_STRICT_BUDGET_RAW_BACKLOG_THRESHOLD: usize = 64;
const LOW_MEMORY_RAW_EVENT_BACKLOG_CAP: usize = 1_024;
const LOW_MEMORY_RAW_EVENT_INGEST_CAP: usize = 256;

fn enrichment_cache_limits(low_memory_host: bool) -> (usize, usize) {
    if low_memory_host {
        (
            LOW_MEMORY_ENRICHMENT_PROCESS_CACHE_ENTRIES,
            LOW_MEMORY_ENRICHMENT_FILE_HASH_ENTRIES,
        )
    } else {
        (500, 10_000)
    }
}

fn build_enrichment_cache(low_memory_host: bool) -> EnrichmentCache {
    let (process_entries, file_hash_entries) = enrichment_cache_limits(low_memory_host);
    EnrichmentCache::new(process_entries, file_hash_entries)
}

fn apply_low_memory_runtime_budget(
    low_memory_host: bool,
    file_event_coalesce_key_limit: &mut usize,
    event_txn_coalesce_key_limit: &mut usize,
    strict_budget_pending_threshold: &mut usize,
    strict_budget_raw_backlog_threshold: &mut usize,
    raw_event_backlog_cap: &mut usize,
    raw_event_ingest_cap: &mut usize,
) {
    if !low_memory_host {
        *raw_event_ingest_cap = (*raw_event_ingest_cap).clamp(128, *raw_event_backlog_cap);
        return;
    }

    *file_event_coalesce_key_limit = (*file_event_coalesce_key_limit)
        .min(LOW_MEMORY_FILE_EVENT_COALESCE_KEY_LIMIT)
        .max(512);
    *event_txn_coalesce_key_limit = (*event_txn_coalesce_key_limit)
        .min(LOW_MEMORY_EVENT_TXN_COALESCE_KEY_LIMIT)
        .max(512);
    *strict_budget_pending_threshold = (*strict_budget_pending_threshold)
        .min(LOW_MEMORY_STRICT_BUDGET_PENDING_THRESHOLD)
        .max(64);
    *strict_budget_raw_backlog_threshold = (*strict_budget_raw_backlog_threshold)
        .min(LOW_MEMORY_STRICT_BUDGET_RAW_BACKLOG_THRESHOLD)
        .max(32);
    *raw_event_backlog_cap = (*raw_event_backlog_cap)
        .min(LOW_MEMORY_RAW_EVENT_BACKLOG_CAP)
        .max(256);
    *raw_event_ingest_cap = (*raw_event_ingest_cap)
        .min(LOW_MEMORY_RAW_EVENT_INGEST_CAP)
        .clamp(128, *raw_event_backlog_cap);
}

#[cfg(test)]
mod runtime_budget_tests {
    use super::{
        apply_low_memory_runtime_budget, enrichment_cache_limits,
        LOW_MEMORY_ENRICHMENT_FILE_HASH_ENTRIES, LOW_MEMORY_ENRICHMENT_PROCESS_CACHE_ENTRIES,
    };

    #[test]
    fn low_memory_budget_clamps_runtime_caps() {
        let mut file_keys = 16_384usize;
        let mut txn_keys = 16_384usize;
        let mut pending_threshold = 512usize;
        let mut raw_threshold = 128usize;
        let mut backlog_cap = 4_096usize;
        let mut ingest_cap = 1_024usize;

        apply_low_memory_runtime_budget(
            true,
            &mut file_keys,
            &mut txn_keys,
            &mut pending_threshold,
            &mut raw_threshold,
            &mut backlog_cap,
            &mut ingest_cap,
        );

        assert_eq!(file_keys, 4_096);
        assert_eq!(txn_keys, 4_096);
        assert_eq!(pending_threshold, 256);
        assert_eq!(raw_threshold, 64);
        assert_eq!(backlog_cap, 1_024);
        assert_eq!(ingest_cap, 256);
    }

    #[test]
    fn low_memory_budget_preserves_existing_stricter_caps() {
        let mut file_keys = 1_024usize;
        let mut txn_keys = 2_048usize;
        let mut pending_threshold = 128usize;
        let mut raw_threshold = 48usize;
        let mut backlog_cap = 512usize;
        let mut ingest_cap = 192usize;

        apply_low_memory_runtime_budget(
            true,
            &mut file_keys,
            &mut txn_keys,
            &mut pending_threshold,
            &mut raw_threshold,
            &mut backlog_cap,
            &mut ingest_cap,
        );

        assert_eq!(file_keys, 1_024);
        assert_eq!(txn_keys, 2_048);
        assert_eq!(pending_threshold, 128);
        assert_eq!(raw_threshold, 48);
        assert_eq!(backlog_cap, 512);
        assert_eq!(ingest_cap, 192);
    }

    #[test]
    fn low_memory_hosts_use_smaller_enrichment_caches() {
        let small = enrichment_cache_limits(true);
        let full = enrichment_cache_limits(false);
        assert_eq!(small.0, LOW_MEMORY_ENRICHMENT_PROCESS_CACHE_ENTRIES);
        assert_eq!(small.1, LOW_MEMORY_ENRICHMENT_FILE_HASH_ENTRIES);
        assert!(full.0 > small.0);
        assert!(full.1 > small.1);
    }
}
