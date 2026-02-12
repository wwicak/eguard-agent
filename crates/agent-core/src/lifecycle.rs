use std::collections::HashMap;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{anyhow, Result};
use serde::Deserialize;
use tracing::{info, warn};

use baseline::{BaselineStatus, BaselineStore, BaselineTransition, ProcessKey};
use compliance::{evaluate, CompliancePolicy};
use detection::{Confidence, DetectionEngine, EventClass, TelemetryEvent};
use grpc_client::{
    Client as GrpcClient, CommandEnvelope, ComplianceEnvelope, EnrollmentEnvelope, EventBuffer,
    EventEnvelope, ResponseEnvelope, TlsConfig, TransportMode,
};
use nac::{posture_from_compliance, Posture};
use platform_linux::{enrich_event_with_cache, EbpfEngine, EnrichmentCache, EventType, RawEvent};
use response::{
    capture_script_content, execute_server_command_with_state, kill_process_tree,
    parse_server_command, plan_action, quarantine_file, CommandOutcome, HostControlState,
    KillRateLimiter, PlannedAction, ProtectedList, ResponseConfig, ServerCommand,
};

use crate::config::{AgentConfig, AgentMode};
use crate::detection_state::{EmergencyRule, EmergencyRuleType, SharedDetectionState};

pub struct AgentRuntime {
    config: AgentConfig,
    buffer: EventBuffer,
    detection_state: SharedDetectionState,
    protected: ProtectedList,
    limiter: KillRateLimiter,
    baseline_store: BaselineStore,
    ebpf_engine: EbpfEngine,
    enrichment_cache: EnrichmentCache,
    client: GrpcClient,
    tick_count: u64,
    runtime_mode: AgentMode,
    consecutive_send_failures: u32,
    enrolled: bool,
    latest_threat_version: Option<String>,
    host_control: HostControlState,
    completed_command_ids: VecDeque<String>,
}

impl AgentRuntime {
    pub fn new(config: AgentConfig) -> Result<Self> {
        let detection_state = SharedDetectionState::new(build_detection_engine(), None);
        let baseline_store = load_baseline_store()?;
        seed_anomaly_baselines(&detection_state, &baseline_store)?;
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

        let initial_mode = derive_runtime_mode(&config.mode, baseline_store.status);

        Ok(Self {
            limiter: KillRateLimiter::new(config.response.max_kills_per_minute),
            protected: ProtectedList::default_linux(),
            baseline_store,
            ebpf_engine,
            enrichment_cache,
            buffer,
            detection_state,
            client,
            config,
            tick_count: 0,
            runtime_mode: initial_mode,
            consecutive_send_failures: 0,
            enrolled: false,
            latest_threat_version: None,
            host_control: HostControlState::default(),
            completed_command_ids: VecDeque::new(),
        })
    }

    pub async fn tick(&mut self, now_unix: i64) -> Result<()> {
        self.tick_count = self.tick_count.saturating_add(1);

        let raw = self.next_raw_event(now_unix);

        let enriched = enrich_event_with_cache(raw, &mut self.enrichment_cache);

        let det_event = to_detection_event(&enriched, now_unix);
        self.observe_baseline(&det_event, now_unix);
        let detection_outcome = self.detection_state.process_event(&det_event)?;
        let confidence = detection_outcome.confidence;
        let response_cfg = self.effective_response_config();
        let action = plan_action(confidence, &response_cfg);

        let comp = evaluate(
            &CompliancePolicy {
                firewall_required: true,
                min_kernel_prefix: None,
            },
            true,
            "6.8.0",
        );
        let posture = posture_from_compliance(&comp.status);
        self.log_posture(posture);

        let envelope = EventEnvelope {
            agent_id: self.config.agent_id.clone(),
            event_type: "process_exec".to_string(),
            payload_json: format!(
                "{{\"exe\":\"{}\"}}",
                enriched.process_exe.unwrap_or_default()
            ),
            created_at_unix: now_unix,
        };

        let forced_degraded = matches!(self.config.mode, AgentMode::Degraded);
        if matches!(self.runtime_mode, AgentMode::Degraded) {
            self.client.set_online(false);
            self.buffer.enqueue(envelope)?;
            warn!(
                pending = self.buffer.pending_count(),
                "server unavailable, buffered event"
            );

            if !forced_degraded && self.tick_count % 6 == 0 {
                self.client.set_online(true);
                match self.client.check_server_state().await {
                    Ok(Some(_)) => {
                        match self
                            .client
                            .send_heartbeat(&self.config.agent_id, &comp.status)
                            .await
                        {
                            Ok(_) => {
                                self.runtime_mode = self.config.mode.clone();
                                self.consecutive_send_failures = 0;
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
        } else {
            self.client.set_online(true);

            if !self.enrolled {
                let hostname =
                    std::env::var("HOSTNAME").unwrap_or_else(|_| self.config.agent_id.clone());
                let enroll = EnrollmentEnvelope {
                    agent_id: self.config.agent_id.clone(),
                    mac: self.config.mac.clone(),
                    hostname,
                };
                if let Err(err) = self.client.enroll(&enroll).await {
                    warn!(error = %err, "enrollment failed");
                } else {
                    self.enrolled = true;
                }
            }

            let mut batch = self.buffer.drain_batch(256)?;
            batch.push(envelope);
            if let Err(err) = self.client.send_events(&batch).await {
                for ev in batch {
                    self.buffer.enqueue(ev)?;
                }
                self.consecutive_send_failures = self.consecutive_send_failures.saturating_add(1);
                if self.consecutive_send_failures >= 3 {
                    self.runtime_mode = AgentMode::Degraded;
                }
                warn!(error = %err, pending = self.buffer.pending_count(), "send failed, events re-buffered");
            } else {
                self.consecutive_send_failures = 0;
            }

            if self.tick_count % 6 == 0 {
                if let Err(err) = self
                    .client
                    .send_heartbeat(&self.config.agent_id, &comp.status)
                    .await
                {
                    warn!(error = %err, "heartbeat failed");
                }
            }

            if self.tick_count % 12 == 0 {
                let compliance = ComplianceEnvelope {
                    agent_id: self.config.agent_id.clone(),
                    policy_id: "default".to_string(),
                    check_type: "runtime_health".to_string(),
                    status: comp.status.clone(),
                    detail: comp.detail.clone(),
                    expected_value: "firewall_enabled=true".to_string(),
                    actual_value: "firewall_enabled=true".to_string(),
                };
                if let Err(err) = self.client.send_compliance(&compliance).await {
                    warn!(error = %err, "compliance send failed");
                }
            }

            if self.tick_count % 30 == 0 {
                match self.client.fetch_latest_threat_intel().await? {
                    Some(v) => {
                        let known_version = self
                            .latest_threat_version
                            .clone()
                            .or(self.detection_state.version()?);
                        let changed = known_version.as_deref() != Some(v.version.as_str());
                        if changed {
                            info!(version = %v.version, bundle = %v.bundle_path, "new threat intel version available");
                            self.reload_detection_state(&v.version)?;
                        }
                        self.latest_threat_version = Some(v.version);
                    }
                    None => {}
                }
            }

            let completed_cursor = self.completed_command_cursor();
            match self
                .client
                .fetch_commands(&self.config.agent_id, &completed_cursor, 10)
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

            if !matches!(action, PlannedAction::AlertOnly | PlannedAction::None) {
                let local = self.execute_planned_action(action, &det_event, now_unix);
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

            info!(
                ?action,
                ?confidence,
                mode = ?self.runtime_mode,
                temporal_hits = detection_outcome.temporal_hits.len(),
                killchain_hits = detection_outcome.kill_chain_hits.len(),
                z1 = detection_outcome.signals.z1_exact_ioc,
                z2 = detection_outcome.signals.z2_temporal,
                z3h = detection_outcome.signals.z3_anomaly_high,
                z4 = detection_outcome.signals.z4_kill_chain,
                yara_hits = detection_outcome.yara_hits.len(),
                "event evaluated"
            );
        }

        let _ = self.protected.is_protected_process("systemd");
        Ok(())
    }

    fn log_posture(&self, posture: Posture) {
        info!(?posture, "computed nac posture");
    }

    fn next_raw_event(&mut self, now_unix: i64) -> RawEvent {
        let timeout = self.adaptive_poll_timeout();
        match self.ebpf_engine.poll_once(timeout) {
            Ok(events) => {
                if let Some(event) = events.into_iter().next() {
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
        let pending = self.buffer.pending_count();
        if pending > 4096 {
            std::time::Duration::from_millis(5)
        } else if pending > 1024 {
            std::time::Duration::from_millis(20)
        } else {
            std::time::Duration::from_millis(100)
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
        } else if self.tick_count % 60 == 0 {
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

        if should_capture_script(action, event) {
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
                    success = false;
                    notes.push(format!("capture_failed:{}", err));
                }
            }
        }

        if requires_kill(action) {
            if event.pid == std::process::id() {
                success = false;
                notes.push("kill_skipped:self_pid".to_string());
            } else if !self.limiter.allow(Instant::now()) {
                success = false;
                notes.push("kill_skipped:rate_limited".to_string());
            } else {
                match kill_process_tree(event.pid, &self.protected) {
                    Ok(report) => notes.push(format!("killed_pids={}", report.killed_pids.len())),
                    Err(err) => {
                        success = false;
                        notes.push(format!("kill_failed:{}", err));
                    }
                }
            }
        }

        if requires_quarantine(action) {
            match event.file_path.as_deref() {
                Some(path) => {
                    let sha = event
                        .file_hash
                        .clone()
                        .unwrap_or_else(|| synthetic_quarantine_id(event));
                    match quarantine_file(Path::new(path), &sha, &self.protected) {
                        Ok(report) => {
                            notes.push(format!("quarantined:{}", report.quarantine_path.display()))
                        }
                        Err(err) => {
                            success = false;
                            notes.push(format!("quarantine_failed:{}", err));
                        }
                    }
                }
                None => {
                    success = false;
                    notes.push("quarantine_failed:missing_file_path".to_string());
                }
            }
        }

        if notes.is_empty() {
            notes.push("no_local_action".to_string());
        }

        LocalActionResult {
            success,
            detail: notes.join("; "),
        }
    }

    fn reload_detection_state(&self, version: &str) -> Result<()> {
        let next_engine = build_detection_engine();
        self.detection_state
            .swap_engine(version.to_string(), next_engine)?;
        info!(version = %version, "detection state hot-reloaded");
        Ok(())
    }

    fn completed_command_cursor(&self) -> Vec<String> {
        self.completed_command_ids.iter().cloned().collect()
    }

    fn track_completed_command(&mut self, command_id: &str) {
        if command_id.is_empty() {
            return;
        }

        self.completed_command_ids.push_back(command_id.to_string());
        while self.completed_command_ids.len() > 256 {
            self.completed_command_ids.pop_front();
        }
    }

    async fn handle_command(&mut self, command: CommandEnvelope, now_unix: i64) {
        let command_id = command.command_id.clone();
        let parsed = parse_server_command(&command.command_type);
        let mut exec = execute_server_command_with_state(parsed, now_unix, &mut self.host_control);

        if parsed == ServerCommand::EmergencyRulePush {
            match self.apply_emergency_rule_from_payload(&command.payload_json) {
                Ok(rule_name) => {
                    exec.detail = format!("emergency rule applied: {}", rule_name);
                }
                Err(err) => {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("emergency rule push rejected: {}", err);
                }
            }
        }

        info!(
            command_id = %command.command_id,
            command_type = %command.command_type,
            payload = %command.payload_json,
            parsed = ?parsed,
            outcome = ?exec.outcome,
            detail = %exec.detail,
            "received command"
        );

        if let Err(err) = self.client.ack_command(&command_id, exec.status).await {
            warn!(error = %err, command_id = %command_id, "failed to ack command");
        }

        let report = ResponseEnvelope {
            agent_id: self.config.agent_id.clone(),
            action_type: format!("command:{}", command.command_type),
            confidence: "high".to_string(),
            success: exec.status == "completed",
            error_message: if exec.status == "completed" {
                String::new()
            } else {
                exec.detail.clone()
            },
        };
        if let Err(err) = self.client.send_response(&report).await {
            warn!(error = %err, command_id = %command.command_id, "failed to send command response report");
        }

        self.track_completed_command(&command_id);
    }

    fn apply_emergency_rule_from_payload(&self, payload_json: &str) -> Result<String> {
        let payload: EmergencyRulePayload = serde_json::from_str(payload_json)
            .map_err(|err| anyhow!("invalid emergency payload: {}", err))?;

        let rule_name = payload.rule_name.trim();
        if rule_name.is_empty() {
            return Err(anyhow!("missing emergency rule name"));
        }

        let rule_content = payload.rule_content.trim();
        if rule_content.is_empty() {
            return Err(anyhow!("missing emergency rule content"));
        }

        let rule_type = parse_emergency_rule_type(&payload.rule_type)?;
        let rule = EmergencyRule {
            name: rule_name.to_string(),
            rule_type,
            rule_content: rule_content.to_string(),
        };

        self.detection_state.apply_emergency_rule(rule)?;
        Ok(rule_name.to_string())
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
        Ok(store) => Ok(store),
        Err(err) => {
            warn!(error = %err, path = %path.display(), "failed loading baseline store, using temp fallback");
            let fallback = std::env::temp_dir().join("eguard-agent-baselines.bin");
            BaselineStore::load_or_new(fallback.clone()).map_err(|fallback_err| {
                anyhow!(
                    "failed to initialize baseline store at {} and fallback {}: {} / {}",
                    path.display(),
                    fallback.display(),
                    err,
                    fallback_err
                )
            })
        }
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
    let objects_dir = std::env::var("EGUARD_EBPF_OBJECTS_DIR")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from);
    let elf_path = std::env::var("EGUARD_EBPF_ELF")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from);
    let map_name = std::env::var("EGUARD_EBPF_RING_MAP")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "events".to_string());

    if let Some(dir) = objects_dir {
        let object_paths = candidate_ebpf_object_paths(&dir);
        if !object_paths.is_empty() {
            match EbpfEngine::from_elfs(&object_paths, &map_name) {
                Ok(engine) => {
                    info!(
                        objects_dir = %dir.display(),
                        object_count = object_paths.len(),
                        map = %map_name,
                        "eBPF engine initialized from object directory"
                    );
                    return engine;
                }
                Err(err) => {
                    warn!(
                        error = %err,
                        objects_dir = %dir.display(),
                        map = %map_name,
                        "failed to initialize eBPF engine from object directory"
                    );
                }
            }
        }
    }

    let Some(elf_path) = elf_path else {
        return EbpfEngine::disabled();
    };

    match EbpfEngine::from_elf(&elf_path, &map_name) {
        Ok(engine) => {
            info!(path = %elf_path.display(), map = %map_name, "eBPF engine initialized");
            engine
        }
        Err(err) => {
            warn!(error = %err, path = %elf_path.display(), map = %map_name, "failed to initialize eBPF engine; using disabled backend");
            EbpfEngine::disabled()
        }
    }
}

fn candidate_ebpf_object_paths(objects_dir: &Path) -> Vec<PathBuf> {
    const OBJECT_NAMES: [&str; 6] = [
        "process_exec_bpf.o",
        "file_open_bpf.o",
        "tcp_connect_bpf.o",
        "dns_query_bpf.o",
        "module_load_bpf.o",
        "lsm_block_bpf.o",
    ];

    let mut out = Vec::new();
    for name in OBJECT_NAMES {
        let candidate = objects_dir.join(name);
        if candidate.exists() {
            out.push(candidate);
        }
    }
    out
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
        platform_linux::EventType::FileOpen => EventClass::FileOpen,
        platform_linux::EventType::TcpConnect => EventClass::NetworkConnect,
        platform_linux::EventType::DnsQuery => EventClass::DnsQuery,
        platform_linux::EventType::ModuleLoad => EventClass::ModuleLoad,
        platform_linux::EventType::LsmBlock => EventClass::Alert,
    }
}

fn build_detection_engine() -> DetectionEngine {
    let mut detection = DetectionEngine::default_with_rules();
    seed_detection_inputs(&mut detection);
    seed_sigma_rules(&mut detection);
    seed_yara_rules(&mut detection);
    detection
}

fn seed_detection_inputs(detection: &mut DetectionEngine) {
    detection.layer1.load_hashes(["deadbeef".to_string()]);
    detection
        .layer1
        .load_domains(["known-c2.example.com".to_string()]);
    detection.layer1.load_ips(["198.51.100.10".to_string()]);
    detection.layer1.load_string_signatures([
        "curl|bash".to_string(),
        "python -c".to_string(),
        "powershell -enc".to_string(),
    ]);
}

fn seed_sigma_rules(detection: &mut DetectionEngine) {
    const BUILTIN_SIGMA_RULE: &str = r#"
title: eguard_builtin_webshell
detection:
  sequence:
    - event_class: process_exec
      process_any_of: [bash, sh]
      parent_any_of: [nginx, apache2, caddy]
      within_secs: 30
    - event_class: network_connect
      dst_port_not_in: [80, 443]
      within_secs: 10
"#;

    let mut loaded = 0usize;
    match detection.load_sigma_rule_yaml(BUILTIN_SIGMA_RULE) {
        Ok(_) => loaded += 1,
        Err(err) => warn!(error = %err, "failed loading built-in SIGMA rule"),
    }

    let rules_dir = Path::new("rules/sigma");
    if rules_dir.exists() {
        match detection.load_sigma_rules_from_dir(rules_dir) {
            Ok(count) => loaded += count,
            Err(err) => {
                warn!(error = %err, path = %rules_dir.display(), "failed loading SIGMA rules from directory")
            }
        }
    }

    info!(loaded_sigma_rules = loaded, "SIGMA rules initialized");
}

fn seed_yara_rules(detection: &mut DetectionEngine) {
    const BUILTIN_YARA_RULE: &str = r#"
rule eguard_builtin_test_marker {
  strings:
    $marker = "eguard-malware-test-marker"
  condition:
    $marker
}
"#;

    let mut loaded = 0usize;
    match detection.load_yara_rules_str(BUILTIN_YARA_RULE) {
        Ok(count) => loaded += count,
        Err(err) => warn!(error = %err, "failed loading built-in YARA rule"),
    }

    let rules_dir = Path::new("rules/yara");
    if rules_dir.exists() {
        match detection.load_yara_rules_from_dir(rules_dir) {
            Ok(count) => {
                loaded += count;
            }
            Err(err) => {
                warn!(error = %err, path = %rules_dir.display(), "failed loading YARA rules from directory")
            }
        }
    }

    info!(loaded_yara_rules = loaded, "YARA rules initialized");
}
