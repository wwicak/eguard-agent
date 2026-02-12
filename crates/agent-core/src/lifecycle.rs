use std::collections::VecDeque;

use anyhow::Result;
use tracing::{info, warn};

use baseline::ProcessBaseline;
use compliance::{evaluate, CompliancePolicy};
use detection::{Confidence, DetectionEngine, EventClass, TelemetryEvent};
use grpc_client::{
    Client as GrpcClient, CommandEnvelope, ComplianceEnvelope, EnrollmentEnvelope, EventBuffer,
    EventEnvelope, ResponseEnvelope, TlsConfig, TransportMode,
};
use nac::{posture_from_compliance, Posture};
use platform_linux::{enrich_event, EventType, RawEvent};
use response::{
    execute_server_command_with_state, parse_server_command, plan_action, HostControlState,
    KillRateLimiter, ProtectedList, PlannedAction, ResponseConfig,
};

use crate::config::{AgentConfig, AgentMode};

pub struct AgentRuntime {
    config: AgentConfig,
    buffer: EventBuffer,
    detection: DetectionEngine,
    protected: ProtectedList,
    limiter: KillRateLimiter,
    baseline: ProcessBaseline,
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
        let mut detection = DetectionEngine::default_with_rules();
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

        let buffer = if config.offline_buffer_backend.eq_ignore_ascii_case("memory") {
            EventBuffer::memory(config.offline_buffer_cap_bytes)
        } else {
            match EventBuffer::sqlite(&config.offline_buffer_path, config.offline_buffer_cap_bytes) {
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

        let initial_mode = config.mode.clone();

        Ok(Self {
            limiter: KillRateLimiter::new(10),
            protected: ProtectedList::default_linux(),
            baseline: ProcessBaseline::new("bash:sshd".to_string()),
            buffer,
            detection,
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

        let raw = RawEvent {
            event_type: EventType::ProcessExec,
            pid: std::process::id(),
            uid: 0,
            ts_ns: (now_unix as u64) * 1_000_000_000,
            payload: "simulated_event".to_string(),
        };

        let enriched = enrich_event(raw);
        self.baseline.observe("process_exec");

        let det_event = to_detection_event(&enriched, now_unix);
        let detection_outcome = self.detection.process_event(&det_event);
        let confidence = detection_outcome.confidence;
        let response_cfg = ResponseConfig {
            autonomous_response: self.config.autonomous_response,
            ..ResponseConfig::default()
        };
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
            payload_json: format!("{{\"exe\":\"{}\"}}", enriched.process_exe.unwrap_or_default()),
            created_at_unix: now_unix,
        };

        let forced_degraded = matches!(self.config.mode, AgentMode::Degraded);
        if matches!(self.runtime_mode, AgentMode::Degraded) {
            self.client.set_online(false);
            self.buffer.enqueue(envelope)?;
            warn!(pending = self.buffer.pending_count(), "server unavailable, buffered event");

            if !forced_degraded && self.tick_count % 6 == 0 {
                self.client.set_online(true);
                match self.client.check_server_state().await {
                    Ok(Some(_)) => {
                        match self.client.send_heartbeat(&self.config.agent_id, &comp.status).await {
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
                let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| self.config.agent_id.clone());
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
                if let Err(err) = self.client.send_heartbeat(&self.config.agent_id, &comp.status).await {
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
                        let changed = self.latest_threat_version.as_deref() != Some(v.version.as_str());
                        if changed {
                            info!(version = %v.version, bundle = %v.bundle_path, "new threat intel version available");
                            self.latest_threat_version = Some(v.version);
                        }
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
                let response = ResponseEnvelope {
                    agent_id: self.config.agent_id.clone(),
                    action_type: format!("{:?}", action).to_ascii_lowercase(),
                    confidence: confidence_label(confidence),
                    success: true,
                    error_message: String::new(),
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
                "event evaluated"
            );
        }

        let _ = self.limiter.allow(std::time::Instant::now());
        let _ = self.protected.is_protected_process("systemd");
        Ok(())
    }

    fn log_posture(&self, posture: Posture) {
        info!(?posture, "computed nac posture");
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
        let exec = execute_server_command_with_state(parsed, now_unix, &mut self.host_control);
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
        ppid: 0,
        uid: enriched.event.uid,
        process,
        parent_process: "unknown".to_string(),
        file_path: None,
        file_hash: None,
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
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
    }
}
