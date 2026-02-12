use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client as HttpClient;
use serde::Deserialize;
use serde_json::json;
use tokio::time::sleep;
use tokio_stream::iter;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tracing::{info, warn};

use crate::pb;
use crate::retry::RetryPolicy;
use crate::types::{
    CommandEnvelope, ComplianceEnvelope, EnrollmentEnvelope, EventEnvelope, ResponseEnvelope,
    ServerState, ThreatIntelVersionEnvelope, TlsConfig, TransportMode,
};

#[derive(Debug, Clone)]
pub struct Client {
    server_addr: String,
    mode: TransportMode,
    retry: RetryPolicy,
    online: bool,
    pending_commands: VecDeque<CommandEnvelope>,
    tls: Option<TlsConfig>,
    http: HttpClient,
}

impl Client {
    pub fn new(server_addr: String) -> Self {
        Self::with_mode(server_addr, TransportMode::Http)
    }

    pub fn with_mode(server_addr: String, mode: TransportMode) -> Self {
        Self {
            server_addr,
            mode,
            retry: RetryPolicy::default(),
            online: true,
            pending_commands: VecDeque::new(),
            tls: None,
            http: HttpClient::new(),
        }
    }

    pub fn set_online(&mut self, online: bool) {
        self.online = online;
    }

    pub fn server_addr(&self) -> &str {
        &self.server_addr
    }

    pub fn configure_tls(&mut self, cfg: TlsConfig) -> Result<()> {
        for path in [&cfg.cert_path, &cfg.key_path, &cfg.ca_path] {
            if !Path::new(path).exists() {
                anyhow::bail!("TLS file does not exist: {}", path);
            }
        }
        self.tls = Some(cfg);
        Ok(())
    }

    pub fn is_tls_configured(&self) -> bool {
        self.tls.is_some()
    }

    pub fn enqueue_mock_command(&mut self, command: CommandEnvelope) {
        self.pending_commands.push_back(command);
    }

    pub fn retry_policy(&self) -> &RetryPolicy {
        &self.retry
    }

    pub async fn send_events(&self, batch: &[EventEnvelope]) -> Result<()> {
        self.ensure_online()?;
        if batch.is_empty() {
            return Ok(());
        }

        match self.mode {
            TransportMode::Http => {
                self.with_retry("send_events_http", || async {
                    let url = self.url_for("/api/v1/endpoint/telemetry");
                    for event in batch {
                        self.http
                            .post(&url)
                            .json(event)
                            .send()
                            .await
                            .with_context(|| format!("failed sending telemetry to {}", url))?
                            .error_for_status()
                            .with_context(|| format!("telemetry rejected by {}", url))?;
                    }
                    Ok(())
                })
                .await?;
            }
            TransportMode::Grpc => {
                self.with_retry("send_events_grpc_stream", || async {
                    let channel = self.connect_channel().await?;
                    let mut client = pb::telemetry_service_client::TelemetryServiceClient::new(channel);
                    let events: Vec<pb::TelemetryEvent> = batch.iter().map(to_pb_telemetry_event).collect();
                    let stream = iter(events);
                    client
                        .stream_events(tonic::Request::new(stream))
                        .await
                        .context("stream_events RPC failed")?;
                    Ok(())
                })
                .await?;
            }
        }

        info!(count = batch.len(), server = %self.server_addr, mode = ?self.mode, "sent event batch");
        Ok(())
    }

    pub async fn enroll(&self, enrollment: &EnrollmentEnvelope) -> Result<()> {
        self.ensure_online()?;
        match self.mode {
            TransportMode::Http => {
                self.with_retry("enroll_http", || async {
                    let url = self.url_for("/api/v1/endpoint/enroll");
                    self.http
                        .post(&url)
                        .json(enrollment)
                        .send()
                        .await
                        .with_context(|| format!("failed sending enrollment to {}", url))?
                        .error_for_status()
                        .with_context(|| format!("enrollment rejected by {}", url))?;
                    Ok(())
                })
                .await?;
            }
            TransportMode::Grpc => {
                self.with_retry("enroll_grpc", || async {
                    let channel = self.connect_channel().await?;
                    let mut client = pb::agent_control_service_client::AgentControlServiceClient::new(channel);
                    let req = pb::EnrollRequest {
                        agent_id: enrollment.agent_id.clone(),
                        mac: enrollment.mac.clone(),
                        hostname: enrollment.hostname.clone(),
                        os_type: "linux".to_string(),
                        agent_version: "0.1.0".to_string(),
                    };
                    client.enroll(req).await.context("enroll RPC failed")?;
                    Ok(())
                })
                .await?;
            }
        }
        Ok(())
    }

    pub async fn send_heartbeat(&self, agent_id: &str, compliance_status: &str) -> Result<()> {
        self.ensure_online()?;
        match self.mode {
            TransportMode::Http => {
                self.with_retry("heartbeat_http", || async {
                    let url = self.url_for("/api/v1/endpoint/heartbeat");
                    let body = json!({
                        "agent_id": agent_id,
                        "agent_version": "0.1.0",
                        "compliance_status": compliance_status,
                    });
                    self.http
                        .post(&url)
                        .json(&body)
                        .send()
                        .await
                        .with_context(|| format!("failed sending heartbeat to {}", url))?
                        .error_for_status()
                        .with_context(|| format!("heartbeat rejected by {}", url))?;
                    Ok(())
                })
                .await?;
            }
            TransportMode::Grpc => {
                self.with_retry("heartbeat_grpc", || async {
                    let channel = self.connect_channel().await?;
                    let mut client = pb::agent_control_service_client::AgentControlServiceClient::new(channel);
                    client
                        .heartbeat(pb::HeartbeatRequest {
                            agent_id: agent_id.to_string(),
                            agent_version: "0.1.0".to_string(),
                            compliance_status: compliance_status.to_string(),
                            sent_at_unix: now_unix(),
                        })
                        .await
                        .context("heartbeat RPC failed")?;
                    Ok(())
                })
                .await?;
            }
        }
        Ok(())
    }

    pub async fn send_compliance(&self, compliance: &ComplianceEnvelope) -> Result<()> {
        self.ensure_online()?;
        match self.mode {
            TransportMode::Http => {
                self.with_retry("compliance_http", || async {
                    let url = self.url_for("/api/v1/endpoint/compliance");
                    self.http
                        .post(&url)
                        .json(compliance)
                        .send()
                        .await
                        .with_context(|| format!("failed sending compliance to {}", url))?
                        .error_for_status()
                        .with_context(|| format!("compliance rejected by {}", url))?;
                    Ok(())
                })
                .await?;
            }
            TransportMode::Grpc => {
                self.with_retry("compliance_grpc", || async {
                    let channel = self.connect_channel().await?;
                    let mut client = pb::compliance_service_client::ComplianceServiceClient::new(channel);
                    client
                        .report_compliance(pb::ComplianceReport {
                            agent_id: compliance.agent_id.clone(),
                            policy_id: compliance.policy_id.clone(),
                            check_type: compliance.check_type.clone(),
                            status: compliance.status.clone(),
                            detail: compliance.detail.clone(),
                            expected_value: compliance.expected_value.clone(),
                            actual_value: compliance.actual_value.clone(),
                            checked_at_unix: now_unix(),
                        })
                        .await
                        .context("report_compliance RPC failed")?;
                    Ok(())
                })
                .await?;
            }
        }
        Ok(())
    }

    pub async fn send_response(&self, response: &ResponseEnvelope) -> Result<()> {
        self.ensure_online()?;
        match self.mode {
            TransportMode::Http => {
                self.with_retry("response_http", || async {
                    let url = self.url_for("/api/v1/endpoint/response");
                    self.http
                        .post(&url)
                        .json(response)
                        .send()
                        .await
                        .with_context(|| format!("failed sending response to {}", url))?
                        .error_for_status()
                        .with_context(|| format!("response rejected by {}", url))?;
                    Ok(())
                })
                .await?;
            }
            TransportMode::Grpc => {
                self.with_retry("response_grpc", || async {
                    let channel = self.connect_channel().await?;
                    let mut client = pb::response_service_client::ResponseServiceClient::new(channel);
                    client
                        .report_response(pb::ResponseReport {
                            agent_id: response.agent_id.clone(),
                            action: response.action_type.clone(),
                            confidence: response.confidence.clone(),
                            success: response.success,
                            detail: response.error_message.clone(),
                            created_at_unix: now_unix(),
                        })
                        .await
                        .context("report_response RPC failed")?;
                    Ok(())
                })
                .await?;
            }
        }
        Ok(())
    }

    pub async fn stream_command_channel(
        &self,
        agent_id: &str,
        completed_command_ids: &[String],
        limit: usize,
    ) -> Result<Vec<CommandEnvelope>> {
        self.ensure_online()?;

        if limit == 0 {
            return Ok(Vec::new());
        }

        match self.mode {
            TransportMode::Http => {
                #[derive(Debug, Deserialize)]
                struct PollResponse {
                    commands: Vec<CommandEnvelope>,
                }

                self.with_retry("command_channel_http", || async {
                    let url = self.url_for("/api/v1/endpoint/command/channel");
                    let completed = completed_command_ids.join(",");
                    let response = self
                        .http
                        .get(&url)
                        .query(&[
                            ("agent_id", agent_id.to_string()),
                            ("limit", limit.to_string()),
                            ("completed_command_ids", completed),
                        ])
                        .send()
                        .await
                        .with_context(|| format!("failed opening command channel to {}", url))?
                        .error_for_status()
                        .with_context(|| format!("command channel rejected by {}", url))?;

                    let payload = response
                        .json::<PollResponse>()
                        .await
                        .context("invalid command channel response payload")?;
                    Ok(payload.commands)
                })
                .await
            }
            TransportMode::Grpc => {
                self.with_retry("command_channel_grpc", || async {
                    let channel = self.connect_channel().await?;
                    let mut client = pb::command_service_client::CommandServiceClient::new(channel);
                    let response = client
                        .command_channel(pb::CommandChannelRequest {
                            agent_id: agent_id.to_string(),
                            completed_command_ids: completed_command_ids.to_vec(),
                            limit: limit as i32,
                        })
                        .await
                        .context("command_channel RPC failed")?;

                    let mut stream = response.into_inner();
                    let mut out = Vec::with_capacity(limit);
                    while out.len() < limit {
                        match tokio::time::timeout(Duration::from_millis(350), stream.message()).await {
                            Ok(Ok(Some(command))) => out.push(from_pb_agent_command(command)),
                            Ok(Ok(None)) => break,
                            Ok(Err(err)) => return Err(err).context("command_channel stream read failed"),
                            Err(_) => break,
                        }
                    }

                    Ok(out)
                })
                .await
            }
        }
    }

    pub async fn fetch_commands(
        &mut self,
        agent_id: &str,
        completed_command_ids: &[String],
        limit: usize,
    ) -> Result<Vec<CommandEnvelope>> {
        self.ensure_online()?;

        match self
            .stream_command_channel(agent_id, completed_command_ids, limit)
            .await
        {
            Ok(mut commands) => {
                if commands.len() > limit {
                    commands.truncate(limit);
                }
                if !commands.is_empty() {
                    return Ok(commands);
                }
            }
            Err(err) => {
                warn!(
                    error = %err,
                    mode = ?self.mode,
                    "command channel unavailable, falling back to polling"
                );
            }
        }

        let server_result: Result<Vec<CommandEnvelope>> = match self.mode {
            TransportMode::Http => {
                #[derive(Debug, Deserialize)]
                struct PollResponse {
                    commands: Vec<CommandEnvelope>,
                }

                self.with_retry("fetch_commands_http", || async {
                    let url = self.url_for("/api/v1/endpoint/command/pending");
                    let response = self
                        .http
                        .get(&url)
                        .query(&[("agent_id", agent_id.to_string()), ("limit", limit.to_string())])
                        .send()
                        .await
                        .with_context(|| format!("failed polling commands from {}", url))?
                        .error_for_status()
                        .with_context(|| format!("command poll rejected by {}", url))?;
                    let payload = response
                        .json::<PollResponse>()
                        .await
                        .context("invalid command poll response payload")?;
                    Ok(payload.commands)
                })
                .await
            }
            TransportMode::Grpc => {
                self.with_retry("fetch_commands_grpc", || async {
                    let channel = self.connect_channel().await?;
                    let mut client = pb::command_service_client::CommandServiceClient::new(channel);
                    let response = client
                        .poll_commands(pb::PollCommandsRequest {
                            agent_id: agent_id.to_string(),
                            limit: limit as i32,
                        })
                        .await
                        .context("poll_commands RPC failed")?
                        .into_inner();

                    Ok(response
                        .commands
                        .into_iter()
                        .map(from_pb_agent_command)
                        .collect::<Vec<_>>())
                })
                .await
            }
        };

        match server_result {
            Ok(mut commands) => {
                if commands.len() > limit {
                    commands.truncate(limit);
                }
                Ok(commands)
            }
            Err(err) => {
                warn!(error = %err, mode = ?self.mode, "failed to fetch commands, falling back to in-memory queue");
                let mut out = Vec::with_capacity(limit);
                for _ in 0..limit {
                    if let Some(cmd) = self.pending_commands.pop_front() {
                        out.push(cmd);
                    } else {
                        break;
                    }
                }
                Ok(out)
            }
        }
    }

    pub async fn ack_command(&self, command_id: &str, status: &str) -> Result<()> {
        self.ensure_online()?;
        match self.mode {
            TransportMode::Http => {
                self.with_retry("ack_command_http", || async {
                    let url = self.url_for("/api/v1/endpoint/command/ack");
                    self.http
                        .post(&url)
                        .json(&json!({"command_id": command_id, "status": status}))
                        .send()
                        .await
                        .with_context(|| format!("failed acking command to {}", url))?
                        .error_for_status()
                        .with_context(|| format!("command ack rejected by {}", url))?;
                    Ok(())
                })
                .await?;
            }
            TransportMode::Grpc => {
                self.with_retry("ack_command_grpc", || async {
                    let channel = self.connect_channel().await?;
                    let mut client = pb::command_service_client::CommandServiceClient::new(channel);
                    client
                        .ack_command(pb::AckCommandRequest {
                            command_id: command_id.to_string(),
                            status: status.to_string(),
                        })
                        .await
                        .context("ack_command RPC failed")?;
                    Ok(())
                })
                .await?;
            }
        }
        Ok(())
    }

    pub async fn fetch_latest_threat_intel(&self) -> Result<Option<ThreatIntelVersionEnvelope>> {
        self.ensure_online()?;
        match self.mode {
            TransportMode::Http => {
                #[derive(Debug, Deserialize)]
                struct VersionsResponse {
                    versions: Vec<ThreatIntelVersionEnvelope>,
                }

                let response = self
                    .with_retry("threat_intel_http", || async {
                        let url = self.url_for("/api/v1/endpoint/threat-intel/version");
                        let response = self
                            .http
                            .get(&url)
                            .query(&[("limit", 1)])
                            .send()
                            .await
                            .with_context(|| format!("failed fetching threat intel from {}", url))?
                            .error_for_status()
                            .with_context(|| format!("threat intel rejected by {}", url))?;
                        response
                            .json::<VersionsResponse>()
                            .await
                            .context("invalid threat intel response payload")
                    })
                    .await;

                match response {
                    Ok(mut res) => Ok(res.versions.drain(..).next()),
                    Err(err) => {
                        warn!(error = %err, "failed to fetch threat intel version");
                        Ok(None)
                    }
                }
            }
            TransportMode::Grpc => {
                self.with_retry("threat_intel_grpc", || async {
                    let channel = self.connect_channel().await?;
                    let mut client = pb::agent_control_service_client::AgentControlServiceClient::new(channel);
                    let res = client
                        .get_latest_threat_intel(pb::ThreatIntelRequest {
                            agent_id: String::new(),
                        })
                        .await
                        .context("get_latest_threat_intel RPC failed")?
                        .into_inner();
                    if res.version.is_empty() {
                        return Ok(None);
                    }
                    Ok(Some(ThreatIntelVersionEnvelope {
                        version: res.version,
                        bundle_path: res.bundle_path,
                        sigma_count: res.sigma_count,
                        yara_count: res.yara_count,
                        ioc_count: res.ioc_count,
                        cve_count: res.cve_count,
                    }))
                })
                .await
            }
        }
    }

    pub async fn check_server_state(&self) -> Result<Option<ServerState>> {
        self.ensure_online()?;
        match self.mode {
            TransportMode::Http => {
                #[derive(Debug, Deserialize)]
                struct StateResponse {
                    state: Option<HashMap<String, serde_json::Value>>,
                }

                let response = self
                    .with_retry("check_state_http", || async {
                        let url = self.url_for("/api/v1/endpoint/state");
                        let response = self
                            .http
                            .get(&url)
                            .send()
                            .await
                            .with_context(|| format!("failed querying state from {}", url))?
                            .error_for_status()
                            .with_context(|| format!("state query rejected by {}", url))?;
                        response
                            .json::<StateResponse>()
                            .await
                            .context("invalid server state response payload")
                    })
                    .await;

                match response {
                    Ok(res) => {
                        if let Some(state) = res.state {
                            let persistence_enabled = state
                                .get("persistence_enabled")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            return Ok(Some(ServerState { persistence_enabled }));
                        }
                        Ok(None)
                    }
                    Err(err) => {
                        warn!(error = %err, "failed to query server state");
                        Ok(None)
                    }
                }
            }
            TransportMode::Grpc => {
                self.with_retry("check_state_grpc", || async {
                    let channel = self.connect_channel().await?;
                    let mut client = pb::agent_control_service_client::AgentControlServiceClient::new(channel);
                    let res = client
                        .ping(pb::PingRequest {
                            agent_id: String::new(),
                        })
                        .await
                        .context("ping RPC failed")?
                        .into_inner();

                    if res.status.is_empty() {
                        Ok(None)
                    } else {
                        Ok(Some(ServerState {
                            persistence_enabled: false,
                        }))
                    }
                })
                .await
            }
        }
    }

    fn ensure_online(&self) -> Result<()> {
        if !self.online {
            anyhow::bail!("server unreachable: {}", self.server_addr);
        }
        Ok(())
    }

    fn grpc_base_url(&self) -> String {
        let raw = self.url_for_base();
        if raw.starts_with("https://") || raw.starts_with("http://") {
            raw
        } else {
            format!("http://{}", raw)
        }
    }

    fn url_for_base(&self) -> String {
        if self.server_addr.starts_with("http://") || self.server_addr.starts_with("https://") {
            return self.server_addr.clone();
        }
        if self.tls.is_some() {
            format!("https://{}", self.server_addr)
        } else {
            format!("http://{}", self.server_addr)
        }
    }

    fn url_for(&self, path: &str) -> String {
        format!("{}{}", self.url_for_base().trim_end_matches('/'), path)
    }

    fn grpc_endpoint(&self) -> Result<Endpoint> {
        let endpoint = Endpoint::from_shared(self.grpc_base_url())
            .context("invalid gRPC endpoint URL")?
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15));

        if let Some(tls) = &self.tls {
            let tls_cfg = self.load_tls_config(tls)?;
            Ok(endpoint.tls_config(tls_cfg).context("invalid gRPC TLS config")?)
        } else {
            Ok(endpoint)
        }
    }

    fn load_tls_config(&self, tls: &TlsConfig) -> Result<ClientTlsConfig> {
        let cert = std::fs::read(&tls.cert_path)
            .with_context(|| format!("failed reading TLS cert {}", tls.cert_path))?;
        let key = std::fs::read(&tls.key_path)
            .with_context(|| format!("failed reading TLS key {}", tls.key_path))?;
        let ca = std::fs::read(&tls.ca_path)
            .with_context(|| format!("failed reading TLS CA {}", tls.ca_path))?;

        Ok(ClientTlsConfig::new()
            .identity(Identity::from_pem(cert, key))
            .ca_certificate(Certificate::from_pem(ca)))
    }

    async fn connect_channel(&self) -> Result<Channel> {
        let endpoint = self.grpc_endpoint()?;
        endpoint
            .connect()
            .await
            .context("failed connecting gRPC channel")
    }

    async fn with_retry<T, F, Fut>(&self, operation_name: &'static str, mut op: F) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let mut attempt = 1u32;
        loop {
            match op().await {
                Ok(result) => return Ok(result),
                Err(err) => {
                    if attempt >= self.retry.max_attempts {
                        return Err(err).with_context(|| {
                            format!(
                                "operation {} failed after {} attempts",
                                operation_name,
                                attempt
                            )
                        });
                    }

                    let delay = self.retry.next_delay(attempt.saturating_sub(1));
                    warn!(
                        operation = operation_name,
                        attempt,
                        delay_ms = delay.as_millis() as u64,
                        error = %err,
                        "transport call failed, retrying"
                    );
                    sleep(delay).await;
                    attempt += 1;
                }
            }
        }
    }
}

fn to_pb_telemetry_event(event: &EventEnvelope) -> pb::TelemetryEvent {
    pb::TelemetryEvent {
        agent_id: event.agent_id.clone(),
        event_type: event.event_type.clone(),
        severity: String::new(),
        rule_name: String::new(),
        payload_json: event.payload_json.clone(),
        labels: HashMap::new(),
        created_at_unix: event.created_at_unix,
    }
}

fn from_pb_agent_command(command: pb::AgentCommand) -> CommandEnvelope {
    CommandEnvelope {
        command_id: command.command_id,
        command_type: command.command_type,
        payload_json: command.payload_json,
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_scheme_defaults_to_http_without_tls() {
        let c = Client::new("10.0.0.1:50051".to_string());
        let u = c.url_for("/api/v1/endpoint/ping");
        assert!(u.starts_with("http://"));
    }

    #[test]
    fn url_scheme_switches_to_https_with_tls() {
        let base = std::env::temp_dir().join(format!(
            "eguard-agent-tls-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        let _ = std::fs::create_dir_all(&base);

        let cert = base.join("agent.crt");
        let key = base.join("agent.key");
        let ca = base.join("ca.crt");
        let _ = std::fs::write(&cert, b"x");
        let _ = std::fs::write(&key, b"x");
        let _ = std::fs::write(&ca, b"x");

        let mut c = Client::new("10.0.0.1:50051".to_string());
        c.configure_tls(TlsConfig {
            cert_path: cert.to_string_lossy().into_owned(),
            key_path: key.to_string_lossy().into_owned(),
            ca_path: ca.to_string_lossy().into_owned(),
        })
        .expect("configure tls");

        let u = c.url_for("/api/v1/endpoint/ping");
        assert!(u.starts_with("https://"));

        let _ = std::fs::remove_file(cert);
        let _ = std::fs::remove_file(key);
        let _ = std::fs::remove_file(ca);
        let _ = std::fs::remove_dir(base);
    }
}
