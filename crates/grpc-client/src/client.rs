use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client as HttpClient;
use tokio::time::sleep;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tracing::{info, warn};

use crate::pb;
use crate::retry::RetryPolicy;
use crate::types::{
    CommandEnvelope, ComplianceEnvelope, EnrollmentEnvelope, EventEnvelope, ResponseEnvelope,
    ServerState, ThreatIntelVersionEnvelope, TlsConfig, TransportMode,
};

#[path = "client/client_grpc.rs"]
mod client_grpc;
#[path = "client/client_http.rs"]
mod client_http;

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
            TransportMode::Http => self.send_events_http(batch).await?,
            TransportMode::Grpc => self.send_events_grpc(batch).await?,
        }

        info!(count = batch.len(), server = %self.server_addr, mode = ?self.mode, "sent event batch");
        Ok(())
    }

    pub async fn enroll(&self, enrollment: &EnrollmentEnvelope) -> Result<()> {
        self.ensure_online()?;
        match self.mode {
            TransportMode::Http => self.enroll_http(enrollment).await?,
            TransportMode::Grpc => self.enroll_grpc(enrollment).await?,
        }
        Ok(())
    }

    pub async fn send_heartbeat(&self, agent_id: &str, compliance_status: &str) -> Result<()> {
        self.ensure_online()?;
        match self.mode {
            TransportMode::Http => {
                self.send_heartbeat_http(agent_id, compliance_status)
                    .await?
            }
            TransportMode::Grpc => {
                self.send_heartbeat_grpc(agent_id, compliance_status)
                    .await?
            }
        }
        Ok(())
    }

    pub async fn send_compliance(&self, compliance: &ComplianceEnvelope) -> Result<()> {
        self.ensure_online()?;
        match self.mode {
            TransportMode::Http => self.send_compliance_http(compliance).await?,
            TransportMode::Grpc => self.send_compliance_grpc(compliance).await?,
        }
        Ok(())
    }

    pub async fn send_response(&self, response: &ResponseEnvelope) -> Result<()> {
        self.ensure_online()?;
        match self.mode {
            TransportMode::Http => self.send_response_http(response).await?,
            TransportMode::Grpc => self.send_response_grpc(response).await?,
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
                self.stream_command_channel_http(agent_id, completed_command_ids, limit)
                    .await
            }
            TransportMode::Grpc => {
                self.stream_command_channel_grpc(agent_id, completed_command_ids, limit)
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
            Ok(commands) => {
                let commands = truncate_commands(commands, limit);
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
            TransportMode::Http => self.poll_commands_http(agent_id, limit).await,
            TransportMode::Grpc => self.poll_commands_grpc(agent_id, limit).await,
        };

        match server_result {
            Ok(commands) => Ok(truncate_commands(commands, limit)),
            Err(err) => {
                warn!(error = %err, mode = ?self.mode, "failed to fetch commands, falling back to in-memory queue");
                Ok(self.take_pending_commands(limit))
            }
        }
    }

    pub async fn ack_command(&self, command_id: &str, status: &str) -> Result<()> {
        self.ensure_online()?;
        match self.mode {
            TransportMode::Http => self.ack_command_http(command_id, status).await?,
            TransportMode::Grpc => self.ack_command_grpc(command_id, status).await?,
        }
        Ok(())
    }

    pub async fn fetch_latest_threat_intel(&self) -> Result<Option<ThreatIntelVersionEnvelope>> {
        self.ensure_online()?;
        match self.mode {
            TransportMode::Http => self.fetch_latest_threat_intel_http().await,
            TransportMode::Grpc => self.fetch_latest_threat_intel_grpc().await,
        }
    }

    pub async fn download_bundle<P: AsRef<Path>>(
        &self,
        bundle_ref: &str,
        dest_path: P,
    ) -> Result<()> {
        self.ensure_online()?;
        self.download_bundle_http(bundle_ref, dest_path).await
    }

    pub async fn check_server_state(&self) -> Result<Option<ServerState>> {
        self.ensure_online()?;
        match self.mode {
            TransportMode::Http => self.check_server_state_http().await,
            TransportMode::Grpc => self.check_server_state_grpc().await,
        }
    }

    fn take_pending_commands(&mut self, limit: usize) -> Vec<CommandEnvelope> {
        let mut out = Vec::with_capacity(limit);
        for _ in 0..limit {
            if let Some(cmd) = self.pending_commands.pop_front() {
                out.push(cmd);
            } else {
                break;
            }
        }
        out
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

    fn resolve_bundle_download_url(&self, bundle_ref: &str) -> Result<String> {
        let bundle_ref = bundle_ref.trim();
        if bundle_ref.is_empty() {
            anyhow::bail!("bundle reference cannot be empty");
        }

        if bundle_ref.starts_with("http://") || bundle_ref.starts_with("https://") {
            return Ok(bundle_ref.to_string());
        }

        if bundle_ref.starts_with("/") {
            return Ok(self.url_for(bundle_ref));
        }

        if bundle_ref.starts_with("api/") {
            return Ok(self.url_for(&format!("/{}", bundle_ref)));
        }

        anyhow::bail!("unsupported bundle reference '{}'", bundle_ref);
    }

    fn grpc_endpoint(&self) -> Result<Endpoint> {
        let endpoint = Endpoint::from_shared(self.grpc_base_url())
            .context("invalid gRPC endpoint URL")?
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15));

        if let Some(tls) = &self.tls {
            let tls_cfg = self.load_tls_config(tls)?;
            Ok(endpoint
                .tls_config(tls_cfg)
                .context("invalid gRPC TLS config")?)
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
                                operation_name, attempt
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

fn truncate_commands(mut commands: Vec<CommandEnvelope>, limit: usize) -> Vec<CommandEnvelope> {
    if commands.len() > limit {
        commands.truncate(limit);
    }
    commands
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
mod tests;
