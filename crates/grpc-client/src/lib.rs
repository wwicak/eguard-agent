use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client as HttpClient;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tonic::transport::Endpoint;
use tracing::{info, warn};

pub mod pb {
    tonic::include_proto!("eguard.v1");
}

pub const DEFAULT_BUFFER_CAP_BYTES: usize = 100 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    Http,
    Grpc,
}

impl TransportMode {
    pub fn from_str(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "grpc" | "tonic" => Self::Grpc,
            _ => Self::Http,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub agent_id: String,
    pub event_type: String,
    pub payload_json: String,
    pub created_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandEnvelope {
    pub command_id: String,
    pub command_type: String,
    pub payload_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentEnvelope {
    pub agent_id: String,
    pub mac: String,
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceEnvelope {
    pub agent_id: String,
    pub policy_id: String,
    pub check_type: String,
    pub status: String,
    pub detail: String,
    pub expected_value: String,
    pub actual_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub agent_id: String,
    pub action_type: String,
    pub confidence: String,
    pub success: bool,
    pub error_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelVersionEnvelope {
    pub version: String,
    pub bundle_path: String,
    pub sigma_count: i64,
    pub yara_count: i64,
    pub ioc_count: i64,
    pub cve_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub ca_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerState {
    pub persistence_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub min_backoff: Duration,
    pub max_backoff: Duration,
    pub multiplier: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            min_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            multiplier: 2,
        }
    }
}

impl RetryPolicy {
    pub fn next_delay(&self, attempt: u32) -> Duration {
        let factor = self.multiplier.saturating_pow(attempt);
        let d = self.min_backoff.saturating_mul(factor);
        d.min(self.max_backoff)
    }
}

#[derive(Debug)]
pub struct OfflineBuffer {
    queue: VecDeque<EventEnvelope>,
    current_bytes: usize,
    cap_bytes: usize,
}

impl OfflineBuffer {
    pub fn new(cap_bytes: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            current_bytes: 0,
            cap_bytes,
        }
    }

    pub fn enqueue(&mut self, event: EventEnvelope) {
        let size = estimate_event_size(&event);
        while self.current_bytes.saturating_add(size) > self.cap_bytes {
            if let Some(old) = self.queue.pop_front() {
                self.current_bytes = self.current_bytes.saturating_sub(estimate_event_size(&old));
            } else {
                break;
            }
        }
        self.current_bytes = self.current_bytes.saturating_add(size);
        self.queue.push_back(event);
    }

    pub fn drain_batch(&mut self, max_items: usize) -> Vec<EventEnvelope> {
        let mut out = Vec::with_capacity(max_items);
        for _ in 0..max_items {
            if let Some(ev) = self.queue.pop_front() {
                self.current_bytes = self.current_bytes.saturating_sub(estimate_event_size(&ev));
                out.push(ev);
            } else {
                break;
            }
        }
        out
    }

    pub fn pending_count(&self) -> usize {
        self.queue.len()
    }

    pub fn pending_bytes(&self) -> usize {
        self.current_bytes
    }
}

impl Default for OfflineBuffer {
    fn default() -> Self {
        Self::new(DEFAULT_BUFFER_CAP_BYTES)
    }
}

pub fn estimate_event_size(e: &EventEnvelope) -> usize {
    e.agent_id.len() + e.event_type.len() + e.payload_json.len() + 16
}

#[derive(Debug)]
pub struct SqliteBuffer {
    conn: Connection,
    cap_bytes: usize,
}

impl SqliteBuffer {
    pub fn new(path: &str, cap_bytes: usize) -> Result<Self> {
        if let Some(parent) = Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed creating sqlite parent dir {}", parent.display()))?;
            }
        }

        let conn = Connection::open(path)
            .with_context(|| format!("failed opening sqlite buffer {}", path))?;
        conn.execute_batch(
            "
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            CREATE TABLE IF NOT EXISTS offline_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at_unix INTEGER NOT NULL,
                size_bytes INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_offline_events_id ON offline_events(id);
        ",
        )
        .context("failed initializing sqlite schema")?;

        Ok(Self { conn, cap_bytes })
    }

    pub fn enqueue(&mut self, event: EventEnvelope) -> Result<()> {
        let size = estimate_event_size(&event) as i64;
        self.conn.execute(
            "INSERT INTO offline_events(agent_id,event_type,payload_json,created_at_unix,size_bytes) VALUES(?1,?2,?3,?4,?5)",
            params![event.agent_id, event.event_type, event.payload_json, event.created_at_unix, size],
        )?;
        self.enforce_cap()
    }

    pub fn drain_batch(&mut self, max_items: usize) -> Result<Vec<EventEnvelope>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, agent_id, event_type, payload_json, created_at_unix FROM offline_events ORDER BY id ASC LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![max_items as i64], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                EventEnvelope {
                    agent_id: row.get::<_, String>(1)?,
                    event_type: row.get::<_, String>(2)?,
                    payload_json: row.get::<_, String>(3)?,
                    created_at_unix: row.get::<_, i64>(4)?,
                },
            ))
        })?;

        let mut ids = Vec::new();
        let mut out = Vec::new();
        for row in rows {
            let (id, event) = row?;
            ids.push(id);
            out.push(event);
        }
        drop(stmt);

        for id in ids {
            self.conn
                .execute("DELETE FROM offline_events WHERE id = ?1", params![id])?;
        }

        Ok(out)
    }

    pub fn pending_count(&self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM offline_events", [], |row| row.get(0))?;
        Ok(count.max(0) as usize)
    }

    pub fn pending_bytes(&self) -> Result<usize> {
        let total: Option<i64> = self
            .conn
            .query_row("SELECT SUM(size_bytes) FROM offline_events", [], |row| row.get(0))
            .optional()?
            .flatten();
        Ok(total.unwrap_or(0).max(0) as usize)
    }

    fn enforce_cap(&mut self) -> Result<()> {
        loop {
            let bytes = self.pending_bytes()?;
            if bytes <= self.cap_bytes {
                break;
            }

            let deleted = self.conn.execute(
                "DELETE FROM offline_events WHERE id = (SELECT id FROM offline_events ORDER BY id ASC LIMIT 1)",
                [],
            )?;
            if deleted == 0 {
                break;
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum EventBuffer {
    Memory(OfflineBuffer),
    Sqlite(SqliteBuffer),
}

impl EventBuffer {
    pub fn memory(cap_bytes: usize) -> Self {
        Self::Memory(OfflineBuffer::new(cap_bytes))
    }

    pub fn sqlite(path: &str, cap_bytes: usize) -> Result<Self> {
        Ok(Self::Sqlite(SqliteBuffer::new(path, cap_bytes)?))
    }

    pub fn enqueue(&mut self, event: EventEnvelope) -> Result<()> {
        match self {
            Self::Memory(buf) => {
                buf.enqueue(event);
                Ok(())
            }
            Self::Sqlite(buf) => buf.enqueue(event),
        }
    }

    pub fn drain_batch(&mut self, max_items: usize) -> Result<Vec<EventEnvelope>> {
        match self {
            Self::Memory(buf) => Ok(buf.drain_batch(max_items)),
            Self::Sqlite(buf) => buf.drain_batch(max_items),
        }
    }

    pub fn pending_count(&self) -> usize {
        match self {
            Self::Memory(buf) => buf.pending_count(),
            Self::Sqlite(buf) => match buf.pending_count() {
                Ok(v) => v,
                Err(err) => {
                    warn!(error = %err, "failed reading sqlite pending count");
                    0
                }
            },
        }
    }

    pub fn pending_bytes(&self) -> usize {
        match self {
            Self::Memory(buf) => buf.pending_bytes(),
            Self::Sqlite(buf) => match buf.pending_bytes() {
                Ok(v) => v,
                Err(err) => {
                    warn!(error = %err, "failed reading sqlite pending bytes");
                    0
                }
            },
        }
    }
}

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
        match self.mode {
            TransportMode::Http => {
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
            }
            TransportMode::Grpc => {
                let mut client = pb::telemetry_service_client::TelemetryServiceClient::connect(self.grpc_base_url()).await?;
                for event in batch {
                    let req = pb::TelemetryEvent {
                        agent_id: event.agent_id.clone(),
                        event_type: event.event_type.clone(),
                        severity: String::new(),
                        rule_name: String::new(),
                        payload_json: event.payload_json.clone(),
                        labels: HashMap::new(),
                        created_at_unix: event.created_at_unix,
                    };
                    client.send_event(req).await?;
                }
            }
        }
        info!(count = batch.len(), server = %self.server_addr, mode = ?self.mode, "sent event batch");
        Ok(())
    }

    pub async fn enroll(&self, enrollment: &EnrollmentEnvelope) -> Result<()> {
        self.ensure_online()?;
        match self.mode {
            TransportMode::Http => {
                let url = self.url_for("/api/v1/endpoint/enroll");
                self.http
                    .post(&url)
                    .json(enrollment)
                    .send()
                    .await
                    .with_context(|| format!("failed sending enrollment to {}", url))?
                    .error_for_status()
                    .with_context(|| format!("enrollment rejected by {}", url))?;
            }
            TransportMode::Grpc => {
                let mut client = pb::agent_control_service_client::AgentControlServiceClient::connect(self.grpc_base_url()).await?;
                let req = pb::EnrollRequest {
                    agent_id: enrollment.agent_id.clone(),
                    mac: enrollment.mac.clone(),
                    hostname: enrollment.hostname.clone(),
                    os_type: "linux".to_string(),
                    agent_version: "0.1.0".to_string(),
                };
                client.enroll(req).await?;
            }
        }
        Ok(())
    }

    pub async fn send_heartbeat(&self, agent_id: &str, compliance_status: &str) -> Result<()> {
        self.ensure_online()?;
        match self.mode {
            TransportMode::Http => {
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
            }
            TransportMode::Grpc => {
                let mut client = pb::agent_control_service_client::AgentControlServiceClient::connect(self.grpc_base_url()).await?;
                client
                    .heartbeat(pb::HeartbeatRequest {
                        agent_id: agent_id.to_string(),
                        agent_version: "0.1.0".to_string(),
                        compliance_status: compliance_status.to_string(),
                        sent_at_unix: now_unix(),
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
                let url = self.url_for("/api/v1/endpoint/compliance");
                self.http
                    .post(&url)
                    .json(compliance)
                    .send()
                    .await
                    .with_context(|| format!("failed sending compliance to {}", url))?
                    .error_for_status()
                    .with_context(|| format!("compliance rejected by {}", url))?;
            }
            TransportMode::Grpc => {
                let mut client = pb::compliance_service_client::ComplianceServiceClient::connect(self.grpc_base_url()).await?;
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
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn send_response(&self, response: &ResponseEnvelope) -> Result<()> {
        self.ensure_online()?;
        match self.mode {
            TransportMode::Http => {
                let url = self.url_for("/api/v1/endpoint/response");
                self.http
                    .post(&url)
                    .json(response)
                    .send()
                    .await
                    .with_context(|| format!("failed sending response to {}", url))?
                    .error_for_status()
                    .with_context(|| format!("response rejected by {}", url))?;
            }
            TransportMode::Grpc => {
                let mut client = pb::response_service_client::ResponseServiceClient::connect(self.grpc_base_url()).await?;
                client
                    .report_response(pb::ResponseReport {
                        agent_id: response.agent_id.clone(),
                        action: response.action_type.clone(),
                        confidence: response.confidence.clone(),
                        success: response.success,
                        detail: response.error_message.clone(),
                        created_at_unix: now_unix(),
                    })
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn fetch_commands(&mut self, agent_id: &str, limit: usize) -> Result<Vec<CommandEnvelope>> {
        self.ensure_online()?;

        let server_result = match self.mode {
            TransportMode::Http => {
                #[derive(Debug, Deserialize)]
                struct PollResponse {
                    commands: Vec<CommandEnvelope>,
                }
                let url = self.url_for("/api/v1/endpoint/command/pending");
                let response = self
                    .http
                    .get(&url)
                    .query(&[("agent_id", agent_id)])
                    .send()
                    .await;
                match response {
                    Ok(resp) => match resp.error_for_status() {
                        Ok(resp) => resp.json::<PollResponse>().await.map(|v| v.commands),
                        Err(err) => Err(err),
                    },
                    Err(err) => Err(err),
                }
            }
            TransportMode::Grpc => {
                let mut client = pb::command_service_client::CommandServiceClient::connect(self.grpc_base_url()).await?;
                client
                    .poll_commands(pb::PollCommandsRequest {
                        agent_id: agent_id.to_string(),
                        limit: limit as i32,
                    })
                    .await
                    .map(|r| {
                        r.into_inner()
                            .commands
                            .into_iter()
                            .map(|c| CommandEnvelope {
                                command_id: c.command_id,
                                command_type: c.command_type,
                                payload_json: c.payload_json,
                            })
                            .collect::<Vec<_>>()
                    })
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
                let url = self.url_for("/api/v1/endpoint/command/ack");
                self.http
                    .post(&url)
                    .json(&json!({"command_id": command_id, "status": status}))
                    .send()
                    .await
                    .with_context(|| format!("failed acking command to {}", url))?
                    .error_for_status()
                    .with_context(|| format!("command ack rejected by {}", url))?;
            }
            TransportMode::Grpc => {
                let mut client = pb::command_service_client::CommandServiceClient::connect(self.grpc_base_url()).await?;
                client
                    .ack_command(pb::AckCommandRequest {
                        command_id: command_id.to_string(),
                        status: status.to_string(),
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
                let url = self.url_for("/api/v1/endpoint/threat-intel/version");
                #[derive(Debug, Deserialize)]
                struct VersionsResponse {
                    versions: Vec<ThreatIntelVersionEnvelope>,
                }

                let response = self
                    .http
                    .get(&url)
                    .query(&[("limit", 1)])
                    .send()
                    .await;

                let response = match response {
                    Ok(resp) => match resp.error_for_status() {
                        Ok(resp) => resp.json::<VersionsResponse>().await,
                        Err(err) => Err(err),
                    },
                    Err(err) => Err(err),
                };

                match response {
                    Ok(mut res) => Ok(res.versions.drain(..).next()),
                    Err(err) => {
                        warn!(error = %err, "failed to fetch threat intel version");
                        Ok(None)
                    }
                }
            }
            TransportMode::Grpc => {
                let mut client = pb::agent_control_service_client::AgentControlServiceClient::connect(self.grpc_base_url()).await?;
                let res = client
                    .get_latest_threat_intel(pb::ThreatIntelRequest {
                        agent_id: String::new(),
                    })
                    .await?
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
            }
        }
    }

    pub async fn check_server_state(&self) -> Result<Option<ServerState>> {
        self.ensure_online()?;
        match self.mode {
            TransportMode::Http => {
                let url = self.url_for("/api/v1/endpoint/state");
                #[derive(Debug, Deserialize)]
                struct StateResponse {
                    state: Option<HashMap<String, serde_json::Value>>,
                }

                let response = self
                    .http
                    .get(&url)
                    .send()
                    .await;

                let response = match response {
                    Ok(resp) => match resp.error_for_status() {
                        Ok(resp) => resp.json::<StateResponse>().await,
                        Err(err) => Err(err),
                    },
                    Err(err) => Err(err),
                };

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
                let mut client = pb::agent_control_service_client::AgentControlServiceClient::connect(self.grpc_base_url()).await?;
                let res = client
                    .ping(pb::PingRequest {
                        agent_id: String::new(),
                    })
                    .await?
                    .into_inner();
                if res.status.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(ServerState {
                        persistence_enabled: false,
                    }))
                }
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

    async fn _grpc_endpoint(&self) -> Result<Endpoint> {
        Ok(Endpoint::from_shared(self.grpc_base_url())?)
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

    fn sample_event(i: i64) -> EventEnvelope {
        EventEnvelope {
            agent_id: "a1".to_string(),
            event_type: "process_exec".to_string(),
            payload_json: format!("{{\"n\":{i}}}"),
            created_at_unix: i,
        }
    }

    #[test]
    fn memory_buffer_enforces_cap() {
        let mut b = OfflineBuffer::new(80);
        for i in 0..20 {
            b.enqueue(sample_event(i));
        }
        assert!(b.pending_count() < 20);
        assert!(b.pending_bytes() <= 80);
    }

    #[test]
    fn sqlite_buffer_roundtrip() {
        let unique = format!(
            "eguard-agent-test-{}.db",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        );
        let path = std::env::temp_dir().join(unique);
        let path_str = path.to_string_lossy().into_owned();

        let mut b = SqliteBuffer::new(&path_str, 1024).expect("sqlite open");
        b.enqueue(sample_event(1)).expect("enqueue 1");
        b.enqueue(sample_event(2)).expect("enqueue 2");

        let out = b.drain_batch(10).expect("drain");
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].created_at_unix, 1);
        assert_eq!(out[1].created_at_unix, 2);

        let _ = std::fs::remove_file(path);
    }

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
