use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::{
    Certificate as HttpCertificate, Client as HttpClient, Identity as HttpIdentity, Url as HttpUrl,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::time::sleep;
use tonic::transport::{
    Certificate as TonicCertificate, Channel, ClientTlsConfig, Endpoint, Identity as TonicIdentity,
};
use tonic::Code;
use tracing::{info, warn};

use crate::pb;
use crate::retry::RetryPolicy;
use crate::types::{
    CommandEnvelope, ComplianceEnvelope, EnrollmentEnvelope, EnrollmentResultEnvelope,
    EventEnvelope, FleetBaselineEnvelope, InventoryEnvelope, PolicyEnvelope, ResponseEnvelope,
    ServerState, ThreatIntelVersionEnvelope, TlsConfig, TransportMode,
};

#[path = "client/client_grpc.rs"]
mod client_grpc;
#[path = "client/client_http.rs"]
mod client_http;

pub(crate) const MAX_GRPC_RECV_MSG_SIZE_BYTES: usize = 16 << 20;
const TLS_PINNED_CA_SHA256_ENV: &str = "EGUARD_TLS_PINNED_CA_SHA256";
const TLS_CA_PIN_PATH_ENV: &str = "EGUARD_TLS_CA_PIN_PATH";
const TLS_BOOTSTRAP_PIN_ON_FIRST_USE_ENV: &str = "EGUARD_TLS_BOOTSTRAP_PIN_ON_FIRST_USE";
const ALLOW_EXTERNAL_BUNDLE_URLS_ENV: &str = "EGUARD_ALLOW_EXTERNAL_BUNDLE_URLS";

#[derive(Debug, Clone)]
pub struct Client {
    server_addr: String,
    mode: TransportMode,
    retry: RetryPolicy,
    online: bool,
    agent_version: String,
    pending_commands: VecDeque<CommandEnvelope>,
    tls: Option<TlsConfig>,
    http: HttpClient,
    grpc_reporting_force_http: Arc<AtomicBool>,
    grpc_channel_cache: Arc<Mutex<Option<Channel>>>,
    #[cfg(test)]
    grpc_channel_override: Option<Channel>,
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
            agent_version: default_agent_version(),
            pending_commands: VecDeque::new(),
            tls: None,
            http: Self::build_http_client(None)
                .expect("default HTTP client construction should not fail"),
            grpc_reporting_force_http: Arc::new(AtomicBool::new(false)),
            grpc_channel_cache: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            grpc_channel_override: None,
        }
    }

    pub fn set_online(&mut self, online: bool) {
        self.online = online;
    }

    pub fn is_online(&self) -> bool {
        self.online
    }

    pub fn server_addr(&self) -> &str {
        &self.server_addr
    }

    pub fn set_agent_version(&mut self, version: impl Into<String>) {
        self.agent_version = version.into();
    }

    pub fn agent_version(&self) -> &str {
        &self.agent_version
    }

    pub fn configure_tls(&mut self, cfg: TlsConfig) -> Result<()> {
        for path in [&cfg.cert_path, &cfg.key_path, &cfg.ca_path] {
            if !Path::new(path).exists() {
                anyhow::bail!("TLS file does not exist: {}", path);
            }
        }

        self.enforce_ca_pin(&cfg)?;
        self.http = Self::build_http_client(Some(&cfg))?;
        self.tls = Some(cfg);
        self.grpc_reporting_force_http
            .store(false, Ordering::Relaxed);
        if let Ok(mut cached) = self.grpc_channel_cache.lock() {
            *cached = None;
        }
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
            TransportMode::Grpc => {
                if self.grpc_reporting_force_http.load(Ordering::Relaxed) {
                    match self.send_events_grpc(batch).await {
                        Ok(()) => {
                            self.grpc_reporting_force_http
                                .store(false, Ordering::Relaxed);
                        }
                        Err(err) => {
                            warn!(
                                error = %err,
                                "gRPC telemetry send still unavailable; using HTTP telemetry fallback"
                            );
                            self.send_events_http(batch).await?;
                        }
                    }
                } else if let Err(err) = self.send_events_grpc(batch).await {
                    warn!(
                        error = %err,
                        "gRPC telemetry send failed, temporarily forcing HTTP telemetry fallback"
                    );
                    self.grpc_reporting_force_http
                        .store(true, Ordering::Relaxed);
                    self.send_events_http(batch).await?;
                }
            }
        }

        info!(count = batch.len(), server = %self.server_addr, mode = ?self.mode, "sent event batch");
        Ok(())
    }

    pub async fn enroll(&self, enrollment: &EnrollmentEnvelope) -> Result<()> {
        self.enroll_with_material(enrollment).await.map(|_| ())
    }

    pub async fn enroll_with_material(
        &self,
        enrollment: &EnrollmentEnvelope,
    ) -> Result<Option<EnrollmentResultEnvelope>> {
        self.ensure_online()?;
        match self.mode {
            TransportMode::Http => {
                self.enroll_http(enrollment).await?;
                Ok(None)
            }
            TransportMode::Grpc => self.enroll_grpc(enrollment).await,
        }
    }

    pub async fn send_heartbeat(&self, agent_id: &str, compliance_status: &str) -> Result<()> {
        self.send_heartbeat_with_config(agent_id, compliance_status, "", "")
            .await
    }

    pub async fn send_heartbeat_with_config(
        &self,
        agent_id: &str,
        compliance_status: &str,
        config_version: &str,
        baseline_status: &str,
    ) -> Result<()> {
        self.ensure_online()?;
        match self.mode {
            TransportMode::Http => {
                self.send_heartbeat_http(
                    agent_id,
                    compliance_status,
                    config_version,
                    baseline_status,
                )
                .await?
            }
            TransportMode::Grpc => {
                self.send_heartbeat_grpc(
                    agent_id,
                    compliance_status,
                    config_version,
                    baseline_status,
                )
                .await?
            }
        }
        Ok(())
    }

    pub async fn send_compliance(&self, compliance: &ComplianceEnvelope) -> Result<()> {
        self.ensure_online()?;
        match self.mode {
            TransportMode::Http => self.send_compliance_http(compliance).await?,
            TransportMode::Grpc => {
                if self.grpc_reporting_force_http.load(Ordering::Relaxed) {
                    match self.send_compliance_grpc(compliance).await {
                        Ok(()) => {
                            self.grpc_reporting_force_http
                                .store(false, Ordering::Relaxed);
                        }
                        Err(err) => {
                            warn!(
                                error = %err,
                                "gRPC compliance report still unavailable; using HTTP compliance fallback"
                            );
                            self.send_compliance_http(compliance).await?;
                        }
                    }
                } else if let Err(err) = self.send_compliance_grpc(compliance).await {
                    warn!(
                        error = %err,
                        "gRPC compliance report failed, temporarily forcing HTTP compliance fallback"
                    );
                    self.grpc_reporting_force_http
                        .store(true, Ordering::Relaxed);
                    self.send_compliance_http(compliance).await?;
                }
            }
        }
        Ok(())
    }

    pub async fn send_inventory(&self, inventory: &InventoryEnvelope) -> Result<()> {
        self.ensure_online()?;
        match self.mode {
            TransportMode::Http => self.send_inventory_http(inventory).await?,
            TransportMode::Grpc => {
                if let Err(err) = self.send_inventory_grpc(inventory).await {
                    warn!(error = %err, "gRPC inventory report failed, falling back to HTTP");
                    self.send_inventory_http(inventory).await?;
                }
            }
        }
        Ok(())
    }

    pub async fn send_response(&self, response: &ResponseEnvelope) -> Result<()> {
        self.ensure_online()?;
        match self.mode {
            TransportMode::Http => self.send_response_http(response).await?,
            TransportMode::Grpc => {
                if self.grpc_reporting_force_http.load(Ordering::Relaxed) {
                    match self.send_response_grpc(response).await {
                        Ok(()) => {
                            self.grpc_reporting_force_http
                                .store(false, Ordering::Relaxed);
                        }
                        Err(err) => {
                            warn!(
                                error = %err,
                                "gRPC response report still unavailable; using HTTP response fallback"
                            );
                            self.send_response_http(response).await?;
                        }
                    }
                } else if let Err(err) = self.send_response_grpc(response).await {
                    warn!(
                        error = %err,
                        "gRPC response report failed, temporarily forcing HTTP response fallback"
                    );
                    self.grpc_reporting_force_http
                        .store(true, Ordering::Relaxed);
                    self.send_response_http(response).await?;
                }
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
        if limit == 0 {
            return Ok(Vec::new());
        }

        let local = self.take_pending_commands(limit);
        if !local.is_empty() {
            return Ok(local);
        }

        self.ensure_online()?;

        if matches!(self.mode, TransportMode::Http) {
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
        }

        let server_result: Result<Vec<CommandEnvelope>> = match self.mode {
            TransportMode::Http => self.poll_commands_http(agent_id, limit).await,
            TransportMode::Grpc => match self.poll_commands_grpc(agent_id, limit).await {
                Ok(commands) => Ok(commands),
                Err(err) => {
                    warn!(
                        error = %err,
                        "gRPC command poll failed, falling back to HTTP command poll endpoint"
                    );
                    self.poll_commands_http(agent_id, limit).await
                }
            },
        };

        match server_result {
            Ok(commands) => Ok(truncate_commands(commands, limit)),
            Err(err) => {
                warn!(error = %err, mode = ?self.mode, "failed to fetch commands, falling back to in-memory queue");
                Ok(self.take_pending_commands(limit))
            }
        }
    }

    pub async fn ack_command(&self, agent_id: &str, command_id: &str, status: &str) -> Result<()> {
        self.ack_command_with_result(agent_id, command_id, status, None).await
    }

    pub async fn ack_command_with_result(
        &self,
        agent_id: &str,
        command_id: &str,
        status: &str,
        result_json: Option<&str>,
    ) -> Result<()> {
        self.ensure_online()?;
        match self.mode {
            TransportMode::Http => {
                self.ack_command_http(agent_id, command_id, status, result_json).await?
            }
            TransportMode::Grpc => {
                self.ack_command_grpc(agent_id, command_id, status, result_json).await?
            }
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

    pub async fn fetch_fleet_baselines(&self, limit: usize) -> Result<Vec<FleetBaselineEnvelope>> {
        self.ensure_online()?;
        self.fetch_fleet_baselines_http(limit).await
    }

    pub async fn fetch_policy(&self, agent_id: &str) -> Result<Option<PolicyEnvelope>> {
        self.ensure_online()?;
        match self.mode {
            TransportMode::Http => self.fetch_policy_http(agent_id).await,
            TransportMode::Grpc => match self.fetch_policy_grpc(agent_id).await {
                Ok(policy) => Ok(policy),
                Err(err) => {
                    warn!(
                        error = %err,
                        "gRPC policy fetch failed, falling back to HTTP policy endpoint"
                    );
                    self.fetch_policy_http(agent_id).await
                }
            },
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
            if !allow_external_bundle_urls() {
                let bundle_url = HttpUrl::parse(bundle_ref)
                    .with_context(|| format!("invalid absolute bundle URL '{}'", bundle_ref))?;
                let server_url = HttpUrl::parse(&self.url_for_base()).with_context(|| {
                    format!("invalid server base URL '{}'", self.url_for_base())
                })?;

                let same_host = bundle_url.host_str() == server_url.host_str()
                    && bundle_url.port_or_known_default() == server_url.port_or_known_default();
                if !same_host {
                    anyhow::bail!(
                        "external bundle URL '{}' is not allowed by default; set {}=1 to allow",
                        bundle_ref,
                        ALLOW_EXTERNAL_BUNDLE_URLS_ENV
                    );
                }
            }

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
            .timeout(Duration::from_secs(15))
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(10))
            .keep_alive_while_idle(true);

        if let Some(tls) = &self.tls {
            let tls_cfg = self.load_tls_config(tls)?;
            Ok(endpoint
                .tls_config(tls_cfg)
                .context("invalid gRPC TLS config")?)
        } else {
            Ok(endpoint)
        }
    }

    /// Invalidate the cached gRPC channel so the next call creates a fresh connection.
    fn invalidate_channel_cache(&self) {
        if let Ok(mut cached) = self.grpc_channel_cache.lock() {
            *cached = None;
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
            .identity(TonicIdentity::from_pem(cert, key))
            .ca_certificate(TonicCertificate::from_pem(ca)))
    }

    fn build_http_client(tls: Option<&TlsConfig>) -> Result<HttpClient> {
        let mut builder = HttpClient::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .tcp_keepalive(Duration::from_secs(30))
            .pool_idle_timeout(Duration::from_secs(60))
            .pool_max_idle_per_host(2);

        if let Some(tls) = tls {
            let cert = std::fs::read(&tls.cert_path)
                .with_context(|| format!("failed reading TLS cert {}", tls.cert_path))?;
            let key = std::fs::read(&tls.key_path)
                .with_context(|| format!("failed reading TLS key {}", tls.key_path))?;
            let ca = std::fs::read(&tls.ca_path)
                .with_context(|| format!("failed reading TLS CA {}", tls.ca_path))?;

            let mut identity_pem = Vec::with_capacity(cert.len() + key.len() + 1);
            identity_pem.extend_from_slice(&cert);
            if !cert.ends_with(b"\n") {
                identity_pem.push(b'\n');
            }
            identity_pem.extend_from_slice(&key);

            let identity =
                HttpIdentity::from_pem(&identity_pem).context("invalid HTTP TLS identity PEM")?;
            let ca_cert = HttpCertificate::from_pem(&ca).context("invalid HTTP TLS CA PEM")?;

            builder = builder.identity(identity).add_root_certificate(ca_cert);
        }

        builder.build().context("failed building HTTP client")
    }

    fn enforce_ca_pin(&self, tls: &TlsConfig) -> Result<()> {
        let ca_bytes = std::fs::read(&tls.ca_path)
            .with_context(|| format!("failed reading TLS CA {}", tls.ca_path))?;
        let actual_hash = sha256_hex(&ca_bytes);

        if let Some(expected_hash) = read_pinned_hash_from_literal(tls.pinned_ca_sha256.as_deref())?
        {
            if expected_hash != actual_hash {
                anyhow::bail!(
                    "TLS CA pin mismatch from TLS config: expected {}, got {}",
                    expected_hash,
                    actual_hash
                );
            }
            return Ok(());
        }

        if let Some(expected_hash) = read_pinned_hash_from_env()? {
            if expected_hash != actual_hash {
                anyhow::bail!(
                    "TLS CA pin mismatch from {}: expected {}, got {}",
                    TLS_PINNED_CA_SHA256_ENV,
                    expected_hash,
                    actual_hash
                );
            }
            return Ok(());
        }

        let pin_path = resolve_pin_path(&tls.ca_path, tls.ca_pin_path.as_deref());
        if pin_path.exists() {
            let pinned_hash = read_pinned_hash_from_file(&pin_path)?;
            if pinned_hash != actual_hash {
                anyhow::bail!(
                    "TLS CA pin mismatch at {}: expected {}, got {}",
                    pin_path.display(),
                    pinned_hash,
                    actual_hash
                );
            }
            return Ok(());
        }

        if !allow_tofu_pin_bootstrap() {
            anyhow::bail!(
                "TLS CA pin is missing (expected at {} or via {} / {} / config pin). Refusing TOFU by default; set {}=1 only for controlled bootstrap",
                pin_path.display(),
                TLS_PINNED_CA_SHA256_ENV,
                TLS_CA_PIN_PATH_ENV,
                TLS_BOOTSTRAP_PIN_ON_FIRST_USE_ENV,
            );
        }

        if let Some(parent) = pin_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed creating TLS pin directory {}", parent.display())
            })?;
        }
        std::fs::write(&pin_path, format!("{}\n", actual_hash))
            .with_context(|| format!("failed writing TLS CA pin {}", pin_path.display()))?;
        warn!(
            pin_path = %pin_path.display(),
            ca_path = %tls.ca_path,
            "bootstrapped TLS CA pin via first-use override"
        );

        Ok(())
    }

    #[cfg(test)]
    fn set_test_channel_override(&mut self, channel: Channel) {
        self.grpc_channel_override = Some(channel);
    }

    async fn connect_channel(&self) -> Result<Channel> {
        #[cfg(test)]
        if let Some(channel) = &self.grpc_channel_override {
            return Ok(channel.clone());
        }

        if let Ok(cached) = self.grpc_channel_cache.lock() {
            if let Some(channel) = cached.as_ref() {
                return Ok(channel.clone());
            }
        }

        let endpoint = self.grpc_endpoint()?;
        let channel = endpoint
            .connect()
            .await
            .context("failed connecting gRPC channel")?;

        if let Ok(mut cached) = self.grpc_channel_cache.lock() {
            *cached = Some(channel.clone());
        }

        Ok(channel)
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
                    if !is_retryable_transport_error(&err) {
                        return Err(err).with_context(|| {
                            format!(
                                "operation {} failed with non-retryable error on attempt {}",
                                operation_name, attempt
                            )
                        });
                    }

                    // Invalidate cached channel on connection errors so retries
                    // create a fresh connection instead of reusing a dead one.
                    if is_connection_error(&err) {
                        self.invalidate_channel_cache();
                    }

                    if attempt >= self.retry.max_attempts {
                        return Err(err).with_context(|| {
                            format!(
                                "operation {} failed after {} attempts",
                                operation_name, attempt
                            )
                        });
                    }

                    let delay = self.retry.next_delay_with_jitter(attempt.saturating_sub(1));
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

fn is_retryable_transport_error(err: &anyhow::Error) -> bool {
    for cause in err.chain() {
        if let Some(status) = cause.downcast_ref::<tonic::Status>() {
            return !matches!(
                status.code(),
                Code::InvalidArgument
                    | Code::Unauthenticated
                    | Code::AlreadyExists
                    | Code::PermissionDenied
                    | Code::FailedPrecondition
            );
        }

        if let Some(http_err) = cause.downcast_ref::<reqwest::Error>() {
            if let Some(status) = http_err.status() {
                if matches!(status.as_u16(), 400 | 401 | 403 | 404 | 409 | 422) {
                    return false;
                }
            }
        }
    }

    let lower = err.to_string().to_ascii_lowercase();
    let non_retryable_markers = [
        "invalid argument",
        "unauthenticated",
        "already exists",
        "permission denied",
        "failed precondition",
        "auth_misconfigured",
        "invalid_authentication",
        "authentication_required",
    ];
    !non_retryable_markers
        .iter()
        .any(|marker| lower.contains(marker))
}

/// Detect connection-level errors that indicate the gRPC channel is dead
/// and should be invalidated so retries create a fresh connection.
fn is_connection_error(err: &anyhow::Error) -> bool {
    let lower = err.to_string().to_ascii_lowercase();
    let connection_markers = [
        "failed connecting",
        "connection refused",
        "connection reset",
        "broken pipe",
        "transport error",
        "channel closed",
        "hyper",
        "h2 protocol error",
        "stream_events rpc failed",
    ];
    connection_markers
        .iter()
        .any(|marker| lower.contains(marker))
}

fn default_agent_version() -> String {
    std::env::var("EGUARD_AGENT_VERSION").unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string())
}

fn allow_tofu_pin_bootstrap() -> bool {
    std::env::var(TLS_BOOTSTRAP_PIN_ON_FIRST_USE_ENV)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn allow_external_bundle_urls() -> bool {
    std::env::var(ALLOW_EXTERNAL_BUNDLE_URLS_ENV)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn resolve_pin_path(ca_path: &str, configured_pin_path: Option<&str>) -> PathBuf {
    if let Some(path) = configured_pin_path {
        let path = path.trim();
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }

    if let Ok(path) = std::env::var(TLS_CA_PIN_PATH_ENV) {
        let path = path.trim();
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }

    let ca = PathBuf::from(ca_path);
    let file_name = ca
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("ca.crt");
    ca.with_file_name(format!("{}.pin.sha256", file_name))
}

fn read_pinned_hash_from_literal(raw: Option<&str>) -> Result<Option<String>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let normalized = normalize_sha256_hex(raw)?;
    Ok(Some(normalized))
}

fn read_pinned_hash_from_env() -> Result<Option<String>> {
    let raw = match std::env::var(TLS_PINNED_CA_SHA256_ENV) {
        Ok(raw) => raw,
        Err(_) => return Ok(None),
    };
    let normalized = normalize_sha256_hex(&raw)?;
    Ok(Some(normalized))
}

fn read_pinned_hash_from_file(path: &Path) -> Result<String> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed reading TLS CA pin {}", path.display()))?;
    normalize_sha256_hex(&raw)
}

fn normalize_sha256_hex(raw: &str) -> Result<String> {
    let value = raw
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(raw.trim())
        .to_ascii_lowercase();
    if value.len() != 64 || !value.bytes().all(|ch| ch.is_ascii_hexdigit()) {
        anyhow::bail!(
            "invalid SHA-256 fingerprint '{}': expected 64 hex chars",
            value
        );
    }
    Ok(value)
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    out
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => '0',
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
        event_id: format!("{}-{}", event.agent_id, event.created_at_unix),
        agent_id: event.agent_id.clone(),
        event_type: map_event_type(&event.event_type) as i32,
        severity: map_severity(&event.severity) as i32,
        timestamp: event.created_at_unix,
        pid: 0,
        ppid: 0,
        uid: 0,
        comm: String::new(),
        parent_comm: String::new(),
        rule_name: event.rule_name.clone(),
        payload_json: event.payload_json.clone(),
        labels: HashMap::new(),
        created_at_unix: event.created_at_unix,
        detail: None,
    }
}

fn from_pb_agent_command(command: pb::AgentCommand) -> CommandEnvelope {
    CommandEnvelope {
        command_id: command.command_id,
        command_type: command.command_type,
        payload_json: command.payload_json,
    }
}

fn from_pb_server_command(command: pb::ServerCommand) -> CommandEnvelope {
    let payload_json = match command.params {
        Some(pb::server_command::Params::Isolate(params)) => {
            json!({"allow_server_connection": params.allow_server_connection}).to_string()
        }
        Some(pb::server_command::Params::Scan(params)) => json!({
            "paths": params.paths,
            "yara_scan": params.yara_scan,
            "ioc_scan": params.ioc_scan
        })
        .to_string(),
        Some(pb::server_command::Params::Update(params)) => json!({
            "target_version": params.target_version,
            "download_url": params.download_url,
            "checksum": params.checksum
        })
        .to_string(),
        Some(pb::server_command::Params::Forensics(params)) => json!({
            "memory_dump": params.memory_dump,
            "process_list": params.process_list,
            "network_connections": params.network_connections,
            "open_files": params.open_files,
            "loaded_modules": params.loaded_modules,
            "target_pids": params.target_pids
        })
        .to_string(),
        Some(pb::server_command::Params::ConfigChange(params)) => json!({
            "config_json": params.config_json,
            "config_version": params.config_version
        })
        .to_string(),
        Some(pb::server_command::Params::RestoreQuarantine(params)) => json!({
            "sha256": params.sha256,
            "original_path": params.original_path
        })
        .to_string(),
        Some(pb::server_command::Params::Uninstall(params)) => json!({
            "auth_token": params.auth_token,
            "wipe_data": params.wipe_data
        })
        .to_string(),
        Some(pb::server_command::Params::Lock(params)) => {
            json!({"force": params.force, "reason": params.reason}).to_string()
        }
        Some(pb::server_command::Params::Wipe(params)) => {
            json!({"force": params.force, "reason": params.reason}).to_string()
        }
        Some(pb::server_command::Params::Retire(params)) => {
            json!({"force": params.force, "reason": params.reason}).to_string()
        }
        Some(pb::server_command::Params::Restart(params)) => {
            json!({"force": params.force, "reason": params.reason}).to_string()
        }
        Some(pb::server_command::Params::LostMode(params)) => {
            json!({"force": params.force, "reason": params.reason}).to_string()
        }
        Some(pb::server_command::Params::Locate(params)) => {
            json!({"high_accuracy": params.high_accuracy}).to_string()
        }
        Some(pb::server_command::Params::InstallApp(params)) => json!({
            "package_name": params.package_name,
            "version": params.version,
            "managed": params.managed
        })
        .to_string(),
        Some(pb::server_command::Params::RemoveApp(params)) => json!({
            "package_name": params.package_name,
            "version": params.version,
            "managed": params.managed
        })
        .to_string(),
        Some(pb::server_command::Params::UpdateApp(params)) => json!({
            "package_name": params.package_name,
            "version": params.version,
            "managed": params.managed
        })
        .to_string(),
        Some(pb::server_command::Params::ApplyProfile(params)) => json!({
            "profile_id": params.profile_id,
            "profile_json": params.profile_json
        })
        .to_string(),
        None => String::new(),
    };

    CommandEnvelope {
        command_id: command.command_id,
        command_type: map_command_type(command.command_type),
        payload_json,
    }
}

fn map_event_type(raw: &str) -> pb::EventType {
    match raw.trim().to_ascii_lowercase().as_str() {
        "process_exec" | "exec" => pb::EventType::ProcessExec,
        "file_open" | "file" => pb::EventType::FileOpen,
        "tcp_connect" | "tcp" => pb::EventType::TcpConnect,
        "dns_query" | "dns" => pb::EventType::DnsQuery,
        "module_load" | "module" => pb::EventType::ModuleLoad,
        "user_login" | "login" => pb::EventType::UserLogin,
        "alert" => pb::EventType::Alert,
        _ => pb::EventType::ProcessExec,
    }
}

fn map_severity(raw: &str) -> pb::Severity {
    match raw.trim().to_ascii_lowercase().as_str() {
        "low" => pb::Severity::Low,
        "medium" | "med" => pb::Severity::Medium,
        "high" => pb::Severity::High,
        "critical" => pb::Severity::Critical,
        _ => pb::Severity::Info,
    }
}

fn map_command_type(raw: i32) -> String {
    match pb::CommandType::try_from(raw).unwrap_or(pb::CommandType::RunScan) {
        pb::CommandType::IsolateHost => "isolate_host",
        pb::CommandType::UnisolateHost => "unisolate_host",
        pb::CommandType::RunScan => "run_scan",
        pb::CommandType::UpdateRules => "update_rules",
        pb::CommandType::ForensicsCollect => "forensics_collect",
        pb::CommandType::ConfigChange => "config_change",
        pb::CommandType::RestoreQuarantine => "restore_quarantine",
        pb::CommandType::Uninstall => "uninstall",
        pb::CommandType::EmergencyRulePush => "emergency_rule_push",
        pb::CommandType::LockDevice => "lock_device",
        pb::CommandType::WipeDevice => "wipe_device",
        pb::CommandType::RetireDevice => "retire_device",
        pb::CommandType::RestartDevice => "restart_device",
        pb::CommandType::LostMode => "lost_mode",
        pb::CommandType::LocateDevice => "locate_device",
        pb::CommandType::InstallApp => "install_app",
        pb::CommandType::RemoveApp => "remove_app",
        pb::CommandType::UpdateApp => "update_app",
        pb::CommandType::ApplyProfile => "apply_profile",
    }
    .to_string()
}

fn map_response_action(raw: &str) -> pb::ResponseAction {
    match raw.trim().to_ascii_lowercase().as_str() {
        "kill_process" | "kill" => pb::ResponseAction::KillProcess,
        "kill_tree" => pb::ResponseAction::KillTree,
        "quarantine_file" | "quarantine" => pb::ResponseAction::QuarantineFile,
        "block_execution" => pb::ResponseAction::BlockExecution,
        "block_connection" => pb::ResponseAction::BlockConnection,
        "capture_script" => pb::ResponseAction::CaptureScript,
        "network_isolate" => pb::ResponseAction::NetworkIsolate,
        _ => pb::ResponseAction::KillProcess,
    }
}

fn map_response_confidence(raw: &str) -> pb::ResponseConfidence {
    match raw.trim().to_ascii_lowercase().as_str() {
        "definite" => pb::ResponseConfidence::Definite,
        "very_high" | "very-high" => pb::ResponseConfidence::VeryHigh,
        "high" => pb::ResponseConfidence::High,
        "medium" => pb::ResponseConfidence::Medium,
        "low" => pb::ResponseConfidence::Low,
        "none" => pb::ResponseConfidence::None,
        _ => pb::ResponseConfidence::Medium,
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::await_holding_lock)]
mod tests;
#[cfg(test)]
mod tests_mappings;
