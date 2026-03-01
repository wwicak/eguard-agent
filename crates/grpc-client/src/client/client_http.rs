use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::warn;

use crate::types::{
    BaselineProfileEnvelope, CommandEnvelope, ComplianceEnvelope, EnrollmentEnvelope,
    EventEnvelope, FleetBaselineEnvelope, InventoryEnvelope, PolicyEnvelope, ResponseEnvelope,
    ServerState, ThreatIntelVersionEnvelope,
};

use super::Client;

const PATH_ENROLL: &str = "/api/v1/endpoint/enroll";
const PATH_TELEMETRY: &str = "/api/v1/endpoint/telemetry";
const PATH_HEARTBEAT: &str = "/api/v1/endpoint/heartbeat";
const PATH_COMPLIANCE: &str = "/api/v1/endpoint/compliance";
const PATH_INVENTORY: &str = "/api/v1/endpoint/inventory";
const PATH_RESPONSE: &str = "/api/v1/endpoint/response";
const PATH_COMMAND_CHANNEL: &str = "/api/v1/endpoint/command/channel";
const PATH_COMMAND_PENDING: &str = "/api/v1/endpoint/command/pending";
const PATH_COMMAND_ACK: &str = "/api/v1/endpoint/command/ack";
const PATH_THREAT_INTEL_VERSION: &str = "/api/v1/endpoint/threat-intel/version";
const PATH_BASELINE_FLEET: &str = "/api/v1/endpoint/baseline/fleet";
const PATH_BASELINE_BATCH: &str = "/api/v1/endpoint/baseline/batch";
const PATH_POLICY: &str = "/api/v1/endpoint/policy";
const PATH_SERVER_STATE: &str = "/api/v1/endpoint/state";
const DEFAULT_MAX_BUNDLE_DOWNLOAD_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Deserialize)]
struct CommandPollResponse {
    commands: Vec<CommandEnvelope>,
}

#[derive(Debug, Deserialize)]
struct ThreatIntelVersionsResponse {
    versions: Vec<ThreatIntelVersionEnvelope>,
}

#[derive(Debug, Deserialize)]
struct StateResponse {
    state: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
struct FleetBaselineResponse {
    #[serde(default)]
    fleet_baselines: Vec<FleetBaselineEnvelope>,
}

#[derive(Debug, Serialize)]
struct BaselineBatchRequest<'a> {
    agent_id: &'a str,
    baselines: &'a [BaselineProfileEnvelope],
}

impl Client {
    pub(super) async fn send_events_http(&self, batch: &[EventEnvelope]) -> Result<()> {
        let url = self.url_for(PATH_TELEMETRY);
        let payloads = batch
            .iter()
            .map(|event| {
                let severity = if event.severity.is_empty() {
                    "info"
                } else {
                    &event.severity
                };
                Ok(json!({
                    "agent_id": event.agent_id,
                    "event_type": event.event_type,
                    "severity": severity,
                    "rule_name": event.rule_name,
                    "event_data": payload_json_to_event_data(&event.payload_json),
                }))
            })
            .collect::<Result<Vec<_>>>()?;

        self.with_retry("send_events_http", || {
            let url = url.clone();
            let payloads = payloads.clone();
            async move {
                for payload in &payloads {
                    self.post_json_request(&url, payload, "telemetry").await?;
                }
                Ok(())
            }
        })
        .await
    }

    pub(super) async fn enroll_http(&self, enrollment: &EnrollmentEnvelope) -> Result<()> {
        self.post_json_with_retry("enroll_http", PATH_ENROLL, enrollment, "enrollment")
            .await
    }

    pub(super) async fn send_heartbeat_http(
        &self,
        agent_id: &str,
        compliance_status: &str,
        config_version: &str,
        baseline_status: &str,
    ) -> Result<()> {
        let body = json!({
            "agent_id": agent_id,
            "agent_version": self.agent_version.clone(),
            "compliance_status": compliance_status,
            "config_version": config_version,
            "baseline_status": baseline_status,
        });
        self.post_json_with_retry("heartbeat_http", PATH_HEARTBEAT, &body, "heartbeat")
            .await
    }

    pub(super) async fn send_compliance_http(&self, compliance: &ComplianceEnvelope) -> Result<()> {
        self.post_json_with_retry("compliance_http", PATH_COMPLIANCE, compliance, "compliance")
            .await
    }

    pub(super) async fn send_inventory_http(&self, inventory: &InventoryEnvelope) -> Result<()> {
        self.post_json_with_retry("inventory_http", PATH_INVENTORY, inventory, "inventory")
            .await
    }

    pub(super) async fn send_baseline_profiles_http(
        &self,
        agent_id: &str,
        profiles: &[BaselineProfileEnvelope],
    ) -> Result<()> {
        if profiles.is_empty() {
            return Ok(());
        }

        let payload = BaselineBatchRequest {
            agent_id,
            baselines: profiles,
        };

        self.post_json_with_retry(
            "baseline_batch_http",
            PATH_BASELINE_BATCH,
            &payload,
            "baseline batch",
        )
        .await
    }

    pub(super) async fn send_response_http(&self, response: &ResponseEnvelope) -> Result<()> {
        self.post_json_with_retry("response_http", PATH_RESPONSE, response, "response")
            .await
    }

    pub(super) async fn stream_command_channel_http(
        &self,
        agent_id: &str,
        completed_command_ids: &[String],
        limit: usize,
    ) -> Result<Vec<CommandEnvelope>> {
        let query = vec![
            ("agent_id".to_string(), agent_id.to_string()),
            ("limit".to_string(), limit.to_string()),
            (
                "completed_command_ids".to_string(),
                completed_command_ids.join(","),
            ),
        ];
        let payload: CommandPollResponse = self
            .get_json_with_retry(
                "command_channel_http",
                PATH_COMMAND_CHANNEL,
                query,
                "command channel",
            )
            .await?;
        Ok(payload.commands)
    }

    pub(super) async fn poll_commands_http(
        &self,
        agent_id: &str,
        limit: usize,
    ) -> Result<Vec<CommandEnvelope>> {
        let query = vec![
            ("agent_id".to_string(), agent_id.to_string()),
            ("limit".to_string(), limit.to_string()),
        ];
        let payload: CommandPollResponse = self
            .get_json_with_retry(
                "fetch_commands_http",
                PATH_COMMAND_PENDING,
                query,
                "command poll",
            )
            .await?;
        Ok(payload.commands)
    }

    pub(super) async fn ack_command_http(
        &self,
        agent_id: &str,
        command_id: &str,
        status: &str,
        result_json: Option<&str>,
    ) -> Result<()> {
        let mut payload = json!({
            "agent_id": agent_id,
            "command_id": command_id,
            "status": status,
        });
        if let Some(rj) = result_json {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(rj) {
                payload["result_data"] = parsed;
            }
        }
        self.post_json_with_retry(
            "ack_command_http",
            PATH_COMMAND_ACK,
            &payload,
            "command ack",
        )
        .await
    }

    pub(super) async fn fetch_latest_threat_intel_http(
        &self,
    ) -> Result<Option<ThreatIntelVersionEnvelope>> {
        let query = vec![("limit".to_string(), "1".to_string())];
        let response: Result<ThreatIntelVersionsResponse> = self
            .get_json_with_retry(
                "threat_intel_http",
                PATH_THREAT_INTEL_VERSION,
                query,
                "threat intel",
            )
            .await;

        match response {
            Ok(mut res) => Ok(res.versions.drain(..).next()),
            Err(err) => {
                warn!(error = %err, "failed to fetch threat intel version");
                Ok(None)
            }
        }
    }

    pub(super) async fn fetch_fleet_baselines_http(
        &self,
        limit: usize,
    ) -> Result<Vec<FleetBaselineEnvelope>> {
        let bounded_limit = if limit == 0 { 1 } else { limit.min(1000) };
        let query = vec![("limit".to_string(), bounded_limit.to_string())];
        let response: FleetBaselineResponse = self
            .get_json_with_retry(
                "fleet_baseline_http",
                PATH_BASELINE_FLEET,
                query,
                "fleet baseline",
            )
            .await?;
        Ok(response.fleet_baselines)
    }

    pub(super) async fn fetch_policy_http(&self, agent_id: &str) -> Result<Option<PolicyEnvelope>> {
        let query = vec![("agent_id".to_string(), agent_id.to_string())];
        let response: PolicyEnvelope = self
            .get_json_with_retry("fetch_policy_http", PATH_POLICY, query, "policy")
            .await?;

        if response.policy_id.trim().is_empty()
            && response.config_version.trim().is_empty()
            && response.policy_json.trim().is_empty()
            && response.certificate_policy.is_none()
        {
            Ok(None)
        } else {
            Ok(Some(response))
        }
    }

    pub(super) async fn download_bundle_http<P: AsRef<Path>>(
        &self,
        bundle_ref: &str,
        dest_path: P,
    ) -> Result<()> {
        let request_url = self.resolve_bundle_download_url(bundle_ref)?;
        let destination: PathBuf = dest_path.as_ref().to_path_buf();
        let payload = self
            .get_bytes_from_url_with_retry("download_bundle_http", &request_url, "bundle")
            .await?;

        Self::ensure_destination_parent(&destination)?;
        std::fs::write(&destination, &payload)
            .with_context(|| format!("failed writing bundle to {}", destination.display()))?;
        Ok(())
    }

    pub(super) async fn check_server_state_http(&self) -> Result<Option<ServerState>> {
        let response: Result<StateResponse> = self
            .get_json_with_retry(
                "check_state_http",
                PATH_SERVER_STATE,
                Vec::new(),
                "server state",
            )
            .await;

        match response {
            Ok(res) => Ok(parse_server_state_response(res)),
            Err(err) => {
                warn!(error = %err, "failed to query server state");
                Ok(None)
            }
        }
    }

    async fn post_json_with_retry<T: Serialize + ?Sized>(
        &self,
        operation_name: &'static str,
        path: &str,
        payload: &T,
        request_name: &'static str,
    ) -> Result<()> {
        let url = self.url_for(path);
        let body = serde_json::to_value(payload)
            .with_context(|| format!("failed serializing {} payload", request_name))?;

        self.with_retry(operation_name, || {
            let url = url.clone();
            let body = body.clone();
            async move { self.post_json_request(&url, &body, request_name).await }
        })
        .await
    }

    async fn post_json_request<T: Serialize + ?Sized>(
        &self,
        url: &str,
        payload: &T,
        request_name: &str,
    ) -> Result<()> {
        self.http
            .post(url)
            .json(payload)
            .send()
            .await
            .with_context(|| format!("failed sending {} to {}", request_name, url))?
            .error_for_status()
            .with_context(|| format!("{} rejected by {}", request_name, url))?;
        Ok(())
    }

    async fn get_json_with_retry<T: DeserializeOwned>(
        &self,
        operation_name: &'static str,
        path: &str,
        query: Vec<(String, String)>,
        request_name: &'static str,
    ) -> Result<T> {
        let url = self.url_for(path);
        self.with_retry(operation_name, || {
            let url = url.clone();
            let query = query.clone();
            async move { self.get_json_request(&url, &query, request_name).await }
        })
        .await
    }

    async fn get_json_request<T: DeserializeOwned>(
        &self,
        url: &str,
        query: &[(String, String)],
        request_name: &str,
    ) -> Result<T> {
        let response = self
            .http
            .get(url)
            .query(query)
            .send()
            .await
            .with_context(|| format!("failed fetching {} from {}", request_name, url))?
            .error_for_status()
            .with_context(|| format!("{} rejected by {}", request_name, url))?;
        response
            .json::<T>()
            .await
            .with_context(|| format!("invalid {} response payload", request_name))
    }

    async fn get_bytes_from_url_with_retry(
        &self,
        operation_name: &'static str,
        url: &str,
        request_name: &'static str,
    ) -> Result<Vec<u8>> {
        let url = url.to_string();
        self.with_retry(operation_name, || {
            let url = url.clone();
            async move { self.get_bytes_request(&url, request_name).await }
        })
        .await
    }

    async fn get_bytes_request(&self, url: &str, request_name: &str) -> Result<Vec<u8>> {
        let mut response = self
            .http
            .get(url)
            .send()
            .await
            .with_context(|| format!("failed downloading {} from {}", request_name, url))?
            .error_for_status()
            .with_context(|| format!("{} download rejected by {}", request_name, url))?;

        let max_bytes = max_bundle_download_bytes();
        if let Some(content_length) = response.content_length() {
            if content_length > max_bytes as u64 {
                anyhow::bail!(
                    "{} response from {} exceeds max size: {} > {} bytes",
                    request_name,
                    url,
                    content_length,
                    max_bytes
                );
            }
        }

        let mut payload = Vec::new();
        while let Some(chunk) = response.chunk().await.with_context(|| {
            format!(
                "failed reading {} response chunk from {}",
                request_name, url
            )
        })? {
            if payload.len().saturating_add(chunk.len()) > max_bytes {
                anyhow::bail!(
                    "{} response from {} exceeds max size while streaming: {} > {} bytes",
                    request_name,
                    url,
                    payload.len().saturating_add(chunk.len()),
                    max_bytes
                );
            }
            payload.extend_from_slice(&chunk);
        }

        Ok(payload)
    }

    fn ensure_destination_parent(destination: &Path) -> Result<()> {
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed creating bundle destination directory {}",
                    parent.display()
                )
            })?;
        }
        Ok(())
    }
}

fn payload_json_to_event_data(raw_payload: &str) -> serde_json::Value {
    let trimmed = raw_payload.trim();
    if trimmed.is_empty() {
        return json!({});
    }

    match serde_json::from_str::<serde_json::Value>(trimmed) {
        Ok(serde_json::Value::Object(map)) => serde_json::Value::Object(map),
        Ok(value) => json!({"value": value}),
        Err(_) => json!({"raw": raw_payload}),
    }
}

fn parse_server_state_response(response: StateResponse) -> Option<ServerState> {
    let state = response.state?;
    let persistence_enabled = state
        .get("persistence_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    Some(ServerState {
        persistence_enabled,
    })
}

fn max_bundle_download_bytes() -> usize {
    std::env::var("EGUARD_MAX_BUNDLE_DOWNLOAD_BYTES")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_MAX_BUNDLE_DOWNLOAD_BYTES)
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, OnceLock};

    use super::{max_bundle_download_bytes, DEFAULT_MAX_BUNDLE_DOWNLOAD_BYTES};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn max_bundle_download_bytes_uses_default_when_env_invalid() {
        let _guard = env_lock().lock().expect("env lock");
        std::env::set_var("EGUARD_MAX_BUNDLE_DOWNLOAD_BYTES", "0");
        assert_eq!(
            max_bundle_download_bytes(),
            DEFAULT_MAX_BUNDLE_DOWNLOAD_BYTES
        );

        std::env::set_var("EGUARD_MAX_BUNDLE_DOWNLOAD_BYTES", "invalid");
        assert_eq!(
            max_bundle_download_bytes(),
            DEFAULT_MAX_BUNDLE_DOWNLOAD_BYTES
        );

        std::env::remove_var("EGUARD_MAX_BUNDLE_DOWNLOAD_BYTES");
    }

    #[test]
    fn max_bundle_download_bytes_reads_env_override() {
        let _guard = env_lock().lock().expect("env lock");
        std::env::set_var("EGUARD_MAX_BUNDLE_DOWNLOAD_BYTES", "1048576");
        assert_eq!(max_bundle_download_bytes(), 1_048_576);
        std::env::remove_var("EGUARD_MAX_BUNDLE_DOWNLOAD_BYTES");
    }
}
