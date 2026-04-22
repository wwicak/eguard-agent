use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use tracing::info;

use crate::types::{TunnelDecision, TunnelRequest, TunnelSession};

#[derive(Debug, Clone)]
pub struct TunnelClientConfig {
    pub base_url: String,
    pub request_timeout_secs: u64,
}

impl Default for TunnelClientConfig {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:50054".to_string(),
            request_timeout_secs: 10,
        }
    }
}

#[derive(Clone)]
pub struct TunnelClient {
    http: Client,
    cfg: TunnelClientConfig,
}

impl TunnelClient {
    pub fn new(cfg: TunnelClientConfig) -> Result<Self> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(cfg.request_timeout_secs))
            .build()
            .context("build ztna tunnel client")?;
        Ok(Self { http, cfg })
    }

    pub async fn request_tunnel(&self, req: &TunnelRequest) -> Result<TunnelDecision> {
        let url = format!(
            "{}/api/v1/ztna/tunnel/request",
            self.cfg.base_url.trim_end_matches('/')
        );
        info!(url = %url, app_id = %req.app_id, forward_host = ?req.forward_host, forward_port = ?req.forward_port, "ztna request_tunnel send start");
        let resp = self
            .http
            .post(&url)
            .json(req)
            .send()
            .await
            .context("send ztna request_tunnel")?;
        info!(url = %url, status = %resp.status(), "ztna request_tunnel send complete");
        if !resp.status().is_success() {
            return Err(anyhow!(
                "ztna request_tunnel failed: status={}",
                resp.status()
            ));
        }
        info!(url = %url, "ztna request_tunnel decode start");
        resp.json::<TunnelDecision>()
            .await
            .context("decode ztna tunnel decision")
            .map(|decision| {
                info!(url = %url, status = %decision.status, has_grant = decision.grant.is_some(), "ztna request_tunnel decode complete");
                decision
            })
    }

    pub async fn release_tunnel(&self, session_id: &str) -> Result<()> {
        let url = format!(
            "{}/api/v1/ztna/tunnel/release",
            self.cfg.base_url.trim_end_matches('/')
        );
        let resp = self
            .http
            .post(&url)
            .json(&serde_json::json!({ "session_id": session_id }))
            .send()
            .await
            .context("send ztna release_tunnel")?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "ztna release_tunnel failed: status={}",
                resp.status()
            ));
        }
        Ok(())
    }

    pub async fn list_sessions(&self) -> Result<Vec<TunnelSession>> {
        let url = format!(
            "{}/api/v1/ztna/sessions",
            self.cfg.base_url.trim_end_matches('/')
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .context("send ztna list_sessions")?;
        if !resp.status().is_success() {
            return Err(anyhow!("ztna list_sessions failed: status={}", resp.status()));
        }
        let value = resp
            .json::<serde_json::Value>()
            .await
            .context("decode ztna sessions payload")?;
        let sessions = value
            .get("sessions")
            .cloned()
            .unwrap_or_else(|| serde_json::Value::Array(Vec::new()));
        serde_json::from_value::<Vec<TunnelSession>>(sessions).context("parse ztna sessions")
    }
}
