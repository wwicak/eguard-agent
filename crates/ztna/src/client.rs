use anyhow::{anyhow, Context, Result};
use reqwest::Client;

use crate::types::{TunnelDecision, TunnelRequest};

#[derive(Debug, Clone)]
pub struct TunnelClientConfig {
    pub base_url: String,
    pub request_timeout_secs: u64,
}

impl Default for TunnelClientConfig {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:50053".to_string(),
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
        let resp = self
            .http
            .post(&url)
            .json(req)
            .send()
            .await
            .context("send ztna request_tunnel")?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "ztna request_tunnel failed: status={}",
                resp.status()
            ));
        }
        resp.json::<TunnelDecision>()
            .await
            .context("decode ztna tunnel decision")
    }
}
