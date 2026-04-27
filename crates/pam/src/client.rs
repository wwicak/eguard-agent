use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct PamHttpClient {
    http: Client,
    base_url: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckoutRequest {
    pub agent_id: String,
    pub app_id: String,
    pub credential_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_duration_min: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CheckoutEnvelope {
    pub status: String,
    #[serde(default)]
    pub checkout: Option<CheckoutRecord>,
    #[serde(default)]
    pub credential: Option<ResolvedCredential>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CheckoutRecord {
    pub id: i64,
    pub credential_id: i64,
    pub agent_id: String,
    #[serde(default)]
    pub user_id: String,
    pub status: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResolvedCredential {
    pub id: i64,
    pub credential_type: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub private_key_pem: String,
    #[serde(default)]
    pub passphrase: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListCheckoutsEnvelope {
    pub status: String,
    #[serde(default)]
    pub checkouts: Vec<PamCheckoutRecord>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PamCheckoutRecord {
    pub id: i64,
    pub credential_id: i64,
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BrowserTerminalSessionRequest {
    pub agent_id: String,
    pub app_id: String,
    pub credential_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_duration_min: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BrowserTerminalSessionEnvelope {
    pub status: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub expires_at: String,
    #[serde(default)]
    pub checkout_id: i64,
}

impl PamHttpClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let http = Client::builder().build().context("build pam http client")?;
        Ok(Self {
            http,
            base_url: base_url.into(),
        })
    }

    pub async fn checkout(&self, req: &CheckoutRequest) -> Result<CheckoutEnvelope> {
        let url = format!(
            "{}/api/v1/ztna/pam/checkouts",
            self.base_url.trim_end_matches('/')
        );
        let resp = self
            .http
            .post(&url)
            .json(req)
            .send()
            .await
            .context("send pam checkout request")?;
        if resp.status().as_u16() == 403 {
            let deny = resp
                .json::<CheckoutEnvelope>()
                .await
                .context("decode pam deny response")?;
            return Ok(deny);
        }
        if !resp.status().is_success() {
            return Err(anyhow!("pam checkout failed: status={}", resp.status()));
        }
        resp.json::<CheckoutEnvelope>()
            .await
            .context("decode pam checkout response")
    }

    pub async fn list_checkouts(&self) -> Result<ListCheckoutsEnvelope> {
        let url = format!(
            "{}/api/v1/ztna/pam/checkouts",
            self.base_url.trim_end_matches('/')
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .context("send pam list checkouts request")?;
        if !resp.status().is_success() {
            return Err(anyhow!("pam list checkouts failed: status={}", resp.status()));
        }
        resp.json::<ListCheckoutsEnvelope>()
            .await
            .context("decode pam list checkouts response")
    }

    pub async fn checkin(&self, checkout_id: i64, reason: Option<&str>) -> Result<()> {
        let url = format!(
            "{}/api/v1/ztna/pam/checkouts/{}/checkin",
            self.base_url.trim_end_matches('/'),
            checkout_id
        );
        let resp = self
            .http
            .post(&url)
            .json(&serde_json::json!({ "reason": reason.unwrap_or("") }))
            .send()
            .await
            .context("send pam checkin request")?;
        if !resp.status().is_success() {
            return Err(anyhow!("pam checkin failed: status={}", resp.status()));
        }
        Ok(())
    }

    pub async fn create_browser_terminal_session(
        &self,
        req: &BrowserTerminalSessionRequest,
    ) -> Result<BrowserTerminalSessionEnvelope> {
        let url = format!(
            "{}/api/v1/ztna/browser-terminal/session",
            self.base_url.trim_end_matches('/'),
        );
        let resp = self
            .http
            .post(&url)
            .json(req)
            .send()
            .await
            .context("send browser terminal session request")?;
        if !resp.status().is_success() {
            return Err(anyhow!("browser terminal session failed: status={}", resp.status()));
        }
        resp.json::<BrowserTerminalSessionEnvelope>()
            .await
            .context("decode browser terminal session response")
    }
}
