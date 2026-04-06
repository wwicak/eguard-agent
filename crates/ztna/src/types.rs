use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelRequest {
    pub agent_id: String,
    pub app_id: String,
    pub agent_wg_public_key: String,
    pub forward_host: Option<String>,
    pub forward_port: Option<u16>,
    pub preferred_transport: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelGrant {
    pub session_id: String,
    pub session_token: String,
    pub server_wg_public_key: String,
    pub server_endpoint: String,
    pub tunnel_ip: String,
    pub allowed_ips: Vec<String>,
    pub ttl_seconds: i32,
    pub transport: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelDecision {
    pub status: String,
    pub grant: Option<TunnelGrant>,
}
