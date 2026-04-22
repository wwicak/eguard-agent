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
    #[serde(default)]
    pub session_token: String,
    pub server_wg_public_key: String,
    pub server_endpoint: String,
    pub tunnel_ip: String,
    #[serde(default)]
    pub service_ip: String,
    pub allowed_ips: Vec<String>,
    pub ttl_seconds: i32,
    pub transport: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelDecision {
    pub status: String,
    #[serde(default)]
    pub grant: Option<TunnelGrant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelSession {
    pub session_id: String,
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub app_id: String,
    #[serde(default)]
    pub tunnel_ip: String,
    #[serde(default)]
    pub transport: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub bytes_tx: i64,
    #[serde(default)]
    pub bytes_rx: i64,
    #[serde(default)]
    pub active_connections: i32,
    #[serde(default)]
    pub tunnel_latency_ms: i32,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub last_activity_at: String,
}

#[cfg(test)]
mod tests {
    use super::TunnelDecision;

    #[test]
    fn parses_grant_without_session_token() {
        let raw = r#"{
            "status": "grant",
            "grant": {
                "session_id": "abc123",
                "server_wg_public_key": "pubkey",
                "server_endpoint": "138.252.193.169:51820",
                "tunnel_ip": "100.64.0.13",
                "service_ip": "100.64.0.14",
                "allowed_ips": ["100.64.0.14/32"],
                "ttl_seconds": 1800,
                "transport": "wireguard"
            }
        }"#;

        let parsed: TunnelDecision = serde_json::from_str(raw).expect("parse tunnel decision");
        let grant = parsed.grant.expect("grant payload");
        assert_eq!(grant.session_id, "abc123");
        assert!(grant.session_token.is_empty());
        assert_eq!(grant.service_ip, "100.64.0.14");
    }
}
