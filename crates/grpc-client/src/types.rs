use serde::{Deserialize, Serialize};

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enrollment_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
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
