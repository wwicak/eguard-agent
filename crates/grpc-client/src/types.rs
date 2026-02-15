use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    Http,
    Grpc,
}

impl TransportMode {
    pub fn parse(raw: &str) -> Self {
        raw.parse().unwrap_or(Self::Http)
    }
}

impl std::str::FromStr for TransportMode {
    type Err = std::convert::Infallible;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "grpc" | "tonic" => Ok(Self::Grpc),
            _ => Ok(Self::Http),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub agent_id: String,
    pub event_type: String,
    pub severity: String,
    pub rule_name: String,
    pub payload_json: String,
    pub created_at_unix: i64,
}

impl EventEnvelope {
    /// Convenience constructor with info severity (used for non-detection events).
    pub fn info(agent_id: String, event_type: String, payload_json: String, created_at_unix: i64) -> Self {
        Self {
            agent_id,
            event_type,
            severity: "info".to_string(),
            rule_name: String::new(),
            payload_json,
            created_at_unix,
        }
    }
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
pub struct EnrollmentResultEnvelope {
    pub agent_id: String,
    #[serde(default)]
    pub signed_certificate: Vec<u8>,
    #[serde(default)]
    pub ca_certificate: Vec<u8>,
    #[serde(default)]
    pub initial_policy: String,
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
    #[serde(default)]
    pub published_at_unix: i64,
    pub sigma_count: i64,
    pub yara_count: i64,
    pub ioc_count: i64,
    pub cve_count: i64,
    #[serde(default)]
    pub custom_rule_count: i64,
    #[serde(default)]
    pub custom_rule_version_hash: String,
    #[serde(default)]
    pub bundle_signature_path: String,
    #[serde(default)]
    pub bundle_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CertificatePolicyEnvelope {
    #[serde(default)]
    pub pinned_ca_sha256: String,
    #[serde(default)]
    pub rotate_before_expiry_days: i32,
    #[serde(default)]
    pub seamless_rotation: bool,
    #[serde(default)]
    pub require_client_cert_for_all_rpcs_except_enroll: bool,
    #[serde(default)]
    pub grpc_max_recv_msg_size_bytes: i32,
    #[serde(default)]
    pub grpc_port: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyEnvelope {
    #[serde(default)]
    pub policy_id: String,
    #[serde(default)]
    pub config_version: String,
    #[serde(default)]
    pub policy_json: String,
    #[serde(default)]
    pub certificate_policy: Option<CertificatePolicyEnvelope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetBaselineEnvelope {
    pub process_key: String,
    pub median_distribution: HashMap<String, f64>,
    pub agent_count: i64,
    pub stddev_kl: f64,
    #[serde(default)]
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub ca_path: String,
    #[serde(default)]
    pub pinned_ca_sha256: Option<String>,
    #[serde(default)]
    pub ca_pin_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerState {
    pub persistence_enabled: bool,
}

#[cfg(test)]
mod tests;
