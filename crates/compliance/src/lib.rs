use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompliancePolicy {
    pub firewall_required: bool,
    pub min_kernel_prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceResult {
    pub status: String,
    pub detail: String,
}

pub fn evaluate(policy: &CompliancePolicy, firewall_enabled: bool, kernel_version: &str) -> ComplianceResult {
    if policy.firewall_required && !firewall_enabled {
        return ComplianceResult {
            status: "fail".to_string(),
            detail: "firewall disabled".to_string(),
        };
    }

    if let Some(prefix) = &policy.min_kernel_prefix {
        if !kernel_version.starts_with(prefix) {
            return ComplianceResult {
                status: "fail".to_string(),
                detail: format!("kernel {} does not match required prefix {}", kernel_version, prefix),
            };
        }
    }

    ComplianceResult {
        status: "pass".to_string(),
        detail: "policy checks passed".to_string(),
    }
}
