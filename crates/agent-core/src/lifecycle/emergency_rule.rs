use anyhow::{anyhow, Result};

use crate::detection_state::EmergencyRuleType;

pub(super) fn parse_emergency_rule_type(raw: &str) -> Result<EmergencyRuleType> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "ioc_hash" => Ok(EmergencyRuleType::IocHash),
        "ioc_domain" => Ok(EmergencyRuleType::IocDomain),
        "ioc_ip" => Ok(EmergencyRuleType::IocIP),
        "sigma" | "yara" | "signature" => Ok(EmergencyRuleType::Signature),
        other => Err(anyhow!("unsupported emergency rule type: {}", other)),
    }
}
