#![allow(dead_code)]

use serde_json::json;

use super::EventEnvelope;

pub fn build_fim_event(
    agent_id: &str,
    file_path: &str,
    change_type: &str,
    old_hash: &str,
    new_hash: &str,
    now_unix: i64,
) -> EventEnvelope {
    let payload_json = json!({
        "observed_at_unix": now_unix,
        "fim": {
            "file_path": file_path,
            "change_type": change_type,
            "old_hash": old_hash,
            "new_hash": new_hash,
        },
        "detection": {
            "rule_type": "fim",
            "detection_layers": ["FIM"],
        },
        "audit": {
            "primary_rule_name": "fim_change",
            "rule_type": "fim",
        }
    })
    .to_string();

    EventEnvelope {
        agent_id: agent_id.to_string(),
        event_type: "fim_change".to_string(),
        severity: "medium".to_string(),
        rule_name: "fim_change".to_string(),
        payload_json,
        created_at_unix: now_unix,
    }
}

pub fn build_usb_event(
    agent_id: &str,
    device_class: &str,
    vendor_id: &str,
    action: &str,
    violation: bool,
    reason: &str,
    now_unix: i64,
) -> EventEnvelope {
    let severity = if violation { "high" } else { "info" };

    let payload_json = json!({
        "observed_at_unix": now_unix,
        "usb": {
            "device_class": device_class,
            "vendor_id": vendor_id,
            "action": action,
            "violation": violation,
            "reason": reason,
        },
        "detection": {
            "rule_type": "usb_control",
            "detection_layers": ["USB_control"],
        },
        "audit": {
            "primary_rule_name": "usb_violation",
            "rule_type": "usb_control",
        }
    })
    .to_string();

    EventEnvelope {
        agent_id: agent_id.to_string(),
        event_type: "usb_violation".to_string(),
        severity: severity.to_string(),
        rule_name: "usb_violation".to_string(),
        payload_json,
        created_at_unix: now_unix,
    }
}

pub fn build_deception_event(
    agent_id: &str,
    name: &str,
    token_type: &str,
    path: &str,
    now_unix: i64,
) -> EventEnvelope {
    let payload_json = json!({
        "observed_at_unix": now_unix,
        "deception": {
            "token_name": name,
            "token_type": token_type,
            "path": path,
        },
        "detection": {
            "rule_type": "deception",
            "detection_layers": ["deception_token"],
        },
        "audit": {
            "primary_rule_name": "deception_alert",
            "rule_type": "deception",
        }
    })
    .to_string();

    EventEnvelope {
        agent_id: agent_id.to_string(),
        event_type: "deception_alert".to_string(),
        severity: "high".to_string(),
        rule_name: "deception_alert".to_string(),
        payload_json,
        created_at_unix: now_unix,
    }
}

pub fn build_vulnerability_event(
    agent_id: &str,
    cve_id: &str,
    severity: &str,
    cvss: f64,
    product: &str,
    now_unix: i64,
) -> EventEnvelope {
    let payload_json = json!({
        "observed_at_unix": now_unix,
        "vulnerability": {
            "cve_id": cve_id,
            "severity": severity,
            "cvss": cvss,
            "product": product,
        },
        "detection": {
            "rule_type": "vulnerability",
            "detection_layers": ["vulnerability_scan"],
        },
        "audit": {
            "primary_rule_name": cve_id,
            "rule_type": "vulnerability",
        }
    })
    .to_string();

    EventEnvelope {
        agent_id: agent_id.to_string(),
        event_type: "vulnerability_match".to_string(),
        severity: severity.to_string(),
        rule_name: cve_id.to_string(),
        payload_json,
        created_at_unix: now_unix,
    }
}

pub fn build_hunting_event(
    agent_id: &str,
    query_name: &str,
    technique_id: &str,
    findings_count: u32,
    severity: &str,
    now_unix: i64,
) -> EventEnvelope {
    let payload_json = json!({
        "observed_at_unix": now_unix,
        "hunting": {
            "query_name": query_name,
            "technique_id": technique_id,
            "findings_count": findings_count,
        },
        "detection": {
            "rule_type": "threat_hunting",
            "detection_layers": ["threat_hunting"],
        },
        "audit": {
            "primary_rule_name": query_name,
            "rule_type": "threat_hunting",
        }
    })
    .to_string();

    EventEnvelope {
        agent_id: agent_id.to_string(),
        event_type: "hunting_finding".to_string(),
        severity: severity.to_string(),
        rule_name: query_name.to_string(),
        payload_json,
        created_at_unix: now_unix,
    }
}

pub fn build_zero_trust_event(
    agent_id: &str,
    score: u8,
    action: &str,
    factors: &serde_json::Value,
    now_unix: i64,
) -> EventEnvelope {
    let severity = if score < 30 {
        "critical"
    } else if score < 50 {
        "high"
    } else if score < 70 {
        "medium"
    } else {
        "low"
    };

    let payload_json = json!({
        "observed_at_unix": now_unix,
        "zero_trust": {
            "score": score,
            "action": action,
            "factors": factors,
        },
        "detection": {
            "rule_type": "zero_trust",
            "detection_layers": ["zero_trust_scoring"],
        },
        "audit": {
            "primary_rule_name": "zero_trust_score",
            "rule_type": "zero_trust",
        }
    })
    .to_string();

    EventEnvelope {
        agent_id: agent_id.to_string(),
        event_type: "zero_trust_score".to_string(),
        severity: severity.to_string(),
        rule_name: "zero_trust_score".to_string(),
        payload_json,
        created_at_unix: now_unix,
    }
}
