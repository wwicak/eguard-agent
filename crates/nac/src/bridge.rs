pub const EVENT_MALWARE_DETECTED: u32 = 1300010;
pub const EVENT_SUSPICIOUS_BEHAVIOR: u32 = 1300011;
pub const EVENT_UNAUTHORIZED_MODULE: u32 = 1300012;
pub const EVENT_C2_COMMUNICATION: u32 = 1300013;
pub const EVENT_COMPLIANCE_FAIL: u32 = 1300014;
pub const EVENT_AGENT_TAMPER: u32 = 1300015;
pub const EVENT_LATERAL_MOVEMENT: u32 = 1300016;
pub const EVENT_PRIVILEGE_ESCALATION: u32 = 1300017;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeAction {
    ReevaluateAccess,
    EmailAdmin,
    Log,
    RoleQuarantine,
    RoleNonCompliant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertEvent {
    pub rule_type: String,
    pub rule_name: String,
    pub severity: Severity,
    pub mitre_techniques: Vec<String>,
    pub description: String,
}

impl AlertEvent {
    pub fn new(
        rule_type: &str,
        rule_name: &str,
        severity: Severity,
        mitre_techniques: &[&str],
        description: &str,
    ) -> Self {
        Self {
            rule_type: rule_type.to_string(),
            rule_name: rule_name.to_string(),
            severity,
            mitre_techniques: mitre_techniques.iter().map(|v| v.to_string()).collect(),
            description: description.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityEvent {
    pub event_id: u32,
    pub title: &'static str,
    pub actions: Vec<BridgeAction>,
}

pub fn map_alert_to_security_event(alert: &AlertEvent) -> Option<SecurityEvent> {
    let rule_type = alert.rule_type.to_ascii_lowercase();
    let rule_name = alert.rule_name.to_ascii_lowercase();

    if rule_type == "yara" && alert.severity >= Severity::High {
        return Some(SecurityEvent {
            event_id: EVENT_MALWARE_DETECTED,
            title: "Malware detected (YARA)",
            actions: vec![
                BridgeAction::ReevaluateAccess,
                BridgeAction::EmailAdmin,
                BridgeAction::RoleQuarantine,
            ],
        });
    }

    if rule_name == "unauthorized_kernel_module" {
        return Some(SecurityEvent {
            event_id: EVENT_UNAUTHORIZED_MODULE,
            title: "Unauthorized kernel module",
            actions: vec![BridgeAction::ReevaluateAccess, BridgeAction::EmailAdmin],
        });
    }

    if rule_type == "ioc" && contains_any(&alert.mitre_techniques, &["T1071"]) {
        return Some(SecurityEvent {
            event_id: EVENT_C2_COMMUNICATION,
            title: "DNS to C2 domain",
            actions: vec![BridgeAction::ReevaluateAccess, BridgeAction::EmailAdmin],
        });
    }

    if rule_name == "compliance_failed"
        || (rule_type == "compliance" && alert.severity >= Severity::Medium)
    {
        return Some(SecurityEvent {
            event_id: EVENT_COMPLIANCE_FAIL,
            title: "Compliance failed",
            actions: vec![
                BridgeAction::ReevaluateAccess,
                BridgeAction::RoleNonCompliant,
            ],
        });
    }

    if rule_name == "agent_tamper" {
        return Some(SecurityEvent {
            event_id: EVENT_AGENT_TAMPER,
            title: "Agent tamper detected",
            actions: vec![BridgeAction::ReevaluateAccess, BridgeAction::EmailAdmin],
        });
    }

    if rule_type == "sigma" && alert.severity >= Severity::High {
        return Some(SecurityEvent {
            event_id: EVENT_SUSPICIOUS_BEHAVIOR,
            title: "Suspicious process (SIGMA)",
            actions: vec![BridgeAction::EmailAdmin, BridgeAction::Log],
        });
    }

    if contains_any(&alert.mitre_techniques, &["T1021", "T1534"]) {
        return Some(SecurityEvent {
            event_id: EVENT_LATERAL_MOVEMENT,
            title: "Lateral movement",
            actions: vec![BridgeAction::EmailAdmin, BridgeAction::Log],
        });
    }

    if contains_any(&alert.mitre_techniques, &["T1548", "T1068"]) {
        return Some(SecurityEvent {
            event_id: EVENT_PRIVILEGE_ESCALATION,
            title: "Privilege escalation",
            actions: vec![BridgeAction::ReevaluateAccess, BridgeAction::EmailAdmin],
        });
    }

    None
}

pub fn bridge_alert_to_security_event<E, F>(
    alert: &AlertEvent,
    mac: &str,
    mut trigger: F,
) -> Result<bool, E>
where
    F: FnMut(&str, u32, &str) -> Result<(), E>,
{
    let Some(event) = map_alert_to_security_event(alert) else {
        return Ok(false);
    };
    trigger(mac, event.event_id, &alert.description)?;
    Ok(true)
}

fn contains_any(techniques: &[String], needles: &[&str]) -> bool {
    techniques.iter().any(|tech| {
        needles
            .iter()
            .any(|needle| tech.eq_ignore_ascii_case(needle))
    })
}
