use nac::{
    bridge_alert_to_security_event, map_alert_to_security_event, AlertEvent, BridgeAction,
    Severity, EVENT_AGENT_TAMPER, EVENT_C2_COMMUNICATION, EVENT_COMPLIANCE_FAIL,
    EVENT_LATERAL_MOVEMENT, EVENT_MALWARE_DETECTED, EVENT_PRIVILEGE_ESCALATION,
    EVENT_SUSPICIOUS_BEHAVIOR, EVENT_UNAUTHORIZED_MODULE,
};

#[test]
// AC-NAC-012
fn yara_high_maps_to_malware_event_and_quarantine_actions() {
    let alert = AlertEvent::new("yara", "rule", Severity::High, &[], "malware");
    let event = map_alert_to_security_event(&alert).expect("event");
    assert_eq!(event.event_id, EVENT_MALWARE_DETECTED);
    assert_eq!(
        event.actions,
        vec![
            BridgeAction::ReevaluateAccess,
            BridgeAction::EmailAdmin,
            BridgeAction::RoleQuarantine
        ]
    );
}

#[test]
// AC-NAC-013
fn sigma_high_maps_to_suspicious_behavior_event() {
    let alert = AlertEvent::new(
        "sigma",
        "rule",
        Severity::Critical,
        &[],
        "suspicious process",
    );
    let event = map_alert_to_security_event(&alert).expect("event");
    assert_eq!(event.event_id, EVENT_SUSPICIOUS_BEHAVIOR);
    assert_eq!(
        event.actions,
        vec![BridgeAction::EmailAdmin, BridgeAction::Log]
    );
}

#[test]
// AC-NAC-014
fn unauthorized_kernel_module_maps_to_expected_event() {
    let alert = AlertEvent::new(
        "sigma",
        "unauthorized_kernel_module",
        Severity::Low,
        &[],
        "module detected",
    );
    let event = map_alert_to_security_event(&alert).expect("event");
    assert_eq!(event.event_id, EVENT_UNAUTHORIZED_MODULE);
    assert_eq!(
        event.actions,
        vec![BridgeAction::ReevaluateAccess, BridgeAction::EmailAdmin]
    );
}

#[test]
// AC-NAC-015
fn ioc_with_t1071_maps_to_c2_event() {
    let alert = AlertEvent::new("ioc", "rule", Severity::Medium, &["T1071"], "dns to c2");
    let event = map_alert_to_security_event(&alert).expect("event");
    assert_eq!(event.event_id, EVENT_C2_COMMUNICATION);
    assert_eq!(
        event.actions,
        vec![BridgeAction::ReevaluateAccess, BridgeAction::EmailAdmin]
    );
}

#[test]
// AC-NAC-016
fn compliance_failure_maps_to_noncompliant_role_event() {
    let alert = AlertEvent::new(
        "compliance",
        "compliance_failed",
        Severity::Medium,
        &[],
        "policy failed",
    );
    let event = map_alert_to_security_event(&alert).expect("event");
    assert_eq!(event.event_id, EVENT_COMPLIANCE_FAIL);
    assert_eq!(
        event.actions,
        vec![
            BridgeAction::ReevaluateAccess,
            BridgeAction::RoleNonCompliant
        ]
    );
}

#[test]
// AC-NAC-017
fn tamper_rule_maps_to_tamper_event() {
    let alert = AlertEvent::new("sigma", "agent_tamper", Severity::High, &[], "tamper");
    let event = map_alert_to_security_event(&alert).expect("event");
    assert_eq!(event.event_id, EVENT_AGENT_TAMPER);
    assert_eq!(
        event.actions,
        vec![BridgeAction::ReevaluateAccess, BridgeAction::EmailAdmin]
    );
}

#[test]
// AC-NAC-018
fn lateral_movement_mitre_maps_to_expected_event() {
    let alert = AlertEvent::new(
        "sigma",
        "rule",
        Severity::Medium,
        &["T1534"],
        "lateral move",
    );
    let event = map_alert_to_security_event(&alert).expect("event");
    assert_eq!(event.event_id, EVENT_LATERAL_MOVEMENT);
    assert_eq!(
        event.actions,
        vec![BridgeAction::EmailAdmin, BridgeAction::Log]
    );
}

#[test]
// AC-NAC-019
fn privilege_escalation_mitre_maps_to_expected_event() {
    let alert = AlertEvent::new("sigma", "rule", Severity::Medium, &["T1068"], "privesc");
    let event = map_alert_to_security_event(&alert).expect("event");
    assert_eq!(event.event_id, EVENT_PRIVILEGE_ESCALATION);
    assert_eq!(
        event.actions,
        vec![BridgeAction::ReevaluateAccess, BridgeAction::EmailAdmin]
    );
}

#[test]
// AC-NAC-020
fn bridge_forwards_mac_event_id_and_description_to_trigger() {
    let alert = AlertEvent::new("yara", "rule", Severity::High, &[], "desc text");
    let mut captured: Option<(String, u32, String)> = None;

    let bridged = bridge_alert_to_security_event(&alert, "aa:bb:cc:dd:ee:ff", |mac, id, desc| {
        captured = Some((mac.to_string(), id, desc.to_string()));
        Ok::<(), ()>(())
    })
    .expect("bridge result");

    assert!(bridged);
    assert_eq!(
        captured,
        Some((
            "aa:bb:cc:dd:ee:ff".to_string(),
            EVENT_MALWARE_DETECTED,
            "desc text".to_string()
        ))
    );
}
