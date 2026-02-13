use nac::{assign_vlan, AccessContext, Posture, VlanAssignment, LEARNING_PERIOD_SECS};

fn learning_context(now_unix: u64) -> AccessContext {
    AccessContext {
        agent_installed: true,
        enrollment_complete: true,
        first_heartbeat_seen: true,
        learning_started_unix: Some(1_000),
        now_unix,
        compliance: Posture::Unknown,
        critical_alert_active: false,
        last_heartbeat_unix: Some(now_unix),
        dead_heartbeat_timeout_secs: 120,
    }
}

#[test]
// AC-NAC-001 AC-NAC-005
fn no_agent_routes_to_registration_vlan() {
    let ctx = AccessContext::default();
    assert_eq!(assign_vlan(&ctx), VlanAssignment::Registration);
}

#[test]
// AC-NAC-003 AC-NAC-006
fn learning_agent_after_first_heartbeat_routes_to_learning_vlan() {
    let now = 1_000 + LEARNING_PERIOD_SECS - 1;
    let ctx = learning_context(now);
    assert_eq!(assign_vlan(&ctx), VlanAssignment::AgentLearning);
}

#[test]
// AC-NAC-004 AC-NAC-007 AC-NAC-008
fn active_agent_after_learning_period_uses_compliance_posture() {
    let now = 1_000 + LEARNING_PERIOD_SECS + 1;

    let compliant = AccessContext {
        compliance: Posture::Compliant,
        ..learning_context(now)
    };
    assert_eq!(assign_vlan(&compliant), VlanAssignment::Production);

    let non_compliant = AccessContext {
        compliance: Posture::NonCompliant,
        ..learning_context(now)
    };
    assert_eq!(assign_vlan(&non_compliant), VlanAssignment::Restricted);
}

#[test]
// AC-NAC-009
fn critical_alert_always_quarantines_active_agent() {
    let now = 1_000 + LEARNING_PERIOD_SECS + 1;
    let ctx = AccessContext {
        compliance: Posture::Compliant,
        critical_alert_active: true,
        ..learning_context(now)
    };
    assert_eq!(assign_vlan(&ctx), VlanAssignment::Quarantine);
}

#[test]
// AC-NAC-010
fn dead_agent_quarantines_when_heartbeat_timeout_exceeded() {
    let now = 10_000;
    let ctx = AccessContext {
        last_heartbeat_unix: Some(now - 121),
        dead_heartbeat_timeout_secs: 120,
        ..learning_context(now)
    };
    assert_eq!(assign_vlan(&ctx), VlanAssignment::Quarantine);
}
