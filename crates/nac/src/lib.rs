mod bridge;
mod policy;

pub use bridge::{
    bridge_alert_to_security_event, map_alert_to_security_event, AlertEvent, BridgeAction,
    SecurityEvent, Severity, EVENT_AGENT_TAMPER, EVENT_C2_COMMUNICATION, EVENT_COMPLIANCE_FAIL,
    EVENT_LATERAL_MOVEMENT, EVENT_MALWARE_DETECTED, EVENT_PRIVILEGE_ESCALATION,
    EVENT_SUSPICIOUS_BEHAVIOR, EVENT_UNAUTHORIZED_MODULE,
};
pub use policy::{
    assign_vlan, build_captive_portal_install, detect_install_target, posture_from_compliance,
    AccessContext, CaptivePortalInstall, InstallTarget, Posture, VlanAssignment,
    DEFAULT_DEAD_HEARTBEAT_TIMEOUT_SECS, LEARNING_PERIOD_SECS,
};
