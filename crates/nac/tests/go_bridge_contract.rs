use std::path::PathBuf;

fn go_bridge_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("go")
        .join("agent")
        .join("server")
        .join("nac_bridge.go")
}

#[test]
// AC-NAC-011
fn go_nac_bridge_exists_at_designated_path() {
    let path = go_bridge_path();
    assert!(
        path.exists(),
        "expected NAC bridge file at {}",
        path.display()
    );

    let src = std::fs::read_to_string(path).expect("read nac_bridge.go");
    assert!(src.contains("func BridgeAlertToSecurityEvent("));
    assert!(src.contains("func mapAlertToSecurityEvent("));
}

#[test]
// AC-NAC-012 AC-NAC-013 AC-NAC-014 AC-NAC-015 AC-NAC-016 AC-NAC-017 AC-NAC-018 AC-NAC-019 AC-NAC-020
fn go_nac_bridge_defines_event_mapping_and_trigger_call_contract() {
    let src = std::fs::read_to_string(go_bridge_path()).expect("read nac_bridge.go");

    for expected in [
        "EventMalwareDetected     = 1300010",
        "EventSuspiciousBehavior  = 1300011",
        "EventUnauthorizedModule  = 1300012",
        "EventC2Communication     = 1300013",
        "EventComplianceFail      = 1300014",
        "EventAgentTamper         = 1300015",
        "EventLateralMovement     = 1300016",
        "EventPrivilegeEscalation = 1300017",
        "return security_event.Trigger(mac, eventID, alert.Description)",
        "strings.EqualFold(alert.RuleType, \"yara\") && alert.Severity >= SeverityHigh",
        "strings.EqualFold(alert.RuleType, \"sigma\") && alert.Severity >= SeverityHigh",
        "strings.EqualFold(alert.RuleName, \"unauthorized_kernel_module\")",
        "strings.EqualFold(alert.RuleType, \"ioc\") && containsAny(alert.MITRETechniques, \"T1071\")",
        "strings.EqualFold(alert.RuleName, \"compliance_failed\")",
        "strings.EqualFold(alert.RuleName, \"agent_tamper\")",
        "containsAny(alert.MITRETechniques, \"T1021\", \"T1534\")",
        "containsAny(alert.MITRETechniques, \"T1548\", \"T1068\")",
    ] {
        assert!(
            src.contains(expected),
            "missing contract snippet in nac_bridge.go: {expected}"
        );
    }
}
