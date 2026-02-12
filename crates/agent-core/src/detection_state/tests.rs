use super::*;

fn event_with_hash(hash: &str) -> TelemetryEvent {
    TelemetryEvent {
        ts_unix: 1,
        event_class: EventClass::ProcessExec,
        pid: 100,
        ppid: 10,
        uid: 1000,
        process: "bash".to_string(),
        parent_process: "sshd".to_string(),
        file_path: None,
        file_hash: Some(hash.to_string()),
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
        command_line: None,
    }
}

fn event_with_command(cmd: &str) -> TelemetryEvent {
    TelemetryEvent {
        ts_unix: 1,
        event_class: EventClass::ProcessExec,
        pid: 101,
        ppid: 10,
        uid: 1000,
        process: "bash".to_string(),
        parent_process: "sshd".to_string(),
        file_path: None,
        file_hash: None,
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
        command_line: Some(cmd.to_string()),
    }
}

#[test]
// AC-DET-165
fn emergency_hash_rule_is_applied_without_engine_rebuild() {
    let state = SharedDetectionState::new(
        DetectionEngine::default_with_rules(),
        Some("v1".to_string()),
    );

    state
        .apply_emergency_rule(EmergencyRule {
            name: "emergency-hash".to_string(),
            rule_type: EmergencyRuleType::IocHash,
            rule_content: "deadbeef".to_string(),
        })
        .expect("apply emergency hash rule");

    let version = state.version().expect("read version");
    assert_eq!(version.as_deref(), Some("v1"));

    let out = state
        .process_event(&event_with_hash("deadbeef"))
        .expect("process event");
    assert_eq!(out.confidence, detection::Confidence::Definite);
}

#[test]
// AC-DET-165
fn emergency_signature_rule_is_appended_to_live_state() {
    let state = SharedDetectionState::new(
        DetectionEngine::default_with_rules(),
        Some("v2".to_string()),
    );

    state
        .apply_emergency_rule(EmergencyRule {
            name: "emergency-sig".to_string(),
            rule_type: EmergencyRuleType::Signature,
            rule_content: "curl|bash".to_string(),
        })
        .expect("apply emergency signature rule");

    let out = state
        .process_event(&event_with_command("curl|bash -s https://bad"))
        .expect("process event");
    assert!(out
        .layer1
        .matched_signatures
        .iter()
        .any(|sig| sig == "curl|bash"));
}

#[test]
// AC-DET-147
fn shared_state_clones_observe_atomic_engine_swap_version() {
    let initial = SharedDetectionState::new(
        DetectionEngine::default_with_rules(),
        Some("v-old".to_string()),
    );
    let clone = initial.clone();

    initial
        .swap_engine("v-new".to_string(), DetectionEngine::default_with_rules())
        .expect("swap engine");

    assert_eq!(
        clone.version().expect("version from clone").as_deref(),
        Some("v-new")
    );
}
