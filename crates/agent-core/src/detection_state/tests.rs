use super::*;
use std::time::{Duration, Instant};

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

#[test]
// AC-DET-146 AC-DET-148 AC-DET-149 AC-DET-150
fn rule_reload_swaps_atomically_and_keeps_old_rules_live_during_build() {
    let mut old_engine = DetectionEngine::default_with_rules();
    old_engine.layer1.load_hashes(["hash-old".to_string()]);
    let state = SharedDetectionState::new(old_engine, Some("v-old".to_string()));

    assert_eq!(
        state
            .process_event(&event_with_hash("hash-old"))
            .expect("process old hash")
            .confidence,
        detection::Confidence::Definite
    );

    // Simulate "compilation/build" time before atomic swap; old rules stay live.
    std::thread::sleep(Duration::from_millis(20));
    for _ in 0..10 {
        assert_eq!(
            state
                .process_event(&event_with_hash("hash-old"))
                .expect("old rule remains active before swap")
                .confidence,
            detection::Confidence::Definite
        );
    }

    let mut next_engine = DetectionEngine::default_with_rules();
    next_engine.layer1.load_hashes(["hash-new".to_string()]);

    let swap_started = Instant::now();
    state
        .swap_engine("v-new".to_string(), next_engine)
        .expect("swap engine");
    let swap_elapsed = swap_started.elapsed();

    assert!(swap_elapsed < Duration::from_millis(5));

    assert_eq!(
        state.version().expect("version after swap").as_deref(),
        Some("v-new")
    );
    assert_eq!(
        state
            .process_event(&event_with_hash("hash-new"))
            .expect("process new hash")
            .confidence,
        detection::Confidence::Definite
    );
    assert_ne!(
        state
            .process_event(&event_with_hash("hash-old"))
            .expect("process old hash after swap")
            .confidence,
        detection::Confidence::Definite
    );
}

#[test]
// AC-DET-164
fn emergency_rule_apply_stays_within_single_rule_compile_budget() {
    let state = SharedDetectionState::new(
        DetectionEngine::default_with_rules(),
        Some("v-latency".to_string()),
    );

    let started = Instant::now();
    state
        .apply_emergency_rule(EmergencyRule {
            name: "emergency-latency".to_string(),
            rule_type: EmergencyRuleType::Signature,
            rule_content: "curl|bash".to_string(),
        })
        .expect("apply emergency signature rule");
    assert!(started.elapsed() < Duration::from_millis(100));

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
// AC-DET-167
fn emergency_rule_is_reconciled_by_next_bundle_swap() {
    let state = SharedDetectionState::new(
        DetectionEngine::default_with_rules(),
        Some("v-emergency".to_string()),
    );

    state
        .apply_emergency_rule(EmergencyRule {
            name: "emergency-sig".to_string(),
            rule_type: EmergencyRuleType::Signature,
            rule_content: "curl|bash".to_string(),
        })
        .expect("apply emergency signature");

    assert!(state
        .process_event(&event_with_command("curl|bash -s https://bad"))
        .expect("evaluate with emergency signature")
        .layer1
        .matched_signatures
        .iter()
        .any(|sig| sig == "curl|bash"));

    let mut bundle_engine = DetectionEngine::default_with_rules();
    bundle_engine
        .layer1
        .load_string_signatures(["curl|bash".to_string()]);
    state
        .swap_engine("v-bundle".to_string(), bundle_engine)
        .expect("swap to reconciled bundle");

    assert_eq!(
        state.version().expect("version").as_deref(),
        Some("v-bundle")
    );
    assert!(state
        .process_event(&event_with_command("curl|bash -s https://bad"))
        .expect("evaluate with reconciled bundle signature")
        .layer1
        .matched_signatures
        .iter()
        .any(|sig| sig == "curl|bash"));
}
