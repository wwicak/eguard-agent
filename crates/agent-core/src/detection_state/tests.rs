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
        session_id: 10,
        file_path: None,
        file_write: false,
        file_hash: Some(hash.to_string()),
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
        command_line: None,
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
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
        session_id: 10,
        file_path: None,
        file_write: false,
        file_hash: None,
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
        command_line: Some(cmd.to_string()),
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    }
}

fn event_with_hash_for_pid(pid: u32, hash: &str) -> TelemetryEvent {
    let mut event = event_with_hash(hash);
    event.pid = pid;
    event.session_id = pid;
    event
}

fn event_process_exec_for_pid(pid: u32, process: &str, parent: &str, ts: i64) -> TelemetryEvent {
    TelemetryEvent {
        ts_unix: ts,
        event_class: EventClass::ProcessExec,
        pid,
        ppid: 10,
        uid: 1000,
        process: process.to_string(),
        parent_process: parent.to_string(),
        session_id: pid,
        file_path: None,
        file_write: false,
        file_hash: None,
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
        command_line: None,
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    }
}

fn event_network_for_pid(
    pid: u32,
    process: &str,
    parent: &str,
    ts: i64,
    port: u16,
) -> TelemetryEvent {
    TelemetryEvent {
        ts_unix: ts,
        event_class: EventClass::NetworkConnect,
        pid,
        ppid: 10,
        uid: 1000,
        process: process.to_string(),
        parent_process: parent.to_string(),
        session_id: pid,
        file_path: None,
        file_write: false,
        file_hash: None,
        dst_port: Some(port),
        dst_ip: Some("203.0.113.77".to_string()),
        dst_domain: Some("c2.shard-test.example".to_string()),
        command_line: None,
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
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

#[test]
fn sharded_state_routes_events_by_pid_consistently() {
    let mut shard0 = DetectionEngine::default_with_rules();
    shard0.layer1.load_hashes(["hash-s0".to_string()]);

    let state =
        SharedDetectionState::new_with_shards(shard0, Some("v-shard-1".to_string()), 2, || {
            let mut shard1 = DetectionEngine::default_with_rules();
            shard1.layer1.load_hashes(["hash-s1".to_string()]);
            shard1
        });

    assert_eq!(state.shard_count(), 2);
    assert_eq!(
        state.version().expect("version").as_deref(),
        Some("v-shard-1")
    );

    assert_eq!(
        state
            .process_event(&event_with_hash_for_pid(200, "hash-s0"))
            .expect("shard-0 match")
            .confidence,
        detection::Confidence::Definite
    );
    assert_eq!(
        state
            .process_event(&event_with_hash_for_pid(201, "hash-s1"))
            .expect("shard-1 match")
            .confidence,
        detection::Confidence::Definite
    );

    assert_ne!(
        state
            .process_event(&event_with_hash_for_pid(200, "hash-s1"))
            .expect("cross-shard mismatch")
            .confidence,
        detection::Confidence::Definite
    );
    assert_ne!(
        state
            .process_event(&event_with_hash_for_pid(201, "hash-s0"))
            .expect("cross-shard mismatch")
            .confidence,
        detection::Confidence::Definite
    );
}

#[test]
fn sharded_emergency_rule_push_applies_to_all_shards() {
    let state = SharedDetectionState::new_with_shards(
        DetectionEngine::default_with_rules(),
        Some("v-shard-emergency".to_string()),
        4,
        DetectionEngine::default_with_rules,
    );

    state
        .apply_emergency_rule(EmergencyRule {
            name: "emergency-hash-all-shards".to_string(),
            rule_type: EmergencyRuleType::IocHash,
            rule_content: "deadbeef".to_string(),
        })
        .expect("apply emergency hash");

    for pid in 500..504u32 {
        assert_eq!(
            state
                .process_event(&event_with_hash_for_pid(pid, "deadbeef"))
                .expect("evaluate emergency hash")
                .confidence,
            detection::Confidence::Definite
        );
    }
}

#[test]
fn sharded_swap_engine_with_builder_reloads_every_shard() {
    let mut shard0 = DetectionEngine::default_with_rules();
    shard0.layer1.load_hashes(["old-s0".to_string()]);

    let state =
        SharedDetectionState::new_with_shards(shard0, Some("v-old-sharded".to_string()), 2, || {
            let mut shard1 = DetectionEngine::default_with_rules();
            shard1.layer1.load_hashes(["old-s1".to_string()]);
            shard1
        });

    let mut next0 = DetectionEngine::default_with_rules();
    next0.layer1.load_hashes(["new-s0".to_string()]);
    state
        .swap_engine_with_builder("v-new-sharded".to_string(), next0, || {
            let mut next1 = DetectionEngine::default_with_rules();
            next1.layer1.load_hashes(["new-s1".to_string()]);
            next1
        })
        .expect("swap shard engines");

    assert_eq!(
        state.version().expect("version after swap").as_deref(),
        Some("v-new-sharded")
    );
    assert_eq!(
        state
            .process_event(&event_with_hash_for_pid(700, "new-s0"))
            .expect("new shard0 hash")
            .confidence,
        detection::Confidence::Definite
    );
    assert_eq!(
        state
            .process_event(&event_with_hash_for_pid(701, "new-s1"))
            .expect("new shard1 hash")
            .confidence,
        detection::Confidence::Definite
    );
    assert_ne!(
        state
            .process_event(&event_with_hash_for_pid(700, "old-s0"))
            .expect("old shard0 hash")
            .confidence,
        detection::Confidence::Definite
    );
    assert_ne!(
        state
            .process_event(&event_with_hash_for_pid(701, "old-s1"))
            .expect("old shard1 hash")
            .confidence,
        detection::Confidence::Definite
    );
}

#[test]
fn sharded_workers_preserve_per_entity_event_order_for_temporal_rules() {
    let state = SharedDetectionState::new_with_shards(
        DetectionEngine::default_with_rules(),
        Some("v-order".to_string()),
        4,
        DetectionEngine::default_with_rules,
    );

    let pid = 900u32;
    let first = event_process_exec_for_pid(pid, "bash", "nginx", 1);
    let second = event_network_for_pid(pid, "bash", "nginx", 2, 4444);

    let out1 = state.process_event(&first).expect("process first");
    assert!(out1.temporal_hits.is_empty());

    let out2 = state.process_event(&second).expect("process second");
    assert!(out2.temporal_hits.iter().any(|rule| rule == "phi_webshell"));
}
