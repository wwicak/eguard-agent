use std::collections::HashMap;

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
        file_path: None,
        file_hash: None,
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
        command_line: None,
    }
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
    assert_eq!(l1.check_hash("nope"), Layer1Result::Clean);
    assert_eq!(l1.check_domain("BAD.EXAMPLE"), Layer1Result::ExactMatch);
    assert_eq!(l1.check_ip("1.2.3.4"), Layer1Result::ExactMatch);

    let mut ev = event(1, EventClass::ProcessExec, "bash", "sshd", 1000);
    ev.command_line = Some("curl|bash -s evil".to_string());
    let hit = l1.check_event(&ev);
    assert!(hit.matched_signatures.iter().any(|s| s == "curl|bash"));
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
// AC-DET-021
fn temporal_engine_detects_webshell_pattern() {
    let mut t = TemporalEngine::with_default_rules();

    let mut e1 = event(1, EventClass::ProcessExec, "bash", "nginx", 33);
    e1.pid = 200;
    assert!(t.observe(&e1).is_empty());

    let mut e2 = event(5, EventClass::NetworkConnect, "bash", "nginx", 33);
    e2.pid = 200;
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
    assert!(t.observe(&e1).is_empty());

    let mut e2 = event(20, EventClass::ProcessExec, "su", "bash", 0);
    e2.pid = 220;
    let hits = t.observe(&e2);
    assert!(hits.iter().any(|h| h == "phi_priv_esc"));
}

#[test]
// AC-DET-024
fn temporal_engine_entity_isolation_prevents_cross_pid_matches() {
    let mut t = TemporalEngine::with_default_rules();

    let mut e1 = event(50, EventClass::ProcessExec, "bash", "nginx", 33);
    e1.pid = 1001;
    assert!(t.observe(&e1).is_empty());

    let mut e2 = event(55, EventClass::NetworkConnect, "bash", "nginx", 33);
    e2.pid = 2002;
    e2.dst_port = Some(8443);

    let hits = t.observe(&e2);
    assert!(hits.iter().all(|h| h != "phi_webshell"));
}

#[test]
// AC-DET-028 AC-DET-076
fn temporal_engine_rejects_reorder_beyond_tolerance() {
    let mut t = TemporalEngine::with_default_rules();

    let mut e1 = event(200, EventClass::ProcessExec, "bash", "nginx", 33);
    e1.pid = 303;
    assert!(t.observe(&e1).is_empty());

    let mut e2 = event(197, EventClass::NetworkConnect, "bash", "nginx", 33);
    e2.pid = 303;
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
// AC-DET-050 AC-DET-051
fn layer4_matches_default_template() {
    let mut l4 = Layer4Engine::with_default_templates();

    let mut parent = event(1, EventClass::ProcessExec, "nginx", "systemd", 33);
    parent.pid = 10;
    parent.ppid = 1;
    let _ = l4.observe(&parent);

    let mut child = event(2, EventClass::ProcessExec, "bash", "nginx", 33);
    child.pid = 11;
    child.ppid = 10;
    let _ = l4.observe(&child);

    let mut net = event(4, EventClass::NetworkConnect, "bash", "nginx", 33);
    net.pid = 11;
    net.ppid = 10;
    net.dst_port = Some(9001);
    let hits = l4.observe(&net);
    assert!(hits.iter().any(|h| h == "killchain_webshell_network"));
}

#[test]
fn engine_runs_all_layers() {
    let mut d = DetectionEngine::default_with_rules();
    d.layer1.load_hashes(["deadbeef".to_string()]);

    let mut ev = event(1, EventClass::ProcessExec, "bash", "sshd", 1000);
    ev.file_hash = Some("deadbeef".to_string());
    let out = d.process_event(&ev);
    assert_eq!(out.confidence, Confidence::Definite);
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
      within_secs: 10
"#;

    let mut t = TemporalEngine::new();
    let name = t
        .add_sigma_rule_yaml(sigma_yaml)
        .expect("compile sigma rule");
    assert_eq!(name, "sigma_webshell_network");

    let mut e1 = event(10, EventClass::ProcessExec, "bash", "nginx", 33);
    e1.pid = 404;
    assert!(t.observe(&e1).is_empty());

    let mut e2 = event(15, EventClass::NetworkConnect, "bash", "nginx", 33);
    e2.pid = 404;
    e2.dst_port = Some(8443);
    let hits = t.observe(&e2);
    assert!(hits.iter().any(|v| v == "sigma_webshell_network"));
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
// AC-DET-038
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
// AC-DET-021
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
    };
    assert_eq!(confidence_policy(&s), Confidence::Definite);

    let s = DetectionSignals {
        z1_exact_ioc: false,
        z2_temporal: true,
        z3_anomaly_high: true,
        z3_anomaly_med: true,
        z4_kill_chain: false,
        l1_prefilter_hit: true,
    };
    assert_eq!(confidence_policy(&s), Confidence::VeryHigh);
}

#[test]
fn layer1_prefilter_negative_short_circuits_to_clean() {
    let mut l1 = IocLayer1::new();
    let store = IocExactStore::in_memory().expect("in-memory sqlite store");
    store
        .load_hashes(["hash-only-in-store".to_string()])
        .expect("load sqlite hash");
    l1.set_exact_store(store);

    assert_eq!(l1.check_hash("hash-only-in-store"), Layer1Result::Clean);
}
