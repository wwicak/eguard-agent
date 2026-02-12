use std::collections::HashMap;
use std::collections::VecDeque;

use crate::*;
use crate::types::EVENT_CLASSES;

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
// AC-DET-050 AC-DET-051 AC-DET-088
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
            },
            TemplatePredicate {
                process_any_of: Some(crate::util::set_of(["mid"])),
                uid_eq: None,
                uid_ne: None,
                require_network_non_web: false,
                require_module_loaded: false,
                require_sensitive_file_access: false,
            },
            TemplatePredicate {
                process_any_of: Some(crate::util::set_of(["leaf"])),
                uid_eq: None,
                uid_ne: None,
                require_network_non_web: true,
                require_module_loaded: false,
                require_sensitive_file_access: false,
            },
        ],
        max_depth: 1,
        max_inter_stage_secs: 30,
    });

    let mut root = event(1, EventClass::ProcessExec, "root", "systemd", 1000);
    root.pid = 10;
    root.ppid = 1;
    let _ = l4.observe(&root);

    let mut mid = event(2, EventClass::ProcessExec, "mid", "root", 1000);
    mid.pid = 11;
    mid.ppid = 10;
    let _ = l4.observe(&mid);

    let mut leaf = event(3, EventClass::NetworkConnect, "leaf", "mid", 1000);
    leaf.pid = 12;
    leaf.ppid = 11;
    leaf.dst_port = Some(9001);
    let hits = l4.observe(&leaf);
    assert!(hits.iter().all(|h| h != "bounded_depth_chain"));
}

#[test]
// AC-DET-054
fn layer4_graph_state_is_pruned_by_sliding_window_to_stay_bounded() {
    let mut l4 = Layer4Engine::new(10);

    for i in 0..1_000u32 {
        let mut ev = event(0, EventClass::ProcessExec, "bash", "init", 1000);
        ev.pid = 10_000 + i;
        ev.ppid = 1;
        let _ = l4.observe(&ev);
    }

    let mut now = event(1_000, EventClass::ProcessExec, "bash", "init", 1000);
    now.pid = 99_999;
    now.ppid = 1;
    let _ = l4.observe(&now);

    assert!(l4.debug_graph_node_count() <= 2);
}

#[test]
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
                },
                TemplatePredicate {
                    process_any_of: Some(std::iter::once("never-match".to_string()).collect()),
                    uid_eq: None,
                    uid_ne: None,
                    require_network_non_web: true,
                    require_module_loaded: false,
                    require_sensitive_file_access: false,
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
        let _ = l4.observe(&ev);
    }

    let mut trigger = event(201, EventClass::NetworkConnect, "bash", "bash", 1000);
    trigger.pid = 20_199;
    trigger.ppid = 20_198;
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
    let out = d.process_event(&ev);
    assert_eq!(out.confidence, Confidence::Definite);
}

#[test]
// AC-DET-080
fn detection_outcome_includes_rule_names_and_matched_fields_for_traceability() {
    let mut engine = DetectionEngine::default_with_rules();
    engine.layer1.load_hashes(["deadbeef".to_string()]);

    let mut first = event(1, EventClass::ProcessExec, "bash", "nginx", 1000);
    first.pid = 700;
    first.file_hash = Some("deadbeef".to_string());
    let first_out = engine.process_event(&first);
    assert!(first_out.layer1.matched_fields.iter().any(|f| f == "file_hash"));

    let mut second = event(2, EventClass::NetworkConnect, "bash", "nginx", 1000);
    second.pid = 700;
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
    engine.layer3.set_baseline("python:bash".to_string(), baseline);

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

#[test]
// AC-DET-093 AC-DET-094
fn replay_reports_precision_recall_and_false_alarm_upper_bound_by_confidence() {
    let mut events = Vec::new();
    let mut malicious = std::collections::HashSet::new();
    for i in 0..30i64 {
        let mut ev = event(i, EventClass::ProcessExec, "bash", "sshd", 1000);
        if i % 10 == 0 {
            ev.file_hash = Some("deadbeef".to_string());
            malicious.insert(i as usize);
        }
        events.push(ev);
    }

    let mut engine = DetectionEngine::default_with_rules();
    engine.layer1.load_hashes(["deadbeef".to_string()]);
    let summary = replay_events(&mut engine, &events);

    let predicted_definite: std::collections::HashSet<usize> = summary
        .alerts
        .iter()
        .filter(|a| a.confidence == Confidence::Definite)
        .map(|a| a.index)
        .collect();

    let tp = predicted_definite.intersection(&malicious).count();
    let fp = predicted_definite.difference(&malicious).count();
    let fn_ = malicious.difference(&predicted_definite).count();

    let precision = if tp + fp == 0 {
        0.0
    } else {
        tp as f64 / (tp + fp) as f64
    };
    let recall = if tp + fn_ == 0 {
        0.0
    } else {
        tp as f64 / (tp + fn_) as f64
    };
    assert!(precision >= 0.99);
    assert!(recall >= 0.99);

    let benign_trials = events.len() - malicious.len();
    let false_alarms = fp;
    let upper_false_alarm = if false_alarms == 0 {
        1.0 - 0.05f64.powf(1.0 / benign_trials as f64)
    } else {
        1.0
    };
    assert!(upper_false_alarm >= 0.0);
    assert!(upper_false_alarm <= 1.0);
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
    let out = engine.observe(&high).expect("high-entropy spike should alert");
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
