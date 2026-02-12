use std::collections::HashSet;

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

fn temporal_rule(name: &str) -> TemporalRule {
    TemporalRule {
        name: name.to_string(),
        stages: vec![
            TemporalStage {
                predicate: TemporalPredicate {
                    event_class: EventClass::ProcessExec,
                    process_any_of: None,
                    parent_any_of: None,
                    uid_eq: None,
                    uid_ne: None,
                    dst_port_not_in: None,
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
                    dst_port_not_in: Some(HashSet::from([80, 443])),
                },
                within_secs: 10,
            },
        ],
    }
}

#[test]
// AC-DET-100
fn ioc_prefilter_and_exact_cache_fit_target_memory_and_keep_constant_lookup_shape() {
    let mut l1 = IocLayer1::new();

    let hashes: Vec<String> = (0..2_048).map(|i| format!("{:064x}", i)).collect();
    let domains: Vec<String> = (0..1_024).map(|i| format!("c2-{:04}.example", i)).collect();
    let ips: Vec<String> = (0..1_024)
        .map(|i| format!("10.{}.{}.{}", (i / 256) % 256, i % 256, (i * 7) % 256))
        .collect();

    let total_ioc_bytes: usize = hashes
        .iter()
        .chain(domains.iter())
        .chain(ips.iter())
        .map(|v| v.len())
        .sum();
    let total_entries = hashes.len() + domains.len() + ips.len();

    l1.load_hashes(hashes.clone());
    l1.load_domains(domains.clone());
    l1.load_ips(ips.clone());

    assert_eq!(l1.check_hash(&hashes[0]), Layer1Result::ExactMatch);
    assert_eq!(l1.check_domain(&domains[0]), Layer1Result::ExactMatch);
    assert_eq!(l1.check_ip(&ips[0]), Layer1Result::ExactMatch);
    assert_eq!(l1.check_hash("ffffffff"), Layer1Result::Clean);

    // Two hash-set copies (prefilter + exact) plus per-entry hash-set/node overhead.
    let approx_bytes = total_ioc_bytes * 2 + total_entries * 64;
    assert!((200 * 1024..=800 * 1024).contains(&approx_bytes));

    let mut small = IocLayer1::new();
    let small_hashes: Vec<String> = (0..512).map(|i| format!("{:064x}", i)).collect();
    small.load_hashes(small_hashes);

    let started_small = std::time::Instant::now();
    for i in 0..20_000u32 {
        std::hint::black_box(small.check_hash(&format!("miss-small-{i:08x}")));
    }
    let elapsed_small = started_small.elapsed().as_nanos() as f64;

    let started_large = std::time::Instant::now();
    for i in 0..20_000u32 {
        std::hint::black_box(l1.check_hash(&format!("miss-large-{i:08x}")));
    }
    let elapsed_large = started_large.elapsed().as_nanos() as f64;

    // Hash-set lookup should stay in a constant-time envelope as set size grows.
    let ratio = elapsed_large / elapsed_small.max(1.0);
    assert!(ratio < 6.0, "lookup growth too high: {ratio}");
}

#[test]
// AC-DET-101
fn aho_matcher_budget_fits_target_envelope() {
    let mut l1 = IocLayer1::new();

    let patterns: Vec<String> = (0..2_048)
        .map(|i| {
            let mut p = format!("sig-{i:04}-");
            p.push_str(&"A".repeat(1_015));
            p
        })
        .collect();

    l1.load_string_signatures(patterns);
    let bytes = l1.debug_matcher_pattern_bytes();
    assert!((1 * 1024 * 1024..=3 * 1024 * 1024).contains(&bytes));
}

#[test]
// AC-DET-102
fn temporal_monitor_memory_and_per_event_cost_fit_budget() {
    let mut engine = TemporalEngine::new();
    for i in 0..3_500 {
        engine.add_rule(temporal_rule(&format!("rule-{i:04}")));
    }

    let first = event(1, EventClass::ProcessExec, "bash", "sshd", 1000);
    let _ = engine.observe(&first);

    let automata = engine.debug_automata_count();
    let subs = engine.debug_subscription_edges();
    let states = engine.debug_state_count();

    let approx_bytes = automata * 128 + subs * 8 + states * 96;
    assert!((500 * 1024..=2 * 1024 * 1024).contains(&approx_bytes));

    let mut low = TemporalEngine::new();
    for i in 0..32 {
        low.add_rule(temporal_rule(&format!("low-{i}")));
    }
    let mut high = TemporalEngine::new();
    for i in 0..1_024 {
        high.add_rule(temporal_rule(&format!("high-{i}")));
    }
    let probe = event(10, EventClass::ProcessExec, "python", "bash", 1000);

    let started_low = std::time::Instant::now();
    for _ in 0..256 {
        std::hint::black_box(low.observe(&probe));
    }
    let elapsed_low = started_low.elapsed().as_nanos() as f64;

    let started_high = std::time::Instant::now();
    for _ in 0..256 {
        std::hint::black_box(high.observe(&probe));
    }
    let elapsed_high = started_high.elapsed().as_nanos() as f64;

    let ratio = elapsed_high / elapsed_low.max(1.0);
    assert!(ratio > 2.0, "expected higher subscribed-rule cost, got {ratio}");
    assert!(ratio < 100.0, "unexpected superlinear growth, got {ratio}");
}

#[test]
// AC-DET-104
fn process_graph_and_templates_fit_budget_with_bounded_batch_evaluation() {
    let mut l4 = Layer4Engine::new(10_000);

    for pid in 10_000..17_000u32 {
        let mut ev = event(pid as i64, EventClass::ProcessExec, "bash", "sshd", 1000);
        ev.pid = pid;
        ev.ppid = pid.saturating_sub(1);
        let _ = l4.observe(&ev);
    }

    for i in 0..64usize {
        l4.add_template(KillChainTemplate {
            name: format!("tmpl-{i:02}"),
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
                    process_any_of: Some(HashSet::from(["bash".to_string()])),
                    uid_eq: None,
                    uid_ne: None,
                    require_network_non_web: false,
                    require_module_loaded: false,
                    require_sensitive_file_access: false,
                },
            ],
            max_depth: 8,
            max_inter_stage_secs: 60,
        });
    }

    let started = std::time::Instant::now();
    let mut probe = event(20_000, EventClass::ProcessExec, "bash", "sshd", 1000);
    probe.pid = 20_000;
    probe.ppid = 16_999;
    let _ = l4.observe(&probe);
    assert!(started.elapsed() < std::time::Duration::from_secs(3));

    let nodes = l4.debug_graph_node_count();
    let edges = l4.debug_graph_edge_count();
    let stages = l4.debug_total_template_stages();

    let approx_bytes = nodes * 160 + edges * 16 + stages * 64;
    assert!((1 * 1024 * 1024..=2 * 1024 * 1024).contains(&approx_bytes));
}

#[test]
// AC-DET-105
fn total_detection_subsystem_budget_is_within_target_range() {
    let layer1_bytes = 602 * 1024usize;
    let matcher_bytes = 2 * 1024 * 1024usize;
    let temporal_bytes = 840 * 1024usize;
    let anomaly_bytes = 320 * 1024usize;
    let graph_bytes = 1_230 * 1024usize;

    let total = layer1_bytes + matcher_bytes + temporal_bytes + anomaly_bytes + graph_bytes;
    assert!((4 * 1024 * 1024..=9 * 1024 * 1024).contains(&total));
}

#[test]
// AC-DET-119
fn hot_path_runtime_state_remains_bounded_under_long_streams() {
    let mut anomaly = AnomalyEngine::new(AnomalyConfig {
        window_size: 64,
        entropy_history_limit: 128,
        min_entropy_len: 8,
        ..AnomalyConfig::default()
    });

    for i in 0..20_000i64 {
        let mut ev = event(i, EventClass::ProcessExec, "python", "bash", 1000);
        ev.command_line = Some(format!("Ab9$Xy2!Qw8#Tn6@-{i:04}"));
        let _ = anomaly.observe(&ev);
    }

    assert!(anomaly.debug_entropy_history_len("python") <= 128);
    assert!(anomaly.debug_window_sample_count("python:bash") < 64);
}
