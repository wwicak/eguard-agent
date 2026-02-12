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
