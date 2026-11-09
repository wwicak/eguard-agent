use crate::{Confidence, DetectionEngine, DetectionOutcome, TelemetryEvent};

fn evaluate(argv: &[&str]) -> DetectionOutcome {
    let mut engine = DetectionEngine::default_with_rules();
    engine
        .load_sigma_rule_yaml(include_str!(
            "../../../rules/sigma/linux_persistence_cron_systemd.yml"
        ))
        .expect("compile real packaged cron YAML");
    // /proc/<pid>/cmdline and the eBPF argv decoder retain argv[0] and join with spaces.
    let event: TelemetryEvent = serde_json::from_value(serde_json::json!({
        "ts_unix":100, "event_class":"ProcessExec", "pid":100, "ppid":10,
        "uid":1000, "process":argv[0].rsplit('/').next().unwrap(),
        "parent_process":"systemd", "session_id":1,
        "file_write":false, "container_escape":false, "container_privileged":false,
        "command_line":argv.join(" ")
    }))
    .unwrap();
    engine.process_event(&event)
}

fn matched(outcome: &DetectionOutcome) -> bool {
    outcome
        .temporal_hits
        .iter()
        .any(|hit| hit == "linux_persistence_cron_systemd")
}

#[test]
fn cron27_negative_user_environment() {
    for argv in [
        vec![
            "/bin/systemctl",
            "--user",
            "import-environment",
            "DBUS_SESSION_BUS_ADDRESS",
        ],
        vec!["systemctl", "--user", "show-environment"],
    ] {
        assert!(!matched(&evaluate(&argv)), "{}", argv.join(" "));
    }
}

#[test]
fn cron27_negative_is_enabled() {
    assert!(!matched(&evaluate(&["systemctl", "is-enabled", "ssh"])));
}

#[test]
fn cron27_negative_quiet_is_enabled() {
    assert!(!matched(&evaluate(&[
        "systemctl",
        "--quiet",
        "is-enabled",
        "--",
        "ssh.service"
    ])));
}

#[test]
fn cron27_negative_list_enabled() {
    assert!(!matched(&evaluate(&[
        "systemctl",
        "list-unit-files",
        "--state=enabled"
    ])));
}

#[test]
fn cron27_enable_reenable_and_cron_positives_stay_high() {
    for argv in [
        vec!["systemctl", "enable", "evil.service"],
        vec![
            "/usr/bin/systemctl",
            "--user",
            "enable",
            "--now",
            "evil.service",
        ],
        vec!["systemctl", "--now", "enable", "evil.service"],
        vec!["systemctl", "-q", "enable", "evil.service"],
        vec!["systemctl", "--quiet", "enable", "evil.service"],
        vec!["systemctl", "--global", "enable", "evil.service"],
        vec!["systemctl", "--system", "enable", "evil.service"],
        vec!["systemctl", "-f", "enable", "evil.service"],
        vec!["systemctl", "--force", "enable", "evil.service"],
        vec!["systemctl", "--user", "reenable", "evil.service"],
        vec!["crontab", "-l", "/etc/cron.d/x"],
        vec!["systemctl", "reenable", "evil.service"],
    ] {
        let outcome = evaluate(&argv);
        assert!(matched(&outcome), "{}", argv.join(" "));
        assert!(outcome.confidence >= Confidence::High, "{}", argv.join(" "));
    }
}
