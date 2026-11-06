//! Synthetic regressions ported from the A3/A4 audit harnesses (no customer rows).
use detection::{BehavioralEngine, Confidence, DetectionEngine, DetectionSignals, EventClass,
    MlEngine, MlExtraContext, MlFeatures, MlModel, TelemetryEvent};

fn event(process: &str, cmd: &str) -> TelemetryEvent {
    serde_json::from_value(serde_json::json!({
        "ts_unix": 1, "event_class": "ProcessExec", "pid": 42, "ppid": 1,
        "uid": 0, "process": process, "parent_process": "init", "session_id": 1,
        "file_write": false, "command_line": cmd,
        "container_escape": false, "container_privileged": false
    })).unwrap()
}
fn features(e: &TelemetryEvent) -> MlFeatures {
    MlFeatures::extract(e, &DetectionSignals::default(), 0, 0, 0, 0, 0, &MlExtraContext::default())
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
        if let Some(n) = n { ml.load_calibration(vec![0.1; n], 0.01); }
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
        if calibrated { b.calibrate(vec![0.1; 100], 0.01); }
        for i in 0..1200 {
            let mut e = match i % 3 {
                0 => event("chrome.exe", &format!("chrome.exe --type=renderer --field-trial-handle={} --gpu-preferences={}", i, encoded())),
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
    let e = event("powershell.exe", &format!("powershell.exe -enc {}", encoded()));
    for n in [0, 99, 100] {
        let mut b = BehavioralEngine::new();
        if n > 0 { b.calibrate(vec![0.1; n], 0.01); }
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
    let hosts = ["settings-win.data.microsoft.com", "clientservices.googleapis.com",
        "optimizationguide-pa.googleapis.com", "r3---sn-2uuxa3vh-jb3l.googlevideo.com"];
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
            if a.dimension == "dns_tunnel" { assert!(a.gated); assert_eq!(a.magnitude, 1.5); hits += 1; }
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
        ("tar", "/etc/eguard-agent/agent.conf", EventClass::FileOpen, false),
        ("dpkg", "/usr/bin/eguard-agent.dpkg-new", EventClass::FileOpen, true),
        ("eguard-agent", "/usr/bin/eguard-agent", EventClass::ProcessExec, false),
        ("bash", "/tmp/etc/eguard-agent/agent.conf", EventClass::FileOpen, true),
    ] {
        let mut e = event(p, ""); e.file_path = Some(path.into()); e.event_class = class; e.file_write = write;
        assert!(detection::detect_tamper_indicators(&e).is_empty(), "{p}: {path}");
    }
    let mut e = event("bash", ""); e.event_class = EventClass::FileOpen;
    e.file_path = Some("/etc/eguard-agent/agent.conf".into()); e.file_write = true;
    assert_eq!(detection::detect_tamper_indicators(&e), ["tamper:agent_file_mutation"]);
}

#[test]
fn rafix_ml_never_upgrades_rule_confidence() {
    let mut d = DetectionEngine::default_with_rules();
    let mut model = MlModel::default(); model.bias = 20.0; model.weights.fill(0.0);
    d.layer5.reload_model(model).unwrap();
    d.layer5.load_calibration(vec![0.1; 100], 0.01);
    let o = d.process_event(&event("svchost.exe", "svchost.exe -k netsvcs"));
    assert_eq!(o.confidence, Confidence::Low);
}
