use super::AgentRuntime;
use detection::{Confidence, DetectionOutcome, YaraEngine};

#[test]
fn yara_combined_evidence_is_alert_only_but_hash_and_deception_are_unchanged() {
    let mut engine = YaraEngine::new();
    engine.load_rules_str("rule fixture { meta: score = 75 strings: $a = \"synthetic\" condition: $a at 0 and filesize <= 128 }").unwrap();
    let mut outcome = DetectionOutcome {
        confidence: Confidence::VeryHigh,
        yara_hits: engine.scan_bytes("x", b"synthetic"),
        kill_chain_hits: vec!["same_file".into()],
        exploit_indicators: vec!["exploit".into()],
        ..Default::default()
    };
    assert!(!outcome.yara_hits.is_empty());
    assert!(!AgentRuntime::has_concrete_response_evidence(&outcome));
    outcome.confidence = Confidence::Definite;
    outcome.signals.z1_exact_ioc = true;
    outcome.layer1.result = detection::Layer1Result::ExactMatch;
    outcome.layer1.matched_fields = vec!["file_hash".into()];
    assert!(AgentRuntime::has_concrete_response_evidence(&outcome));
    outcome.signals.z1_exact_ioc = false;
    outcome.signals.deception_triggered = true;
    assert!(AgentRuntime::has_concrete_response_evidence(&outcome));
}

#[test]
fn incomplete_findings_use_low_alert_only_buffer_and_real_health_label() {
    let _guard = crate::test_support::TestEnvGuard::new(&[
        "EGUARD_BASELINE_PATH",
        "EGUARD_EBPF_REPLAY_PATH",
    ]);
    let root = std::env::temp_dir().join(format!(
        "eguard-yara-low-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(root.clone());
    std::env::set_var("EGUARD_BASELINE_PATH", root.join("baseline"));
    #[cfg(target_os = "linux")]
    {
        let replay = root.join("replay");
        std::fs::write(&replay, b"").unwrap();
        std::env::set_var("EGUARD_EBPF_REPLAY_PATH", replay);
    }
    let mut config = crate::config::AgentConfig::default();
    config.offline_buffer_backend = "memory".into();
    config.server_addr = "127.0.0.1:1".into();
    let mut runtime = AgentRuntime::new(config).unwrap();
    let outcome = DetectionOutcome {
        yara_scan_incomplete: vec![detection::YaraIncomplete {
            reason: "timeout".into(),
            path: "synthetic/path".into(),
            sha256: "a".repeat(64),
            pack_hash: "b".repeat(64),
        }],
        ..Default::default()
    };
    runtime.buffer_yara_incomplete(&outcome, 123).unwrap();
    let rows = runtime.buffer.peek_batch(10).unwrap();
    assert_eq!(rows.len(), 1);
    let event = &rows[0].1;
    assert_eq!(event.rule_name, "yara_scan_incomplete");
    assert_eq!(event.severity, "low");
    let payload: serde_json::Value = serde_json::from_str(&event.payload_json).unwrap();
    assert_eq!(payload["alert_only"], true);
    assert_eq!(payload["auto_response"], false);
    assert_eq!(payload["sha256"], "a".repeat(64));
    assert!(runtime.pending_response_actions.is_empty());
    assert!(runtime
        .build_heartbeat_runtime_payload("active")
        .status
        .last_detection
        .contains("yara_backend=yara-x"));
}
