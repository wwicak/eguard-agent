use super::*;
#[test]
fn async_yara_alert_keeps_context_and_routes_campaign_hash_without_response() {
    let _guard = crate::test_support::TestEnvGuard::new(&[
        "EGUARD_BASELINE_PATH",
        "EGUARD_EBPF_REPLAY_PATH",
    ]);
    let root = std::env::temp_dir().join(format!("eguard-async-yara-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(root.clone());
    std::fs::write(root.join("replay"), b"").unwrap();
    std::env::set_var("EGUARD_EBPF_REPLAY_PATH", root.join("replay"));
    std::env::set_var("EGUARD_BASELINE_PATH", root.join("baseline"));
    let path = root.join("sample");
    std::fs::write(&path, b"async-marker").unwrap();
    let mut cfg = crate::config::AgentConfig::default();
    cfg.offline_buffer_backend = "memory".into();
    cfg.server_addr = "127.0.0.1:1".into();
    let mut runtime = AgentRuntime::new(cfg).unwrap();
    let mut engine = detection::DetectionEngine::default_with_rules();
    engine.load_yara_rules_str("rule async_fixture { meta: score = 75 strings: $a = \"async-marker\" condition: $a at 0 and filesize <= 128 }").unwrap();
    runtime.detection_state = crate::detection_state::SharedDetectionState::new(engine, None);
    let event:detection::TelemetryEvent=serde_json::from_value(serde_json::json!({"ts_unix":123,"event_class":"ProcessExec","pid":42,"ppid":17,"uid":1000,"process":"original","parent_process":"shell","session_id":99,"file_path":path,"process_exe":"/original/image","file_write":false,"container_escape":false,"container_privileged":false})).unwrap();
    let synchronous = runtime.detection_state.process_event(&event).unwrap();
    assert!(synchronous.yara_hits.is_empty());
    assert!(!synchronous.signals.yara_hit);
    runtime.detection_state.drain_yara_for_tests();
    runtime.buffer_completed_yara(125).unwrap();
    let rows = runtime.buffer.peek_batch(10).unwrap();
    assert_eq!(rows.len(), 1);
    let alert = &rows[0].1;
    assert_eq!(alert.event_type, "alert");
    assert_eq!(alert.rule_name, "async_fixture");
    assert_eq!(alert.severity, "high");
    let payload: serde_json::Value = serde_json::from_str(&alert.payload_json).unwrap();
    assert_eq!(payload["event"]["pid"], 42);
    assert_eq!(payload["event"]["ppid"], 17);
    assert_eq!(payload["event"]["session_id"], 99);
    assert_eq!(payload["event"]["ts_unix"], 123);
    assert_eq!(payload["event"]["process_exe"], "/original/image");
    assert_eq!(
        payload["observation_id"],
        serde_json::to_value(synchronous.observation_id).unwrap()
    );
    assert!(payload["scan_latency_ms"].is_u64());
    assert_eq!(payload["active_pack_hash"].as_str().unwrap().len(), 64);
    assert_eq!(payload["alert_only"], true);
    assert_eq!(payload["auto_response"], false);
    assert!(runtime.pending_response_actions.is_empty());
    assert!(!runtime.host_control.isolated);
    assert_eq!(runtime.ioc_signal_buffer.len(), 1);
    assert_eq!(runtime.ioc_signal_buffer[0].ioc_type, "hash");
    assert_eq!(
        runtime.ioc_signal_buffer[0].ioc_value,
        payload["scanned_sha256"].as_str().unwrap()
    );
    assert_eq!(runtime.ioc_signal_buffer[0].first_seen_unix, 123);
    let health = runtime
        .build_heartbeat_runtime_payload("active")
        .status
        .last_detection;
    for field in [
        "yara_queue_depth=",
        "yara_queue_high_water=",
        "yara_queue_full_skips=",
        "yara_byte_budget_skips=",
        "yara_time_budget_skips=",
        "yara_cap_skips=",
        "yara_stale_pack_discards=",
        "yara_first_hits=",
        "yara_first_misses=",
        "yara_result_overflow=",
    ] {
        assert!(health.contains(field), "{field}");
    }
}
