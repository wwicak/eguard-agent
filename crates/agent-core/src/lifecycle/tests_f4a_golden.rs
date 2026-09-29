//! Baseline fixture generated at i2-start-f4a-fields with the real replay/binary codec.
use super::*;

#[test]
fn f4a_legacy_envelope_and_detection_golden() {
    let _lock = shared_env_var_lock().lock().unwrap();
    let mut cfg = crate::config::AgentConfig::default();
    cfg.agent_id = "golden-agent".into();
    cfg.offline_buffer_backend = "memory".into();
    cfg.server_addr = "127.0.0.1:1".into();
    cfg.self_protection_integrity_check_interval_secs = 0;
    let types = [
        "process_exec",
        "file_open",
        "tcp_connect",
        "dns_query",
        "module_load",
        "lsm_block",
        "process_exit",
        "file_write",
        "file_rename",
        "file_unlink",
    ];
    let mut lines = Vec::new();
    for event_type in types {
        for text in ["ordinary", "evil;,=%2F", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaé"] {
            // The final comm's UTF-8 sequence is truncated at byte 31 by the real
            // replay encoder, exercising non-UTF8 binary input to the decoder.
            lines.push(
                serde_json::json!({"event_type":event_type,"pid":4242,"uid":1000,
                "ts_ns":1700000000000000000u64,"ppid":42,"cgroup_id":123,
                "comm":text,"parent_comm":text,"path":text,"cmdline":text,
                "file_path":text,"src":text,"dst":text,"domain":text,
                "module_name":text,"subject":text,"flags":2,"mode":384,
                "fd":7,"size":12345,"reason":3,"qtype":28,"qclass":1,
                "src_ip":"192.0.2.1","dst_ip":"198.51.100.2","src_port":1234,"dst_port":443})
                .to_string(),
            );
        }
    }
    let path = std::env::temp_dir().join(format!(
        "eguard-f4a-golden-{}-{}.ndjson",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&path, lines.join("\n")).unwrap();
    let previous_replay = std::env::var_os("EGUARD_EBPF_REPLAY_PATH");
    std::env::set_var("EGUARD_EBPF_REPLAY_PATH", &path);
    let runtime = AgentRuntime::new(cfg);
    match previous_replay {
        Some(value) => std::env::set_var("EGUARD_EBPF_REPLAY_PATH", value),
        None => std::env::remove_var("EGUARD_EBPF_REPLAY_PATH"),
    }
    let runtime = runtime.unwrap();
    let mut engine = platform_linux::EbpfEngine::from_replay(&path).unwrap();
    let mut raw = Vec::new();
    loop {
        let batch = engine.poll_once(std::time::Duration::ZERO).unwrap();
        if batch.is_empty() {
            break;
        }
        raw.extend(batch);
    }
    std::fs::remove_file(&path).unwrap();
    assert_eq!(raw.len(), 30);
    let mut output = Vec::new();
    for event in raw {
        // Deterministic metadata; never inspect the host's process or filesystem.
        let enriched = platform_linux::EnrichedEvent {
            event,
            process_exe: Some("/fixture/bin/process".into()),
            process_exe_sha256: None,
            process_cmdline: Some("fixture --arg".into()),
            parent_process: Some("fixture-parent".into()),
            parent_chain: vec![42, 1],
            file_path: None,
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };
        let event = to_detection_event(&enriched, 1700000000);
        let outcome = detection::DetectionOutcome::default();
        let txn = EventTxn::from_enriched(&enriched, &event, 1700000000);
        let envelope = runtime.build_event_envelope(
            &enriched,
            &event,
            &outcome,
            &txn,
            outcome.confidence,
            1700000000,
        );
        output.push(serde_json::json!({"detection":event,"envelope":{
            "agent_id":envelope.agent_id,"event_type":envelope.event_type,"severity":envelope.severity,
            "rule_name":envelope.rule_name,"payload_json":envelope.payload_json,"created_at_unix":envelope.created_at_unix}}));
    }
    let actual = serde_json::to_string_pretty(&output).unwrap() + "\n";
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/f4a-legacy.json");
    assert_eq!(actual, std::fs::read_to_string(fixture).unwrap());
}
