//! Baseline fixture generated at i3-start-f4b-consumers with the real replay/binary codec.
use super::*;

#[test]
fn f4b_process_exit_unmodified_replay_preserves_legacy_detection() {
    let path = std::env::temp_dir().join(format!(
        "eguard-f4b-exit-{}-{}.ndjson",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    // An impossible Linux PID prevents host /proc metadata from masking the
    // codec-to-enrichment mapping, without replacing any enriched fields.
    std::fs::write(&path, r#"{"event_type":"process_exit","pid":4294967295,"uid":1000,"ts_ns":1700000000000000000,"comm":"ordinary"}"#).unwrap();
    let mut engine = platform_linux::EbpfEngine::from_replay(&path).unwrap();
    let raw = engine.poll_once(std::time::Duration::ZERO).unwrap();
    std::fs::remove_file(path).unwrap();
    assert_eq!(raw.len(), 1);
    assert_eq!(raw[0].fields.comm.as_deref(), Some("ordinary"));
    let enriched = platform_linux::enrich_event(raw.into_iter().next().unwrap());
    assert_eq!(enriched.process_cmdline, None);
    let event = to_detection_event(&enriched, 1700000000);
    assert_eq!(event.process, "unknown");
    assert_eq!(event.command_line, None);
    assert!(detection_event::should_drop_low_value_windows_event(
        &enriched, &event
    ));
}

#[test]
fn f4a_legacy_envelope_and_detection_golden() {
    let _lock = shared_env_var_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let root = std::env::temp_dir().join(format!(
        "eguard-f4a-golden-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let previous_data_dir = std::env::var_os("EGUARD_AGENT_DATA_DIR");
    std::env::set_var("EGUARD_AGENT_DATA_DIR", &root);
    let mut cfg = crate::config::AgentConfig::default();
    match previous_data_dir {
        Some(value) => std::env::set_var("EGUARD_AGENT_DATA_DIR", value),
        None => std::env::remove_var("EGUARD_AGENT_DATA_DIR"),
    }
    cfg.agent_id = "golden-agent".into();
    cfg.offline_buffer_backend = "memory".into();
    cfg.server_addr = "127.0.0.1:1".into();
    cfg.self_protection_integrity_check_interval_secs = 0;
    let lines = linux_codec_corpus();
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
        // Impossible PIDs make /proc deterministic without replacing event metadata.
        let mut cache = platform_linux::EnrichmentCache::default();
        cache.prime_process_metadata(&event);
        let enriched = platform_linux::enrich_event_with_cache(event, &mut cache);
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
        output.push(serde_json::json!({"detection":event,"envelope":envelope}));
    }
    let actual = serde_json::to_string_pretty(&output).unwrap() + "\n";
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/f4a-legacy.json");
    let expected = std::fs::read_to_string(fixture).unwrap();
    std::fs::remove_dir_all(root).unwrap();
    assert_eq!(actual, expected);
}

fn linux_codec_corpus() -> Vec<String> {
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
                serde_json::json!({"event_type":event_type,"pid":4294967295u32,"uid":1000,
                "ts_ns":1700000000000000000u64,"ppid":4294967294u32,"cgroup_id":123,
                "comm":text,"parent_comm":format!("parent-{text}"),"path":text,"cmdline":format!("cmd-{text}"),
                "file_path":text,"src":format!("src-{text}"),"dst":format!("dst-{text}"),"domain":text,
                "module_name":text,"subject":text,"flags":2,"mode":384,
                "fd":7,"size":12345,"reason":3,"qtype":28,"qclass":1,
                "src_ip":"192.0.2.1","dst_ip":"198.51.100.2","src_port":1234,"dst_port":443})
                .to_string(),
            );
        }
    }
    lines
}

#[test]
fn f4b_all_linux_codec_enrichment_differential() {
    let path =
        std::env::temp_dir().join(format!("eguard-differential-{}.ndjson", std::process::id()));
    std::fs::write(&path, linux_codec_corpus().join("\n")).unwrap();
    let mut engine = platform_linux::EbpfEngine::from_replay(&path).unwrap();
    let mut count = 0;
    loop {
        let batch = engine.poll_once(std::time::Duration::ZERO).unwrap();
        if batch.is_empty() {
            break;
        }
        for raw in batch {
            let mut fallback = raw.clone();
            fallback.fields = platform_linux::RawEventFields::default();
            let enrich = |event| {
                let mut cache = platform_linux::EnrichmentCache::default();
                cache.prime_process_metadata(&event);
                platform_linux::enrich_event_with_cache(event, &mut cache)
            };
            let typed = enrich(raw.clone());
            let legacy = enrich(fallback);
            let mut typed_json = serde_json::to_value(&typed).unwrap();
            let mut legacy_json = serde_json::to_value(&legacy).unwrap();
            typed_json.as_object_mut().unwrap().remove("event");
            legacy_json.as_object_mut().unwrap().remove("event");
            assert_eq!(
                typed_json, legacy_json,
                "enrichment {:?}: {}",
                raw.event_type, raw.payload
            );
            assert_eq!(
                serde_json::to_value(to_detection_event(&typed, 1700000000)).unwrap(),
                serde_json::to_value(to_detection_event(&legacy, 1700000000)).unwrap(),
                "detection {:?}: {}",
                raw.event_type,
                raw.payload
            );
            count += 1;
        }
    }
    std::fs::remove_file(path).unwrap();
    assert_eq!(
        count, 30,
        "all ten codec event types, three adversarial variants"
    );
}
