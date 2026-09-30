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
    let lines = linux_codec_corpus(false);
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

fn linux_codec_corpus(include_empty_variants: bool) -> Vec<String> {
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
        if !include_empty_variants {
            continue;
        }
        // Exercise every textual codec slot, both absent together and mixed with
        // populated peers. IP text is encoded as binary addresses by replay.
        let keys = [
            "comm",
            "parent_comm",
            "path",
            "cmdline",
            "file_path",
            "src",
            "dst",
            "domain",
            "module_name",
            "subject",
            "src_ip",
            "dst_ip",
        ];
        for empty in ["", "   ", "\t\n", " \t "] {
            for variant in 0..3 {
                let mut value = serde_json::json!({"event_type":event_type,
                    "pid":4294967295u32,"uid":1000,"ppid":4294967294u32,
                    "ts_ns":1700000000000000000u64,"cgroup_id":123,
                    "flags":2,"mode":384,"fd":7,"size":12345,"reason":3,
                    "qtype":28,"qclass":1,"src_port":1234,"dst_port":443});
                for (index, key) in keys.iter().enumerate() {
                    value[*key] = serde_json::json!(if variant == 0 || index % 2 == variant - 1 {
                        empty
                    } else {
                        "populated"
                    });
                }
                lines.push(value.to_string());
            }
        }
    }
    lines
}

#[test]
fn f4b_all_linux_codec_enrichment_differential() {
    let path =
        std::env::temp_dir().join(format!("eguard-differential-{}.ndjson", std::process::id()));
    std::fs::write(&path, linux_codec_corpus(true).join("\n")).unwrap();
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
        count, 150,
        "all ten codec event types, three adversarial and twelve empty/mixed variants"
    );
}

// Payload byte lengths, independent of replay (which only emits current layouts).
// Include both sides of every size check, historical/current complete records,
// and every legacy rename split (384..512), including odd-length splits.
#[test]
fn f4b_binary_layout_enrichment_differential() {
    let layouts: [(u8, Vec<usize>); 10] = [
        (1, vec![0, 1, 43, 44, 363, 364, 395, 396, 397]),
        // Put the reviewer's exact record first, so the baseline proof is explicit.
        (2, vec![264, 0, 1, 7, 8, 263, 339, 340, 341]),
        (3, vec![0, 1, 15, 16, 47, 48, 49]),
        (4, vec![0, 1, 3, 4, 131, 132, 133]),
        (5, vec![0, 1, 63, 64, 65]),
        (6, vec![0, 1, 3, 4, 131, 132, 133]),
        (7, vec![0, 1, 31, 32, 33]),
        (8, vec![0, 1, 11, 12, 267, 268, 269]),
        (
            9,
            std::iter::once(0)
                .chain(std::iter::once(1))
                .chain(383..=513)
                .collect(),
        ),
        (10, vec![0, 1, 255, 256, 257]),
    ];
    let mut count = 0;
    // Test FileOpen first to make the pre-fix failure identify the review case.
    for index in [1, 0, 2, 3, 4, 5, 6, 7, 8, 9] {
        let (kind, lengths) = &layouts[index];
        for &len in lengths {
            for v2 in [false, true] {
                // empty, distinct, both mixed directions, whitespace, controls,
                // delimiters/quotes and malformed UTF-8; network families 2/10.
                for variant in 0..8 {
                    let mut body = vec![0u8; len];
                    let put = |body: &mut [u8], offset: usize, bytes: &[u8]| {
                        if offset < body.len() {
                            let n = bytes.len().min(body.len() - offset);
                            body[offset..offset + n].copy_from_slice(&bytes[..n]);
                        }
                    };
                    let slots: Vec<(usize, usize)> = match kind {
                        1 => {
                            put(&mut body, 0, &4294967294u32.to_le_bytes());
                            put(&mut body, 4, &123u64.to_le_bytes());
                            if len >= 396 {
                                vec![(12, 32), (44, 32), (76, 160), (236, 160)]
                            } else {
                                vec![(12, 32), (44, 160), (204, 160)]
                            }
                        }
                        2 => {
                            put(&mut body, 0, &2u32.to_le_bytes());
                            put(&mut body, 4, &384u32.to_le_bytes());
                            if len >= 340 {
                                put(&mut body, 8, &4294967294u32.to_le_bytes());
                                put(&mut body, 12, &123u64.to_le_bytes());
                                vec![(20, 32), (52, 32), (84, 256)]
                            } else {
                                vec![(8, 256)]
                            }
                        }
                        3 => {
                            put(
                                &mut body,
                                0,
                                &(if variant % 2 == 0 { 2u16 } else { 10u16 }).to_le_bytes(),
                            );
                            put(&mut body, 2, &1234u16.to_le_bytes());
                            put(&mut body, 4, &443u16.to_le_bytes());
                            put(&mut body, 6, &[6]);
                            if variant != 0 {
                                put(&mut body, 8, &[192, 0, 2, 1, 198, 51, 100, 2]);
                                put(&mut body, 31, &[1]);
                                put(&mut body, 47, &[2]);
                            }
                            vec![]
                        }
                        4 => {
                            put(&mut body, 0, &28u16.to_le_bytes());
                            put(&mut body, 2, &1u16.to_le_bytes());
                            vec![(4, 128)]
                        }
                        5 => vec![(0, 64)],
                        6 => {
                            put(&mut body, 0, &[3]);
                            vec![(4, 128)]
                        }
                        7 => vec![(0, len)],
                        8 => {
                            put(&mut body, 0, &7u32.to_le_bytes());
                            put(&mut body, 4, &12345u64.to_le_bytes());
                            vec![(12, 256)]
                        }
                        9 if (384..512).contains(&len) => {
                            vec![(0, len / 2), (len / 2, len - len / 2)]
                        }
                        9 => vec![(0, 256), (256, 256)],
                        10 => vec![(0, 256)],
                        _ => unreachable!(),
                    };
                    for (slot, (offset, width)) in slots.into_iter().enumerate() {
                        let distinct = format!("slot-{slot}-value");
                        let value: &[u8] = match variant {
                            0 => b"",
                            2 if slot % 2 == 0 => b"",
                            3 if slot % 2 == 1 => b"",
                            4 => b"   ",
                            5 => b" \t\n ",
                            6 => b"\"evil;,=%2F\"",
                            7 => b"bad-\xff",
                            _ => distinct.as_bytes(),
                        };
                        put(
                            &mut body,
                            offset,
                            &value[..value.len().min(width.saturating_sub(1))],
                        );
                    }
                    let mut record = vec![0; if v2 { 37 } else { 21 }];
                    record[0] = *kind | if v2 { 0x80 } else { 0 };
                    record[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
                    record[9..13].copy_from_slice(&1000u32.to_le_bytes());
                    record[13..21].copy_from_slice(&1700000000000000000u64.to_le_bytes());
                    if v2 {
                        record[21..29].copy_from_slice(&123456u64.to_le_bytes());
                        record[29..37].copy_from_slice(&654321u64.to_le_bytes());
                    }
                    record.extend_from_slice(&body);
                    let raw = platform_linux::decode_binary_for_test(&record).unwrap();
                    let mut fallback = raw.clone();
                    fallback.fields = platform_linux::RawEventFields::default();
                    let enrich = |event| {
                        let mut cache = platform_linux::EnrichmentCache::default();
                        cache.prime_process_metadata(&event);
                        platform_linux::enrich_event_with_cache(event, &mut cache)
                    };
                    let typed = enrich(raw.clone());
                    let legacy = enrich(fallback);
                    let mut a = serde_json::to_value(&typed).unwrap();
                    let mut b = serde_json::to_value(&legacy).unwrap();
                    a.as_object_mut().unwrap().remove("event");
                    b.as_object_mut().unwrap().remove("event");
                    assert_eq!(
                        a, b,
                        "enrichment kind={kind} body={len} v2={v2} variant={variant} payload={:?}",
                        raw.payload
                    );
                    assert_eq!(
                        serde_json::to_value(to_detection_event(&typed, 1700000000)).unwrap(),
                        serde_json::to_value(to_detection_event(&legacy, 1700000000)).unwrap(),
                        "detection kind={kind} body={len} v2={v2} variant={variant}"
                    );
                    count += 1;
                }
            }
        }
    }
    assert_eq!(
        count,
        layouts
            .iter()
            .map(|(_, lengths)| lengths.len())
            .sum::<usize>()
            * 16
    );
    eprintln!("binary layout parity: {count} records");
}
