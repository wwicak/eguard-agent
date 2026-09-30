//! Cross-platform codec/enrichment golden; native OS collection is not simulated.
use super::*;
use crate::platform::EventType;

fn lossless(value: serde_json::Value) -> Result<platform_linux::EnrichedEvent, String> {
    let decoded: platform_linux::EnrichedEvent =
        serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    // Equality of the complete round trip rejects unknown AND missing fields,
    // including optional fields that serde ordinarily defaults to None.
    if serde_json::to_value(&decoded).unwrap() != value {
        return Err("cross-platform enrichment schema is not lossless".into());
    }
    Ok(decoded)
}

fn pairs() -> Vec<(
    platform_linux::EnrichedEvent,
    platform_linux::EnrichedEvent,
    bool,
)> {
    let mut out = Vec::new();
    for event in platform_windows::etw::test_support::corpus() {
        let mut cleared = event.clone();
        cleared.fields = Default::default();
        out.push((
            lossless(serde_json::to_value(platform_windows::enrich_event(event)).unwrap()).unwrap(),
            lossless(serde_json::to_value(platform_windows::enrich_event(cleared)).unwrap())
                .unwrap(),
            false,
        ));
    }
    for event in platform_macos::esf::test_support::corpus() {
        let mut cleared = event.clone();
        cleared.fields = Default::default();
        out.push((
            lossless(serde_json::to_value(platform_macos::enrich_event(event)).unwrap()).unwrap(),
            lossless(serde_json::to_value(platform_macos::enrich_event(cleared)).unwrap()).unwrap(),
            true,
        ));
    }
    out
}

fn assert_windows_quoted_buffer_tag_key(index: usize) {
    let event = platform_windows::etw::test_support::quoted_buffer_probes().remove(index);
    let mut raw: platform_linux::RawEvent =
        serde_json::from_value(serde_json::to_value(&event).unwrap()).unwrap();
    // Explicitly preserve trusted hints across the test-only platform adapter.
    raw.fields = serde_json::from_value(serde_json::to_value(&event.fields).unwrap()).unwrap();
    let expected = if index == 0 {
        "dns_query|dns_query|\"quoted.example\"|-|pid:42|sid:42"
    } else {
        "module_load|module_load|\"quoted.dll\"|-|pid:42|sid:42"
    };
    assert_eq!(EventTxn::from_raw_platform(&raw, false).key, expected);
    raw.fields = Default::default();
    assert_eq!(EventTxn::from_raw_platform(&raw, false).key, expected);
}

#[test]
fn f4c_windows_quoted_dns_keeps_tagged_raw_transaction_key() {
    assert_windows_quoted_buffer_tag_key(0);
}

#[test]
fn f4c_windows_quoted_image_keeps_tagged_raw_transaction_key() {
    assert_windows_quoted_buffer_tag_key(1);
}

#[test]
fn f4c_windows_quoted_general_keeps_tagged_raw_transaction_key() {
    assert_windows_quoted_buffer_tag_key(2);
}

#[test]
fn f4c_conversion_rejects_missing_and_extra_fields() {
    let event = pairs().remove(0).0;
    let mut extra = serde_json::to_value(&event).unwrap();
    extra["unexpected"] = true.into();
    assert!(lossless(extra).is_err());
    let mut missing = serde_json::to_value(&event).unwrap();
    missing.as_object_mut().unwrap().remove("file_path");
    assert!(lossless(missing).is_err());
}

#[test]
fn f4c_full_detection_differential() {
    for (mut typed, legacy, macos) in pairs() {
        assert_eq!(
            EventTxn::from_raw_platform(&typed.event, macos),
            EventTxn::from_raw_platform(&legacy.event, macos),
            "raw transaction: {}",
            typed.event.payload
        );
        let typed_detection = to_detection_event(&typed, 1700000000);
        let legacy_detection = to_detection_event(&legacy, 1700000000);
        assert_eq!(
            serde_json::to_value(typed_detection).unwrap(),
            serde_json::to_value(legacy_detection).unwrap(),
            "{}",
            typed.event.payload
        );
        typed.event.fields = Default::default();
        assert_eq!(
            serde_json::to_value(typed).unwrap(),
            serde_json::to_value(legacy).unwrap()
        );
    }
}

fn assert_macos_raw_parity(events: impl Iterator<Item = platform_macos::RawEvent>) {
    for event in events {
        let typed: platform_linux::RawEvent =
            serde_json::from_value(serde_json::to_value(&event).unwrap()).unwrap();
        let mut raw = typed.clone();
        raw.fields = Default::default();
        assert_eq!(
            EventTxn::from_raw_platform(&typed, true),
            EventTxn::from_raw_platform(&raw, true),
            "{}",
            event.payload
        );
    }
}

#[test]
fn f4c_macos_ipv6_transaction_parity() {
    assert_macos_raw_parity(
        platform_macos::esf::test_support::edge_corpus()
            .into_iter()
            .filter(|event| matches!(event.event_type, platform_macos::EventType::TcpConnect)),
    );
}

#[test]
fn f4c_macos_percent_transaction_parity() {
    assert_macos_raw_parity(
        platform_macos::esf::test_support::edge_corpus()
            .into_iter()
            .filter(|event| event.payload.contains('%')),
    );
}

#[test]
fn f4c_macos_rename_quote_transaction_parity() {
    assert_macos_raw_parity(
        platform_macos::esf::test_support::edge_corpus()
            .into_iter()
            .filter(|event| {
                matches!(event.event_type, platform_macos::EventType::FileRename)
                    && !event.payload.contains('%')
            }),
    );
}

#[test]
fn f4c_partial_typed_keys_use_whole_payload() {
    for (kind, payload) in [
        (EventType::TcpConnect, "dst=[2001:db8::1]:443"),
        (EventType::TcpConnect, "dst=2001:db8::1:443"),
        (EventType::FileRename, "src=/old;dst=\"/quoted new\""),
    ] {
        let raw = RawEvent {
            event_type: kind,
            payload: payload.into(),
            ..Default::default()
        };
        let expected = EventTxn::from_raw_platform(&raw, false);
        for secondary in [false, true] {
            let mut typed = raw.clone();
            if matches!(typed.event_type, EventType::TcpConnect) {
                if secondary {
                    typed.fields.dst_port = Some(999);
                } else {
                    typed.fields.dst_ip = Some("192.0.2.99".into());
                }
            } else if secondary {
                typed.fields.secondary_path = Some("/disagree-destination".into());
            } else {
                typed.fields.path = Some("/disagree-source".into());
            }
            assert_eq!(
                EventTxn::from_raw_platform(&typed, false),
                expected,
                "{payload}"
            );
        }
    }
}

#[test]
fn f4c_macos_transactions_ignore_enrichment_hints() {
    for (mut typed, legacy, macos) in pairs().into_iter().filter(|pair| pair.2) {
        typed.event.fields.path = Some("/disagree".into());
        typed.event.fields.secondary_path = Some("/disagree-destination".into());
        typed.event.fields.module = Some("disagree-module".into());
        typed.event.fields.domain = Some("disagree.example".into());
        typed.event.fields.dst_ip = Some("192.0.2.99".into());
        typed.event.fields.dst_port = Some(999);
        assert_eq!(
            EventTxn::from_raw_platform(&typed.event, macos),
            EventTxn::from_raw_platform(&legacy.event, macos)
        );
    }
}

#[test]
fn f4c_decoder_enrichment_detection_envelope_golden() {
    let _lock = shared_env_var_lock()
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let root = std::env::temp_dir().join(format!("eguard-f4c-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let previous = std::env::var_os("EGUARD_AGENT_DATA_DIR");
    std::env::set_var("EGUARD_AGENT_DATA_DIR", &root);
    let mut cfg = crate::config::AgentConfig::default();
    match previous {
        Some(value) => std::env::set_var("EGUARD_AGENT_DATA_DIR", value),
        None => std::env::remove_var("EGUARD_AGENT_DATA_DIR"),
    }
    cfg.agent_id = "golden-agent".into();
    cfg.offline_buffer_backend = "memory".into();
    cfg.server_addr = "127.0.0.1:1".into();
    cfg.self_protection_integrity_check_interval_secs = 0;
    let runtime = AgentRuntime::new(cfg).unwrap();
    let mut output = Vec::new();
    for (enriched, _, _) in pairs() {
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
    if let Some(path) = std::env::var_os("EGUARD_F4C_GENERATE_GOLDEN") {
        std::fs::write(path, &actual).unwrap();
    } else {
        let expected = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/f4c-platforms.json"),
        )
        .unwrap();
        assert_eq!(actual, expected);
    }
    std::fs::remove_dir_all(root).unwrap();
}
