//! Deterministic real-decoder corpus; compiled only for regression tests.
use super::{codec::decode_etw_record_versioned, providers::*, security_auditing};
use crate::RawEvent;

fn wide(data: &mut Vec<u8>, offset: usize, value: &str) {
    data.resize(offset, 0);
    data.extend(value.encode_utf16().chain([0]).flat_map(u16::to_le_bytes));
}

pub fn corpus() -> Vec<RawEvent> {
    let mut out = Vec::new();
    let pid = u32::MAX;
    let mut decode = |provider, opcode, version, data: &[u8]| {
        if let Some(event) = decode_etw_record_versioned(
            provider,
            opcode,
            version,
            pid,
            1_700_000_000_000_000_000,
            data,
        ) {
            out.push(event);
        }
    };
    for name in [r"C:\f4c\distinct.exe", "", "  C:\\mixed;name,=x.exe  "] {
        for version in 0..=6 {
            for opcode in [1, 2] {
                let modern = if opcode == 1 {
                    version >= 3
                } else {
                    version >= 2
                };
                let mut data = vec![0; if modern { 56 } else { 24 }];
                data[..4].copy_from_slice(&pid.to_le_bytes());
                if opcode == 1 {
                    let offset = if modern { 20 } else { 12 };
                    data[offset..offset + 4].copy_from_slice(&12345u32.to_le_bytes());
                    wide(&mut data, if modern { 56 } else { 24 }, name);
                } else if modern {
                    data.resize(84, 0);
                    data.extend_from_slice(name.as_bytes());
                    data.push(0);
                } else {
                    wide(&mut data, 24, name);
                }
                decode(KERNEL_PROCESS, opcode, version, &data);
            }
        }
        for (opcode, offsets) in [
            (0, &[8, 4][..]),
            (32, &[8, 4]),
            (35, &[8, 4]),
            (36, &[8, 4]),
            (64, &[32, 28, 24]),
            (12, &[28, 32, 24]),
            (14, &[36, 32]),
            (26, &[36, 32]),
        ] {
            for offset in offsets {
                let mut data = Vec::new();
                wide(&mut data, *offset, name);
                decode(KERNEL_FILE, opcode, 0, &data);
            }
        }
        for opcode in [68, 70, 71, 15] {
            for len in [0, 16, 24, 32, 40, 48] {
                decode(KERNEL_FILE, opcode, 0, &vec![0; len]);
            }
        }
        for offset in [36, 24, 0] {
            let mut data = Vec::new();
            wide(&mut data, offset, name);
            decode(IMAGE_LOAD, 10, 0, &data);
            decode(KERNEL_GENERAL, 10, 0, &data);
        }
        let mut data = Vec::new();
        wide(&mut data, 0, name);
        decode(DNS_CLIENT, 1, 0, &data);
    }
    for len in [0, 19, 20, 44] {
        let mut data = vec![0; len];
        if len >= 20 {
            data[..4].copy_from_slice(&pid.to_le_bytes());
            data[8..12].copy_from_slice(&[192, 0, 2, 17]);
            data[12..16].copy_from_slice(&[198, 51, 100, 23]);
            data[16..18].copy_from_slice(&443u16.to_be_bytes());
        }
        decode(KERNEL_NETWORK, 10, 0, &data);
    }
    for version in 0..=6 {
        for opcode in [1, 2] {
            decode(KERNEL_PROCESS, opcode, version, b"short");
        }
    }
    for command in ["", "distinct --one", "mixed;comma,=value"] {
        let fields = [
            ("NewProcessId", "4294967295"),
            ("NewProcessName", r"C:\f4c\audit.exe"),
            ("CommandLine", command),
            ("ProcessId", "12345"),
            ("ParentProcessName", "parent.exe"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        out.push(
            security_auditing::build_process_create_event(&fields, 1_700_000_000_000_000_000)
                .unwrap(),
        );
    }
    out
}

#[test]
fn f4c_windows_enrichment_prefers_typed_domain() {
    let mut event = corpus()
        .into_iter()
        .find(|event| matches!(event.event_type, crate::EventType::DnsQuery))
        .unwrap();
    event.fields.domain = Some("typed.example".into());
    assert_eq!(
        crate::enrich_event(event).dst_domain.as_deref(),
        Some("typed.example")
    );
}

#[test]
fn f4c_windows_decoder_fields_and_enrichment_differential() {
    let events = corpus();
    assert!(events.iter().any(|e| e.fields.path.is_some()));
    assert!(events.iter().any(|e| e.fields.domain.is_some()));
    assert!(events.iter().any(|e| e.fields.module.is_some()));
    let mut dns = events
        .iter()
        .find(|event| event.fields.domain.is_some())
        .unwrap()
        .clone();
    dns.fields.domain = Some("typed.example".into());
    assert_eq!(
        crate::enrich_event(dns).dst_domain.as_deref(),
        Some("typed.example")
    );
    for event in events {
        if event.payload == "short" {
            assert_eq!(event.fields, Default::default());
        }
        let mut cleared = event.clone();
        cleared.fields = Default::default();
        let mut typed = crate::enrich_event(event);
        let legacy = crate::enrich_event(cleared);
        typed.event.fields = Default::default();
        assert_eq!(
            serde_json::to_value(typed).unwrap(),
            serde_json::to_value(legacy).unwrap()
        );
    }
}
