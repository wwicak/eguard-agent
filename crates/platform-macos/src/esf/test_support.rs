//! Real eslogger decoder corpus, unavailable in production builds.
use crate::RawEvent;

pub fn corpus() -> Vec<RawEvent> {
    let mut out = Vec::new();
    for kind in [
        "exec",
        "exit",
        "open",
        "write",
        "rename",
        "unlink",
        "connect",
        "dns",
        "load",
        "lsm_block",
    ] {
        for value in ["/f4c/distinct", "", "  /mixed;comma,=value  "] {
            for nested in [false, true] {
                let mut input = serde_json::json!({
                    "event_type": kind, "pid": 4294967295u32, "uid": 501,
                    "ts_ns": 1700000000000000000u64,
                    "path": value, "cmdline": value, "dst": value,
                    "dst_ip": "192.0.2.17", "dst_port": 443,
                    "domain": value, "subject": value, "flags": 2
                });
                if nested {
                    input = serde_json::json!({"event_type": kind, "pid": 4294967295u32, "uid": 501, "ts_ns": 1700000000000000000u64, "event": input});
                }
                if let Some(event) = super::decode_event_value(&input) {
                    out.push(event);
                }
            }
        }
        let input = serde_json::json!({"event_type": kind, "pid": 4294967295u32, "uid": 501, "ts_ns": 1700000000000000000u64});
        if let Some(event) = super::decode_event_value(&input) {
            out.push(event);
        }
    }
    out
}

#[test]
fn f4c_macos_decoder_fields_and_enrichment_differential() {
    let events = corpus();
    assert!(events.iter().any(|event| event.fields.path.is_some()));
    assert!(events.iter().any(|event| event.fields.domain.is_some()));
    for event in events {
        if event.payload.starts_with('{') {
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
    let replay = super::parse_event_line(r#"{"event_type":"ProcessExec","pid":4294967295,"uid":501,"ts_ns":42,"payload":"path=/safe","fields":{"path":"/injected"}}"#).unwrap();
    assert_eq!(replay.fields, Default::default());
}
