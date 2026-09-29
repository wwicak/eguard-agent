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
        "module_load",
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
    // Integer ES versions and Ventura key-discriminated layouts.
    for code in [
        0, 42, 1, 72, 8, 25, 52, 32, 54, 60, 73, 75, 74, 43, 35, 71, 82, 83, 9,
    ] {
        for schema in [0, 1] {
            for value in ["/f4c/integer", "", " /mixed;comma,=x "] {
                let input = serde_json::json!({"schema_version":schema,"event_type":code,"pid":4294967295u32,"uid":501,"ts_ns":1700000000000000000u64,"path":value,"cmdline":value,"dst_ip":value,"dst_port":0});
                out.push(super::decode_event_value(&input).unwrap());
            }
        }
    }
    for key in [
        "exec",
        "exit",
        "fork",
        "open",
        "write",
        "truncate",
        "create",
        "rename",
        "unlink",
        "deleteextattr",
        "close",
        "link",
        "mmap",
        "kextload",
        "uipc_connect",
        "uipc_bind",
    ] {
        for value in ["/f4c/nested", "", " /mixed;comma,=x "] {
            let input = serde_json::json!({"schema_version":1,"event_type":999,"pid":4294967295u32,"uid":501,"ts_ns":1700000000000000000u64,"process":{"audit_token":{"pidversion":12},"parent_audit_token":{"pidversion":11}},"event":{key:{"path":value,"target":{"executable":{"path":value},"audit_token":{"pid":4294967295u32,"pidversion":13}},"args":[value,"--distinct"],"destination":{"existing_file":{"path":value}}}}});
            out.push(super::decode_event_value(&input).unwrap());
        }
    }
    out
}

#[test]
fn f4c_macos_enrichment_prefers_typed_domain() {
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
fn f4c_macos_decoder_fields_and_enrichment_differential() {
    let events = corpus();
    assert!(events.iter().any(|event| event.fields.path.is_some()));
    assert!(events.iter().any(|event| event.fields.domain.is_some()));
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
