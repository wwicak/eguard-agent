//! Real eslogger decoder corpus, unavailable in production builds.
use crate::RawEvent;

fn alternate(value: &str, distinct: &str) -> String {
    if value.is_empty() {
        String::new()
    } else if value.starts_with(' ') {
        // Mixed rows deliberately leave selected fields absent while retaining
        // distinct delimiter-sensitive values in the other fields.
        if distinct.contains("command") || distinct.contains("subject") {
            return String::new();
        }
        format!("  {distinct};comma,=mixed  ")
    } else {
        distinct.to_owned()
    }
}

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
                    "path": value, "cmdline": alternate(value, "command --arg"), "dst": alternate(value, "/rename/destination"),
                    "dst_ip": alternate(value, "192.0.2.17"), "dst_port": 443,
                    "domain": alternate(value, "distinct.example"), "subject": alternate(value, "denied-subject"), "flags": 2
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
                let input = serde_json::json!({"schema_version":schema,"event_type":code,"pid":4294967295u32,"uid":501,"ts_ns":1700000000000000000u64,"path":value,"cmdline":alternate(value,"integer --cmd"),"dst":alternate(value,"/integer/destination"),"domain":alternate(value,"integer.example"),"subject":alternate(value,"integer-subject"),"dst_ip":alternate(value,"198.51.100.23"),"dst_port":8443});
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
            let input = serde_json::json!({"schema_version":1,"event_type":999,"pid":4294967295u32,"uid":501,"ts_ns":1700000000000000000u64,"process":{"audit_token":{"pidversion":12},"parent_audit_token":{"pidversion":11}},"event":{key:{"path":value,"target":{"executable":{"path":alternate(value,"/target/executable")},"audit_token":{"pid":4294967295u32,"pidversion":13}},"args":[alternate(value,"command"),"--distinct"],"destination":{"existing_file":{"path":alternate(value,"/nested/destination")}}}}});
            out.push(super::decode_event_value(&input).unwrap());
        }
    }
    out.extend(edge_corpus());
    out
}

pub fn edge_corpus() -> Vec<RawEvent> {
    let mut out = Vec::new();
    for ip in [
        "2001:db8::1",
        "[2001:db8::1]",
        "2001:db8::1:443",
        "[2001:db8::1:443]",
    ] {
        let input = serde_json::json!({"event_type":"connect","pid":4294967295u32,"uid":501,"ts_ns":1700000000000000000u64,"dst_ip":ip,"dst_port":443});
        out.push(super::decode_event_value(&input).unwrap());
    }
    for kind in ["exec", "open", "rename", "unlink", "module_load", "dns"] {
        for value in [
            "/tmp/literal%2Fname",
            "/tmp/literal%25name",
            "/tmp/literal%invalid",
            "\"/tmp/quoted path\"",
            "/tmp/unquoted path",
        ] {
            let input = serde_json::json!({"event_type":kind,"pid":4294967295u32,"uid":501,"ts_ns":1700000000000000000u64,"path":value,"dst":value,"domain":value});
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

#[test]
fn f4c_unknown_schema_fields_are_untrusted() {
    for schema in [6, 7, 255] {
        let input = serde_json::json!({"schema_version":schema,"event_type":"exec","pid":1,"path":"/unknown"});
        assert_eq!(
            super::decode_event_value(&input).unwrap().fields,
            Default::default()
        );
    }
}

#[test]
fn f4c_offline_native_json_has_no_typed_trust() {
    for input in [
        r#"{"event_type":"exec","pid":1,"path":"/offline"}"#,
        r#"{"event_type":"connect","pid":1,"dst_ip":"2001:db8::1","dst_port":443}"#,
        r#"{"event_type":"rename","pid":1,"path":"/old","dst":"/new"}"#,
    ] {
        assert_eq!(
            super::parse_event_line(input).unwrap().fields,
            Default::default()
        );
    }
}

#[test]
fn f4c_malformed_replay_cannot_inject_fields() {
    for key in ["fields", "Fields", "FIELDS"] {
        for nested in [false, true] {
            let fields =
                serde_json::json!({key: {"path":"/injected", "domain":"injected.example"}});
            let mut input = serde_json::json!({"event_type":"exec", "pid":1});
            if nested {
                input["event"] = fields;
            } else {
                input
                    .as_object_mut()
                    .unwrap()
                    .extend(fields.as_object().unwrap().clone());
            }
            let event = super::parse_event_line(&input.to_string()).unwrap();
            assert_eq!(event.fields, Default::default(), "{input}");
        }
    }
    for injected in [
        r#"{"path":"/injected"}"#,
        r#"{"domain":"injected.example"}"#,
    ] {
        for kind in ["ProcessExec", "DnsQuery"] {
            let replay = format!(
                r#"{{"event_type":"{kind}","pid":1,"uid":501,"ts_ns":42,"pid_start_ns":"malformed","payload":"path=/safe","fields":{injected}}}"#
            );
            assert!(super::parse_event_line(&replay).is_none());
            let native = format!(
                r#"{{"event_type":"{kind}","pid":1,"uid":501,"ts_ns":42,"pid_start_ns":"malformed","event":{{"fields":{injected}}}}}"#
            );
            let event = super::parse_event_line(&native).unwrap();
            assert_eq!(event.fields, Default::default());
            // Replay payload remains legacy-compatible; no typed trust is granted.
        }
    }
}
