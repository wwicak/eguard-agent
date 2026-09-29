use super::{encode_replay_event, parse_raw_event};

#[test]
fn codec_payload_round_trips_every_userspace_field() {
    let value = "a;,=%\n%3Bz";
    let cases = [
        (
            "process_exec",
            vec![
                ("comm", "comm"),
                ("parent_comm", "parent_comm"),
                ("path", "path"),
                ("cmdline", "cmdline"),
            ],
        ),
        (
            "file_open",
            vec![
                ("file_path", "path"),
                ("comm", "comm"),
                ("parent_comm", "parent_comm"),
            ],
        ),
        ("file_write", vec![("file_path", "path")]),
        ("file_rename", vec![("src", "src"), ("dst", "dst")]),
        ("file_unlink", vec![("file_path", "path")]),
        ("dns_query", vec![("domain", "qname")]),
        ("module_load", vec![("module_name", "module")]),
        ("lsm_block", vec![("subject", "subject")]),
    ];
    for (kind, fields) in cases {
        let mut input = serde_json::json!({"event_type": kind, "pid": 1234, "ppid": 4321});
        for (source, _) in &fields {
            input[*source] = value.into();
        }
        let bytes = encode_replay_event(&input.to_string()).unwrap();
        let event = parse_raw_event(&bytes).unwrap();
        let parsed = crate::parse_kv_fields(&event.payload);
        for (_, key) in fields {
            assert_eq!(
                parsed.get(key).map(String::as_str),
                Some(value),
                "{kind}.{key}: {}",
                event.payload
            );
        }
        assert!(!event.payload.contains('\n'));
        assert!(event.payload.contains("%3D"));
        assert!(event.payload.contains("%253B"));
    }
}

#[test]
fn codec_payload_fallback_cannot_inject_security_fields() {
    let mut raw = vec![0; 21];
    raw[0] = 1;
    raw.extend_from_slice(b"x;ppid=123");
    let event = parse_raw_event(&raw).unwrap();
    assert!(!event.payload.contains("ppid="));
    assert_eq!(crate::decode_payload_value(&event.payload), "x;ppid=123");
}
