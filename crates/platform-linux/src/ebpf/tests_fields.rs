use super::{codec::parse_raw_event, replay_codec::encode_replay_event};
use crate::RawEventFields;

#[test]
fn typed_fields_cover_every_replay_event_type() {
    let text = "a;,=%2F";
    let cases = [
        (
            "process_exec",
            serde_json::json!({"ppid":42,"cgroup_id":123,"comm":text,"parent_comm":text,"path":text,"cmdline":text}),
        ),
        (
            "file_open",
            serde_json::json!({"flags":2,"mode":384,"ppid":42,"cgroup_id":123,"comm":text,"parent_comm":text,"path":text}),
        ),
        (
            "tcp_connect",
            serde_json::json!({"family":2,"protocol":6,"src_ip":"192.0.2.1","dst_ip":"198.51.100.2","src_port":1234,"dst_port":443}),
        ),
        (
            "dns_query",
            serde_json::json!({"qtype":28,"qclass":1,"domain":text}),
        ),
        ("module_load", serde_json::json!({"module":text})),
        ("lsm_block", serde_json::json!({"reason":3,"subject":text})),
        ("process_exit", serde_json::json!({"comm":text})),
        (
            "file_write",
            serde_json::json!({"fd":7,"size":12345,"path":text}),
        ),
        (
            "file_rename",
            serde_json::json!({"path":text,"secondary_path":text}),
        ),
        ("file_unlink", serde_json::json!({"path":text})),
    ];
    let mut results = Vec::new();
    let mut expectations = Vec::new();
    for (kind, expected) in cases {
        let input = serde_json::json!({"event_type":kind,"pid":4242,"uid":1000,
            "ppid":42,"cgroup_id":123,"comm":text,"parent_comm":text,"path":text,"cmdline":text,
            "file_path":text,"src":text,"dst":text,"domain":text,"module_name":text,
            "subject":text,"flags":2,"mode":384,"fd":7,"size":12345,"reason":3,
            "qtype":28,"qclass":1,"src_ip":"192.0.2.1","dst_ip":"198.51.100.2",
            "src_port":1234,"dst_port":443});
        let binary = encode_replay_event(&input.to_string()).unwrap();
        let event = parse_raw_event(&binary).unwrap();
        let mut actual = serde_json::to_value(&event).unwrap()["fields"].clone();
        if let Some(fields) = actual.as_object_mut() {
            fields.retain(|_, value| !value.is_null());
        }
        results.push((kind, actual));
        expectations.push((kind, expected));
    }
    assert_eq!(results, expectations);
}

fn decode(kind: u8, body: &[u8]) -> crate::RawEvent {
    let mut raw = vec![0; 21];
    raw[0] = kind;
    raw.extend_from_slice(body);
    parse_raw_event(&raw).unwrap()
}

#[test]
fn typed_fields_binary_legacy_ipv6_non_utf8_and_short_records() {
    let mut exec = vec![0; 364]; // legacy exec without parent_comm
    exec[..4].copy_from_slice(&42u32.to_le_bytes());
    exec[12..16].copy_from_slice(b"x;\xff\0");
    exec[44..46].copy_from_slice(b"/x");
    exec[204..210].copy_from_slice(b"a\0b\0c\0");
    let fields = decode(1, &exec).fields;
    assert_eq!(fields.comm.as_deref(), Some("x;�"));
    assert_eq!(fields.path.as_deref(), Some("/x"));
    assert_eq!(fields.cmdline.as_deref(), Some("a b c"));
    assert_eq!(fields.ppid, Some(42));
    assert_eq!(fields.parent_comm, None);
    let mut open = vec![0; 264];
    open[..4].copy_from_slice(&2u32.to_le_bytes());
    open[8..12].copy_from_slice(b"x;\xff\0");
    let fields = decode(2, &open).fields;
    assert_eq!(fields.path.as_deref(), Some("x;�"));
    assert_eq!(fields.flags, Some(2));
    assert_eq!(fields.ppid, None);
    let mut network = vec![0; 48];
    network[..2].copy_from_slice(&10u16.to_le_bytes());
    network[31] = 1;
    network[47] = 2;
    let fields = decode(3, &network).fields;
    assert_eq!(fields.src_ip.as_deref(), Some("::1"));
    assert_eq!(fields.dst_ip.as_deref(), Some("::2"));
    let mut rename = vec![0; 384];
    rename[0] = b'a';
    rename[192] = b'b';
    let fields = decode(9, &rename).fields;
    assert_eq!(fields.path.as_deref(), Some("a"));
    assert_eq!(fields.secondary_path.as_deref(), Some("b"));
    for kind in [1, 2, 3, 4, 6, 8] {
        assert_eq!(
            decode(kind, b"x").fields,
            RawEventFields::default(),
            "short {kind}"
        );
    }
    assert_eq!(decode(8, &[0; 12]).fields.size, Some(0));
    assert_eq!(decode(6, &[0; 4]).fields.reason, Some(0));
}
