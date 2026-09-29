use super::*;

fn binary(offset: usize, value: &str) -> Vec<u8> {
    let mut data = vec![0; offset];
    for ch in value.encode_utf16().chain(std::iter::once(0)) {
        data.extend_from_slice(&ch.to_le_bytes());
    }
    data
}

#[test]
fn codec_payload_round_trips_windows_strings() {
    let value = "C:\\a;,=%\n%3Bz";
    let cases = [
        (decode_kernel_process(1, 1, 1, &binary(24, value)), "path"),
        (decode_kernel_process(2, 1, 1, &binary(24, value)), "path"),
        (decode_kernel_file(32, 1, 1, &binary(8, value)), "path"),
        (decode_kernel_file(64, 1, 1, &binary(32, value)), "path"),
        (decode_kernel_file(12, 1, 1, &binary(24, value)), "path"),
        (decode_kernel_file(14, 1, 1, &binary(36, value)), "path"),
        (decode_kernel_file(26, 1, 1, &binary(36, value)), "path"),
        (decode_dns_client(0, 1, 1, &binary(0, value)), "qname"),
        (decode_image_load(0, 1, 1, &binary(36, value)), "module"),
    ];
    for (event, key) in cases {
        let event = event.unwrap();
        let fields = crate::parse_kv_fields(&event.payload);
        assert_eq!(
            fields.get(key).map(String::as_str),
            Some(value),
            "{}",
            event.payload
        );
        assert!(!event.payload.contains('\n'));
    }
}

#[test]
fn codec_payload_round_trips_windows_audit_strings() {
    let value = "a;,=%\n%3Bz";
    let fields = std::collections::HashMap::from([
        ("NewProcessId".into(), "123".into()),
        ("NewProcessName".into(), value.into()),
        ("ParentProcessName".into(), value.into()),
        ("CommandLine".into(), value.into()),
    ]);
    let event = super::super::security_auditing::build_process_create_event(&fields, 1).unwrap();
    let fields = crate::parse_kv_fields(&event.payload);
    for key in ["path", "parent_process", "cmdline"] {
        assert_eq!(fields.get(key).map(String::as_str), Some(value));
    }
}
