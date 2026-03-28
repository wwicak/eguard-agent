use serde::Serialize;

use crate::platform::{EnrichedEvent, EventType, RawEvent};

use detection::TelemetryEvent;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct EventTxn {
    pub event_class: String,
    pub operation: String,
    pub subject: Option<String>,
    pub object: Option<String>,
    pub pid: u32,
    pub uid: u32,
    pub session_id: u32,
    pub ts_unix: i64,
    pub key: String,
}

impl EventTxn {
    pub(super) fn from_enriched(
        enriched: &EnrichedEvent,
        event: &TelemetryEvent,
        now_unix: i64,
    ) -> Self {
        let operation = operation_from_event_type(&enriched.event.event_type).to_string();

        let subject = match enriched.event.event_type {
            EventType::TcpConnect => event
                .dst_domain
                .clone()
                .or_else(|| event.dst_ip.clone())
                .or_else(|| event.file_path.clone())
                .or_else(|| Some(event.process.clone())),
            EventType::DnsQuery => event
                .dst_domain
                .clone()
                .or_else(|| event.file_path.clone())
                .or_else(|| Some(event.process.clone())),
            _ => event
                .file_path
                .clone()
                .or_else(|| enriched.process_exe.clone())
                .or_else(|| Some(event.process.clone())),
        };

        let object = match enriched.event.event_type {
            EventType::FileRename => enriched.file_path_secondary.clone(),
            EventType::TcpConnect => network_endpoint(event.dst_ip.as_deref(), event.dst_port),
            _ => None,
        };

        let key = build_txn_key(
            event.event_class.as_str(),
            &operation,
            subject.as_deref(),
            object.as_deref(),
            event.pid,
            event.session_id,
        );

        Self {
            event_class: event.event_class.as_str().to_string(),
            operation,
            subject,
            object,
            pid: event.pid,
            uid: event.uid,
            session_id: event.session_id,
            ts_unix: now_unix,
            key,
        }
    }

    pub(super) fn from_raw(raw: &RawEvent) -> Self {
        let operation = operation_from_event_type(&raw.event_type).to_string();
        let (subject, object) = match raw.event_type {
            EventType::FileRename => {
                let (src, dst) = parse_rename_paths(&raw.payload);
                let subject = dst.clone().or(src);
                (subject, dst)
            }
            EventType::TcpConnect => {
                let endpoint = parse_payload_field(&raw.payload, "dst")
                    .or_else(|| parse_payload_field(&raw.payload, "endpoint"))
                    .or_else(|| {
                        let dst_ip = parse_payload_field(&raw.payload, "dst_ip")
                            .or_else(|| parse_payload_field(&raw.payload, "ip"));
                        let dst_port = parse_payload_field(&raw.payload, "dst_port")
                            .or_else(|| parse_payload_field(&raw.payload, "port"))
                            .and_then(|raw| raw.parse::<u16>().ok());
                        network_endpoint(dst_ip.as_deref(), dst_port).or(dst_ip)
                    });
                (endpoint.clone(), endpoint)
            }
            EventType::DnsQuery => {
                let domain = parse_payload_field(&raw.payload, "dst_domain")
                    .or_else(|| parse_payload_field(&raw.payload, "qname"))
                    .or_else(|| parse_payload_field(&raw.payload, "domain"));
                (domain, None)
            }
            EventType::ProcessExec => {
                let process = parse_payload_field(&raw.payload, "path")
                    .or_else(|| parse_payload_field(&raw.payload, "exe"))
                    .or_else(|| {
                        let trimmed = raw.payload.trim();
                        (!trimmed.is_empty() && !trimmed.contains('=')).then(|| trimmed.to_string())
                    });
                (process, None)
            }
            EventType::ModuleLoad => {
                let module = parse_payload_field(&raw.payload, "module")
                    .or_else(|| parse_payload_field(&raw.payload, "path"))
                    .or_else(|| {
                        let trimmed = raw.payload.trim();
                        (!trimmed.is_empty()).then(|| trimmed.to_string())
                    });
                (module, None)
            }
            _ => {
                let path = parse_payload_field(&raw.payload, "path").or_else(|| {
                    let trimmed = raw.payload.trim();
                    (!trimmed.is_empty() && !trimmed.contains('=')).then(|| trimmed.to_string())
                });
                (path, None)
            }
        };

        let ts_unix = (raw.ts_ns / 1_000_000_000).min(i64::MAX as u64) as i64;
        let key = build_txn_key(
            map_event_class(&raw.event_type),
            &operation,
            subject.as_deref(),
            object.as_deref(),
            raw.pid,
            raw.pid,
        );

        Self {
            event_class: map_event_class(&raw.event_type).to_string(),
            operation,
            subject,
            object,
            pid: raw.pid,
            uid: raw.uid,
            session_id: raw.pid,
            ts_unix,
            key,
        }
    }
}

pub(super) fn coalesce_file_event_key(raw: &RawEvent) -> Option<String> {
    match raw.event_type {
        EventType::FileOpen => {
            let txn = EventTxn::from_raw(raw);
            txn.subject.as_deref().map(|subject| {
                format!(
                    "{}:{}:{}",
                    txn.operation,
                    file_open_access_intent(&raw.payload),
                    normalize_value(subject)
                )
            })
        }
        EventType::FileWrite | EventType::FileRename | EventType::FileUnlink => {
            let txn = EventTxn::from_raw(raw);
            txn.subject
                .as_deref()
                .map(|subject| format!("{}:{}", txn.operation, normalize_value(subject)))
        }
        _ => None,
    }
}

fn map_event_class(event_type: &EventType) -> &'static str {
    match event_type {
        EventType::ProcessExec => "process_exec",
        EventType::ProcessExit => "process_exit",
        EventType::FileOpen
        | EventType::FileWrite
        | EventType::FileRename
        | EventType::FileUnlink => "file_open",
        EventType::TcpConnect => "network_connect",
        EventType::DnsQuery => "dns_query",
        EventType::ModuleLoad => "module_load",
        EventType::LsmBlock => "alert",
    }
}

fn operation_from_event_type(event_type: &EventType) -> &'static str {
    match event_type {
        EventType::ProcessExec => "process_exec",
        EventType::ProcessExit => "process_exit",
        EventType::FileOpen => "file_open",
        EventType::FileWrite => "file_write",
        EventType::FileRename => "file_rename",
        EventType::FileUnlink => "file_unlink",
        EventType::TcpConnect => "tcp_connect",
        EventType::DnsQuery => "dns_query",
        EventType::ModuleLoad => "module_load",
        EventType::LsmBlock => "lsm_block",
    }
}

fn network_endpoint(dst_ip: Option<&str>, dst_port: Option<u16>) -> Option<String> {
    match (dst_ip, dst_port) {
        (Some(ip), Some(port)) => Some(format!("{}:{}", ip, port)),
        (Some(ip), None) => Some(ip.to_string()),
        _ => None,
    }
}

fn build_txn_key(
    event_class: &str,
    operation: &str,
    subject: Option<&str>,
    object: Option<&str>,
    pid: u32,
    session_id: u32,
) -> String {
    let subject = subject
        .map(normalize_value)
        .unwrap_or_else(|| "-".to_string());
    let object = object
        .map(normalize_value)
        .unwrap_or_else(|| "-".to_string());
    format!(
        "{}|{}|{}|{}|pid:{}|sid:{}",
        event_class, operation, subject, object, pid, session_id
    )
}

fn normalize_value(value: &str) -> String {
    value.trim().replace('\\', "/").to_ascii_lowercase()
}

fn parse_payload_field(payload: &str, field: &str) -> Option<String> {
    payload
        .split([';', ','])
        .filter_map(|segment| segment.split_once('='))
        .find_map(|(key, value)| {
            if key.trim().eq_ignore_ascii_case(field) {
                let value = decode_payload_value(value.trim());
                if value.is_empty() {
                    None
                } else {
                    Some(value)
                }
            } else {
                None
            }
        })
}

fn decode_payload_value(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = &raw[index + 1..index + 3];
            if let Ok(value) = u8::from_str_radix(hex, 16) {
                out.push(value as char);
                index += 3;
                continue;
            }
        }

        if let Some(ch) = raw[index..].chars().next() {
            out.push(ch);
            index += ch.len_utf8();
        } else {
            break;
        }
    }

    out
}

fn parse_rename_paths(payload: &str) -> (Option<String>, Option<String>) {
    let src = parse_payload_field(payload, "src")
        .or_else(|| parse_payload_field(payload, "old"))
        .or_else(|| parse_payload_field(payload, "old_path"));
    let dst = parse_payload_field(payload, "dst")
        .or_else(|| parse_payload_field(payload, "new"))
        .or_else(|| parse_payload_field(payload, "new_path"));
    (src, dst)
}

fn file_open_access_intent(payload: &str) -> &'static str {
    if parse_file_write_flags(
        parse_payload_field(payload, "flags").as_deref(),
        parse_payload_field(payload, "mode").as_deref(),
    ) {
        "write"
    } else {
        "read"
    }
}

fn parse_file_write_flags(flags: Option<&str>, mode: Option<&str>) -> bool {
    let flags_val = flags
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    let mode_val = mode
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);

    const O_WRONLY: u32 = 1;
    const O_RDWR: u32 = 2;
    const O_CREAT: u32 = 0x40;
    const O_TRUNC: u32 = 0x200;

    let write_intent = (flags_val & O_WRONLY) != 0 || (flags_val & O_RDWR) != 0;
    let destructive = (flags_val & O_TRUNC) != 0 || (flags_val & O_CREAT) != 0;
    let executable_bit = (mode_val & 0o111) != 0;

    write_intent || destructive || executable_bit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalesce_file_event_key_normalizes_windows_separators() {
        let raw = RawEvent {
            event_type: EventType::FileWrite,
            pid: 10,
            uid: 0,
            ts_ns: 1,
            payload: r#"path=C:\Windows\Temp\Artifact.bin"#.to_string(),
        };

        let key = coalesce_file_event_key(&raw).expect("file coalesce key");
        assert_eq!(key, "file_write:c:/windows/temp/artifact.bin");
    }

    #[test]
    fn coalesce_file_event_key_distinguishes_read_and_write_file_open_modes() {
        let write_raw = RawEvent {
            event_type: EventType::FileOpen,
            pid: 10,
            uid: 0,
            ts_ns: 1,
            payload: "path=/tmp/eicar.com;flags=65;mode=420".to_string(),
        };
        let read_raw = RawEvent {
            event_type: EventType::FileOpen,
            pid: 10,
            uid: 0,
            ts_ns: 2,
            payload: "path=/tmp/eicar.com;flags=0;mode=0".to_string(),
        };

        let write_key = coalesce_file_event_key(&write_raw).expect("write key");
        let read_key = coalesce_file_event_key(&read_raw).expect("read key");

        assert_eq!(write_key, "file_open:write:/tmp/eicar.com");
        assert_eq!(read_key, "file_open:read:/tmp/eicar.com");
    }

    #[test]
    fn from_raw_file_rename_prefers_destination_subject() {
        let raw = RawEvent {
            event_type: EventType::FileRename,
            pid: 11,
            uid: 0,
            ts_ns: 1,
            payload: "src=/tmp/a.tmp;dst=/opt/app/a.bin".to_string(),
        };

        let txn = EventTxn::from_raw(&raw);
        assert_eq!(txn.operation, "file_rename");
        assert_eq!(txn.subject.as_deref(), Some("/opt/app/a.bin"));
        assert_eq!(txn.object.as_deref(), Some("/opt/app/a.bin"));
        assert!(txn.key.contains("file_open|file_rename"));
    }

    #[test]
    fn from_raw_tcp_connect_parses_dst_ip_and_port_fields() {
        let raw = RawEvent {
            event_type: EventType::TcpConnect,
            pid: 77,
            uid: 0,
            ts_ns: 1,
            payload: "dst_ip=203.0.113.9;dst_port=8443".to_string(),
        };

        let txn = EventTxn::from_raw(&raw);
        assert_eq!(txn.operation, "tcp_connect");
        assert_eq!(txn.subject.as_deref(), Some("203.0.113.9:8443"));
        assert_eq!(txn.object.as_deref(), Some("203.0.113.9:8443"));
    }

    #[test]
    fn from_enriched_builds_stable_transaction_key() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::TcpConnect,
                pid: 200,
                uid: 0,
                ts_ns: 1_700_000_000_000_000_000,
                payload: "dst=203.0.113.5:443".to_string(),
            },
            process_exe: Some("/usr/bin/curl".to_string()),
            process_exe_sha256: None,
            process_cmdline: Some("curl https://example.com".to_string()),
            parent_process: Some("bash".to_string()),
            parent_chain: vec![199, 1],
            file_path: None,
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: Some("203.0.113.5".to_string()),
            dst_port: Some(443),
            dst_domain: Some("example.com".to_string()),
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = TelemetryEvent {
            ts_unix: 1_700_000_000,
            event_class: detection::EventClass::NetworkConnect,
            pid: 200,
            ppid: 199,
            uid: 0,
            process: "curl".to_string(),
            parent_process: "bash".to_string(),
            session_id: 1,
            file_path: None,
            file_write: false,
            file_hash: None,
            dst_port: Some(443),
            dst_ip: Some("203.0.113.5".to_string()),
            dst_domain: Some("example.com".to_string()),
            command_line: Some("curl https://example.com".to_string()),
            event_size: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let txn = EventTxn::from_enriched(&enriched, &event, 1_700_000_000);
        assert_eq!(txn.event_class, "network_connect");
        assert_eq!(txn.operation, "tcp_connect");
        assert_eq!(txn.subject.as_deref(), Some("example.com"));
        assert_eq!(txn.object.as_deref(), Some("203.0.113.5:443"));
        assert!(txn.key.contains("network_connect|tcp_connect"));
    }
}
