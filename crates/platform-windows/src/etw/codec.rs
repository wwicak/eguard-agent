//! ETW event decoding: maps raw ETW event records to `RawEvent`.
//!
//! Two entry points:
//! - `decode_etw_event()` — text-mode (replay path, unchanged)
//! - `decode_etw_record()` — binary-mode (real ETW `UserData` parsing)
//!
//! On non-Windows builds the binary decoders are only exercised via tests;
//! the real call site lives inside the `cfg(windows)` consumer callback.

// Binary codec helpers are only called from the Windows consumer callback.
// On non-Windows they're tested but not linked into any runtime path.
#![allow(dead_code)]

use crate::{EventType, RawEvent};

// ── Text-mode decoder (replay path) ─────────────────────────────────

/// Decode a text-mode ETW event buffer into a `RawEvent`.
///
/// Used by the replay subsystem where payloads are pre-formatted key=value strings.
pub fn decode_etw_event(
    provider_guid: &str,
    opcode: u8,
    pid: u32,
    ts_ns: u64,
    data: &[u8],
) -> Option<RawEvent> {
    let event_type = map_provider_opcode(provider_guid, opcode)?;
    let payload = String::from_utf8_lossy(data).into_owned();

    Some(RawEvent {
        event_type,
        pid,
        uid: 0, // Windows uses SIDs, resolved during enrichment
        ts_ns,
        payload,
    })
}

// ── Binary-mode decoder (real ETW records) ───────────────────────────

/// Decode a real ETW `EVENT_RECORD.UserData` buffer into a `RawEvent`.
///
/// Each provider+opcode combination has a specific binary layout. We parse
/// the fields we need and format them as `key=value;key=value` payloads
/// compatible with the enrichment pipeline.
pub fn decode_etw_record(
    provider_guid: &str,
    opcode: u8,
    pid: u32,
    ts_ns: u64,
    user_data: &[u8],
) -> Option<RawEvent> {
    use super::providers::*;

    match provider_guid {
        KERNEL_PROCESS => decode_kernel_process(opcode, pid, ts_ns, user_data),
        KERNEL_FILE => decode_kernel_file(opcode, pid, ts_ns, user_data),
        KERNEL_NETWORK => decode_kernel_network(opcode, pid, ts_ns, user_data),
        DNS_CLIENT => decode_dns_client(opcode, pid, ts_ns, user_data),
        KERNEL_GENERAL | IMAGE_LOAD => decode_image_load(opcode, pid, ts_ns, user_data),
        _ => {
            tracing::trace!(provider = provider_guid, opcode, "unmapped ETW record");
            None
        }
    }
}

// ── Per-provider binary parsers ──────────────────────────────────────

/// Microsoft-Windows-Kernel-Process
///
/// Event ID 1 (ProcessStart): ProcessID(u32), CreateTime(u64), ParentProcessID(u32),
///   SessionID(u32), Flags(u32), ImageName(UTF-16, variable)
/// Event ID 2 (ProcessStop): ProcessID(u32), CreateTime(u64), ExitTime(u64),
///   ExitCode(u32), ImageName(UTF-16, variable)
fn decode_kernel_process(opcode: u8, pid: u32, ts_ns: u64, data: &[u8]) -> Option<RawEvent> {
    match opcode {
        // ProcessStart
        1 => {
            // Minimum: ProcessID(4) + CreateTime(8) + ParentID(4) + SessionID(4) + Flags(4) = 24
            if data.len() < 24 {
                return fallback_event(EventType::ProcessExec, pid, ts_ns, data);
            }
            let parent_pid = read_u32_le(data, 12);
            let session_id = read_u32_le(data, 16);
            let image_name = read_utf16_str(data, 24);

            let mut payload = format!("ppid={parent_pid};session_id={session_id}");
            if let Some(name) = image_name {
                payload.push_str(&format!(";path={name}"));
            }

            Some(RawEvent {
                event_type: EventType::ProcessExec,
                pid,
                uid: 0,
                ts_ns,
                payload,
            })
        }
        // ProcessStop
        2 => {
            // ProcessID(4) + CreateTime(8) + ExitTime(8) + ExitCode(4) = 24
            if data.len() < 24 {
                return fallback_event(EventType::ProcessExit, pid, ts_ns, data);
            }
            let exit_code = read_u32_le(data, 20);
            let image_name = read_utf16_str(data, 24);

            let mut payload = format!("exit_code={exit_code}");
            if let Some(name) = image_name {
                payload.push_str(&format!(";path={name}"));
            }

            Some(RawEvent {
                event_type: EventType::ProcessExit,
                pid,
                uid: 0,
                ts_ns,
                payload,
            })
        }
        _ => None,
    }
}

/// Microsoft-Windows-Kernel-File
///
/// Event ID 12 (Create): IrpPtr(8) + FileObject(8) + CreateOptions(4) +
///   FileAttributes(4) + ShareAccess(4) + FileName(UTF-16)
/// Event ID 15 (Write): ByteOffset(8) + IrpPtr(8) + FileObject(8) + FileKey(8) +
///   ExtraInfo(8) + InfoClass(4) + IoSize(4) + IoFlags(4)
/// Event ID 14 (Rename): IrpPtr(8) + FileObject(8) + FileKey(8) + ExtraInfo(8) +
///   InfoClass(4) + FileName(UTF-16)
/// Event ID 26 (Delete): same layout as Rename
fn decode_kernel_file(opcode: u8, pid: u32, ts_ns: u64, data: &[u8]) -> Option<RawEvent> {
    match opcode {
        // FileCreate
        12 | 0 | 32 => {
            // IrpPtr(8) + FileObject(8) + CreateOptions(4) + FileAttributes(4) + ShareAccess(4) = 28
            let filename = read_utf16_str(data, 28);
            let payload = match filename {
                Some(name) => format!("path={name}"),
                None => String::new(),
            };
            Some(RawEvent {
                event_type: EventType::FileOpen,
                pid,
                uid: 0,
                ts_ns,
                payload,
            })
        }
        // FileWrite
        15 | 35 => {
            // ByteOffset(8)+IrpPtr(8)+FileObject(8)+FileKey(8)+ExtraInfo(8)+InfoClass(4)+IoSize(4)+IoFlags(4) = 52
            let io_size = if data.len() >= 52 {
                read_u32_le(data, 48)
            } else {
                0
            };
            Some(RawEvent {
                event_type: EventType::FileWrite,
                pid,
                uid: 0,
                ts_ns,
                payload: format!("size={io_size}"),
            })
        }
        // FileRename
        14 | 64 => {
            // IrpPtr(8)+FileObject(8)+FileKey(8)+ExtraInfo(8)+InfoClass(4) = 36
            let filename = read_utf16_str(data, 36);
            let payload = match filename {
                Some(name) => format!("path={name}"),
                None => String::new(),
            };
            Some(RawEvent {
                event_type: EventType::FileRename,
                pid,
                uid: 0,
                ts_ns,
                payload,
            })
        }
        // FileDelete
        26 | 70 => {
            // Same layout as Rename.
            let filename = read_utf16_str(data, 36);
            let payload = match filename {
                Some(name) => format!("path={name}"),
                None => String::new(),
            };
            Some(RawEvent {
                event_type: EventType::FileUnlink,
                pid,
                uid: 0,
                ts_ns,
                payload,
            })
        }
        _ => None,
    }
}

/// Microsoft-Windows-Kernel-Network (TCP/IP events).
///
/// Classic layout: PID(4) + size(4) + daddr(4) + saddr(4) + dport(2) + sport(2) = 20 bytes (IPv4).
/// IPv6: PID(4) + size(4) + daddr(16) + saddr(16) + dport(2) + sport(2) = 44 bytes.
fn decode_kernel_network(_opcode: u8, pid: u32, ts_ns: u64, data: &[u8]) -> Option<RawEvent> {
    // Try IPv4 first (20 bytes minimum).
    if data.len() >= 20 {
        let dst_ip = format_ipv4(data, 8);
        let src_ip = format_ipv4(data, 12);
        let dst_port = read_u16_be(data, 16); // Network byte order
        let src_port = read_u16_be(data, 18);

        let payload =
            format!("src_ip={src_ip};src_port={src_port};dst_ip={dst_ip};dst_port={dst_port}");
        return Some(RawEvent {
            event_type: EventType::TcpConnect,
            pid,
            uid: 0,
            ts_ns,
            payload,
        });
    }

    // Fallback for unknown/short buffers.
    fallback_event(EventType::TcpConnect, pid, ts_ns, data)
}

/// Microsoft-Windows-DNS-Client.
///
/// Event ID 3011/3008: QueryName is typically a UTF-16 string at the start of UserData.
fn decode_dns_client(_opcode: u8, pid: u32, ts_ns: u64, data: &[u8]) -> Option<RawEvent> {
    let qname = read_utf16_str(data, 0);
    let payload = match qname {
        Some(name) if !name.is_empty() => format!("qname={name}"),
        _ => return None, // No useful data to emit.
    };
    Some(RawEvent {
        event_type: EventType::DnsQuery,
        pid,
        uid: 0,
        ts_ns,
        payload,
    })
}

/// Kernel-General / Image Load provider.
///
/// Image load events typically have: ImageBase(8) + ImageSize(8) + ProcessId(4) +
///   ImageCheckSum(4) + ... + FileName(UTF-16).
/// We extract just the module path from the trailing UTF-16 string.
fn decode_image_load(_opcode: u8, pid: u32, ts_ns: u64, data: &[u8]) -> Option<RawEvent> {
    // ImageBase(8) + ImageSize(8) + ProcessId(4) + ImageCheckSum(4) +
    // TimeDateStamp(4) + DefaultBase(8) = 36 bytes before the filename.
    let module_path = read_utf16_str(data, 36)
        .or_else(|| read_utf16_str(data, 24))
        .or_else(|| read_utf16_str(data, 0));

    let payload = match module_path {
        Some(name) if !name.is_empty() => format!("module={name}"),
        _ => return None,
    };
    Some(RawEvent {
        event_type: EventType::ModuleLoad,
        pid,
        uid: 0,
        ts_ns,
        payload,
    })
}

// ── Shared helpers ───────────────────────────────────────────────────

/// Map a provider GUID + opcode to our canonical EventType.
fn map_provider_opcode(provider_guid: &str, opcode: u8) -> Option<EventType> {
    use super::providers::*;

    match provider_guid {
        KERNEL_PROCESS => match opcode {
            1 => Some(EventType::ProcessExec),
            2 => Some(EventType::ProcessExit),
            _ => None,
        },
        KERNEL_FILE => match opcode {
            // Design-doc canonical IDs.
            12 => Some(EventType::FileOpen),
            15 => Some(EventType::FileWrite),
            14 => Some(EventType::FileRename),
            26 => Some(EventType::FileUnlink),
            // Legacy aliases retained while parser/event manifests evolve.
            0 | 32 => Some(EventType::FileOpen),
            35 => Some(EventType::FileWrite),
            64 => Some(EventType::FileRename),
            70 => Some(EventType::FileUnlink),
            _ => None,
        },
        KERNEL_NETWORK => Some(EventType::TcpConnect),
        DNS_CLIENT => Some(EventType::DnsQuery),
        KERNEL_GENERAL | IMAGE_LOAD => Some(EventType::ModuleLoad),
        _ => {
            tracing::trace!(provider = provider_guid, opcode, "unmapped ETW event");
            None
        }
    }
}

/// Build a fallback RawEvent when binary parsing can't extract structured fields.
fn fallback_event(event_type: EventType, pid: u32, ts_ns: u64, data: &[u8]) -> Option<RawEvent> {
    let payload = if data.is_empty() {
        String::new()
    } else {
        String::from_utf8_lossy(data).into_owned()
    };
    Some(RawEvent {
        event_type,
        pid,
        uid: 0,
        ts_ns,
        payload,
    })
}

/// Read a little-endian u32 from `data` at `offset`. Returns 0 if out of bounds.
fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// Read a big-endian u16 (network byte order) from `data` at `offset`.
fn read_u16_be(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

/// Read a null-terminated UTF-16LE string starting at `offset`.
fn read_utf16_str(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() {
        return None;
    }

    let remaining = &data[offset..];
    // Need at least 2 bytes for one UTF-16 code unit.
    if remaining.len() < 2 {
        return None;
    }

    let mut chars = Vec::new();
    let mut i = 0;
    while i + 1 < remaining.len() {
        let code_unit = u16::from_le_bytes([remaining[i], remaining[i + 1]]);
        if code_unit == 0 {
            break;
        }
        chars.push(code_unit);
        i += 2;
    }

    if chars.is_empty() {
        return None;
    }

    Some(String::from_utf16_lossy(&chars))
}

/// Format 4 bytes starting at `offset` as an IPv4 dotted-decimal string.
fn format_ipv4(data: &[u8], offset: usize) -> String {
    if offset + 4 > data.len() {
        return "0.0.0.0".to_string();
    }
    format!(
        "{}.{}.{}.{}",
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventType;

    #[test]
    fn decodes_design_doc_file_event_ids() {
        let create = decode_etw_event(
            super::super::providers::KERNEL_FILE,
            12,
            123,
            42,
            b"path=C:\\a.txt",
        )
        .expect("event should decode");
        assert!(matches!(create.event_type, EventType::FileOpen));

        let write = decode_etw_event(
            super::super::providers::KERNEL_FILE,
            15,
            123,
            42,
            b"path=C:\\a.txt;size=12",
        )
        .expect("event should decode");
        assert!(matches!(write.event_type, EventType::FileWrite));

        let rename = decode_etw_event(
            super::super::providers::KERNEL_FILE,
            14,
            123,
            42,
            b"src=C:\\a.txt;dst=C:\\b.txt",
        )
        .expect("event should decode");
        assert!(matches!(rename.event_type, EventType::FileRename));

        let unlink = decode_etw_event(
            super::super::providers::KERNEL_FILE,
            26,
            123,
            42,
            b"path=C:\\b.txt",
        )
        .expect("event should decode");
        assert!(matches!(unlink.event_type, EventType::FileUnlink));
    }

    #[test]
    fn maps_kernel_general_to_module_load() {
        let evt = decode_etw_event(
            super::super::providers::KERNEL_GENERAL,
            15,
            1,
            1,
            b"path=C:\\Windows\\System32\\foo.dll",
        )
        .expect("event should decode");

        assert!(matches!(evt.event_type, EventType::ModuleLoad));
    }

    // ── Binary decoder tests ─────────────────────────────────────────

    #[test]
    fn decode_kernel_process_start_binary() {
        // Build binary: ProcessID(4) + CreateTime(8) + ParentID(4) + SessionID(4) + Flags(4) + ImageName(UTF-16)
        let mut data = Vec::new();
        data.extend_from_slice(&100u32.to_le_bytes()); // ProcessID
        data.extend_from_slice(&0u64.to_le_bytes()); // CreateTime
        data.extend_from_slice(&50u32.to_le_bytes()); // ParentID
        data.extend_from_slice(&1u32.to_le_bytes()); // SessionID
        data.extend_from_slice(&0u32.to_le_bytes()); // Flags
                                                     // Append "cmd.exe" as UTF-16LE null-terminated
        for ch in "cmd.exe".encode_utf16() {
            data.extend_from_slice(&ch.to_le_bytes());
        }
        data.extend_from_slice(&0u16.to_le_bytes()); // null terminator

        let event = decode_etw_record(super::super::providers::KERNEL_PROCESS, 1, 100, 999, &data)
            .expect("should decode");

        assert!(matches!(event.event_type, EventType::ProcessExec));
        assert_eq!(event.pid, 100);
        assert!(event.payload.contains("ppid=50"));
        assert!(event.payload.contains("session_id=1"));
        assert!(event.payload.contains("path=cmd.exe"));
    }

    #[test]
    fn decode_kernel_process_stop_binary() {
        let mut data = Vec::new();
        data.extend_from_slice(&200u32.to_le_bytes()); // ProcessID
        data.extend_from_slice(&0u64.to_le_bytes()); // CreateTime
        data.extend_from_slice(&0u64.to_le_bytes()); // ExitTime
        data.extend_from_slice(&1u32.to_le_bytes()); // ExitCode
        for ch in "svchost.exe".encode_utf16() {
            data.extend_from_slice(&ch.to_le_bytes());
        }
        data.extend_from_slice(&0u16.to_le_bytes());

        let event = decode_etw_record(super::super::providers::KERNEL_PROCESS, 2, 200, 1000, &data)
            .expect("should decode");

        assert!(matches!(event.event_type, EventType::ProcessExit));
        assert!(event.payload.contains("exit_code=1"));
        assert!(event.payload.contains("path=svchost.exe"));
    }

    #[test]
    fn decode_kernel_file_create_binary() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u64.to_le_bytes()); // IrpPtr
        data.extend_from_slice(&0u64.to_le_bytes()); // FileObject
        data.extend_from_slice(&0u32.to_le_bytes()); // CreateOptions
        data.extend_from_slice(&0u32.to_le_bytes()); // FileAttributes
        data.extend_from_slice(&0u32.to_le_bytes()); // ShareAccess
                                                     // Filename: "C:\test.txt"
        for ch in r"C:\test.txt".encode_utf16() {
            data.extend_from_slice(&ch.to_le_bytes());
        }
        data.extend_from_slice(&0u16.to_le_bytes());

        let event = decode_etw_record(super::super::providers::KERNEL_FILE, 12, 42, 500, &data)
            .expect("should decode");

        assert!(matches!(event.event_type, EventType::FileOpen));
        assert!(event.payload.contains(r"path=C:\test.txt"));
    }

    #[test]
    fn decode_kernel_network_ipv4_binary() {
        let mut data = Vec::new();
        data.extend_from_slice(&1000u32.to_le_bytes()); // PID
        data.extend_from_slice(&64u32.to_le_bytes()); // size
        data.extend_from_slice(&[203, 0, 113, 1]); // daddr: 203.0.113.1
        data.extend_from_slice(&[10, 0, 0, 1]); // saddr: 10.0.0.1
        data.extend_from_slice(&443u16.to_be_bytes()); // dport (network order)
        data.extend_from_slice(&50000u16.to_be_bytes()); // sport

        let event = decode_etw_record(
            super::super::providers::KERNEL_NETWORK,
            10,
            1000,
            700,
            &data,
        )
        .expect("should decode");

        assert!(matches!(event.event_type, EventType::TcpConnect));
        assert!(event.payload.contains("dst_ip=203.0.113.1"));
        assert!(event.payload.contains("dst_port=443"));
        assert!(event.payload.contains("src_ip=10.0.0.1"));
        assert!(event.payload.contains("src_port=50000"));
    }

    #[test]
    fn decode_dns_client_binary() {
        let mut data = Vec::new();
        for ch in "evil-c2.example.com".encode_utf16() {
            data.extend_from_slice(&ch.to_le_bytes());
        }
        data.extend_from_slice(&0u16.to_le_bytes());

        let event = decode_etw_record(super::super::providers::DNS_CLIENT, 0, 500, 800, &data)
            .expect("should decode");

        assert!(matches!(event.event_type, EventType::DnsQuery));
        assert!(event.payload.contains("qname=evil-c2.example.com"));
    }

    #[test]
    fn read_utf16_str_handles_empty() {
        assert!(read_utf16_str(&[], 0).is_none());
        assert!(read_utf16_str(&[0, 0], 0).is_none()); // just null terminator
    }

    #[test]
    fn read_utf16_str_without_null_terminator() {
        // "AB" without null terminator — should still parse.
        let data = [0x41, 0x00, 0x42, 0x00];
        let result = read_utf16_str(&data, 0).expect("should parse");
        assert_eq!(result, "AB");
    }

    #[test]
    fn format_ipv4_normal() {
        let data = [192, 168, 1, 100];
        assert_eq!(format_ipv4(&data, 0), "192.168.1.100");
    }

    #[test]
    fn format_ipv4_short_buffer() {
        assert_eq!(format_ipv4(&[1, 2], 0), "0.0.0.0");
    }
}
