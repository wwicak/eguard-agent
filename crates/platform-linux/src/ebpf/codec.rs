use crate::{EventType, RawEvent};

use super::types::{EbpfError, Result, EVENT_HEADER_SIZE};

fn read_u16_le(raw: &[u8], offset: usize) -> Result<u16> {
    let end = offset.saturating_add(2);
    let bytes = raw
        .get(offset..end)
        .ok_or_else(|| EbpfError::Parse(format!("u16 out of bounds at offset {}", offset)))?;
    let mut out = [0u8; 2];
    out.copy_from_slice(bytes);
    Ok(u16::from_le_bytes(out))
}

fn read_u32_le(raw: &[u8], offset: usize) -> Result<u32> {
    let end = offset.saturating_add(4);
    let bytes = raw
        .get(offset..end)
        .ok_or_else(|| EbpfError::Parse(format!("u32 out of bounds at offset {}", offset)))?;
    let mut out = [0u8; 4];
    out.copy_from_slice(bytes);
    Ok(u32::from_le_bytes(out))
}

fn read_u64_le(raw: &[u8], offset: usize) -> Result<u64> {
    let end = offset.saturating_add(8);
    let bytes = raw
        .get(offset..end)
        .ok_or_else(|| EbpfError::Parse(format!("u64 out of bounds at offset {}", offset)))?;
    let mut out = [0u8; 8];
    out.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(out))
}

pub(super) fn parse_raw_event(raw: &[u8]) -> Result<RawEvent> {
    if raw.len() < EVENT_HEADER_SIZE {
        return Err(EbpfError::Parse(format!(
            "event shorter than header: got {} bytes, need at least {}",
            raw.len(),
            EVENT_HEADER_SIZE
        )));
    }

    let event_type = parse_event_type(raw[0])?;
    let pid = read_u32_le(raw, 1)?;
    let uid = read_u32_le(raw, 9)?;
    let timestamp_ns = read_u64_le(raw, 13)?;
    let payload = parse_payload(event_type, &raw[EVENT_HEADER_SIZE..]);

    Ok(RawEvent {
        event_type,
        pid,
        uid,
        ts_ns: timestamp_ns,
        payload,
    })
}

pub(super) fn parse_event_type(raw: u8) -> Result<EventType> {
    match raw {
        1 => Ok(EventType::ProcessExec),
        2 => Ok(EventType::FileOpen),
        3 => Ok(EventType::TcpConnect),
        4 => Ok(EventType::DnsQuery),
        5 => Ok(EventType::ModuleLoad),
        6 => Ok(EventType::LsmBlock),
        7 => Ok(EventType::ProcessExit),
        8 => Ok(EventType::FileWrite),
        9 => Ok(EventType::FileRename),
        10 => Ok(EventType::FileUnlink),
        other => Err(EbpfError::Parse(format!("unknown event type id {}", other))),
    }
}

fn parse_payload(event_type: EventType, raw: &[u8]) -> String {
    match event_type {
        EventType::ProcessExec => parse_process_exec_payload(raw),
        EventType::ProcessExit => parse_c_string(raw),
        EventType::FileOpen => parse_file_open_payload(raw),
        EventType::FileWrite => parse_file_write_payload(raw),
        EventType::FileRename => parse_file_rename_payload(raw),
        EventType::FileUnlink => parse_file_unlink_payload(raw),
        EventType::TcpConnect => parse_tcp_connect_payload(raw),
        EventType::DnsQuery => parse_dns_query_payload(raw),
        EventType::ModuleLoad => parse_module_load_payload(raw),
        EventType::LsmBlock => parse_lsm_block_payload(raw),
    }
}

fn parse_process_exec_payload(raw: &[u8]) -> String {
    if raw.len() < 4 + 8 + 32 {
        return parse_c_string(raw);
    }

    let ppid = read_u32_le(raw, 0).unwrap_or_default();
    let cgroup_id = read_u64_le(raw, 4).unwrap_or_default();
    let comm = parse_c_string(slice_window(raw, 12, 32));
    let path = parse_c_string(slice_window(raw, 44, 160));
    let cmdline = parse_c_string(slice_window(raw, 204, 160));

    if comm.is_empty() && path.is_empty() && cmdline.is_empty() {
        return parse_c_string(raw);
    }

    format!(
        "ppid={};cgroup_id={};comm={};path={};cmdline={}",
        ppid, cgroup_id, comm, path, cmdline
    )
}

fn parse_file_open_payload(raw: &[u8]) -> String {
    if raw.len() < 8 {
        return parse_c_string(raw);
    }

    let flags = read_u32_le(raw, 0).unwrap_or_default();
    let mode = read_u32_le(raw, 4).unwrap_or_default();
    let path = parse_c_string(slice_window(raw, 8, 256));
    if path.is_empty() {
        return parse_c_string(raw);
    }

    format!("path={};flags={};mode={}", path, flags, mode)
}

fn parse_file_write_payload(raw: &[u8]) -> String {
    if raw.len() < 12 {
        return parse_c_string(raw);
    }

    let fd = read_u32_le(raw, 0).unwrap_or_default();
    let size = read_u64_le(raw, 4).unwrap_or_default();
    let path = parse_c_string(slice_window(raw, 12, 256));
    if path.is_empty() {
        return format!("fd={};size={}", fd, size);
    }

    format!("path={};fd={};size={}", path, fd, size)
}

fn parse_file_rename_payload(raw: &[u8]) -> String {
    let old_path = parse_c_string(slice_window(raw, 0, 256));
    let new_path = parse_c_string(slice_window(raw, 256, 256));
    if old_path.is_empty() && new_path.is_empty() {
        return parse_c_string(raw);
    }
    format!("src={};dst={}", old_path, new_path)
}

fn parse_file_unlink_payload(raw: &[u8]) -> String {
    let path = parse_c_string(slice_window(raw, 0, 256));
    if path.is_empty() {
        return parse_c_string(raw);
    }
    format!("path={}", path)
}

fn parse_tcp_connect_payload(raw: &[u8]) -> String {
    if raw.len() < 16 {
        return parse_c_string(raw);
    }

    let family = read_u16_le(raw, 0).unwrap_or_default();
    let sport = read_u16_le(raw, 2).unwrap_or_default();
    let dport = read_u16_le(raw, 4).unwrap_or_default();
    let protocol = raw.get(6).copied().unwrap_or_default();
    let saddr_v4 = read_ipv4(raw, 8).unwrap_or([0u8; 4]);
    let daddr_v4 = read_ipv4(raw, 12).unwrap_or([0u8; 4]);

    let (src_ip, dst_ip) = if family == 10 && raw.len() >= 48 {
        let src_v6 = read_ipv6(raw, 16);
        let dst_v6 = read_ipv6(raw, 32);
        match (src_v6, dst_v6) {
            (Some(src), Some(dst)) => (format_ipv6(src), format_ipv6(dst)),
            _ => (format_ipv4(saddr_v4), format_ipv4(daddr_v4)),
        }
    } else {
        (format_ipv4(saddr_v4), format_ipv4(daddr_v4))
    };

    format!(
        "family={};protocol={};src_ip={};src_port={};dst_ip={};dst_port={}",
        family, protocol, src_ip, sport, dst_ip, dport
    )
}

fn parse_dns_query_payload(raw: &[u8]) -> String {
    if raw.len() < 4 {
        return parse_c_string(raw);
    }

    let qtype = read_u16_le(raw, 0).unwrap_or_default();
    let qclass = read_u16_le(raw, 2).unwrap_or_default();
    let qname = parse_c_string(slice_window(raw, 4, 128));
    if qname.is_empty() {
        return parse_c_string(raw);
    }

    format!("qname={};qtype={};qclass={}", qname, qtype, qclass)
}

fn parse_module_load_payload(raw: &[u8]) -> String {
    let module_name = parse_c_string(slice_window(raw, 0, 64));
    if module_name.is_empty() {
        return parse_c_string(raw);
    }

    format!("module={}", module_name)
}

fn parse_lsm_block_payload(raw: &[u8]) -> String {
    if raw.len() < 4 {
        return parse_c_string(raw);
    }

    let reason = raw[0];
    let subject = parse_c_string(slice_window(raw, 4, 128));
    if subject.is_empty() {
        return format!("reason={}", reason);
    }

    format!("reason={};subject={}", reason, subject)
}

fn format_ipv4(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

fn format_ipv6(ip: [u8; 16]) -> String {
    std::net::Ipv6Addr::from(ip).to_string()
}

fn read_ipv4(raw: &[u8], offset: usize) -> Option<[u8; 4]> {
    let end = offset.checked_add(4)?;
    let bytes = raw.get(offset..end)?;
    let mut out = [0u8; 4];
    out.copy_from_slice(bytes);
    Some(out)
}

fn read_ipv6(raw: &[u8], offset: usize) -> Option<[u8; 16]> {
    let end = offset.checked_add(16)?;
    let bytes = raw.get(offset..end)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(bytes);
    Some(out)
}

fn parse_c_string(raw: &[u8]) -> String {
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

fn slice_window(raw: &[u8], offset: usize, max_len: usize) -> &[u8] {
    if offset >= raw.len() {
        return &[];
    }

    let end = raw.len().min(offset.saturating_add(max_len));
    &raw[offset..end]
}

#[cfg(any(test, feature = "ebpf-libbpf"))]
pub(super) fn parse_fallback_dropped_events(raw: &[u8]) -> Option<u64> {
    use super::types::FALLBACK_DROPPED_OFFSET;

    let end = FALLBACK_DROPPED_OFFSET.checked_add(std::mem::size_of::<u64>())?;
    let bytes = raw.get(FALLBACK_DROPPED_OFFSET..end)?;
    let mut out = [0u8; 8];
    out.copy_from_slice(bytes);
    Some(u64::from_le_bytes(out))
}
