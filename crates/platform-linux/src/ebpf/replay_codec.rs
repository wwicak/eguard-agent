use super::types::{EbpfError, Result};

/// Convert a single NDJSON line into the binary format that `parse_raw_event` expects.
pub(super) fn encode_replay_event(json_line: &str) -> Result<Vec<u8>> {
    let v: serde_json::Value = serde_json::from_str(json_line)
        .map_err(|e| EbpfError::Parse(format!("replay JSON: {}", e)))?;

    let event_type_str = v
        .get("event_type")
        .and_then(|v| v.as_str())
        .unwrap_or("process_exec");

    let type_id: u8 = match event_type_str {
        "process_exec" => 1,
        "file_open" => 2,
        "tcp_connect" | "network_connect" => 3,
        "dns_query" => 4,
        "module_load" => 5,
        "lsm_block" => 6,
        "process_exit" => 7,
        "file_write" => 8,
        "file_rename" => 9,
        "file_unlink" => 10,
        other => {
            return Err(EbpfError::Parse(format!(
                "unknown replay event_type: {}",
                other
            )));
        }
    };

    let pid = v.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let uid = v.get("uid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let ts_ns = v.get("ts_ns").and_then(|v| v.as_u64()).unwrap_or(0);

    // Build header: type(1) + pid(4) + ???(4 — uid occupies offset 9..13) + uid(4) + ts_ns(8)
    // Header layout from parse_raw_event:
    //   offset 0:  event_type (u8)
    //   offset 1:  pid        (u32 LE)
    //   offset 5:  ??? 4 bytes (from read_u32_le(raw, 9) → uid at byte 9)
    // Wait, let me re-read the header parsing:
    //   let event_type = parse_event_type(raw[0])?;         // offset 0, 1 byte
    //   let pid = read_u32_le(raw, 1)?;                     // offset 1, 4 bytes  → [1..5)
    //   let uid = read_u32_le(raw, 9)?;                     // offset 9, 4 bytes  → [9..13)
    //   let timestamp_ns = read_u64_le(raw, 13)?;           // offset 13, 8 bytes → [13..21)
    // EVENT_HEADER_SIZE = 1 + 4 + 4 + 4 + 8 = 21
    // So bytes [5..9) are 4 padding/unused bytes (likely ppid in the kernel struct).

    let ppid_field = v.get("ppid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

    let mut buf = Vec::with_capacity(256);
    buf.push(type_id); // offset 0
    buf.extend_from_slice(&pid.to_le_bytes()); // offset 1..5
    buf.extend_from_slice(&ppid_field.to_le_bytes()); // offset 5..9 (unused in parse but keep layout)
    buf.extend_from_slice(&uid.to_le_bytes()); // offset 9..13
    buf.extend_from_slice(&ts_ns.to_le_bytes()); // offset 13..21

    // Append payload based on event type
    match type_id {
        1 => encode_process_exec_payload(&v, &mut buf),
        2 => encode_file_open_payload(&v, &mut buf),
        3 => encode_tcp_connect_payload(&v, &mut buf),
        4 => encode_dns_query_payload(&v, &mut buf),
        5 => encode_module_load_payload(&v, &mut buf),
        6 => encode_lsm_block_payload(&v, &mut buf),
        7 => encode_process_exit_payload(&v, &mut buf),
        8 => encode_file_write_payload(&v, &mut buf),
        9 => encode_file_rename_payload(&v, &mut buf),
        10 => encode_file_unlink_payload(&v, &mut buf),
        _ => {}
    }

    Ok(buf)
}

fn push_c_string_padded(buf: &mut Vec<u8>, value: &str, max_len: usize) {
    let bytes = value.as_bytes();
    let copy_len = bytes.len().min(max_len.saturating_sub(1));
    buf.extend_from_slice(&bytes[..copy_len]);
    // Pad remainder with NUL
    for _ in copy_len..max_len {
        buf.push(0);
    }
}

fn encode_process_exec_payload(v: &serde_json::Value, buf: &mut Vec<u8>) {
    let ppid = v.get("ppid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let cgroup_id = v.get("cgroup_id").and_then(|v| v.as_u64()).unwrap_or(0);
    let comm = v.get("comm").and_then(|v| v.as_str()).unwrap_or("");
    let path = v.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let cmdline = v.get("cmdline").and_then(|v| v.as_str()).unwrap_or("");

    buf.extend_from_slice(&ppid.to_le_bytes());
    buf.extend_from_slice(&cgroup_id.to_le_bytes());
    push_c_string_padded(buf, comm, 32);
    push_c_string_padded(buf, path, 160);
    push_c_string_padded(buf, cmdline, 160);
}

fn encode_file_open_payload(v: &serde_json::Value, buf: &mut Vec<u8>) {
    let flags = v.get("flags").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let mode = v.get("mode").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let path = v.get("file_path").and_then(|v| v.as_str()).unwrap_or("");

    buf.extend_from_slice(&flags.to_le_bytes());
    buf.extend_from_slice(&mode.to_le_bytes());
    push_c_string_padded(buf, path, 256);
}

fn encode_file_write_payload(v: &serde_json::Value, buf: &mut Vec<u8>) {
    let fd = v.get("fd").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let size = v.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
    let path = v.get("file_path").and_then(|v| v.as_str()).unwrap_or("");

    buf.extend_from_slice(&fd.to_le_bytes());
    buf.extend_from_slice(&size.to_le_bytes());
    push_c_string_padded(buf, path, 256);
}

fn encode_file_rename_payload(v: &serde_json::Value, buf: &mut Vec<u8>) {
    let src = v
        .get("src")
        .or_else(|| v.get("old_path"))
        .or_else(|| v.get("old"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let dst = v
        .get("dst")
        .or_else(|| v.get("new_path"))
        .or_else(|| v.get("new"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    push_c_string_padded(buf, src, 256);
    push_c_string_padded(buf, dst, 256);
}

fn encode_file_unlink_payload(v: &serde_json::Value, buf: &mut Vec<u8>) {
    let path = v.get("file_path").and_then(|v| v.as_str()).unwrap_or("");
    push_c_string_padded(buf, path, 256);
}

fn encode_tcp_connect_payload(v: &serde_json::Value, buf: &mut Vec<u8>) {
    let family: u16 = 2; // AF_INET
    let sport: u16 = v.get("src_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
    let dport: u16 = v.get("dst_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
    let protocol: u8 = 6; // TCP

    let dst_ip_str = v.get("dst_ip").and_then(|v| v.as_str()).unwrap_or("0.0.0.0");
    let src_ip_str = v.get("src_ip").and_then(|v| v.as_str()).unwrap_or("0.0.0.0");

    let saddr = parse_ipv4_to_u32(src_ip_str);
    let daddr = parse_ipv4_to_u32(dst_ip_str);

    buf.extend_from_slice(&family.to_le_bytes());
    buf.extend_from_slice(&sport.to_le_bytes());
    buf.extend_from_slice(&dport.to_le_bytes());
    buf.push(protocol);
    buf.push(0);
    buf.extend_from_slice(&saddr.to_le_bytes());
    buf.extend_from_slice(&daddr.to_le_bytes());
}

fn encode_dns_query_payload(v: &serde_json::Value, buf: &mut Vec<u8>) {
    let qtype: u16 = v.get("qtype").and_then(|v| v.as_u64()).unwrap_or(1) as u16;
    let qclass: u16 = v.get("qclass").and_then(|v| v.as_u64()).unwrap_or(1) as u16;
    let qname = v.get("domain").and_then(|v| v.as_str()).unwrap_or("");

    buf.extend_from_slice(&qtype.to_le_bytes());
    buf.extend_from_slice(&qclass.to_le_bytes());
    push_c_string_padded(buf, qname, 128);
}

fn encode_module_load_payload(v: &serde_json::Value, buf: &mut Vec<u8>) {
    let module = v.get("module_name").and_then(|v| v.as_str()).unwrap_or("");
    push_c_string_padded(buf, module, 64);
}

fn encode_lsm_block_payload(v: &serde_json::Value, buf: &mut Vec<u8>) {
    let reason: u8 = v.get("reason").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
    buf.push(reason);
    buf.extend_from_slice(&[0u8; 3]); // padding to offset 4
    let subject = v.get("subject").and_then(|v| v.as_str()).unwrap_or("");
    push_c_string_padded(buf, subject, 128);
}

fn encode_process_exit_payload(v: &serde_json::Value, buf: &mut Vec<u8>) {
    let comm = v.get("comm").and_then(|v| v.as_str()).unwrap_or("");
    push_c_string_padded(buf, comm, 32);
}

fn parse_ipv4_to_u32(ip: &str) -> u32 {
    let parts: Vec<u8> = ip
        .split('.')
        .filter_map(|s| s.parse::<u8>().ok())
        .collect();
    if parts.len() == 4 {
        u32::from_be_bytes([parts[0], parts[1], parts[2], parts[3]])
    } else {
        0
    }
}
