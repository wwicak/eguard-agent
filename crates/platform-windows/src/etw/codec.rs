//! ETW event decoding: maps raw ETW event records to `RawEvent`.

use crate::{EventType, RawEvent};

/// Decode a raw ETW event buffer into a `RawEvent`.
///
/// `provider_guid` identifies which provider emitted the event,
/// `opcode` is the ETW opcode, and `data` is the event payload bytes.
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
            0 | 32 => Some(EventType::FileOpen),
            35 => Some(EventType::FileWrite),
            64 => Some(EventType::FileRename),
            70 => Some(EventType::FileUnlink),
            _ => None,
        },
        KERNEL_NETWORK => Some(EventType::TcpConnect),
        DNS_CLIENT => Some(EventType::DnsQuery),
        IMAGE_LOAD => Some(EventType::ModuleLoad),
        _ => {
            tracing::trace!(provider = provider_guid, opcode, "unmapped ETW event");
            None
        }
    }
}
