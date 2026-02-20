//! ETW event decoding: maps raw ETW event records to `RawEvent`.

use crate::{EventType, RawEvent};

/// Decode a raw ETW event buffer into a `RawEvent`.
///
/// `provider_guid` identifies which provider emitted the event,
/// `opcode` is the ETW opcode (or event id for many manifest providers),
/// and `data` is the event payload bytes.
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

#[cfg(test)]
mod tests {
    use super::decode_etw_event;
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
}
