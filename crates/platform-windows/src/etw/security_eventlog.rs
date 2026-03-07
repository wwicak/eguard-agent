//! Native Windows Security event-log reader for process creation (4688).
//!
//! Some hosts expose richer process-create truth in the Security log even when
//! direct ETW subscription to `Microsoft-Windows-Security-Auditing` is sparse
//! or unavailable. This reader tails new 4688 events and converts them into the
//! same `RawEvent` shape used by the ETW pipeline.

use crate::RawEvent;
use std::collections::HashMap;

pub struct SecurityEventLogReader {
    #[cfg(target_os = "windows")]
    last_record_id: u64,
    #[cfg(target_os = "windows")]
    initialized: bool,
}

impl SecurityEventLogReader {
    pub fn new() -> Self {
        Self {
            #[cfg(target_os = "windows")]
            last_record_id: 0,
            #[cfg(target_os = "windows")]
            initialized: false,
        }
    }

    pub fn poll_events(&mut self, max_batch: usize) -> Result<Vec<RawEvent>, String> {
        #[cfg(target_os = "windows")]
        {
            if max_batch == 0 {
                return Ok(Vec::new());
            }

            if !self.initialized {
                self.last_record_id = latest_process_create_record_id()?.unwrap_or(0);
                self.initialized = true;
                return Ok(Vec::new());
            }

            let query = format!(
                "*[System[(EventID=4688 and EventRecordID>{})]]",
                self.last_record_id
            );
            let xml_events = query_security_log(&query, max_batch, false)?;

            let mut events = Vec::new();
            for xml in xml_events {
                let Some(record_id) = extract_tag_value(&xml, "EventRecordID")
                    .and_then(|value| value.parse::<u64>().ok())
                else {
                    continue;
                };
                self.last_record_id = self.last_record_id.max(record_id);

                if let Some(event) = parse_process_create_xml(&xml) {
                    events.push(event);
                }
            }

            Ok(events)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = max_batch;
            Ok(Vec::new())
        }
    }
}

impl Default for SecurityEventLogReader {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_process_create_xml(xml: &str) -> Option<RawEvent> {
    let mut fields = HashMap::new();
    for name in [
        "NewProcessId",
        "NewProcessName",
        "CommandLine",
        "ParentProcessName",
        "ProcessId",
        "CreatorProcessId",
        "ParentProcessId",
    ] {
        if let Some(value) = extract_named_data(xml, name).filter(|value| !value.trim().is_empty())
        {
            fields.insert(name.to_string(), value);
        }
    }

    super::security_auditing::build_process_create_event(&fields, unix_now_ns())
}

fn extract_named_data(xml: &str, name: &str) -> Option<String> {
    for quote in ['"', '\''] {
        let needle = format!("<Data Name={quote}{name}{quote}>");
        if let Some(start) = xml.find(&needle) {
            let value_start = start + needle.len();
            let rest = &xml[value_start..];
            let end = rest.find("</Data>")?;
            return Some(unescape_xml_entities(&rest[..end]));
        }
    }
    None
}

fn extract_tag_value(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let rest = &xml[start..];
    let end = rest.find(&close)?;
    Some(unescape_xml_entities(&rest[..end]))
}

fn unescape_xml_entities(raw: &str) -> String {
    raw.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&#xD;&#xA;", " ")
        .replace("&#xD;", " ")
        .replace("&#xA;", " ")
}

fn unix_now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

#[cfg(target_os = "windows")]
fn latest_process_create_record_id() -> Result<Option<u64>, String> {
    let mut xml_events = query_security_log("*[System[(EventID=4688)]]", 1, true)?;
    Ok(xml_events
        .pop()
        .and_then(|xml| extract_tag_value(&xml, "EventRecordID"))
        .and_then(|value| value.parse::<u64>().ok()))
}

#[cfg(target_os = "windows")]
fn query_security_log(
    query: &str,
    max_events: usize,
    reverse: bool,
) -> Result<Vec<String>, String> {
    use widestring::U16CString;
    use windows::{
        core::PCWSTR,
        Win32::System::EventLog::{
            EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection, EVT_HANDLE,
        },
    };

    let channel =
        U16CString::from_str("Security").map_err(|err| format!("wide Security path: {err}"))?;
    let query_wide =
        U16CString::from_str(query).map_err(|err| format!("wide Security query: {err}"))?;
    let mut flags = EvtQueryChannelPath.0;
    if reverse {
        flags |= EvtQueryReverseDirection.0;
    }

    let query_handle = unsafe {
        EvtQuery(
            EVT_HANDLE(0),
            PCWSTR(channel.as_ptr()),
            PCWSTR(query_wide.as_ptr()),
            flags,
        )
    }
    .map_err(|err| format!("EvtQuery Security 4688 events: {err}"))?;

    let mut events = Vec::new();
    let mut returned = 0u32;
    let mut handles = vec![0isize; max_events.max(1)];

    loop {
        let result = unsafe { EvtNext(query_handle, &mut handles, 0, 0, &mut returned) };
        if result.is_err() || returned == 0 {
            break;
        }

        for raw_handle in handles.iter().take(returned as usize) {
            let event_handle = EVT_HANDLE(*raw_handle);
            if let Some(xml) = render_event_xml(event_handle) {
                events.push(xml);
                if events.len() >= max_events {
                    let _ = unsafe { EvtClose(event_handle) };
                    let _ = unsafe { EvtClose(query_handle) };
                    return Ok(events);
                }
            }
            let _ = unsafe { EvtClose(event_handle) };
        }
    }

    let _ = unsafe { EvtClose(query_handle) };
    Ok(events)
}

#[cfg(target_os = "windows")]
fn render_event_xml(event_handle: windows::Win32::System::EventLog::EVT_HANDLE) -> Option<String> {
    use windows::Win32::System::EventLog::{EvtRender, EvtRenderEventXml, EVT_HANDLE};

    let mut used = 0u32;
    let mut property_count = 0u32;
    let mut buffer = vec![0u16; 64 * 1024];

    let render = unsafe {
        EvtRender(
            EVT_HANDLE(0),
            event_handle,
            EvtRenderEventXml.0,
            (buffer.len() * std::mem::size_of::<u16>()) as u32,
            Some(buffer.as_mut_ptr() as *mut core::ffi::c_void),
            &mut used,
            &mut property_count,
        )
    };

    if render.is_err() {
        if used == 0 {
            return None;
        }

        let needed_units = (used as usize / std::mem::size_of::<u16>()).saturating_add(1);
        buffer.resize(needed_units, 0);
        if unsafe {
            EvtRender(
                EVT_HANDLE(0),
                event_handle,
                EvtRenderEventXml.0,
                (buffer.len() * std::mem::size_of::<u16>()) as u32,
                Some(buffer.as_mut_ptr() as *mut core::ffi::c_void),
                &mut used,
                &mut property_count,
            )
        }
        .is_err()
        {
            return None;
        }
    }

    let len = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or((used as usize / std::mem::size_of::<u16>()).min(buffer.len()));
    Some(String::from_utf16_lossy(&buffer[..len]))
}

#[cfg(test)]
mod tests {
    use super::{
        extract_named_data, extract_tag_value, parse_process_create_xml, unescape_xml_entities,
    };

    const SAMPLE_XML: &str = r#"<Event>
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4688</EventID>
    <EventRecordID>12345</EventRecordID>
  </System>
  <EventData>
    <Data Name="NewProcessName">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="NewProcessId">0x14f4</Data>
    <Data Name="ProcessId">0x3c8</Data>
    <Data Name="ParentProcessName">C:\Windows\System32\cmd.exe</Data>
    <Data Name="CommandLine">powershell.exe -Command &quot;Get-Process; Get-Service&quot;</Data>
  </EventData>
</Event>"#;

    #[test]
    fn extracts_named_event_data_from_security_xml() {
        assert_eq!(
            extract_named_data(SAMPLE_XML, "NewProcessName").as_deref(),
            Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        );
        assert_eq!(
            extract_named_data(SAMPLE_XML, "ProcessId").as_deref(),
            Some("0x3c8")
        );
    }

    #[test]
    fn extracts_record_id_from_security_xml() {
        assert_eq!(
            extract_tag_value(SAMPLE_XML, "EventRecordID").as_deref(),
            Some("12345")
        );
    }

    #[test]
    fn unescapes_common_xml_entities() {
        assert_eq!(
            unescape_xml_entities("&quot;hello &amp; world&quot;"),
            "\"hello & world\""
        );
    }

    #[test]
    fn parses_security_xml_into_process_event() {
        let event = parse_process_create_xml(SAMPLE_XML).expect("process create raw event");
        assert_eq!(event.pid, 5364);
        assert!(event.payload.contains("ppid=968"));
        assert!(event.payload.contains("parent_process=cmd.exe"));
        assert!(event
            .payload
            .contains("cmdline=powershell.exe -Command \"Get-Process%3B Get-Service\""));
    }
}
