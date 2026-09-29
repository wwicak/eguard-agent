//! Metadata-only PrintService Operational event reader.

use crate::{EventType, RawEvent};
use tracing::info;

const CHANNEL: &str = "Microsoft-Windows-PrintService/Operational";
const PRINTED_EVENT_ID: u32 = 307;

pub struct PrintEventLogReader {
    #[cfg(target_os = "windows")]
    last_record_id: u64,
    #[cfg(target_os = "windows")]
    initialized: bool,
}

impl PrintEventLogReader {
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
                // Optional channel errors must not permanently disable monitoring.
                // The ETW engine handles this error without interrupting other sources.
                self.last_record_id = latest_record_id()?.unwrap_or(0);
                self.initialized = true;
                return Ok(Vec::new());
            }

            let query = format!(
                "*[System[(EventID={PRINTED_EVENT_ID} and EventRecordID>{})]]",
                self.last_record_id
            );
            let mut events = Vec::new();
            let xml_events = query_log(&query, max_batch, false)?;
            let debug = std::env::var("EGUARD_DEBUG_EVENT_LOG")
                .ok()
                .is_some_and(|value| !value.trim().is_empty());
            if debug && !xml_events.is_empty() {
                info!(count = xml_events.len(), "PrintService events polled");
            }
            for xml in xml_events {
                let Some(record_id) = extract_tag_value(&xml, "EventRecordID")
                    .and_then(|value| value.parse::<u64>().ok())
                else {
                    continue;
                };
                self.last_record_id = self.last_record_id.max(record_id);
                if let Some(event) = parse_print_job_xml(&xml) {
                    events.push(event);
                } else if debug {
                    info!("PrintService Event 307 metadata parse failed");
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

impl Default for PrintEventLogReader {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_print_job_xml(xml: &str) -> Option<RawEvent> {
    let job_id = extract_param(xml, 1)?;
    let document = extract_param(xml, 2)?;
    let user = extract_param(xml, 3)?;
    let client = extract_param(xml, 4).unwrap_or_default();
    let printer = extract_param(xml, 5)?;
    let port = extract_param(xml, 6).unwrap_or_default();
    let bytes = extract_param(xml, 7).unwrap_or_default();
    let pages = extract_param(xml, 8).unwrap_or_default();
    let pid = extract_attribute(xml, "Execution", "ProcessID")
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or_default();

    Some(RawEvent {
        event_type: EventType::PrintJob,
        pid,
        uid: 0,
        ts_ns: unix_now_ns(),
        payload: [
            ("job_id", job_id),
            ("document", document),
            ("user", user),
            ("client", client),
            ("printer", printer),
            ("port", port),
            ("status", "completed".to_string()),
            ("bytes", bytes),
            ("pages", pages),
        ]
        .into_iter()
        .map(|(key, value)| format!("{key}={}", encode_payload_value(&value)))
        .collect::<Vec<_>>()
        .join(";"),
    })
}

fn extract_param(xml: &str, number: usize) -> Option<String> {
    extract_tag_value(xml, &format!("Param{number}"))
        .or_else(|| extract_named_data(xml, &format!("param{number}")))
}

fn extract_named_data(xml: &str, name: &str) -> Option<String> {
    for quote in ['"', '\''] {
        let needle = format!("<Data Name={quote}{name}{quote}>");
        if let Some(start) = xml.find(&needle) {
            let rest = &xml[start + needle.len()..];
            return Some(unescape_xml_entities(&rest[..rest.find("</Data>")?]));
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

fn extract_attribute(xml: &str, tag: &str, attribute: &str) -> Option<String> {
    let tag_start = xml.find(&format!("<{tag} "))?;
    let tag_end = xml[tag_start..].find('>')? + tag_start;
    let fragment = &xml[tag_start..tag_end];
    for quote in ['"', '\''] {
        let needle = format!("{attribute}={quote}");
        if let Some(start) = fragment.find(&needle) {
            let rest = &fragment[start + needle.len()..];
            return Some(rest[..rest.find(quote)?].to_string());
        }
    }
    None
}

fn unescape_xml_entities(raw: &str) -> String {
    raw.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn encode_payload_value(raw: &str) -> String {
    raw.replace('%', "%25")
        .replace(';', "%3B")
        .replace(',', "%2C")
        .replace('\n', " ")
        .replace('\r', " ")
}

fn unix_now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

#[cfg(target_os = "windows")]
fn latest_record_id() -> Result<Option<u64>, String> {
    let mut events = query_log(&format!("*[System[(EventID={PRINTED_EVENT_ID})]]"), 1, true)?;
    Ok(events
        .pop()
        .and_then(|xml| extract_tag_value(&xml, "EventRecordID"))
        .and_then(|value| value.parse::<u64>().ok()))
}

#[cfg(target_os = "windows")]
fn query_log(query: &str, max_events: usize, reverse: bool) -> Result<Vec<String>, String> {
    use widestring::U16CString;
    use windows::{
        core::{HRESULT, PCWSTR},
        Win32::{
            Foundation::ERROR_NO_MORE_ITEMS,
            System::EventLog::{
                EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection,
                EvtRender, EvtRenderEventXml, EVT_HANDLE,
            },
        },
    };

    let channel =
        U16CString::from_str(CHANNEL).map_err(|err| format!("wide print channel: {err}"))?;
    let query = U16CString::from_str(query).map_err(|err| format!("wide print query: {err}"))?;
    let mut flags = EvtQueryChannelPath.0;
    if reverse {
        flags |= EvtQueryReverseDirection.0;
    }
    let handle = unsafe {
        EvtQuery(
            EVT_HANDLE(0),
            PCWSTR(channel.as_ptr()),
            PCWSTR(query.as_ptr()),
            flags,
        )
    }
    .map_err(|err| format!("EvtQuery PrintService 307 events: {err}"))?;

    let result = (|| {
        let mut output = Vec::new();
        let mut returned = 0u32;
        // One handle per EvtNext avoids leaking the rest of a batch on early exit.
        let mut handles = [0isize; 1];
        let mut attempted = 0usize;
        while attempted < max_events {
            match unsafe { EvtNext(handle, &mut handles, 0, 0, &mut returned) } {
                Err(err) if err.code() == HRESULT::from_win32(ERROR_NO_MORE_ITEMS.0) => break,
                Err(err) => return Err(format!("EvtNext PrintService 307 events: {err}")),
                Ok(()) if returned == 0 => break,
                Ok(()) => {}
            }
            attempted += 1;
            let event = EVT_HANDLE(handles[0]);
            let rendered = (|| {
                let mut used = 0u32;
                let mut count = 0u32;
                let mut buffer = vec![0u16; 64 * 1024];
                for _ in 0..2 {
                    match unsafe {
                        EvtRender(
                            EVT_HANDLE(0),
                            event,
                            EvtRenderEventXml.0,
                            (buffer.len() * 2) as u32,
                            Some(buffer.as_mut_ptr().cast()),
                            &mut used,
                            &mut count,
                        )
                    } {
                        Ok(()) => {
                            let len = buffer
                                .iter()
                                .position(|unit| *unit == 0)
                                .unwrap_or(buffer.len());
                            return Ok(String::from_utf16_lossy(&buffer[..len]));
                        }
                        Err(_err) if (used as usize) > buffer.len() * 2 => {
                            buffer.resize((used as usize / 2).saturating_add(1), 0);
                        }
                        Err(err) => return Err(format!("EvtRender PrintService 307 event: {err}")),
                    }
                }
                Err("EvtRender PrintService 307 event exceeded buffer".to_string())
            })();
            let _ = unsafe { EvtClose(event) };
            match rendered {
                Ok(xml) => output.push(xml),
                Err(err) => {
                    tracing::warn!(error = %err, "skipping unrenderable PrintService event")
                }
            }
        }
        Ok(output)
    })();
    let _ = unsafe { EvtClose(handle) };
    result
}

#[cfg(test)]
mod tests {
    use super::parse_print_job_xml;
    use crate::EventType;

    const PRINTED_XML: &str = r#"<Event>
  <System><EventID>307</EventID><EventRecordID>812</EventRecordID>
    <Execution ProcessID="1300" ThreadID="24" /></System>
  <UserData><DocumentPrinted xmlns="http://manifests.microsoft.com/win/2005/08/windows/printing/spooler/core/events">
    <Param1>42</Param1><Param2>Quarterly Report.pdf</Param2>
    <Param3>CONTOSO\alice</Param3><Param4>TEST-PC</Param4>
    <Param5>Disposable Test Printer</Param5><Param6>PORTPROMPT:</Param6>
    <Param7>4096</Param7><Param8>3</Param8>
  </DocumentPrinted></UserData>
</Event>"#;

    #[test]
    fn parses_completed_print_job_as_metadata_only_event() {
        let event = parse_print_job_xml(PRINTED_XML).expect("print job event");
        assert!(matches!(event.event_type, EventType::PrintJob));
        assert_eq!(event.pid, 1300);
        assert!(event.payload.contains("job_id=42"));
        assert!(event.payload.contains("document=Quarterly Report.pdf"));
        assert!(event.payload.contains("user=CONTOSO\\alice"));
        assert!(event.payload.contains("printer=Disposable Test Printer"));
        assert!(event.payload.contains("status=completed"));
        assert!(event.payload.contains("pages=3"));
        assert!(!event.payload.contains("spool_content"));
        assert!(!event.payload.contains("command_line"));
    }
}
