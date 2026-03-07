//! Security Auditing ETW helpers.
//!
//! We use process-creation audit event 4688 as a stronger source of truth for
//! process image / parent / command-line attribution than kernel ETW alone.

use crate::{EventType, RawEvent};
use std::collections::HashMap;

const PROCESS_CREATE_EVENT_ID: u16 = 4688;

pub fn build_process_create_event(
    fields: &HashMap<String, String>,
    ts_ns: u64,
) -> Option<RawEvent> {
    let pid = fields
        .get("NewProcessId")
        .and_then(|value| parse_windows_pid(value))?;

    let process_path = fields
        .get("NewProcessName")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())?;

    let parent_pid = ["ProcessId", "CreatorProcessId", "ParentProcessId"]
        .iter()
        .find_map(|key| fields.get(*key))
        .and_then(|value| parse_windows_pid(value));

    let parent_process = fields
        .get("ParentProcessName")
        .map(|value| process_name_or_path(value))
        .filter(|value| !value.is_empty());

    let command_line = fields
        .get("CommandLine")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty());

    let mut payload = format!(
        "path={};audit_event_id={PROCESS_CREATE_EVENT_ID}",
        escape_payload_value(process_path)
    );
    if let Some(ppid) = parent_pid.filter(|value| *value > 0) {
        payload.push_str(&format!(";ppid={ppid}"));
    }
    if let Some(parent) = parent_process {
        payload.push_str(&format!(
            ";parent_process={}",
            escape_payload_value(&parent)
        ));
    }
    if let Some(command_line) = command_line {
        payload.push_str(&format!(";cmdline={}", escape_payload_value(command_line)));
    }

    Some(RawEvent {
        event_type: EventType::ProcessExec,
        pid,
        uid: 0,
        ts_ns,
        payload,
    })
}

fn process_name_or_path(raw: &str) -> String {
    let trimmed = raw.trim().trim_matches('"');
    trimmed
        .rsplit(['\\', '/'])
        .next()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(trimmed)
        .to_string()
}

fn escape_payload_value(raw: &str) -> String {
    raw.replace('%', "%25")
        .replace(';', "%3B")
        .replace(',', "%2C")
        .replace('=', "%3D")
        .replace('\r', " ")
        .replace('\n', " ")
}

fn parse_windows_pid(raw: &str) -> Option<u32> {
    let trimmed = raw.trim().trim_matches('"');
    if trimmed.is_empty() {
        return None;
    }

    if let Some(stripped) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(stripped, 16)
            .ok()
            .and_then(|value| u32::try_from(value).ok());
    }

    trimmed.parse::<u32>().ok()
}

#[cfg(target_os = "windows")]
pub fn decode_security_auditing_record(
    record: &windows::Win32::System::Diagnostics::Etw::EVENT_RECORD,
    ts_ns: u64,
) -> Option<RawEvent> {
    use widestring::U16CString;
    use windows::Win32::{
        Foundation::ERROR_SUCCESS,
        System::Diagnostics::Etw::{
            TdhGetProperty, TdhGetPropertySize, EVENT_RECORD, PROPERTY_DATA_DESCRIPTOR,
        },
    };

    if record.EventHeader.EventDescriptor.Id != PROCESS_CREATE_EVENT_ID {
        return None;
    }

    fn read_property(record: &EVENT_RECORD, name: &str) -> Option<String> {
        let name_wide = U16CString::from_str(name).ok()?;
        let descriptor = PROPERTY_DATA_DESCRIPTOR {
            PropertyName: name_wide.as_ptr() as u64,
            ArrayIndex: u32::MAX,
            Reserved: 0,
        };

        let mut size = 0u32;
        let status = unsafe { TdhGetPropertySize(record, None, &[descriptor], &mut size) };
        if status != ERROR_SUCCESS.0 || size == 0 {
            return None;
        }

        let mut buffer = vec![0u8; size as usize];
        let status = unsafe { TdhGetProperty(record, None, &[descriptor], &mut buffer) };
        if status != ERROR_SUCCESS.0 {
            return None;
        }

        decode_property_buffer(&buffer)
    }

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
        if let Some(value) = read_property(record, name).filter(|value| !value.trim().is_empty()) {
            fields.insert(name.to_string(), value);
        }
    }

    build_process_create_event(&fields, ts_ns)
}

#[cfg(target_os = "windows")]
fn decode_property_buffer(buffer: &[u8]) -> Option<String> {
    if buffer.is_empty() {
        return None;
    }

    if buffer.len() == 4 {
        return Some(u32::from_le_bytes(buffer[..4].try_into().ok()?).to_string());
    }
    if buffer.len() == 8 {
        let value = u64::from_le_bytes(buffer[..8].try_into().ok()?);
        if let Ok(pid) = u32::try_from(value) {
            return Some(pid.to_string());
        }
        return Some(format!("0x{value:x}"));
    }

    if let Some(value) = decode_utf16ish(buffer) {
        return Some(value);
    }

    decode_ansiish(buffer)
}

#[cfg(target_os = "windows")]
fn decode_utf16ish(buffer: &[u8]) -> Option<String> {
    if buffer.len() < 2 || buffer.len() % 2 != 0 {
        return None;
    }

    let mut units = Vec::with_capacity(buffer.len() / 2);
    for chunk in buffer.chunks_exact(2) {
        units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }

    let end = units
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(units.len());
    let text = String::from_utf16_lossy(&units[..end]).trim().to_string();
    if text.is_empty() || text.chars().all(|ch| ch.is_control()) {
        return None;
    }

    Some(text)
}

#[cfg(target_os = "windows")]
fn decode_ansiish(buffer: &[u8]) -> Option<String> {
    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    let text = String::from_utf8_lossy(&buffer[..end]).trim().to_string();
    if text.is_empty() || text.chars().all(|ch| ch.is_control()) {
        return None;
    }
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::{build_process_create_event, parse_windows_pid};
    use std::collections::HashMap;

    #[test]
    fn builds_security_auditing_process_create_payload() {
        let mut fields = HashMap::new();
        fields.insert("NewProcessId".to_string(), "0x14f4".to_string());
        fields.insert(
            "NewProcessName".to_string(),
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
        );
        fields.insert("ProcessId".to_string(), "0x3c8".to_string());
        fields.insert(
            "ParentProcessName".to_string(),
            r"C:\Windows\System32\cmd.exe".to_string(),
        );
        fields.insert(
            "CommandLine".to_string(),
            r#"powershell.exe -NoProfile -Command "Get-Process; Get-Service""#.to_string(),
        );

        let event = build_process_create_event(&fields, 123).expect("security process event");
        assert!(matches!(event.event_type, crate::EventType::ProcessExec));
        assert_eq!(event.pid, 0x14f4);
        assert!(event.payload.contains("ppid=968"));
        assert!(event.payload.contains("parent_process=cmd.exe"));
        assert!(event.payload.contains("audit_event_id=4688"));
        assert!(event
            .payload
            .contains("cmdline=powershell.exe -NoProfile -Command \"Get-Process%3B Get-Service\""));
    }

    #[test]
    fn parse_windows_pid_accepts_hex_and_decimal() {
        assert_eq!(parse_windows_pid("0x14f4"), Some(5364));
        assert_eq!(parse_windows_pid("5364"), Some(5364));
        assert_eq!(parse_windows_pid(""), None);
    }
}
