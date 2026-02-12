use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    ProcessExec,
    FileOpen,
    TcpConnect,
    DnsQuery,
    ModuleLoad,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvent {
    pub event_type: EventType,
    pub pid: u32,
    pub uid: u32,
    pub ts_ns: u64,
    pub payload: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedEvent {
    pub event: RawEvent,
    pub process_exe: Option<String>,
    pub process_cmdline: Option<String>,
    pub parent_chain: Vec<u32>,
}

pub fn platform_name() -> &'static str {
    "linux"
}

pub fn enrich_event(raw: RawEvent) -> EnrichedEvent {
    let exe = std::fs::read_link(format!("/proc/{}/exe", raw.pid))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());

    let cmdline = std::fs::read(format!("/proc/{}/cmdline", raw.pid))
        .ok()
        .and_then(|buf| {
            let parts: Vec<String> = buf
                .split(|b| *b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect();
            if parts.is_empty() {
                None
            } else {
                Some(parts.join(" "))
            }
        });

    EnrichedEvent {
        event: raw,
        process_exe: exe,
        process_cmdline: cmdline,
        parent_chain: Vec::new(),
    }
}
