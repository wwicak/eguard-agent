#![no_main]

use std::sync::Mutex;

use detection::{DetectionEngine, EventClass, TelemetryEvent};
use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;

static DETECTION_ENGINE: Lazy<Mutex<DetectionEngine>> =
    Lazy::new(|| Mutex::new(DetectionEngine::default_with_rules()));

fn bounded_text(data: &[u8], offset: usize, len: usize) -> String {
    let start = offset.min(data.len());
    let end = (start + len).min(data.len());
    String::from_utf8_lossy(&data[start..end]).to_string()
}

fn event_class(tag: u8) -> EventClass {
    match tag % 7 {
        0 => EventClass::ProcessExec,
        1 => EventClass::FileOpen,
        2 => EventClass::NetworkConnect,
        3 => EventClass::DnsQuery,
        4 => EventClass::ModuleLoad,
        5 => EventClass::Login,
        _ => EventClass::Alert,
    }
}

fuzz_target!(|data: &[u8]| {
    let pid = data.first().copied().unwrap_or_default() as u32;
    let ppid = data.get(1).copied().unwrap_or_default() as u32;
    let uid = data.get(2).copied().unwrap_or_default() as u32;
    let ts = data
        .get(3)
        .copied()
        .map(i64::from)
        .unwrap_or_default();

    let event = TelemetryEvent {
        ts_unix: ts,
        event_class: event_class(data.get(4).copied().unwrap_or_default()),
        pid,
        ppid,
        uid,
        process: bounded_text(data, 5, 32),
        parent_process: bounded_text(data, 37, 32),
        file_path: Some(bounded_text(data, 69, 48)),
        file_hash: Some(bounded_text(data, 117, 64)),
        dst_port: data.get(181).copied().map(u16::from),
        dst_ip: Some(bounded_text(data, 182, 32)),
        dst_domain: Some(bounded_text(data, 214, 64)),
        command_line: Some(bounded_text(data, 278, 96)),
    };

    if let Ok(mut engine) = DETECTION_ENGINE.lock() {
        let _ = engine.process_event(&event);
    }
});
