use crate::types::{EventClass, TelemetryEvent};

const TAMPER_PATH_MARKERS: &[&str] = &[
    "/proc/self/exe",
    "/usr/bin/eguard-agent",
    "/opt/eguard-agent",
    "/etc/eguard-agent/agent.conf",
    "/etc/eguard-agent/bootstrap.conf",
];

pub fn detect_tamper_indicators(event: &TelemetryEvent) -> Vec<String> {
    let is_file_event = matches!(
        event.event_class,
        EventClass::FileOpen | EventClass::ProcessExec
    );
    if !is_file_event {
        return Vec::new();
    }

    let path = event
        .file_path
        .as_deref()
        .or(event.command_line.as_deref())
        .unwrap_or("");
    if path.is_empty() {
        return Vec::new();
    }

    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    let mut indicators = Vec::new();
    for marker in TAMPER_PATH_MARKERS {
        if normalized.contains(&marker.to_ascii_lowercase()) {
            indicators.push(format!("tamper:{}", marker));
        }
    }

    indicators
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{EventClass, TelemetryEvent};

    fn event(path: &str) -> TelemetryEvent {
        TelemetryEvent {
            ts_unix: 0,
            event_class: EventClass::FileOpen,
            pid: 2,
            ppid: 1,
            uid: 0,
            process: "cp".to_string(),
            parent_process: "init".to_string(),
            session_id: 2,
            file_path: Some(path.to_string()),
            file_write: false,
            file_hash: None,
            dst_port: None,
            dst_ip: None,
            dst_domain: None,
            command_line: None,
            event_size: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        }
    }

    #[test]
    // AC-DET-226
    fn tamper_indicator_matches_agent_binary() {
        let ev = event("/usr/bin/eguard-agent");
        let indicators = detect_tamper_indicators(&ev);
        assert!(indicators
            .iter()
            .any(|v| v.contains("/usr/bin/eguard-agent")));
    }
}
