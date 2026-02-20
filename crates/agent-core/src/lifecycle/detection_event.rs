use detection::{Confidence, EventClass, TelemetryEvent};

pub(super) fn confidence_label(c: Confidence) -> String {
    format!("{:?}", c).to_ascii_lowercase()
}

pub(super) fn confidence_to_severity(c: Confidence) -> &'static str {
    match c {
        Confidence::Definite => "critical",
        Confidence::VeryHigh => "high",
        Confidence::High => "high",
        Confidence::Medium => "medium",
        Confidence::Low => "low",
        Confidence::None => "info",
    }
}

pub(super) fn to_detection_event(
    enriched: &crate::platform::EnrichedEvent,
    now_unix: i64,
) -> TelemetryEvent {
    let process = enriched
        .process_exe
        .as_deref()
        .map(process_basename)
        .unwrap_or("unknown")
        .to_string();

    let session_id = enriched
        .parent_chain
        .last()
        .copied()
        .unwrap_or(enriched.event.pid);

    let module_payload = if matches!(
        enriched.event.event_type,
        crate::platform::EventType::ModuleLoad
    ) {
        let trimmed = enriched.event.payload.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    } else {
        None
    };

    let file_path = enriched
        .file_path
        .clone()
        .or(module_payload)
        .or_else(|| enriched.process_exe.clone());

    TelemetryEvent {
        ts_unix: now_unix,
        event_class: map_event_class(&enriched.event.event_type),
        pid: enriched.event.pid,
        ppid: enriched.parent_chain.first().copied().unwrap_or_default(),
        uid: enriched.event.uid,
        process,
        parent_process: enriched
            .parent_process
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        session_id,
        file_path,
        file_write: enriched.file_write,
        file_hash: enriched
            .file_sha256
            .clone()
            .or_else(|| enriched.process_exe_sha256.clone()),
        dst_port: enriched.dst_port,
        dst_ip: enriched.dst_ip.clone(),
        dst_domain: enriched.dst_domain.clone(),
        command_line: enriched.process_cmdline.clone(),
        event_size: enriched.event_size,
        container_runtime: enriched.container_runtime.clone(),
        container_id: enriched.container_id.clone(),
        container_escape: enriched.container_escape,
        container_privileged: enriched.container_privileged,
    }
}

fn process_basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

pub(super) fn map_event_class(event_type: &crate::platform::EventType) -> EventClass {
    match event_type {
        crate::platform::EventType::ProcessExec => EventClass::ProcessExec,
        crate::platform::EventType::ProcessExit => EventClass::ProcessExit,
        crate::platform::EventType::FileOpen => EventClass::FileOpen,
        crate::platform::EventType::FileWrite => EventClass::FileOpen,
        crate::platform::EventType::FileRename => EventClass::FileOpen,
        crate::platform::EventType::FileUnlink => EventClass::FileOpen,
        crate::platform::EventType::TcpConnect => EventClass::NetworkConnect,
        crate::platform::EventType::DnsQuery => EventClass::DnsQuery,
        crate::platform::EventType::ModuleLoad => EventClass::ModuleLoad,
        crate::platform::EventType::LsmBlock => EventClass::Alert,
    }
}

#[cfg(test)]
mod tests {
    use super::process_basename;

    #[test]
    fn process_basename_supports_windows_and_unix_paths() {
        assert_eq!(process_basename("/usr/bin/bash"), "bash");
        assert_eq!(
            process_basename(r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            "powershell.exe"
        );
        assert_eq!(process_basename("name-only"), "name-only");
    }
}
