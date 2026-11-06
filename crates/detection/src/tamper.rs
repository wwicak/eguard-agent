use crate::types::{EventClass, TelemetryEvent};

const AGENT_DIRS: &[&str] = &["/opt/eguard-agent/", "/etc/eguard-agent/", "/var/lib/eguard-agent/"];
const AGENT_FILES: &[&str] = &[
    "/usr/bin/eguard-agent", "/etc/systemd/system/eguard-agent.service",
    "/lib/systemd/system/eguard-agent.service", "/usr/lib/systemd/system/eguard-agent.service",
];

pub fn detect_tamper_indicators(event: &TelemetryEvent) -> Vec<String> {
    // Image execution, reads and /proc/self/exe are not agent tampering.
    if event.event_class != EventClass::FileOpen || !event.file_write {
        return Vec::new();
    }
    let process = crate::behavioral::basename(&event.process);
    if matches!(process.as_str(), "dpkg" | "rpm" | "dnf" | "yum" | "apt" | "apt-get" | "zypper" | "installer" | "package_script_service") {
        return Vec::new();
    }
    let path = event.file_path.as_deref().unwrap_or("");
    let owned = AGENT_DIRS.iter().any(|dir| path.starts_with(dir))
        || AGENT_FILES.iter().any(|file| path == *file || path.starts_with(&format!("{file}.")));
    if owned { vec!["tamper:agent_file_mutation".into()] } else { Vec::new() }
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
        let mut ev = event("/usr/bin/eguard-agent");
        ev.file_write = true;
        let indicators = detect_tamper_indicators(&ev);
        assert!(indicators
            .iter()
            .any(|v| v == "tamper:agent_file_mutation"));
    }
}
