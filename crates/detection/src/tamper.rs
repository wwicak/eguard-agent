use crate::types::{EventClass, TelemetryEvent};

const AGENT_DIRS: &[&str] = &[
    "/opt/eguard-agent/",
    "/etc/eguard-agent/",
    "/var/lib/eguard-agent/",
];
const AGENT_FILES: &[&str] = &[
    "/usr/bin/eguard-agent",
    "/etc/systemd/system/eguard-agent.service",
    "/lib/systemd/system/eguard-agent.service",
    "/usr/lib/systemd/system/eguard-agent.service",
];

pub fn detect_tamper_indicators(event: &TelemetryEvent) -> Vec<String> {
    if event.event_class == EventClass::ProcessExec {
        let installer_parent = matches!(
            crate::behavioral::basename(&event.parent_process).as_str(),
            "dpkg" | "rpm" | "dnf" | "yum" | "apt" | "apt-get" | "package_script_service"
        );
        if !installer_parent && agent_service_control(event) {
            return vec!["tamper:agent_service_control".into()];
        }
        return Vec::new();
    }
    // Image execution, reads and /proc/self/exe are not agent tampering.
    if event.event_class != EventClass::FileOpen || !(event.file_write || event.file_unlink) {
        return Vec::new();
    }
    let process = crate::behavioral::basename(&event.process);
    if matches!(
        process.as_str(),
        "dpkg"
            | "rpm"
            | "dnf"
            | "yum"
            | "apt"
            | "apt-get"
            | "zypper"
            | "installer"
            | "package_script_service"
    ) {
        return Vec::new();
    }
    let path = event.file_path.as_deref().unwrap_or("");
    let owned = AGENT_DIRS.iter().any(|dir| path.starts_with(dir))
        || AGENT_FILES
            .iter()
            .any(|file| path == *file || path.starts_with(&format!("{file}.")));
    if owned {
        vec!["tamper:agent_file_mutation".into()]
    } else {
        Vec::new()
    }
}

fn agent_service_control(event: &TelemetryEvent) -> bool {
    let process = crate::behavioral::basename(&event.process);
    let argv: Vec<_> = event
        .command_line
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .map(|s| s.trim_matches(['\'', '\"']))
        .collect();
    let argv = if argv
        .first()
        .is_some_and(|p| crate::behavioral::basename(p) == process)
    {
        &argv[1..]
    } else {
        &argv[..]
    };
    let target = |a: &&str| matches!(*a, "eguard-agent" | "eguard-agent.service");
    match process.as_str() {
        "systemctl" => {
            argv.iter()
                .find(|a| !a.starts_with('-'))
                .is_some_and(|a| matches!(*a, "stop" | "disable" | "mask" | "kill"))
                && argv.iter().any(target)
        }
        "service" => argv.first().is_some_and(target) && argv.get(1) == Some(&"stop"),
        "pkill" | "killall" => argv.iter().any(target),
        _ => false,
    }
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
            // RAFIX shared: default optional image and unlink semantics in existing fixtures.
            process_exe: None,
            file_unlink: false,
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
        assert!(indicators.iter().any(|v| v == "tamper:agent_file_mutation"));
    }
}
