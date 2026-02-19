use crate::types::{EventClass, TelemetryEvent};

const MODULE_INDICATORS: &[&str] = &[
    "rootkit", "rk", "hide", "keylog", "syscall", "hook", "stealth", "backdoor",
];

pub fn detect_kernel_integrity_indicators(event: &TelemetryEvent) -> Vec<String> {
    if event.event_class == EventClass::Alert
        && event.process.eq_ignore_ascii_case("kernel_integrity_scan")
    {
        return parse_kernel_integrity_scan(event.command_line.as_deref().unwrap_or(""));
    }

    if event.event_class != EventClass::ModuleLoad {
        return Vec::new();
    }

    let module = event
        .file_path
        .as_deref()
        .or_else(|| event.command_line.as_deref())
        .unwrap_or("");
    if module.trim().is_empty() {
        return Vec::new();
    }

    let lower = module.to_ascii_lowercase();
    let mut indicators = Vec::new();
    for marker in MODULE_INDICATORS {
        if lower.contains(marker) {
            indicators.push(format!("kernel_module_{}", marker));
        }
    }

    if indicators.is_empty() {
        if !lower.is_empty() {
            indicators.push("kernel_module_loaded".to_string());
        }
    }

    indicators
}

fn parse_kernel_integrity_scan(command_line: &str) -> Vec<String> {
    let mut indicators = Vec::new();
    for chunk in command_line.split(';') {
        let trimmed = chunk.trim();
        if let Some(list) = trimmed.strip_prefix("indicators=") {
            for item in list.split(',') {
                let indicator = item.trim();
                if indicator.is_empty() || indicator.eq_ignore_ascii_case("none") {
                    continue;
                }
                indicators.push(indicator.to_string());
            }
        }
    }
    indicators
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{EventClass, TelemetryEvent};

    fn event(module: &str) -> TelemetryEvent {
        TelemetryEvent {
            ts_unix: 0,
            event_class: EventClass::ModuleLoad,
            pid: 1,
            ppid: 0,
            uid: 0,
            process: "insmod".to_string(),
            parent_process: "init".to_string(),
            session_id: 1,
            file_path: Some(module.to_string()),
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
    // AC-DET-223
    fn kernel_integrity_indicator_matches_rootkit_module() {
        let ev = event("rootkit_hide");
        let indicators = detect_kernel_integrity_indicators(&ev);
        assert!(indicators.iter().any(|v| v == "kernel_module_rootkit"));
    }

    #[test]
    fn kernel_integrity_indicator_records_any_module() {
        let ev = event("simple_module");
        let indicators = detect_kernel_integrity_indicators(&ev);
        assert!(indicators.iter().any(|v| v == "kernel_module_loaded"));
    }

    #[test]
    fn kernel_integrity_indicator_parses_scan_event() {
        let ev = TelemetryEvent {
            ts_unix: 0,
            event_class: EventClass::Alert,
            pid: 0,
            ppid: 0,
            uid: 0,
            process: "kernel_integrity_scan".to_string(),
            parent_process: String::new(),
            session_id: 0,
            file_path: None,
            file_write: false,
            file_hash: None,
            dst_port: None,
            dst_ip: None,
            dst_domain: None,
            command_line: Some(
                "indicators=hidden_module_sysfs:evil,kprobe_hook:__x64_sys_execve".to_string(),
            ),
            event_size: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };
        let indicators = detect_kernel_integrity_indicators(&ev);
        assert!(indicators.iter().any(|v| v == "hidden_module_sysfs:evil"));
        assert!(indicators
            .iter()
            .any(|v| v == "kprobe_hook:__x64_sys_execve"));
    }
}
