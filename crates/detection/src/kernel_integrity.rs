use crate::types::{EventClass, TelemetryEvent};

const KNOWN_ROOTKITS: &[&str] = &[
    "diamorphine",
    "reptile",
    "reptile_module",
    "suterusu",
    "adore",
    "adore_ng",
    "kovid",
    "khook",
    "puszek",
    "nurupo",
    "rootfoo",
    "brootus",
    "enyelkm",
    "vlany",
    "sutekh",
    "azazel",
];

pub fn kernel_integrity_confidence(indicators: &[String]) -> crate::Confidence {
    indicators
        .iter()
        .map(|i| {
            if i.starts_with("hidden_module_sysfs:")
                || i.starts_with("hidden_module_proc:")
                || i.starts_with("kernel_module_known_rootkit:")
                || i.strip_prefix("unsigned_oot_module:")
                    .is_some_and(|m| KNOWN_ROOTKITS.contains(&m))
            {
                crate::Confidence::High
            } else if [
                "unsigned_oot_module:",
                "kprobe_hook:",
                "ftrace_tracer:",
                "ftrace_filter_count:",
                "bpffs_pinned_object:",
            ]
            .iter()
            .any(|prefix| i.starts_with(prefix))
            {
                crate::Confidence::Medium
            } else {
                crate::Confidence::None
            }
        })
        .max()
        .unwrap_or(crate::Confidence::None)
}

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
        .or(event.command_line.as_deref())
        .unwrap_or("");
    if module.trim().is_empty() {
        return Vec::new();
    }

    let name = crate::behavioral::basename(module)
        .trim_end_matches(".ko")
        .to_string();
    if KNOWN_ROOTKITS.contains(&name.as_str()) {
        vec![format!("kernel_module_known_rootkit:{name}")]
    } else {
        Vec::new()
    }
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
    // AC-DET-223
    fn kernel_integrity_indicator_matches_rootkit_module() {
        let ev = event("diamorphine");
        let indicators = detect_kernel_integrity_indicators(&ev);
        assert!(indicators
            .iter()
            .any(|v| v == "kernel_module_known_rootkit:diamorphine"));
    }

    #[test]
    // AC-DET-240
    fn kernel_integrity_indicator_ignores_benign_module() {
        let ev = event("simple_module");
        let indicators = detect_kernel_integrity_indicators(&ev);
        assert!(
            indicators.is_empty(),
            "benign modules must not produce indicators"
        );
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
            // RAFIX shared: default optional image and unlink semantics in existing fixtures.
            process_exe: None,
            file_unlink: false,
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
