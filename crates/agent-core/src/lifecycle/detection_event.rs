use detection::{Confidence, EventClass, TelemetryEvent};

pub(super) fn confidence_label(c: Confidence) -> &'static str {
    match c {
        Confidence::None => "none",
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
        Confidence::VeryHigh => "very_high",
        Confidence::Definite => "definite",
    }
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
        .filter(|path| !is_low_value_windows_pseudo_identity(path))
        .or(module_payload)
        .or_else(|| {
            matches!(
                enriched.event.event_type,
                crate::platform::EventType::ProcessExec | crate::platform::EventType::ProcessExit
            )
            .then(|| enriched.process_exe.clone())
            .flatten()
        });

    let process_name_from_path = enriched
        .process_exe
        .as_deref()
        .map(process_basename)
        .filter(|value| !value.trim().is_empty());
    let process_name_from_cmd = enriched
        .process_cmdline
        .as_deref()
        .and_then(process_name_from_cmdline)
        .filter(|value| !value.trim().is_empty());
    let authoritative_process_exec = matches!(
        enriched.event.event_type,
        crate::platform::EventType::ProcessExec
    ) && (process_name_from_path.is_some()
        || process_name_from_cmd.is_some());

    let mut process = process_name_from_path
        .or(process_name_from_cmd)
        .unwrap_or("unknown")
        .to_string();

    if is_weak_windows_process_identity(&process) && !authoritative_process_exec {
        if let Some(parent) = enriched
            .parent_process
            .as_deref()
            .filter(|value| !is_weak_windows_process_identity(value))
        {
            process = parent.to_string();
        } else if let Some(inferred) = file_path
            .as_deref()
            .and_then(infer_windows_process_from_file_path)
        {
            process = inferred.to_string();
        }
    }

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
            .filter(|value| !value.trim().is_empty())
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

fn process_name_from_cmdline(cmdline: &str) -> Option<&str> {
    let first = cmdline
        .split(['\0', ' '])
        .find(|segment| !segment.trim().is_empty())?
        .trim();
    if first.is_empty() {
        None
    } else {
        Some(process_basename(first))
    }
}

fn is_weak_windows_process_identity(process: &str) -> bool {
    let lowered = process.trim().to_ascii_lowercase();
    lowered.is_empty()
        || lowered == "unknown"
        || lowered == "system"
        || matches!(
            lowered.as_str(),
            "conhost.exe" | "conhost" | "csrss.exe" | "csrss"
        )
}

fn infer_windows_process_from_file_path(path: &str) -> Option<&'static str> {
    let mut normalized = path.replace('\\', "/").to_ascii_lowercase();
    while normalized.contains("//") {
        normalized = normalized.replace("//", "/");
    }
    if normalized.is_empty() {
        return None;
    }

    if normalized.contains("__psscriptpolicytest_")
        || normalized.contains("windowspowershell/v1.0")
        || normalized.contains("windows powershell")
        || normalized.contains("powershell/modules")
        || normalized.contains("/psreadline/")
    {
        return Some("powershell.exe");
    }

    if normalized.contains("program files/openssh")
        || normalized.contains("windows/system32/openssh")
    {
        return Some("sshd.exe");
    }

    None
}

fn is_low_value_windows_pseudo_identity(process: &str) -> bool {
    let lowered = process.trim().to_ascii_lowercase();
    lowered.is_empty()
        || lowered == "unknown"
        || lowered == "system"
        || lowered == "registry"
        || lowered == "registry.exe"
}

fn is_low_value_windows_host_process(process: &str) -> bool {
    let lowered = process.trim().to_ascii_lowercase();
    matches!(
        lowered.as_str(),
        "conhost.exe"
            | "conhost"
            | "csrss.exe"
            | "csrss"
            | "dllhost.exe"
            | "dllhost"
            | "logonui.exe"
            | "logonui"
            | "lsass.exe"
            | "lsass"
            | "mpdefendercoreservice.exe"
            | "mpdefendercoreservice"
            | "msmpeng.exe"
            | "msmpeng"
            | "services.exe"
            | "services"
            | "sshd-auth.exe"
            | "sshd-auth"
            | "sshd-session.exe"
            | "sshd-session"
            | "sshd.exe"
            | "sshd"
            | "svchost.exe"
            | "svchost"
            | "winlogon.exe"
            | "winlogon"
            | "wmiapsrv.exe"
            | "wmiapsrv"
            | "wmiprvse.exe"
            | "wmiprvse"
    )
}

fn effective_windows_process_basename<'a>(
    enriched: &'a crate::platform::EnrichedEvent,
    event: &'a TelemetryEvent,
) -> Option<&'a str> {
    enriched
        .process_exe
        .as_deref()
        .map(process_basename)
        .or_else(|| {
            event
                .command_line
                .as_deref()
                .and_then(process_name_from_cmdline)
        })
        .or_else(|| {
            let process = event.process.trim();
            (!process.is_empty()).then_some(process)
        })
}

fn is_low_signal_self_image_windows_command_line(
    command_line: Option<&str>,
    process_exe: Option<&str>,
) -> bool {
    let Some(command_line) = command_line
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return false;
    };
    let Some(process_exe) = process_exe.map(str::trim).filter(|value| !value.is_empty()) else {
        return false;
    };

    let normalize = |value: &str| {
        let mut normalized = value
            .trim()
            .trim_matches('"')
            .replace('/', "\\")
            .to_ascii_lowercase();
        while normalized.contains("\\\\") {
            normalized = normalized.replace("\\\\", "\\");
        }
        normalized
    };

    normalize(command_line) == normalize(process_exe)
}

fn is_low_value_windows_system_file_path(path: &str) -> bool {
    let mut normalized = path
        .trim()
        .trim_matches('"')
        .replace('/', "\\")
        .to_ascii_lowercase();
    while normalized.contains("\\\\") {
        normalized = normalized.replace("\\\\", "\\");
    }

    normalized == r"c:\$logfile"
        || normalized == r"c:\$mft"
        || normalized.starts_with(r"c:\windows\winsxs\")
        || normalized.starts_with(r"c:\windows\system32\catroot\")
        || normalized.starts_with(r"c:\windows\system32\catroot2\")
        || normalized.starts_with(r"c:\windows\assembly\")
        || normalized.starts_with(r"c:\windows\microsoft.net\assembly\")
        || normalized.starts_with(r"c:\windows\system32\logfiles\wmi")
        || normalized.starts_with(r"c:\windows\system32\winevt\logs")
        || normalized.starts_with(r"c:\windows\system32\wbem\repository")
        || normalized == r"c:\programdata\microsoft\windows defender\scans\defenderecscache.bin64"
        || normalized
            .starts_with(r"c:\programdata\microsoft\windows defender\support\mpwpptracing-")
        || normalized.starts_with(r"c:\programdata\microsoft\windows\wfp\")
        || normalized.starts_with(r"c:\windows\appcompat\programs\amcache.hve.log")
        || (normalized.starts_with(r"c:\windows\system32\config\")
            && (normalized.ends_with(".log1") || normalized.ends_with(".log2")))
}

fn is_low_value_windows_agent_self_path(path: &str) -> bool {
    let mut normalized = path
        .trim()
        .trim_matches('"')
        .replace('/', "\\")
        .to_ascii_lowercase();
    while normalized.contains("\\\\") {
        normalized = normalized.replace("\\\\", "\\");
    }

    normalized == r"c:\program files\eguard\eguard-agent.exe"
}

fn is_low_value_windows_agent_state_path(path: &str) -> bool {
    let mut normalized = path
        .trim()
        .trim_matches('"')
        .replace('/', "\\")
        .to_ascii_lowercase();
    while normalized.contains("\\\\") {
        normalized = normalized.replace("\\\\", "\\");
    }

    normalized == r"c:\programdata\eguard\logs\agent.log"
        || normalized == r"c:\var\lib\eguard-agent\baselines.journal"
}

fn is_low_value_windows_browser_profile_path(path: &str) -> bool {
    let mut normalized = path
        .trim()
        .trim_matches('"')
        .replace('/', "\\")
        .to_ascii_lowercase();
    while normalized.contains("\\\\") {
        normalized = normalized.replace("\\\\", "\\");
    }

    (normalized.contains(r"\mozilla\firefox\profiles\")
        && (normalized.contains(r"\cache2\")
            || normalized.contains(r"\storage\permanent\chrome\idb\")
            || normalized.contains(r"\datareporting\")
            || normalized.contains(r"\safebrowsing\")
            || normalized.ends_with(r"\prefs.js")))
        || normalized.starts_with(
            r"c:\windows\system32\config\systemprofile\appdata\local\microsoft\windows\webcache\",
        )
        || normalized == r"c:\programdata\microsoft\diagnosis"
        || normalized.starts_with(r"c:\programdata\microsoft\diagnosis\eventstore")
}

fn is_low_value_windows_powershell_policy_test_path(path: &str) -> bool {
    let mut normalized = path
        .trim()
        .trim_matches('"')
        .replace('/', "\\")
        .to_ascii_lowercase();
    while normalized.contains("\\\\") {
        normalized = normalized.replace("\\\\", "\\");
    }

    normalized.starts_with(r"c:\windows\temp\__psscriptpolicytest_")
}

fn is_low_value_windows_powershell_module_path(path: &str) -> bool {
    let mut normalized = path
        .trim()
        .trim_matches('"')
        .replace('/', "\\")
        .to_ascii_lowercase();
    while normalized.contains("\\\\") {
        normalized = normalized.replace("\\\\", "\\");
    }

    normalized.starts_with(r"c:\windows\system32\windowspowershell\v1.0\modules\")
        || normalized == r"c:\windows\system32\winevt\logs\windows powershell.evtx"
}

fn is_low_value_windows_proxy_host_lifecycle_event(event: &TelemetryEvent) -> bool {
    let process = event.process.trim().to_ascii_lowercase();
    if !matches!(
        process.as_str(),
        "conhost.exe" | "conhost" | "csrss.exe" | "csrss"
    ) {
        return false;
    }
    if !event.parent_process.eq_ignore_ascii_case("unknown") {
        return false;
    }
    if event
        .command_line
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some()
    {
        return false;
    }

    event
        .file_path
        .as_deref()
        .map(|path| {
            let mut normalized = path
                .trim()
                .trim_matches('"')
                .replace('/', "\\")
                .to_ascii_lowercase();
            while normalized.contains("\\\\") {
                normalized = normalized.replace("\\\\", "\\");
            }
            normalized.ends_with(r"\conhost.exe") || normalized.ends_with(r"\csrss.exe")
        })
        .unwrap_or(false)
}

pub(super) fn should_drop_low_value_windows_event(
    enriched: &crate::platform::EnrichedEvent,
    event: &TelemetryEvent,
) -> bool {
    if matches!(
        enriched.event.event_type,
        crate::platform::EventType::ProcessExec | crate::platform::EventType::ProcessExit
    ) {
        let has_meaningful_subject = event
            .file_path
            .as_deref()
            .filter(|path| !is_low_value_windows_pseudo_identity(path))
            .is_some();
        let has_meaningful_cmdline = event
            .command_line
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_some();

        if is_low_value_windows_proxy_host_lifecycle_event(event) {
            return true;
        }

        if matches!(
            enriched.event.event_type,
            crate::platform::EventType::ProcessExit
        ) {
            return is_low_value_windows_pseudo_identity(&event.process)
                && is_low_value_windows_pseudo_identity(&event.parent_process)
                && !has_meaningful_subject
                && !has_meaningful_cmdline
                && event.ppid == 0;
        }

        return false;
    }

    if !matches!(
        enriched.event.event_type,
        crate::platform::EventType::FileOpen
            | crate::platform::EventType::FileWrite
            | crate::platform::EventType::FileRename
            | crate::platform::EventType::FileUnlink
    ) {
        return false;
    }

    let has_meaningful_subject = enriched
        .file_path
        .as_deref()
        .filter(|path| !is_low_value_windows_pseudo_identity(path))
        .is_some()
        || enriched
            .file_path_secondary
            .as_deref()
            .filter(|path| !is_low_value_windows_pseudo_identity(path))
            .is_some();
    if has_meaningful_subject {
        if matches!(
            enriched.event.event_type,
            crate::platform::EventType::FileOpen
        ) && !event.file_write
            && event.parent_process.eq_ignore_ascii_case("unknown")
        {
            if event.process.eq_ignore_ascii_case("System")
                && event
                    .file_path
                    .as_deref()
                    .map(|path| {
                        is_low_value_windows_system_file_path(path)
                            || is_low_value_windows_agent_self_path(path)
                            || is_low_value_windows_agent_state_path(path)
                            || is_low_value_windows_browser_profile_path(path)
                    })
                    .unwrap_or(false)
            {
                return true;
            }

            if event.process.eq_ignore_ascii_case("firefox.exe")
                && is_low_signal_self_image_windows_command_line(
                    event.command_line.as_deref(),
                    enriched.process_exe.as_deref(),
                )
                && event
                    .file_path
                    .as_deref()
                    .map(is_low_value_windows_browser_profile_path)
                    .unwrap_or(false)
            {
                return true;
            }

            if event.pid <= 4
                && event.ppid == 0
                && event.process.eq_ignore_ascii_case("powershell.exe")
                && event
                    .command_line
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("")
                    .is_empty()
                && event
                    .file_path
                    .as_deref()
                    .map(|path| {
                        is_low_value_windows_powershell_policy_test_path(path)
                            || is_low_value_windows_powershell_module_path(path)
                    })
                    .unwrap_or(false)
            {
                return true;
            }
        }
        return false;
    }

    if effective_windows_process_basename(enriched, event)
        .map(is_low_value_windows_host_process)
        .unwrap_or(false)
    {
        return true;
    }

    if is_low_signal_self_image_windows_command_line(
        event.command_line.as_deref(),
        enriched.process_exe.as_deref(),
    ) {
        return true;
    }

    if event
        .command_line
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some()
    {
        return false;
    }

    is_low_value_windows_pseudo_identity(&event.process)
        && is_low_value_windows_pseudo_identity(&event.parent_process)
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
    use super::{
        infer_windows_process_from_file_path, process_basename, process_name_from_cmdline,
    };
    use crate::platform::{EnrichedEvent, EventType, RawEvent};
    use detection::Confidence;

    #[test]
    // AC-WIRE-001 AC-WIRE-002 AC-WIRE-003 AC-WIRE-004
    fn confidence_label_returns_snake_case_for_all_variants() {
        assert_eq!(super::confidence_label(Confidence::VeryHigh), "very_high");
        assert_eq!(super::confidence_label(Confidence::None), "none");
        assert_eq!(super::confidence_label(Confidence::Low), "low");
        assert_eq!(super::confidence_label(Confidence::Medium), "medium");
        assert_eq!(super::confidence_label(Confidence::High), "high");
        assert_eq!(super::confidence_label(Confidence::Definite), "definite");

        let all = [
            Confidence::None,
            Confidence::Low,
            Confidence::Medium,
            Confidence::High,
            Confidence::VeryHigh,
            Confidence::Definite,
        ];
        for c in all {
            let label = super::confidence_label(c);
            assert!(
                label.chars().all(|ch| ch.is_ascii_lowercase() || ch == '_'),
                "confidence_label({:?}) = {:?} is not snake_case",
                c,
                label
            );
        }
    }

    #[test]
    fn process_basename_supports_windows_and_unix_paths() {
        assert_eq!(process_basename("/usr/bin/bash"), "bash");
        assert_eq!(
            process_basename(r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            "powershell.exe"
        );
        assert_eq!(process_basename("name-only"), "name-only");
    }

    #[test]
    fn process_name_from_cmdline_uses_first_token_basename() {
        assert_eq!(
            process_name_from_cmdline("/usr/sbin/sshd -D [listener]"),
            Some("sshd")
        );
        assert_eq!(
            process_name_from_cmdline(r"C:\\Windows\\System32\\cmd.exe /c whoami"),
            Some("cmd.exe")
        );
        assert_eq!(process_name_from_cmdline("   "), None);
    }

    #[test]
    fn to_detection_event_ignores_empty_process_exe_and_falls_back_to_cmdline() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::FileOpen,
                pid: 1688,
                uid: 0,
                ts_ns: 1,
                payload: String::new(),
            },
            process_exe: Some(String::new()),
            process_exe_sha256: None,
            process_cmdline: Some(
                r"\\??\\C:\\Windows\\system32\\notepad.exe C:\\Windows\\win.ini".to_string(),
            ),
            parent_process: Some("explorer.exe".to_string()),
            parent_chain: vec![5768],
            file_path: Some(r"C:\\Windows\\Temp\\__PSScriptPolicyTest.ps1".to_string()),
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = super::to_detection_event(&enriched, 123);
        assert_eq!(event.process, "notepad.exe");
        assert_eq!(event.parent_process, "explorer.exe");
    }

    #[test]
    fn to_detection_event_uses_meaningful_parent_when_process_is_proxy_host() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::FileOpen,
                pid: 1688,
                uid: 0,
                ts_ns: 1,
                payload: String::new(),
            },
            process_exe: Some(r"C:\\Windows\\System32\\conhost.exe".to_string()),
            process_exe_sha256: None,
            process_cmdline: None,
            parent_process: Some("powershell.exe".to_string()),
            parent_chain: vec![5768],
            file_path: Some(r"C:\\Windows\\Temp\\script.ps1".to_string()),
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = super::to_detection_event(&enriched, 123);
        assert_eq!(event.process, "powershell.exe");
        assert_eq!(event.parent_process, "powershell.exe");
    }

    #[test]
    fn to_detection_event_preserves_authoritative_process_exec_identity_for_conhost() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::ProcessExec,
                pid: 4242,
                uid: 0,
                ts_ns: 1,
                payload: String::new(),
            },
            process_exe: Some(r"C:\\Windows\\System32\\conhost.exe".to_string()),
            process_exe_sha256: None,
            process_cmdline: Some(
                r"\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1".to_string(),
            ),
            parent_process: Some("powershell.exe".to_string()),
            parent_chain: vec![1337],
            file_path: None,
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = super::to_detection_event(&enriched, 123);
        assert_eq!(event.process, "conhost.exe");
        assert_eq!(event.parent_process, "powershell.exe");
    }

    #[test]
    fn infer_windows_process_from_file_path_detects_powershell_modules() {
        assert_eq!(
            infer_windows_process_from_file_path(
                r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\NetSecurity\\NetSecurity.psd1"
            ),
            Some("powershell.exe")
        );
        assert_eq!(
            infer_windows_process_from_file_path(
                r"C:\\Windows\\Temp\\__PSScriptPolicyTest_abc123.ps1"
            ),
            Some("powershell.exe")
        );
    }

    #[test]
    fn to_detection_event_infers_powershell_when_identity_is_weak() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::FileOpen,
                pid: 4724,
                uid: 0,
                ts_ns: 1,
                payload: String::new(),
            },
            process_exe: None,
            process_exe_sha256: None,
            process_cmdline: None,
            parent_process: Some("unknown".to_string()),
            parent_chain: Vec::new(),
            file_path: Some(
                r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\WindowsUpdateProvider\\MSFT_WUOperations.psm1"
                    .to_string(),
            ),
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = super::to_detection_event(&enriched, 123);
        assert_eq!(event.process, "powershell.exe");
        assert_eq!(event.parent_process, "unknown");
    }

    #[test]
    fn to_detection_event_file_open_without_subject_does_not_keep_pseudo_system_path() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::FileOpen,
                pid: 4,
                uid: 0,
                ts_ns: 1,
                payload: "System".to_string(),
            },
            process_exe: Some("System".to_string()),
            process_exe_sha256: None,
            process_cmdline: None,
            parent_process: Some("unknown".to_string()),
            parent_chain: Vec::new(),
            file_path: Some("System".to_string()),
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = super::to_detection_event(&enriched, 123);
        assert_eq!(event.process, "System");
        assert_eq!(event.file_path, None);
    }

    #[test]
    fn should_drop_low_value_windows_event_for_pseudo_system_file_noise() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::FileOpen,
                pid: 4,
                uid: 0,
                ts_ns: 1,
                payload: "System".to_string(),
            },
            process_exe: Some("System".to_string()),
            process_exe_sha256: None,
            process_cmdline: None,
            parent_process: Some("unknown".to_string()),
            parent_chain: Vec::new(),
            file_path: Some("System".to_string()),
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = super::to_detection_event(&enriched, 123);
        assert!(super::should_drop_low_value_windows_event(
            &enriched, &event
        ));
    }

    #[test]
    fn should_drop_low_value_windows_event_for_system_logfile_open_chatter() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::FileOpen,
                pid: 4,
                uid: 0,
                ts_ns: 1,
                payload: "file_key=0x88".to_string(),
            },
            process_exe: Some("System".to_string()),
            process_exe_sha256: None,
            process_cmdline: None,
            parent_process: Some("unknown".to_string()),
            parent_chain: Vec::new(),
            file_path: Some(
                r"C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx"
                    .to_string(),
            ),
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = super::to_detection_event(&enriched, 123);
        assert_eq!(event.process, "System");
        assert!(super::should_drop_low_value_windows_event(
            &enriched, &event
        ));
    }

    #[test]
    fn should_drop_low_value_windows_event_for_system_winsxs_chatter() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::FileOpen,
                pid: 4,
                uid: 0,
                ts_ns: 1,
                payload: "file_key=0x98".to_string(),
            },
            process_exe: Some("System".to_string()),
            process_exe_sha256: None,
            process_cmdline: None,
            parent_process: Some("unknown".to_string()),
            parent_chain: Vec::new(),
            file_path: Some(
                r"C:\\Windows\\WinSxS\\amd64_microsoft-windows-appid_31bf3856ad364e35_10.0.17763.1_none_4811fa310a50b802".to_string(),
            ),
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = super::to_detection_event(&enriched, 123);
        assert_eq!(event.process, "System");
        assert!(super::should_drop_low_value_windows_event(
            &enriched, &event
        ));
    }

    #[test]
    fn should_drop_low_value_windows_event_for_system_catroot_chatter() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::FileOpen,
                pid: 4,
                uid: 0,
                ts_ns: 1,
                payload: "file_key=0x98b".to_string(),
            },
            process_exe: Some("System".to_string()),
            process_exe_sha256: None,
            process_cmdline: None,
            parent_process: Some("unknown".to_string()),
            parent_chain: Vec::new(),
            file_path: Some(
                r"C:\\Windows\\System32\\CatRoot\\{127D0A1D-4EF2-11D1-8608-00C04FC295EE}"
                    .to_string(),
            ),
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = super::to_detection_event(&enriched, 123);
        assert_eq!(event.process, "System");
        assert!(super::should_drop_low_value_windows_event(
            &enriched, &event
        ));
    }

    #[test]
    fn should_drop_low_value_windows_event_for_system_gac_chatter() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::FileOpen,
                pid: 4,
                uid: 0,
                ts_ns: 1,
                payload: "file_key=0x98c".to_string(),
            },
            process_exe: Some("System".to_string()),
            process_exe_sha256: None,
            process_cmdline: None,
            parent_process: Some("unknown".to_string()),
            parent_chain: Vec::new(),
            file_path: Some(
                r"C:\\Windows\\Microsoft.NET\\assembly\\GAC_MSIL\\System.Management\\v4.0_4.0.0.0__b03f5f7f11d50a3a\\System.Management.dll".to_string(),
            ),
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = super::to_detection_event(&enriched, 123);
        assert_eq!(event.process, "System");
        assert!(super::should_drop_low_value_windows_event(
            &enriched, &event
        ));
    }

    #[test]
    fn should_drop_low_value_windows_event_for_system_agent_binary_open() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::FileOpen,
                pid: 4,
                uid: 0,
                ts_ns: 1,
                payload: "file_key=0x99".to_string(),
            },
            process_exe: Some("System".to_string()),
            process_exe_sha256: None,
            process_cmdline: None,
            parent_process: Some("unknown".to_string()),
            parent_chain: Vec::new(),
            file_path: Some(r"C:\\Program Files\\eGuard\\eguard-agent.exe".to_string()),
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = super::to_detection_event(&enriched, 123);
        assert!(super::should_drop_low_value_windows_event(
            &enriched, &event
        ));
    }

    #[test]
    fn should_drop_low_value_windows_event_for_pid4_powershell_policytest_file_noise() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::FileOpen,
                pid: 4,
                uid: 0,
                ts_ns: 1,
                payload: "file_key=0xaa".to_string(),
            },
            process_exe: Some(
                r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_string(),
            ),
            process_exe_sha256: None,
            process_cmdline: None,
            parent_process: Some("unknown".to_string()),
            parent_chain: Vec::new(),
            file_path: Some(r"C:\\Windows\\Temp\\__PSScriptPolicyTest_demo.abc.ps1".to_string()),
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = super::to_detection_event(&enriched, 123);
        assert!(super::should_drop_low_value_windows_event(
            &enriched, &event
        ));
    }

    #[test]
    fn should_drop_low_value_windows_event_for_pid4_powershell_module_file_noise() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::FileOpen,
                pid: 4,
                uid: 0,
                ts_ns: 1,
                payload: "file_key=0xab".to_string(),
            },
            process_exe: Some(
                r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                    .to_string(),
            ),
            process_exe_sha256: None,
            process_cmdline: None,
            parent_process: Some("unknown".to_string()),
            parent_chain: Vec::new(),
            file_path: Some(
                r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\PrintManagement\\MSFT_Printer.format.ps1xml".to_string(),
            ),
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = super::to_detection_event(&enriched, 123);
        assert!(super::should_drop_low_value_windows_event(
            &enriched, &event
        ));
    }

    #[test]
    fn should_drop_low_value_windows_event_for_firefox_profile_file_chatter() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::FileOpen,
                pid: 4388,
                uid: 0,
                ts_ns: 1,
                payload: "file_key=0xac".to_string(),
            },
            process_exe: Some(
                r"C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe".to_string(),
            ),
            process_exe_sha256: None,
            process_cmdline: Some(
                r#""C:\Program Files (x86)\Mozilla Firefox\firefox.exe""#.to_string(),
            ),
            parent_process: Some("unknown".to_string()),
            parent_chain: vec![4296],
            file_path: Some(
                r"C:\\Users\\Administrator\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\mcpwrwi8.default-release\\storage\\permanent\\chrome\\idb\\1657114595AmcateirvtiSty.sqlite-shm".to_string(),
            ),
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = super::to_detection_event(&enriched, 123);
        assert_eq!(event.process, "firefox.exe");
        assert!(super::should_drop_low_value_windows_event(
            &enriched, &event
        ));
    }

    #[test]
    fn should_drop_low_value_windows_event_for_system_agent_state_chatter() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::FileOpen,
                pid: 4,
                uid: 0,
                ts_ns: 1,
                payload: "file_key=0xad".to_string(),
            },
            process_exe: Some("System".to_string()),
            process_exe_sha256: None,
            process_cmdline: None,
            parent_process: Some("unknown".to_string()),
            parent_chain: Vec::new(),
            file_path: Some(r"C:\\var\\lib\\eguard-agent\\baselines.journal".to_string()),
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = super::to_detection_event(&enriched, 123);
        assert!(super::should_drop_low_value_windows_event(
            &enriched, &event
        ));
    }

    #[test]
    fn should_drop_low_value_windows_event_for_system_browser_profile_chatter() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::FileOpen,
                pid: 4,
                uid: 0,
                ts_ns: 1,
                payload: "file_key=0xae".to_string(),
            },
            process_exe: Some("System".to_string()),
            process_exe_sha256: None,
            process_cmdline: None,
            parent_process: Some("unknown".to_string()),
            parent_chain: Vec::new(),
            file_path: Some(
                r"C:\\Users\\Administrator\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\mcpwrwi8.default-release\\storage\\permanent\\chrome\\idb\\1657114595AmcateirvtiSty.sqlite-shm".to_string(),
            ),
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = super::to_detection_event(&enriched, 123);
        assert!(super::should_drop_low_value_windows_event(
            &enriched, &event
        ));
    }

    #[test]
    fn should_not_drop_firefox_file_event_for_non_profile_user_path() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::FileOpen,
                pid: 4388,
                uid: 0,
                ts_ns: 1,
                payload: "file_key=0xaf".to_string(),
            },
            process_exe: Some(r"C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe".to_string()),
            process_exe_sha256: None,
            process_cmdline: Some(
                r#""C:\Program Files (x86)\Mozilla Firefox\firefox.exe""#.to_string(),
            ),
            parent_process: Some("unknown".to_string()),
            parent_chain: vec![4296],
            file_path: Some(r"C:\\Users\\Administrator\\Downloads\\invoice.zip".to_string()),
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = super::to_detection_event(&enriched, 123);
        assert_eq!(event.process, "firefox.exe");
        assert!(!super::should_drop_low_value_windows_event(
            &enriched, &event
        ));
    }

    #[test]
    fn should_drop_low_value_windows_event_for_pathless_svchost_host_chatter() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::FileOpen,
                pid: 996,
                uid: 0,
                ts_ns: 1,
                payload: "file_object=0x44".to_string(),
            },
            process_exe: Some(r"C:\\Windows\\System32\\svchost.exe".to_string()),
            process_exe_sha256: None,
            process_cmdline: Some(r"C:\\Windows\\system32\\svchost.exe -k netsvcs -p".to_string()),
            parent_process: Some("services.exe".to_string()),
            parent_chain: vec![580],
            file_path: None,
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = super::to_detection_event(&enriched, 123);
        assert_eq!(event.process, "svchost.exe");
        assert_eq!(event.file_path, None);
        assert!(super::should_drop_low_value_windows_event(
            &enriched, &event
        ));
    }

    #[test]
    fn should_drop_low_value_windows_event_for_proxy_host_pathless_chatter() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::FileOpen,
                pid: 1372,
                uid: 0,
                ts_ns: 1,
                payload: "file_object=0x55".to_string(),
            },
            process_exe: Some(r"C:\\Windows\\System32\\conhost.exe".to_string()),
            process_exe_sha256: None,
            process_cmdline: Some(
                r"\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1".to_string(),
            ),
            parent_process: Some("powershell.exe".to_string()),
            parent_chain: vec![2316],
            file_path: None,
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = super::to_detection_event(&enriched, 123);
        assert_eq!(event.process, "powershell.exe");
        assert_eq!(event.parent_process, "powershell.exe");
        assert!(super::should_drop_low_value_windows_event(
            &enriched, &event
        ));
    }

    #[test]
    fn should_drop_pathless_windows_self_image_firefox_chatter() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::FileOpen,
                pid: 4388,
                uid: 0,
                ts_ns: 1,
                payload: "file_object=0x77".to_string(),
            },
            process_exe: Some(r"C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe".to_string()),
            process_exe_sha256: None,
            process_cmdline: Some(
                r#""C:\Program Files (x86)\Mozilla Firefox\firefox.exe""#.to_string(),
            ),
            parent_process: Some("unknown".to_string()),
            parent_chain: vec![4296],
            file_path: None,
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = super::to_detection_event(&enriched, 123);
        assert_eq!(event.process, "firefox.exe");
        assert!(super::should_drop_low_value_windows_event(
            &enriched, &event
        ));
    }

    #[test]
    fn should_not_drop_pathless_windows_powershell_smoke_with_meaningful_cmdline() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::FileOpen,
                pid: 4952,
                uid: 0,
                ts_ns: 1,
                payload: "file_object=0x66".to_string(),
            },
            process_exe: Some(
                r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                    .to_string(),
            ),
            process_exe_sha256: None,
            process_cmdline: Some(
                r#"powershell -NoProfile -ExecutionPolicy Bypass -Command "'eguardtdh038' | Out-File -FilePath C:\Windows\Temp\eguardtdh038.txt -Encoding ascii""#
                    .to_string(),
            ),
            parent_process: Some("cmd.exe".to_string()),
            parent_chain: vec![4540],
            file_path: None,
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = super::to_detection_event(&enriched, 123);
        assert_eq!(event.process, "powershell.exe");
        assert_eq!(event.parent_process, "cmd.exe");
        assert!(!super::should_drop_low_value_windows_event(
            &enriched, &event
        ));
    }

    #[test]
    fn should_drop_proxy_host_process_lifecycle_when_parent_is_unknown() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::ProcessExec,
                pid: 3860,
                uid: 0,
                ts_ns: 1,
                payload: String::new(),
            },
            process_exe: Some(r"C:\\Windows\\System32\\conhost.exe".to_string()),
            process_exe_sha256: None,
            process_cmdline: None,
            parent_process: Some("unknown".to_string()),
            parent_chain: vec![1676],
            file_path: Some(r"C:\\Windows\\System32\\conhost.exe".to_string()),
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = super::to_detection_event(&enriched, 123);
        assert_eq!(event.process, "conhost.exe");
        assert_eq!(event.parent_process, "unknown");
        assert!(super::should_drop_low_value_windows_event(
            &enriched, &event
        ));
    }

    #[test]
    fn should_not_drop_proxy_host_process_lifecycle_when_parent_is_known() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::ProcessExec,
                pid: 4242,
                uid: 0,
                ts_ns: 1,
                payload: String::new(),
            },
            process_exe: Some(r"C:\\Windows\\System32\\conhost.exe".to_string()),
            process_exe_sha256: None,
            process_cmdline: Some(
                r"\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1".to_string(),
            ),
            parent_process: Some("powershell.exe".to_string()),
            parent_chain: vec![1337],
            file_path: Some(r"C:\\Windows\\System32\\conhost.exe".to_string()),
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = super::to_detection_event(&enriched, 123);
        assert_eq!(event.process, "conhost.exe");
        assert_eq!(event.parent_process, "powershell.exe");
        assert!(!super::should_drop_low_value_windows_event(
            &enriched, &event
        ));
    }

    #[test]
    fn should_drop_process_exit_when_identity_and_context_are_unknown() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::ProcessExit,
                pid: 1876,
                uid: 0,
                ts_ns: 1,
                payload: String::new(),
            },
            process_exe: None,
            process_exe_sha256: None,
            process_cmdline: None,
            parent_process: None,
            parent_chain: Vec::new(),
            file_path: None,
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = super::to_detection_event(&enriched, 123);
        assert_eq!(event.process, "unknown");
        assert_eq!(event.parent_process, "unknown");
        assert!(super::should_drop_low_value_windows_event(
            &enriched, &event
        ));
    }

    #[test]
    fn should_not_drop_process_exit_when_identity_is_present() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::ProcessExit,
                pid: 4244,
                uid: 0,
                ts_ns: 1,
                payload: String::new(),
            },
            process_exe: Some(
                r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_string(),
            ),
            process_exe_sha256: None,
            process_cmdline: Some(
                "powershell.exe -NoProfile -File C:\\Windows\\Temp\\demo.ps1".to_string(),
            ),
            parent_process: Some("cmd.exe".to_string()),
            parent_chain: vec![968],
            file_path: None,
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = super::to_detection_event(&enriched, 123);
        assert_eq!(event.process, "powershell.exe");
        assert_eq!(event.parent_process, "cmd.exe");
        assert!(!super::should_drop_low_value_windows_event(
            &enriched, &event
        ));
    }

    #[test]
    fn should_not_drop_windows_file_event_when_real_subject_path_exists() {
        let enriched = EnrichedEvent {
            event: RawEvent {
                event_type: EventType::FileOpen,
                pid: 4,
                uid: 0,
                ts_ns: 1,
                payload: "file_key=0x44".to_string(),
            },
            process_exe: Some("System".to_string()),
            process_exe_sha256: None,
            process_cmdline: None,
            parent_process: Some("unknown".to_string()),
            parent_chain: Vec::new(),
            file_path: Some(r"C:\\Windows\\System32\\kernel32.dll".to_string()),
            file_path_secondary: None,
            file_write: false,
            file_sha256: None,
            event_size: None,
            dst_ip: None,
            dst_port: None,
            dst_domain: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };

        let event = super::to_detection_event(&enriched, 123);
        assert!(!super::should_drop_low_value_windows_event(
            &enriched, &event
        ));
        assert_eq!(
            event.file_path.as_deref(),
            Some(r"C:\\Windows\\System32\\kernel32.dll")
        );
    }
}
