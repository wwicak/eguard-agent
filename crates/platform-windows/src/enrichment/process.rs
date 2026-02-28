//! Process introspection for Windows.
//!
//! Uses command-backed process metadata queries to populate path/cmdline/parent chain.

#[cfg(target_os = "windows")]
use crate::windows_cmd::POWERSHELL_EXE;
#[cfg(target_os = "windows")]
use std::process::Command;

#[cfg(any(test, target_os = "windows"))]
use serde_json::Value;

#[cfg(target_os = "windows")]
const MAX_PARENT_CHAIN_DEPTH: usize = 12;

/// Collected process metadata.
#[derive(Debug, Clone, Default)]
pub struct ProcessInfo {
    pub exe_path: Option<String>,
    pub command_line: Option<String>,
    pub parent_name: Option<String>,
    pub parent_chain: Vec<u32>,
}

/// Query process information for the given PID.
pub fn query_process_info(pid: u32) -> ProcessInfo {
    #[cfg(target_os = "windows")]
    {
        query_process_info_windows(pid)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid;
        ProcessInfo::default()
    }
}

/// Collect the parent chain (up to `MAX_PARENT_CHAIN_DEPTH` ancestors).
pub fn collect_parent_chain(pid: u32) -> Vec<u32> {
    #[cfg(target_os = "windows")]
    {
        collect_parent_chain_windows(pid)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid;
        Vec::new()
    }
}

/// Read the parent PID using process metadata query.
pub fn read_ppid(pid: u32) -> Option<u32> {
    #[cfg(target_os = "windows")]
    {
        read_ppid_windows(pid)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid;
        None
    }
}

// ── Windows implementations ────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn query_process_info_windows(pid: u32) -> ProcessInfo {
    let parent_chain = collect_parent_chain_windows(pid);
    let parent_name = parent_chain
        .first()
        .and_then(|ppid| query_process_name(*ppid));

    let Some(value) = query_process_json(pid) else {
        return ProcessInfo {
            parent_name,
            parent_chain,
            ..ProcessInfo::default()
        };
    };

    ProcessInfo {
        exe_path: value
            .get("ExecutablePath")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        command_line: value
            .get("CommandLine")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        parent_name,
        parent_chain,
    }
}

#[cfg(target_os = "windows")]
fn collect_parent_chain_windows(pid: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let mut current = pid;
    for _ in 0..MAX_PARENT_CHAIN_DEPTH {
        let Some(ppid) = read_ppid_windows(current) else {
            break;
        };
        if ppid == 0 || ppid == current {
            break;
        }
        out.push(ppid);
        current = ppid;
    }
    out
}

#[cfg(target_os = "windows")]
fn read_ppid_windows(pid: u32) -> Option<u32> {
    let value = query_process_json(pid)?;
    extract_parent_pid(&value)
}

#[cfg(target_os = "windows")]
fn query_process_name(pid: u32) -> Option<String> {
    let value = query_process_json(pid)?;
    value
        .get("Name")
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

#[cfg(target_os = "windows")]
fn query_process_json(pid: u32) -> Option<Value> {
    let command = format!(
        "Get-CimInstance Win32_Process -Filter \"ProcessId = {}\" | Select-Object -First 1 ProcessId,ParentProcessId,ExecutablePath,CommandLine,Name | ConvertTo-Json -Compress",
        pid
    );

    let output = Command::new(POWERSHELL_EXE)
        .args(["-NoProfile", "-NonInteractive", "-Command", &command])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if raw.is_empty() {
        return None;
    }

    serde_json::from_str::<Value>(&raw).ok()
}

#[cfg(any(test, target_os = "windows"))]
fn extract_parent_pid(value: &Value) -> Option<u32> {
    value
        .get("ParentProcessId")
        .and_then(Value::as_u64)
        .map(|v| v as u32)
}

#[cfg(test)]
mod tests {
    use super::extract_parent_pid;

    #[test]
    fn extracts_parent_pid_from_json() {
        let value: serde_json::Value =
            serde_json::from_str(r#"{"ParentProcessId":4321}"#).expect("valid json");
        assert_eq!(extract_parent_pid(&value), Some(4321));
    }
}
