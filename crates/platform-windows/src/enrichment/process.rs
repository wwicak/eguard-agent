//! Process introspection for Windows.
//!
//! Uses command-backed process metadata queries to populate path/cmdline/parent chain.

#[cfg(any(test, target_os = "windows"))]
use std::collections::HashMap;
#[cfg(target_os = "windows")]
use std::process::Command;
#[cfg(target_os = "windows")]
use std::sync::{OnceLock, RwLock};
#[cfg(target_os = "windows")]
use std::time::{Duration, Instant};

#[cfg(target_os = "windows")]
use crate::windows_cmd::POWERSHELL_EXE;

#[cfg(any(test, target_os = "windows"))]
use serde_json::Value;

#[cfg(any(test, target_os = "windows"))]
const MAX_PARENT_CHAIN_DEPTH: usize = 12;
#[cfg(target_os = "windows")]
const PROCESS_SNAPSHOT_TTL: Duration = Duration::from_secs(2);

/// Collected process metadata.
#[derive(Debug, Clone, Default)]
pub struct ProcessInfo {
    pub exe_path: Option<String>,
    pub command_line: Option<String>,
    pub parent_name: Option<String>,
    pub parent_chain: Vec<u32>,
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug, Clone, Default)]
struct SnapshotProcessRecord {
    parent_pid: Option<u32>,
    exe_path: Option<String>,
    command_line: Option<String>,
    name: Option<String>,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Default)]
struct SnapshotState {
    refreshed_at: Option<Instant>,
    records: HashMap<u32, SnapshotProcessRecord>,
}

#[cfg(target_os = "windows")]
static PROCESS_SNAPSHOT: OnceLock<RwLock<SnapshotState>> = OnceLock::new();

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
    let snapshot = load_process_snapshot(false);
    if let Some(info) = process_info_from_snapshot(pid, &snapshot) {
        if info.exe_path.is_some() || info.command_line.is_some() || info.parent_name.is_some() {
            return info;
        }
    }

    if let Some(value) = query_process_json(pid) {
        let direct = process_info_from_value(pid, &value, &snapshot);
        if direct.exe_path.is_some()
            || direct.command_line.is_some()
            || direct.parent_name.is_some()
        {
            return direct;
        }
    }

    let refreshed = load_process_snapshot(true);
    process_info_from_snapshot(pid, &refreshed).unwrap_or_default()
}

#[cfg(target_os = "windows")]
fn collect_parent_chain_windows(pid: u32) -> Vec<u32> {
    let snapshot = load_process_snapshot(false);
    let chain = parent_chain_from_snapshot(pid, &snapshot);
    if !chain.is_empty() {
        return chain;
    }

    let refreshed = load_process_snapshot(true);
    parent_chain_from_snapshot(pid, &refreshed)
}

#[cfg(target_os = "windows")]
fn read_ppid_windows(pid: u32) -> Option<u32> {
    let snapshot = load_process_snapshot(false);
    if let Some(record) = snapshot.get(&pid) {
        return record.parent_pid;
    }

    query_process_json(pid).and_then(|value| extract_parent_pid(&value))
}

#[cfg(target_os = "windows")]
fn query_process_name(pid: u32) -> Option<String> {
    let snapshot = load_process_snapshot(false);
    snapshot
        .get(&pid)
        .and_then(record_display_name)
        .or_else(|| query_process_json(pid).and_then(|value| extract_process_name(&value)))
}

#[cfg(target_os = "windows")]
fn load_process_snapshot(force_refresh: bool) -> HashMap<u32, SnapshotProcessRecord> {
    let cache = PROCESS_SNAPSHOT.get_or_init(|| RwLock::new(SnapshotState::default()));

    if let Ok(state) = cache.read() {
        if !force_refresh
            && state
                .refreshed_at
                .map(|instant| instant.elapsed() < PROCESS_SNAPSHOT_TTL)
                .unwrap_or(false)
        {
            return state.records.clone();
        }
    }

    if let Some(fresh) =
        query_process_snapshot_json().and_then(|value| parse_process_snapshot(&value))
    {
        if let Ok(mut state) = cache.write() {
            state.refreshed_at = Some(Instant::now());
            state.records = fresh.clone();
        }
        return fresh;
    }

    cache
        .read()
        .map(|state| state.records.clone())
        .unwrap_or_default()
}

#[cfg(target_os = "windows")]
fn process_info_from_value(
    pid: u32,
    value: &Value,
    snapshot: &HashMap<u32, SnapshotProcessRecord>,
) -> ProcessInfo {
    let parent_pid = extract_parent_pid(value);
    let parent_chain = parent_pid
        .map(|ppid| parent_chain_from_parent(ppid, snapshot))
        .unwrap_or_default();
    let parent_name = parent_pid
        .and_then(|ppid| snapshot.get(&ppid).and_then(record_display_name))
        .or_else(|| parent_pid.and_then(query_process_name));

    ProcessInfo {
        exe_path: extract_executable_path(value)
            .or_else(|| extract_process_name(value))
            .or_else(|| {
                snapshot
                    .get(&pid)
                    .and_then(|record| record.exe_path.clone())
            })
            .or_else(|| snapshot.get(&pid).and_then(record_display_name)),
        command_line: extract_command_line(value).or_else(|| {
            snapshot
                .get(&pid)
                .and_then(|record| record.command_line.clone())
        }),
        parent_name,
        parent_chain,
    }
}

#[cfg(any(test, target_os = "windows"))]
fn process_info_from_snapshot(
    pid: u32,
    snapshot: &HashMap<u32, SnapshotProcessRecord>,
) -> Option<ProcessInfo> {
    let record = snapshot.get(&pid)?;
    let parent_chain = parent_chain_from_snapshot(pid, snapshot);
    let parent_name = parent_chain
        .first()
        .and_then(|ppid| snapshot.get(ppid))
        .and_then(record_display_name);

    Some(ProcessInfo {
        exe_path: record
            .exe_path
            .clone()
            .or_else(|| record_display_name(record)),
        command_line: record.command_line.clone(),
        parent_name,
        parent_chain,
    })
}

#[cfg(any(test, target_os = "windows"))]
fn parent_chain_from_snapshot(
    pid: u32,
    snapshot: &HashMap<u32, SnapshotProcessRecord>,
) -> Vec<u32> {
    let parent_pid = snapshot.get(&pid).and_then(|record| record.parent_pid);
    parent_pid
        .map(|ppid| parent_chain_from_parent(ppid, snapshot))
        .unwrap_or_default()
}

#[cfg(any(test, target_os = "windows"))]
fn parent_chain_from_parent(
    first_parent_pid: u32,
    snapshot: &HashMap<u32, SnapshotProcessRecord>,
) -> Vec<u32> {
    let mut out = Vec::new();
    let mut current = Some(first_parent_pid);

    for _ in 0..MAX_PARENT_CHAIN_DEPTH {
        let Some(ppid) = current.filter(|value| *value > 0) else {
            break;
        };
        if out.contains(&ppid) {
            break;
        }
        out.push(ppid);
        current = snapshot.get(&ppid).and_then(|record| record.parent_pid);
    }

    out
}

#[cfg(target_os = "windows")]
fn query_process_snapshot_json() -> Option<Value> {
    let command = "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine,Name | ConvertTo-Json -Compress";

    let output = Command::new(POWERSHELL_EXE)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ])
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

#[cfg(target_os = "windows")]
fn query_process_json(pid: u32) -> Option<Value> {
    let command = format!(
        "Get-CimInstance Win32_Process -Filter \"ProcessId = {}\" | Select-Object -First 1 ProcessId,ParentProcessId,ExecutablePath,CommandLine,Name | ConvertTo-Json -Compress",
        pid
    );

    let output = Command::new(POWERSHELL_EXE)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &command,
        ])
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
fn parse_process_snapshot(value: &Value) -> Option<HashMap<u32, SnapshotProcessRecord>> {
    let mut out = HashMap::new();

    match value {
        Value::Array(entries) => {
            for entry in entries {
                if let Some((pid, record)) = snapshot_record_from_value(entry) {
                    out.insert(pid, record);
                }
            }
        }
        Value::Object(_) => {
            if let Some((pid, record)) = snapshot_record_from_value(value) {
                out.insert(pid, record);
            }
        }
        _ => return None,
    }

    Some(out)
}

#[cfg(any(test, target_os = "windows"))]
fn snapshot_record_from_value(value: &Value) -> Option<(u32, SnapshotProcessRecord)> {
    let pid = value
        .get("ProcessId")
        .and_then(Value::as_u64)
        .map(|value| value as u32)?;

    Some((
        pid,
        SnapshotProcessRecord {
            parent_pid: extract_parent_pid(value).filter(|value| *value > 0),
            exe_path: extract_executable_path(value),
            command_line: extract_command_line(value),
            name: extract_process_name(value),
        },
    ))
}

#[cfg(any(test, target_os = "windows"))]
fn extract_parent_pid(value: &Value) -> Option<u32> {
    value
        .get("ParentProcessId")
        .and_then(Value::as_u64)
        .map(|v| v as u32)
}

#[cfg(any(test, target_os = "windows"))]
fn extract_executable_path(value: &Value) -> Option<String> {
    json_string(value, "ExecutablePath")
}

#[cfg(any(test, target_os = "windows"))]
fn extract_command_line(value: &Value) -> Option<String> {
    json_string(value, "CommandLine")
}

#[cfg(any(test, target_os = "windows"))]
fn extract_process_name(value: &Value) -> Option<String> {
    json_string(value, "Name")
}

#[cfg(any(test, target_os = "windows"))]
fn json_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

#[cfg(any(test, target_os = "windows"))]
fn record_display_name(record: &SnapshotProcessRecord) -> Option<String> {
    record.name.clone().or_else(|| {
        record
            .exe_path
            .as_deref()
            .map(process_basename)
            .map(ToString::to_string)
    })
}

#[cfg(any(test, target_os = "windows"))]
fn process_basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::{
        extract_parent_pid, parse_process_snapshot, process_basename, process_info_from_snapshot,
    };

    #[test]
    fn extracts_parent_pid_from_json() {
        let value: serde_json::Value =
            serde_json::from_str(r#"{"ParentProcessId":4321}"#).expect("valid json");
        assert_eq!(extract_parent_pid(&value), Some(4321));
    }

    #[test]
    fn parses_process_snapshot_arrays() {
        let value: serde_json::Value = serde_json::from_str(
            r#"[
              {"ProcessId":100,"ParentProcessId":4,"ExecutablePath":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","CommandLine":"powershell -NoProfile","Name":"powershell.exe"},
              {"ProcessId":4,"ParentProcessId":0,"ExecutablePath":null,"CommandLine":null,"Name":"System"}
            ]"#,
        )
        .expect("valid json array");

        let snapshot = parse_process_snapshot(&value).expect("snapshot parsed");
        assert_eq!(snapshot.len(), 2);
        assert_eq!(
            snapshot.get(&100).and_then(|record| record.parent_pid),
            Some(4)
        );
        assert_eq!(
            snapshot.get(&4).and_then(|record| record.name.as_deref()),
            Some("System")
        );
    }

    #[test]
    fn snapshot_process_info_uses_name_when_executable_path_is_missing() {
        let value: serde_json::Value = serde_json::from_str(
            r#"[
              {"ProcessId":100,"ParentProcessId":4,"ExecutablePath":null,"CommandLine":"powershell -NoProfile","Name":"powershell.exe"},
              {"ProcessId":4,"ParentProcessId":0,"ExecutablePath":null,"CommandLine":null,"Name":"System"}
            ]"#,
        )
        .expect("valid json array");

        let snapshot = parse_process_snapshot(&value).expect("snapshot parsed");
        let info = process_info_from_snapshot(100, &snapshot).expect("process info");

        assert_eq!(info.exe_path.as_deref(), Some("powershell.exe"));
        assert_eq!(info.command_line.as_deref(), Some("powershell -NoProfile"));
        assert_eq!(info.parent_name.as_deref(), Some("System"));
        assert_eq!(info.parent_chain, vec![4]);
    }

    #[test]
    fn process_basename_supports_windows_style_paths() {
        assert_eq!(process_basename(r"C:\Windows\System32\cmd.exe"), "cmd.exe");
        assert_eq!(process_basename("powershell.exe"), "powershell.exe");
    }
}
