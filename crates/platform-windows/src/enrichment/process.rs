//! Process introspection for Windows.
//!
//! Uses native Win32 / NT process queries to populate path/cmdline/parent chain
//! without spawning helper shells that create attribution noise.

#[cfg(any(test, target_os = "windows"))]
use std::collections::HashMap;
#[cfg(target_os = "windows")]
use std::mem::size_of;
#[cfg(target_os = "windows")]
use std::sync::{OnceLock, RwLock};
#[cfg(target_os = "windows")]
use std::time::{Duration, Instant};

#[cfg(target_os = "windows")]
use windows::{
    core::PWSTR,
    Wdk::System::Threading::{NtQueryInformationProcess, ProcessCommandLineInformation},
    Win32::{
        Foundation::{
            CloseHandle, HANDLE, STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL,
            STATUS_INFO_LENGTH_MISMATCH,
        },
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
            Threading::{
                OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
                PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
            },
        },
    },
};

#[cfg(any(test, target_os = "windows"))]
const MAX_PARENT_CHAIN_DEPTH: usize = 12;
#[cfg(target_os = "windows")]
const PROCESS_SNAPSHOT_TTL: Duration = Duration::from_millis(1500);

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
    let parent_chain = parent_chain_from_snapshot(pid, &snapshot);
    let parent_name = parent_chain
        .first()
        .and_then(|ppid| snapshot.get(ppid))
        .and_then(record_display_name);

    let mut record = snapshot.get(&pid).cloned().unwrap_or_default();
    if record.exe_path.is_none() {
        record.exe_path = query_process_image_path(pid);
    }
    if record.command_line.is_none() {
        record.command_line = query_process_command_line(pid);
    }
    if record.name.is_none() {
        record.name = record
            .exe_path
            .as_deref()
            .map(process_basename)
            .map(ToString::to_string);
    }

    if !record_is_empty(&record) {
        update_cached_record(pid, record.clone());
    }

    ProcessInfo {
        exe_path: record
            .exe_path
            .clone()
            .or_else(|| record_display_name(&record)),
        command_line: record.command_line,
        parent_name,
        parent_chain,
    }
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

    let refreshed = load_process_snapshot(true);
    refreshed.get(&pid).and_then(|record| record.parent_pid)
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

    if let Some(fresh) = snapshot_processes_native() {
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
fn update_cached_record(pid: u32, record: SnapshotProcessRecord) {
    let cache = PROCESS_SNAPSHOT.get_or_init(|| RwLock::new(SnapshotState::default()));
    if let Ok(mut state) = cache.write() {
        let entry = state.records.entry(pid).or_default();
        if entry.parent_pid.is_none() {
            entry.parent_pid = record.parent_pid;
        }
        if entry.exe_path.is_none() {
            entry.exe_path = record.exe_path;
        }
        if entry.command_line.is_none() {
            entry.command_line = record.command_line;
        }
        if entry.name.is_none() {
            entry.name = record.name;
        }
    }
}

#[cfg(target_os = "windows")]
fn snapshot_processes_native() -> Option<HashMap<u32, SnapshotProcessRecord>> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()? };
    let mut entry = PROCESSENTRY32W::default();
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

    let mut records = HashMap::new();
    let first = unsafe { Process32FirstW(snapshot, &mut entry) };
    if first.is_err() {
        let _ = unsafe { CloseHandle(snapshot) };
        return Some(records);
    }

    loop {
        let pid = entry.th32ProcessID;
        let parent_pid = (entry.th32ParentProcessID != 0).then_some(entry.th32ParentProcessID);
        let name = wide_nul_terminated_to_string(&entry.szExeFile);
        records.insert(
            pid,
            SnapshotProcessRecord {
                parent_pid,
                exe_path: None,
                command_line: None,
                name,
            },
        );

        if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
            break;
        }
    }

    let _ = unsafe { CloseHandle(snapshot) };
    Some(records)
}

#[cfg(target_os = "windows")]
fn query_process_image_path(pid: u32) -> Option<String> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()? };

    let mut buf = vec![0u16; 1024];
    let mut len = buf.len() as u32;
    let result = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
    };
    let _ = unsafe { CloseHandle(handle) };
    if result.is_err() || len == 0 {
        return None;
    }

    Some(String::from_utf16_lossy(&buf[..len as usize]))
}

#[cfg(target_os = "windows")]
fn query_process_command_line(pid: u32) -> Option<String> {
    let handle = unsafe {
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            .ok()
            .or_else(|| OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok())?
    };

    let result = query_process_command_line_from_handle(handle);
    let _ = unsafe { CloseHandle(handle) };
    result
}

#[cfg(target_os = "windows")]
fn query_process_command_line_from_handle(handle: HANDLE) -> Option<String> {
    let buffer = query_process_variable_buffer(handle, ProcessCommandLineInformation)?;
    parse_command_line_query_buffer(&buffer)
}

#[cfg(target_os = "windows")]
fn query_process_variable_buffer(
    handle: HANDLE,
    information_class: windows::Wdk::System::Threading::PROCESSINFOCLASS,
) -> Option<Vec<u8>> {
    let mut return_length = 0u32;
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            information_class,
            std::ptr::null_mut(),
            0,
            &mut return_length,
        )
    };

    if status.is_err()
        && status != STATUS_BUFFER_OVERFLOW
        && status != STATUS_BUFFER_TOO_SMALL
        && status != STATUS_INFO_LENGTH_MISMATCH
    {
        return None;
    }
    if return_length == 0 {
        return None;
    }

    let mut buffer = vec![0u8; return_length as usize];
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            information_class,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            &mut return_length,
        )
    };
    if status.is_err() {
        return None;
    }

    buffer.truncate(return_length as usize);
    Some(buffer)
}

#[cfg(any(test, target_os = "windows"))]
fn parse_command_line_query_buffer(buffer: &[u8]) -> Option<String> {
    if buffer.len() < size_of_unicode_string() {
        return None;
    }

    let header = read_unicode_string_header(buffer)?;
    let byte_len = header.length as usize;
    if byte_len == 0 || byte_len % 2 != 0 {
        return None;
    }

    let buffer_bytes = unicode_string_bytes(buffer, &header, byte_len)?;
    utf16_bytes_to_string(buffer_bytes)
}

#[cfg(any(test, target_os = "windows"))]
fn unicode_string_bytes<'a>(
    backing: &'a [u8],
    header: &RawUnicodeString,
    byte_len: usize,
) -> Option<&'a [u8]> {
    let backing_start = backing.as_ptr() as usize;
    let backing_end = backing_start.checked_add(backing.len())?;
    let target_ptr = header.buffer_ptr;

    if target_ptr >= backing_start && target_ptr.checked_add(byte_len)? <= backing_end {
        let offset = target_ptr.checked_sub(backing_start)?;
        return backing.get(offset..offset + byte_len);
    }

    let inline_start = size_of_unicode_string();
    backing.get(inline_start..inline_start + byte_len)
}

#[cfg(any(test, target_os = "windows"))]
fn utf16_bytes_to_string(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.len() % 2 != 0 {
        return None;
    }

    let wide: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    let value = String::from_utf16_lossy(&wide).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RawUnicodeString {
    length: u16,
    maximum_length: u16,
    buffer_ptr: usize,
}

#[cfg(any(test, target_os = "windows"))]
fn read_unicode_string_header(buffer: &[u8]) -> Option<RawUnicodeString> {
    if buffer.len() < size_of_unicode_string() {
        return None;
    }

    let length = u16::from_le_bytes([buffer[0], buffer[1]]);
    let maximum_length = u16::from_le_bytes([buffer[2], buffer[3]]);
    let pointer_size = size_of::<usize>();
    let ptr_offset = if pointer_size == 8 { 8 } else { 4 };
    let ptr_end = ptr_offset + pointer_size;
    let ptr_bytes = buffer.get(ptr_offset..ptr_end)?;
    let buffer_ptr = if pointer_size == 8 {
        let bytes: [u8; 8] = ptr_bytes.try_into().ok()?;
        u64::from_le_bytes(bytes) as usize
    } else {
        let bytes: [u8; 4] = ptr_bytes.try_into().ok()?;
        u32::from_le_bytes(bytes) as usize
    };

    Some(RawUnicodeString {
        length,
        maximum_length,
        buffer_ptr,
    })
}

#[cfg(any(test, target_os = "windows"))]
fn size_of_unicode_string() -> usize {
    if size_of::<usize>() == 8 {
        16
    } else {
        8
    }
}

#[cfg(target_os = "windows")]
fn record_is_empty(record: &SnapshotProcessRecord) -> bool {
    record.parent_pid.is_none()
        && record.exe_path.is_none()
        && record.command_line.is_none()
        && record.name.is_none()
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

#[cfg(test)]
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

#[cfg(any(test, target_os = "windows"))]
fn wide_nul_terminated_to_string(raw: &[u16]) -> Option<String> {
    let len = raw
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(raw.len());
    let value = String::from_utf16_lossy(&raw[..len]).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        parent_chain_from_snapshot, parse_command_line_query_buffer, process_basename,
        process_info_from_snapshot, size_of_unicode_string, wide_nul_terminated_to_string,
        SnapshotProcessRecord,
    };
    use std::collections::HashMap;

    #[test]
    fn snapshot_process_info_uses_name_when_executable_path_is_missing() {
        let snapshot = HashMap::from([
            (
                100,
                SnapshotProcessRecord {
                    parent_pid: Some(4),
                    exe_path: None,
                    command_line: Some("powershell -NoProfile".to_string()),
                    name: Some("powershell.exe".to_string()),
                },
            ),
            (
                4,
                SnapshotProcessRecord {
                    parent_pid: None,
                    exe_path: None,
                    command_line: None,
                    name: Some("System".to_string()),
                },
            ),
        ]);

        let info = process_info_from_snapshot(100, &snapshot).expect("process info");
        assert_eq!(info.exe_path.as_deref(), Some("powershell.exe"));
        assert_eq!(info.command_line.as_deref(), Some("powershell -NoProfile"));
        assert_eq!(info.parent_name.as_deref(), Some("System"));
        assert_eq!(info.parent_chain, vec![4]);
    }

    #[test]
    fn parent_chain_stops_on_cycles() {
        let snapshot = HashMap::from([
            (
                10,
                SnapshotProcessRecord {
                    parent_pid: Some(20),
                    exe_path: None,
                    command_line: None,
                    name: Some("child.exe".to_string()),
                },
            ),
            (
                20,
                SnapshotProcessRecord {
                    parent_pid: Some(30),
                    exe_path: None,
                    command_line: None,
                    name: Some("mid.exe".to_string()),
                },
            ),
            (
                30,
                SnapshotProcessRecord {
                    parent_pid: Some(20),
                    exe_path: None,
                    command_line: None,
                    name: Some("loop.exe".to_string()),
                },
            ),
        ]);

        assert_eq!(parent_chain_from_snapshot(10, &snapshot), vec![20, 30]);
    }

    #[test]
    fn parse_command_line_buffer_supports_inline_storage() {
        let command = "powershell.exe -NoProfile";
        let utf16: Vec<u16> = command.encode_utf16().collect();
        let byte_len = (utf16.len() * 2) as u16;
        let mut buffer = vec![0u8; size_of_unicode_string() + utf16.len() * 2];
        buffer[0..2].copy_from_slice(&byte_len.to_le_bytes());
        buffer[2..4].copy_from_slice(&byte_len.to_le_bytes());
        for (idx, unit) in utf16.iter().enumerate() {
            let start = size_of_unicode_string() + idx * 2;
            buffer[start..start + 2].copy_from_slice(&unit.to_le_bytes());
        }

        let parsed = parse_command_line_query_buffer(&buffer).expect("parsed command line");
        assert_eq!(parsed, command);
    }

    #[test]
    fn process_basename_supports_windows_style_paths() {
        assert_eq!(process_basename(r"C:\Windows\System32\cmd.exe"), "cmd.exe");
        assert_eq!(process_basename("powershell.exe"), "powershell.exe");
    }

    #[test]
    fn wide_nul_terminated_conversion_trims_after_nul() {
        let raw = [b'p' as u16, b's' as u16, 0, b'x' as u16];
        assert_eq!(wide_nul_terminated_to_string(&raw).as_deref(), Some("ps"));
    }
}
