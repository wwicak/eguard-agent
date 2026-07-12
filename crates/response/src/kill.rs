#[cfg(any(test, target_os = "windows"))]
use std::collections::HashMap;
use std::collections::{HashSet, VecDeque};

#[cfg(target_os = "linux")]
use std::fs;

#[cfg(target_os = "windows")]
use std::mem::size_of;
#[cfg(target_os = "windows")]
use windows::{
    core::{HRESULT, PWSTR},
    Win32::{
        Foundation::{CloseHandle, BOOL, ERROR_NO_MORE_FILES, FILETIME, HANDLE},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
            Threading::{
                GetProcessTimes, IsProcessCritical, OpenProcess, QueryFullProcessImageNameW,
                TerminateProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
                PROCESS_TERMINATE,
            },
        },
    },
};

#[cfg(unix)]
use nix::sys::signal::{kill, Signal as NixSignal};
#[cfg(unix)]
use nix::unistd::Pid;

use crate::errors::{ResponseError, ResponseResult};
use crate::ProtectedList;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    SIGSTOP,
    SIGKILL,
}

#[derive(Debug, Clone)]
pub struct KillReport {
    pub target_pid: u32,
    pub killed_pids: Vec<u32>,
    pub skipped_protected_pids: Vec<u32>,
    pub failed_pids: Vec<u32>,
}

pub trait ProcessIntrospector {
    fn children_of(&self, pid: u32) -> Vec<u32>;
    fn process_name(&self, pid: u32) -> Option<String>;
}

pub trait SignalSender {
    fn send(&self, pid: u32, signal: Signal) -> ResponseResult<()>;
}

#[cfg(not(target_os = "windows"))]
pub struct ProcfsIntrospector;

#[cfg(target_os = "linux")]
impl ProcessIntrospector for ProcfsIntrospector {
    fn children_of(&self, pid: u32) -> Vec<u32> {
        let path = format!("/proc/{}/task/{}/children", pid, pid);
        match fs::read_to_string(path) {
            Ok(content) => content
                .split_whitespace()
                .filter_map(|raw| raw.parse::<u32>().ok())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    fn process_name(&self, pid: u32) -> Option<String> {
        if let Ok(path) = fs::read_link(format!("/proc/{}/exe", pid)) {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                let trimmed = name.trim().trim_end_matches(" (deleted)");
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }

        let comm = fs::read_to_string(format!("/proc/{}/comm", pid)).ok()?;
        let name = comm.trim();
        if name.is_empty() {
            None
        } else {
            Some(name.to_string())
        }
    }
}

// ---- macOS kinfo_proc byte offsets (arm64/x86_64) ----
// The libc crate removed kinfo_proc, so we read raw sysctl bytes at known offsets.
#[cfg(target_os = "macos")]
const KINFO_PROC_SIZE: usize = 648;
#[cfg(target_os = "macos")]
const KP_PROC_P_PID_OFFSET: usize = 68; // offsetof(kinfo_proc, kp_proc.p_pid)
#[cfg(target_os = "macos")]
const KP_PROC_P_COMM_OFFSET: usize = 163; // offsetof(kinfo_proc, kp_proc.p_comm), MAXCOMLEN+1=17
#[cfg(target_os = "macos")]
const KP_EPROC_E_PPID_OFFSET: usize = 560; // offsetof(kinfo_proc, kp_eproc.e_ppid)

#[cfg(target_os = "macos")]
fn read_i32(buf: &[u8], offset: usize) -> i32 {
    if offset + 4 > buf.len() {
        return 0;
    }
    i32::from_ne_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

#[cfg(target_os = "macos")]
fn read_comm(buf: &[u8], offset: usize) -> String {
    buf[offset..]
        .iter()
        .take(16) // MAXCOMLEN
        .take_while(|&&c| c != 0)
        .map(|&c| c as char)
        .collect()
}

/// macOS process introspector that caches the process table snapshot.
///
/// Fetches the full process table once via `sysctl(KERN_PROC_ALL)` on first
/// use, then serves `children_of()` and `process_name()` from the snapshot.
/// This avoids O(n*d) sysctl calls when walking a process tree.
#[cfg(target_os = "macos")]
pub struct MacosProcessIntrospector {
    /// ppid -> Vec<child_pid>
    children_map: std::collections::HashMap<u32, Vec<u32>>,
    /// pid -> process name
    name_map: std::collections::HashMap<u32, String>,
}

#[cfg(target_os = "macos")]
impl MacosProcessIntrospector {
    pub fn snapshot() -> Self {
        let (children_map, name_map) = build_process_maps();
        Self {
            children_map,
            name_map,
        }
    }
}

#[cfg(target_os = "macos")]
impl ProcessIntrospector for MacosProcessIntrospector {
    fn children_of(&self, pid: u32) -> Vec<u32> {
        self.children_map.get(&pid).cloned().unwrap_or_default()
    }

    fn process_name(&self, pid: u32) -> Option<String> {
        self.name_map.get(&pid).cloned()
    }
}

/// Fetch the full process table once and build parent->children + pid->name maps.
///
/// Uses raw byte buffers to read `kinfo_proc` from sysctl because the `libc`
/// crate removed `kinfo_proc` in recent versions.
#[cfg(target_os = "macos")]
fn build_process_maps() -> (
    std::collections::HashMap<u32, Vec<u32>>,
    std::collections::HashMap<u32, String>,
) {
    use std::ptr;

    let mut children_map: std::collections::HashMap<u32, Vec<u32>> =
        std::collections::HashMap::new();
    let mut name_map: std::collections::HashMap<u32, String> = std::collections::HashMap::new();

    let mut mib: [libc::c_int; 4] = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_ALL, 0];
    let mut size: libc::size_t = 0;

    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            ptr::null_mut(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if ret != 0 || size == 0 {
        return (children_map, name_map);
    }

    // Add extra space for processes that may appear between calls.
    size += size / 10;
    let kinfo_size = KINFO_PROC_SIZE;
    let count = size / kinfo_size;
    let mut buf = vec![0u8; count * kinfo_size];

    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        return (children_map, name_map);
    }

    let actual_count = size / kinfo_size;

    for i in 0..actual_count {
        let base = i * kinfo_size;
        if base + kinfo_size > buf.len() {
            break;
        }
        let pid = read_i32(&buf, base + KP_PROC_P_PID_OFFSET) as u32;
        let ppid = read_i32(&buf, base + KP_EPROC_E_PPID_OFFSET) as u32;
        let name = read_comm(&buf, base + KP_PROC_P_COMM_OFFSET);

        if pid != ppid {
            children_map.entry(ppid).or_default().push(pid);
        }
        if !name.is_empty() {
            name_map.insert(pid, name);
        }
    }

    (children_map, name_map)
}

#[cfg(target_os = "macos")]
impl ProcessIntrospector for ProcfsIntrospector {
    fn children_of(&self, pid: u32) -> Vec<u32> {
        // Fallback for the trait-object interface. For tree walks,
        // prefer MacosProcessIntrospector::snapshot() instead.
        let snapshot = MacosProcessIntrospector::snapshot();
        snapshot.children_of(pid)
    }

    fn process_name(&self, pid: u32) -> Option<String> {
        process_name_macos(pid)
    }
}

#[cfg(target_os = "macos")]
fn process_name_macos(pid: u32) -> Option<String> {
    use std::ptr;

    let mut mib: [libc::c_int; 4] = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PID,
        pid as libc::c_int,
    ];
    let mut buf = [0u8; KINFO_PROC_SIZE];
    let mut size = KINFO_PROC_SIZE;

    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            4,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            ptr::null_mut(),
            0,
        )
    };

    if ret != 0 || size == 0 {
        return None;
    }

    let name = read_comm(&buf, KP_PROC_P_COMM_OFFSET);
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

#[cfg(not(any(unix, target_os = "windows")))]
impl ProcessIntrospector for ProcfsIntrospector {
    fn children_of(&self, _pid: u32) -> Vec<u32> {
        Vec::new()
    }

    fn process_name(&self, _pid: u32) -> Option<String> {
        None
    }
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WindowsProcessEntry {
    pid: u32,
    parent_pid: u32,
    creation_time: Option<u64>,
}

#[cfg(any(test, target_os = "windows"))]
fn snapshot_entry_map(
    entries: &[WindowsProcessEntry],
) -> ResponseResult<HashMap<u32, WindowsProcessEntry>> {
    let mut process_entries = HashMap::new();
    for &entry in entries {
        if entry.pid == 0 {
            continue;
        }
        match process_entries.insert(entry.pid, entry) {
            Some(existing) if existing != entry => {
                return Err(ResponseError::Signal(format!(
                    "process snapshot contains conflicting identity or parent for pid {}",
                    entry.pid
                )))
            }
            _ => {}
        }
    }
    Ok(process_entries)
}

#[cfg(any(test, target_os = "windows"))]
fn descendants_from_snapshot(
    root_pid: u32,
    entries: &[WindowsProcessEntry],
    max_descendants: usize,
) -> ResponseResult<Vec<(u32, u32)>> {
    let process_entries = snapshot_entry_map(entries)?;
    let mut children = HashMap::<u32, Vec<u32>>::new();
    let mut edges = HashSet::new();
    for entry in entries {
        if entry.pid != 0
            && process_entries.get(&entry.pid) == Some(entry)
            && edges.insert((entry.pid, entry.parent_pid))
        {
            children
                .entry(entry.parent_pid)
                .or_default()
                .push(entry.pid);
        }
    }

    let mut descendants = Vec::new();
    let mut seen = HashSet::from([root_pid]);
    let mut queue = VecDeque::from([root_pid]);
    while let Some(parent_pid) = queue.pop_front() {
        for &pid in children.get(&parent_pid).into_iter().flatten() {
            if !seen.insert(pid) {
                return Err(ResponseError::Signal(format!(
                    "cycle detected in process snapshot at pid {pid}"
                )));
            }
            if descendants.len() >= max_descendants {
                return Err(ResponseError::Signal(format!(
                    "process tree rooted at {root_pid} exceeds {max_descendants} descendants"
                )));
            }
            descendants.push((pid, parent_pid));
            queue.push_back(pid);
        }
    }
    Ok(descendants)
}

#[cfg(target_os = "windows")]
const MAX_WINDOWS_SNAPSHOT_PROCESSES: usize = 32_768;
#[cfg(target_os = "windows")]
const MAX_WINDOWS_TREE_DESCENDANTS: usize = 4_096;

#[cfg(target_os = "windows")]
struct OwnedWindowsHandle(HANDLE);

#[cfg(target_os = "windows")]
impl Drop for OwnedWindowsHandle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

#[cfg(target_os = "windows")]
trait WindowsProcessApi {
    type Handle;

    fn process_snapshot(&self) -> ResponseResult<Vec<WindowsProcessEntry>>;
    fn open_process(&self, pid: u32) -> ResponseResult<Self::Handle>;
    fn process_creation_time(&self, handle: &Self::Handle) -> ResponseResult<u64>;
    fn process_name(&self, handle: &Self::Handle) -> ResponseResult<String>;
    /// Report whether the OS marks the process as critical (terminating a
    /// critical process triggers bugcheck 0xEF / CRITICAL_PROCESS_DIED). This
    /// is the authoritative availability guard; the static protected-name list
    /// is only a backstop.
    fn is_process_critical(&self, handle: &Self::Handle) -> ResponseResult<bool>;
    fn terminate_process(&self, handle: &Self::Handle) -> ResponseResult<()>;
}

#[cfg(target_os = "windows")]
struct NativeWindowsProcessApi;

#[cfg(target_os = "windows")]
impl WindowsProcessApi for NativeWindowsProcessApi {
    type Handle = OwnedWindowsHandle;

    fn process_snapshot(&self) -> ResponseResult<Vec<WindowsProcessEntry>> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
            .map(OwnedWindowsHandle)
            .map_err(|err| {
                ResponseError::Signal(format!("create Windows process snapshot: {err}"))
            })?;
        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

        match unsafe { Process32FirstW(snapshot.0, &mut entry) } {
            Ok(()) => {}
            Err(err) if err.code() == HRESULT::from_win32(ERROR_NO_MORE_FILES.0) => {
                return Ok(Vec::new())
            }
            Err(err) => {
                return Err(ResponseError::Signal(format!(
                    "read first Windows process snapshot entry: {err}"
                )))
            }
        }

        let mut entries = Vec::new();
        loop {
            if entries.len() >= MAX_WINDOWS_SNAPSHOT_PROCESSES {
                return Err(ResponseError::Signal(format!(
                    "Windows process snapshot exceeds {MAX_WINDOWS_SNAPSHOT_PROCESSES} entries"
                )));
            }
            let creation_time = unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    false,
                    entry.th32ProcessID,
                )
            }
            .map(OwnedWindowsHandle)
            .ok()
            .and_then(|handle| self.process_creation_time(&handle).ok());
            entries.push(WindowsProcessEntry {
                pid: entry.th32ProcessID,
                parent_pid: entry.th32ParentProcessID,
                creation_time,
            });

            match unsafe { Process32NextW(snapshot.0, &mut entry) } {
                Ok(()) => {}
                Err(err) if err.code() == HRESULT::from_win32(ERROR_NO_MORE_FILES.0) => break,
                Err(err) => {
                    return Err(ResponseError::Signal(format!(
                        "read Windows process snapshot entry: {err}"
                    )))
                }
            }
        }
        Ok(entries)
    }

    fn open_process(&self, pid: u32) -> ResponseResult<Self::Handle> {
        unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
                false,
                pid,
            )
        }
        .map(OwnedWindowsHandle)
        .map_err(|err| ResponseError::Signal(format!("open Windows process {pid}: {err}")))
    }

    fn process_creation_time(&self, handle: &Self::Handle) -> ResponseResult<u64> {
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        unsafe { GetProcessTimes(handle.0, &mut creation, &mut exit, &mut kernel, &mut user) }
            .map_err(|err| ResponseError::Signal(format!("query Windows process times: {err}")))?;
        Ok(((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64)
    }

    fn process_name(&self, handle: &Self::Handle) -> ResponseResult<String> {
        let mut path = vec![0u16; 32_768];
        let mut len = path.len() as u32;
        unsafe {
            QueryFullProcessImageNameW(
                handle.0,
                PROCESS_NAME_FORMAT(0),
                PWSTR(path.as_mut_ptr()),
                &mut len,
            )
        }
        .map_err(|err| ResponseError::Signal(format!("query Windows process image name: {err}")))?;
        if len == 0 {
            return Err(ResponseError::Signal(
                "query Windows process image name returned an empty path".to_string(),
            ));
        }

        let path = String::from_utf16(&path[..len as usize]).map_err(|_| {
            ResponseError::Signal("Windows process image name is not valid UTF-16".to_string())
        })?;
        let name = path.rsplit(['\\', '/']).next().unwrap_or_default();
        if name.is_empty() {
            return Err(ResponseError::Signal(
                "Windows process image path has no basename".to_string(),
            ));
        }
        Ok(name.to_string())
    }

    fn is_process_critical(&self, handle: &Self::Handle) -> ResponseResult<bool> {
        let mut critical = BOOL(0);
        unsafe { IsProcessCritical(handle.0, &mut critical) }.map_err(|err| {
            ResponseError::Signal(format!("query Windows process critical flag: {err}"))
        })?;
        Ok(critical.as_bool())
    }

    fn terminate_process(&self, handle: &Self::Handle) -> ResponseResult<()> {
        unsafe { TerminateProcess(handle.0, 1) }
            .map_err(|err| ResponseError::Signal(format!("terminate Windows process: {err}")))
    }
}

#[cfg(target_os = "windows")]
fn windows_pid_is_always_protected(pid: u32) -> bool {
    pid <= 2 || pid == std::process::id()
}

#[cfg(target_os = "windows")]
fn kill_process_tree_windows_with<A: WindowsProcessApi>(
    pid: u32,
    protected: &ProtectedList,
    api: &A,
) -> ResponseResult<KillReport> {
    if pid == 0 {
        return Err(ResponseError::InvalidInput(
            "pid must be greater than zero".to_string(),
        ));
    }
    if windows_pid_is_always_protected(pid) {
        return Err(ResponseError::ProtectedProcess(pid));
    }

    let root_handle = api.open_process(pid)?;
    let root_creation_time = api.process_creation_time(&root_handle)?;
    let root_name = api.process_name(&root_handle)?;
    // Protect the target if either the static list matches OR the OS marks it
    // critical. A failed critical query is treated as critical (fail-closed):
    // missing a kill is an availability-safe outcome; a bugcheck is not.
    if protected.is_protected_process(&root_name)
        || api.is_process_critical(&root_handle).unwrap_or(true)
    {
        return Err(ResponseError::ProtectedProcess(pid));
    }

    let snapshot = api.process_snapshot()?;
    let snapshot_entries = snapshot_entry_map(&snapshot)?;
    if snapshot_entries
        .get(&pid)
        .and_then(|entry| entry.creation_time)
        != Some(root_creation_time)
    {
        return Err(ResponseError::Signal(format!(
            "Windows process {pid} identity does not match the first snapshot"
        )));
    }
    let descendants = descendants_from_snapshot(pid, &snapshot, MAX_WINDOWS_TREE_DESCENDANTS)?;
    let mut protected_pids = Vec::new();
    let mut failed_pids = Vec::new();
    let mut accepted_identities = HashMap::from([(pid, root_creation_time)]);
    let mut child_handles = Vec::new();

    for (child_pid, parent_pid) in descendants {
        if windows_pid_is_always_protected(child_pid) {
            protected_pids.push(child_pid);
            continue;
        }
        let Some(&parent_creation_time) = accepted_identities.get(&parent_pid) else {
            failed_pids.push(child_pid);
            continue;
        };
        let Some(snapshot_creation_time) = snapshot_entries
            .get(&child_pid)
            .and_then(|entry| entry.creation_time)
        else {
            failed_pids.push(child_pid);
            continue;
        };
        let handle = match api.open_process(child_pid) {
            Ok(handle) => handle,
            Err(_) => {
                failed_pids.push(child_pid);
                continue;
            }
        };
        let creation_time = match api.process_creation_time(&handle) {
            Ok(creation_time)
                if creation_time == snapshot_creation_time
                    && creation_time >= parent_creation_time =>
            {
                creation_time
            }
            _ => {
                failed_pids.push(child_pid);
                continue;
            }
        };
        let name = match api.process_name(&handle) {
            Ok(name) => name,
            Err(_) => {
                failed_pids.push(child_pid);
                continue;
            }
        };
        // Fold the OS critical flag into the per-descendant protection decision,
        // fail-closed on a query error (same rationale as the root).
        let is_protected = protected.is_protected_process(&name)
            || api.is_process_critical(&handle).unwrap_or(true);
        if is_protected {
            protected_pids.push(child_pid);
        }
        accepted_identities.insert(child_pid, creation_time);
        child_handles.push((child_pid, parent_pid, creation_time, is_protected, handle));
    }

    // Revalidate identity and parent edges while every accepted process handle is held.
    // Termination then uses only those same verified handles, never a PID lookup.
    let validation_snapshot = api.process_snapshot()?;
    let validation_entries = snapshot_entry_map(&validation_snapshot)?;
    let root_identity_valid = validation_entries
        .get(&pid)
        .and_then(|entry| entry.creation_time)
        == Some(root_creation_time);
    let mut validated_identities = HashSet::new();
    if root_identity_valid {
        validated_identities.insert(pid);
    }
    let mut validated_handles = Vec::new();
    for (child_pid, parent_pid, creation_time, is_protected, handle) in child_handles {
        let entry_matches = validation_entries.get(&child_pid).is_some_and(|entry| {
            entry.parent_pid == parent_pid && entry.creation_time == Some(creation_time)
        });
        if validated_identities.contains(&parent_pid) && entry_matches {
            validated_identities.insert(child_pid);
            if !is_protected {
                validated_handles.push((child_pid, handle));
            }
        } else {
            failed_pids.push(child_pid);
        }
    }

    let mut killed_pids = Vec::new();
    for (child_pid, handle) in validated_handles.iter().rev() {
        match api.terminate_process(handle) {
            Ok(()) => killed_pids.push(*child_pid),
            Err(_) => failed_pids.push(*child_pid),
        }
    }
    if root_identity_valid {
        match api.terminate_process(&root_handle) {
            Ok(()) => killed_pids.push(pid),
            Err(_) => failed_pids.push(pid),
        }
    } else {
        failed_pids.push(pid);
    }

    Ok(KillReport {
        target_pid: pid,
        killed_pids,
        skipped_protected_pids: protected_pids,
        failed_pids,
    })
}

#[cfg(not(target_os = "windows"))]
pub struct NixSignalSender;

#[cfg(unix)]
impl SignalSender for NixSignalSender {
    fn send(&self, pid: u32, signal: Signal) -> ResponseResult<()> {
        // Defense in depth: never cast an out-of-range PID to a signed pid_t.
        // kill(2) interprets 0 as the caller's own process group and any
        // negative value as a process-group broadcast (pid -1 targets every
        // process the caller may signal). A u32 above i32::MAX (e.g.
        // 4_294_967_295) would wrap to a negative pid_t and become a host-wide
        // kill(-1, ...). Only 1..=i32::MAX can name a single process; refuse the
        // rest before the cast reaches the syscall.
        if pid == 0 || pid > i32::MAX as u32 {
            return Err(ResponseError::Signal(format!(
                "refusing to signal invalid pid {pid} (must be 1..={})",
                i32::MAX
            )));
        }

        let nix_signal = match signal {
            Signal::SIGSTOP => NixSignal::SIGSTOP,
            Signal::SIGKILL => NixSignal::SIGKILL,
        };

        match kill(Pid::from_raw(pid as i32), nix_signal) {
            Ok(()) => Ok(()),
            Err(nix::errno::Errno::ESRCH) => {
                // Process already dead — treat as success (goal achieved).
                Ok(())
            }
            Err(err) => Err(ResponseError::Signal(format!(
                "send {:?} to {}: {}",
                signal, pid, err
            ))),
        }
    }
}

#[cfg(not(any(unix, target_os = "windows")))]
impl SignalSender for NixSignalSender {
    fn send(&self, pid: u32, signal: Signal) -> ResponseResult<()> {
        Err(ResponseError::Signal(format!(
            "send {:?} to {} is unsupported on this platform",
            signal, pid
        )))
    }
}

pub fn kill_process_tree(pid: u32, protected: &ProtectedList) -> ResponseResult<KillReport> {
    #[cfg(target_os = "windows")]
    {
        kill_process_tree_windows_with(pid, protected, &NativeWindowsProcessApi)
    }
    #[cfg(target_os = "macos")]
    {
        // Use snapshot-based introspector to avoid O(n*d) sysctl calls.
        let introspector = MacosProcessIntrospector::snapshot();
        kill_process_tree_with(pid, protected, &introspector, &NixSignalSender)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        kill_process_tree_with(pid, protected, &ProcfsIntrospector, &NixSignalSender)
    }
}

#[cfg(any(not(target_os = "windows"), test))]
pub fn kill_process_tree_with(
    pid: u32,
    protected: &ProtectedList,
    introspector: &dyn ProcessIntrospector,
    sender: &dyn SignalSender,
) -> ResponseResult<KillReport> {
    // Reject any value that cannot name a single, live process BEFORE it can be
    // cast to a signed pid_t downstream. On Unix, kill(2) treats 0 as the
    // caller's process group and negatives as process-group broadcasts; because
    // the signal primitive casts u32 -> i32, an out-of-range PID such as
    // 4_294_967_295 would otherwise become kill(-1, ...) and stop/kill almost
    // every process on the host. Legitimate PIDs are 1..=i32::MAX.
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(ResponseError::InvalidInput(format!(
            "pid {pid} is not a valid process id (must be 1..={})",
            i32::MAX
        )));
    }

    // Never let the agent be steered into terminating itself, even if
    // process-name resolution fails open. The local detection path guards this
    // at its caller; enforce it inside the primitive so command-driven kills
    // (which do not run that check) are covered too.
    if pid == std::process::id() {
        return Err(ResponseError::ProtectedProcess(pid));
    }

    if is_pid_protected(pid, protected, introspector) {
        return Err(ResponseError::ProtectedProcess(pid));
    }

    // Bound the blast radius BEFORE emitting any signal: enumerate the tree with
    // a hard descendant cap and fail closed if it is exceeded. This is done
    // before the SIGSTOP so an oversized tree leaves nothing frozen; for any
    // tree within the cap the emitted signal sequence is unchanged
    // (SIGSTOP root, SIGKILL children reversed, SIGKILL root). The Windows path
    // already enforces the equivalent MAX_WINDOWS_TREE_DESCENDANTS bound.
    let mut descendants = Vec::new();
    let mut seen = HashSet::new();
    let _ = seen.insert(pid);
    if !collect_descendants(
        pid,
        introspector,
        &mut descendants,
        &mut seen,
        MAX_UNIX_TREE_DESCENDANTS,
    ) {
        return Err(ResponseError::Signal(format!(
            "process tree rooted at {pid} exceeds {MAX_UNIX_TREE_DESCENDANTS} descendants; refusing mass kill"
        )));
    }

    // Re-validate the root immediately before signalling. Enumeration above can
    // issue many introspection calls on a large tree, during which the root may
    // have exited and its PID been reused (possibly by the agent itself or a
    // protected process). Re-checking self and protection here keeps the
    // check->signal window as tight as it was before enumeration was hoisted.
    // (Full start-time/pidfd identity binding is the tracked P1 follow-up.)
    if pid == std::process::id() {
        return Err(ResponseError::ProtectedProcess(pid));
    }
    if is_pid_protected(pid, protected, introspector) {
        return Err(ResponseError::ProtectedProcess(pid));
    }

    let _ = sender.send(pid, Signal::SIGSTOP);

    let mut killed = Vec::new();
    let mut skipped = Vec::new();

    for child in descendants.iter().rev() {
        if is_pid_protected(*child, protected, introspector) {
            skipped.push(*child);
            continue;
        }
        let _ = sender.send(*child, Signal::SIGKILL);
        killed.push(*child);
    }

    let _ = sender.send(pid, Signal::SIGKILL);
    killed.push(pid);

    Ok(KillReport {
        target_pid: pid,
        killed_pids: killed,
        skipped_protected_pids: skipped,
        failed_pids: Vec::new(),
    })
}

/// Hard cap on the number of descendants a single Unix kill may enumerate,
/// mirroring the Windows `MAX_WINDOWS_TREE_DESCENDANTS` bound. Prevents one
/// accepted root from walking (and signalling) an unbounded process tree.
#[cfg(any(not(target_os = "windows"), test))]
const MAX_UNIX_TREE_DESCENDANTS: usize = 4_096;

/// Breadth-first enumerate descendants of `pid` into `out`, deduplicated via
/// `seen`. Returns `false` if the `max` cap was reached (the tree is larger
/// than we are willing to signal); returns `true` when the full tree fit.
#[cfg(any(not(target_os = "windows"), test))]
fn collect_descendants(
    pid: u32,
    introspector: &dyn ProcessIntrospector,
    out: &mut Vec<u32>,
    seen: &mut HashSet<u32>,
    max: usize,
) -> bool {
    let mut queue = VecDeque::new();
    queue.push_back(pid);
    while let Some(current) = queue.pop_front() {
        for child in introspector.children_of(current) {
            if seen.insert(child) {
                if out.len() >= max {
                    return false;
                }
                out.push(child);
                queue.push_back(child);
            }
        }
    }
    true
}

#[cfg(any(not(target_os = "windows"), test))]
fn is_pid_protected(
    pid: u32,
    protected: &ProtectedList,
    introspector: &dyn ProcessIntrospector,
) -> bool {
    if pid == 1 {
        return true;
    }
    introspector
        .process_name(pid)
        .map(|name| protected.is_protected_process(&name))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests;
