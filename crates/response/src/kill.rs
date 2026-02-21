use std::collections::{HashSet, VecDeque};

#[cfg(target_os = "linux")]
use std::fs;

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
}

pub trait ProcessIntrospector {
    fn children_of(&self, pid: u32) -> Vec<u32>;
    fn process_name(&self, pid: u32) -> Option<String>;
}

pub trait SignalSender {
    fn send(&self, pid: u32, signal: Signal) -> ResponseResult<()>;
}

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
#[cfg(target_os = "macos")]
fn build_process_maps() -> (
    std::collections::HashMap<u32, Vec<u32>>,
    std::collections::HashMap<u32, String>,
) {
    use std::mem;
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
    let kinfo_size = mem::size_of::<libc::kinfo_proc>();
    let count = size / kinfo_size;
    let mut buf: Vec<libc::kinfo_proc> = vec![unsafe { mem::zeroed() }; count];

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

    for kinfo in &buf[..actual_count] {
        let ppid = kinfo.kp_eproc.e_ppid as u32;
        let pid = kinfo.kp_proc.p_pid as u32;

        if pid != ppid {
            children_map.entry(ppid).or_default().push(pid);
        }

        let comm = &kinfo.kp_proc.p_comm;
        let name: String = comm
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8 as char)
            .collect();
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
    use std::mem;
    use std::ptr;

    let mut mib: [libc::c_int; 4] = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PID,
        pid as libc::c_int,
    ];
    let mut info: libc::kinfo_proc = unsafe { mem::zeroed() };
    let mut size = mem::size_of::<libc::kinfo_proc>();

    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            4,
            &mut info as *mut _ as *mut libc::c_void,
            &mut size,
            ptr::null_mut(),
            0,
        )
    };

    if ret != 0 || size == 0 {
        return None;
    }

    let comm = &info.kp_proc.p_comm;
    let name: String = comm
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8 as char)
        .collect();

    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

#[cfg(not(unix))]
impl ProcessIntrospector for ProcfsIntrospector {
    fn children_of(&self, _pid: u32) -> Vec<u32> {
        Vec::new()
    }

    fn process_name(&self, _pid: u32) -> Option<String> {
        None
    }
}

pub struct NixSignalSender;

#[cfg(unix)]
impl SignalSender for NixSignalSender {
    fn send(&self, pid: u32, signal: Signal) -> ResponseResult<()> {
        let nix_signal = match signal {
            Signal::SIGSTOP => NixSignal::SIGSTOP,
            Signal::SIGKILL => NixSignal::SIGKILL,
        };

        kill(Pid::from_raw(pid as i32), nix_signal)
            .map_err(|err| ResponseError::Signal(format!("send {:?} to {}: {}", signal, pid, err)))
    }
}

#[cfg(not(unix))]
impl SignalSender for NixSignalSender {
    fn send(&self, pid: u32, signal: Signal) -> ResponseResult<()> {
        if matches!(signal, Signal::SIGSTOP) {
            // No portable suspend primitive in this fallback path on Windows.
            return Ok(());
        }

        let output = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .output()
            .map_err(ResponseError::Io)?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            format!("taskkill failed with status {}", output.status)
        };

        Err(ResponseError::Signal(format!(
            "send {:?} to {}: {}",
            signal, pid, detail
        )))
    }
}

pub fn kill_process_tree(pid: u32, protected: &ProtectedList) -> ResponseResult<KillReport> {
    #[cfg(target_os = "macos")]
    {
        // Use snapshot-based introspector to avoid O(n*d) sysctl calls.
        let introspector = MacosProcessIntrospector::snapshot();
        kill_process_tree_with(pid, protected, &introspector, &NixSignalSender)
    }
    #[cfg(not(target_os = "macos"))]
    {
        kill_process_tree_with(pid, protected, &ProcfsIntrospector, &NixSignalSender)
    }
}

pub fn kill_process_tree_with(
    pid: u32,
    protected: &ProtectedList,
    introspector: &dyn ProcessIntrospector,
    sender: &dyn SignalSender,
) -> ResponseResult<KillReport> {
    if pid == 0 {
        return Err(ResponseError::InvalidInput(
            "pid must be greater than zero".to_string(),
        ));
    }

    if is_pid_protected(pid, protected, introspector) {
        return Err(ResponseError::ProtectedProcess(pid));
    }

    let _ = sender.send(pid, Signal::SIGSTOP);

    let mut descendants = Vec::new();
    let mut seen = HashSet::new();
    let _ = seen.insert(pid);
    collect_descendants(pid, introspector, &mut descendants, &mut seen);

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
    })
}

fn collect_descendants(
    pid: u32,
    introspector: &dyn ProcessIntrospector,
    out: &mut Vec<u32>,
    seen: &mut HashSet<u32>,
) {
    let mut queue = VecDeque::new();
    queue.push_back(pid);
    while let Some(current) = queue.pop_front() {
        for child in introspector.children_of(current) {
            if seen.insert(child) {
                out.push(child);
                queue.push_back(child);
            }
        }
    }
}

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
