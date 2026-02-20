use std::collections::HashSet;

#[cfg(unix)]
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

#[cfg(unix)]
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
        let comm = fs::read_to_string(format!("/proc/{}/comm", pid)).ok()?;
        let name = comm.trim();
        if name.is_empty() {
            None
        } else {
            Some(name.to_string())
        }
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
    kill_process_tree_with(pid, protected, &ProcfsIntrospector, &NixSignalSender)
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
    for child in introspector.children_of(pid) {
        if !seen.insert(child) {
            continue;
        }
        out.push(child);
        collect_descendants(child, introspector, out, seen);
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
