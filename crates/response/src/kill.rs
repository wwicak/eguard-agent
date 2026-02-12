use std::collections::HashSet;
use std::fs;

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

use crate::errors::{ResponseError, ResponseResult};
use crate::ProtectedList;

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

pub struct NixSignalSender;

impl SignalSender for NixSignalSender {
    fn send(&self, pid: u32, signal: Signal) -> ResponseResult<()> {
        kill(Pid::from_raw(pid as i32), signal)
            .map_err(|err| ResponseError::Signal(format!("send {:?} to {}: {}", signal, pid, err)))
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
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;

    use super::*;

    struct MockIntrospector {
        children: HashMap<u32, Vec<u32>>,
        names: HashMap<u32, String>,
    }

    impl ProcessIntrospector for MockIntrospector {
        fn children_of(&self, pid: u32) -> Vec<u32> {
            self.children.get(&pid).cloned().unwrap_or_default()
        }

        fn process_name(&self, pid: u32) -> Option<String> {
            self.names.get(&pid).cloned()
        }
    }

    #[derive(Default)]
    struct MockSignalSender {
        sent: RefCell<Vec<(u32, Signal)>>,
    }

    impl SignalSender for MockSignalSender {
        fn send(&self, pid: u32, signal: Signal) -> ResponseResult<()> {
            self.sent.borrow_mut().push((pid, signal));
            Ok(())
        }
    }

    #[test]
    fn kill_process_tree_orders_children_before_parent() {
        let introspector = MockIntrospector {
            children: HashMap::from([(100, vec![101, 102]), (101, vec![103])]),
            names: HashMap::from([
                (100, "malware".to_string()),
                (101, "bash".to_string()),
                (102, "python".to_string()),
                (103, "curl".to_string()),
            ]),
        };
        let sender = MockSignalSender::default();
        let protected = ProtectedList::default_linux();

        let report =
            kill_process_tree_with(100, &protected, &introspector, &sender).expect("kill tree");
        assert_eq!(report.target_pid, 100);
        assert_eq!(report.killed_pids, vec![102, 103, 101, 100]);

        let sent = sender.sent.borrow();
        assert_eq!(sent.first(), Some(&(100, Signal::SIGSTOP)));
        assert_eq!(sent.last(), Some(&(100, Signal::SIGKILL)));
    }

    #[test]
    fn protected_processes_are_skipped() {
        let introspector = MockIntrospector {
            children: HashMap::from([(200, vec![201])]),
            names: HashMap::from([(200, "malware".to_string()), (201, "systemd".to_string())]),
        };
        let sender = MockSignalSender::default();
        let protected = ProtectedList::default_linux();

        let report =
            kill_process_tree_with(200, &protected, &introspector, &sender).expect("kill tree");
        assert_eq!(report.skipped_protected_pids, vec![201]);
        assert_eq!(report.killed_pids, vec![200]);
    }
}
