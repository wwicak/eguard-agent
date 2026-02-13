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
// AC-RSP-006 AC-RSP-007 AC-RSP-008 AC-RSP-010 AC-RSP-011 AC-RSP-013
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
// AC-RSP-009
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

#[test]
// AC-RSP-012
fn protected_target_process_returns_error_without_signals() {
    let introspector = MockIntrospector {
        children: HashMap::new(),
        names: HashMap::from([(300, "systemd".to_string())]),
    };
    let sender = MockSignalSender::default();
    let protected = ProtectedList::default_linux();

    let err = kill_process_tree_with(300, &protected, &introspector, &sender)
        .expect_err("protected target must return an error");

    assert!(matches!(err, ResponseError::ProtectedProcess(300)));
    assert!(sender.sent.borrow().is_empty());
}

#[test]
// AC-EBP-089 AC-EBP-123
fn kill_path_latency_stays_within_fallback_budget() {
    let introspector = MockIntrospector {
        children: HashMap::from([(500, vec![501, 502]), (501, vec![503])]),
        names: HashMap::from([
            (500, "malware".to_string()),
            (501, "bash".to_string()),
            (502, "python".to_string()),
            (503, "curl".to_string()),
        ]),
    };
    let sender = MockSignalSender::default();
    let protected = ProtectedList::default_linux();

    let started = std::time::Instant::now();
    let report =
        kill_process_tree_with(500, &protected, &introspector, &sender).expect("kill tree");
    assert_eq!(report.killed_pids, vec![502, 503, 501, 500]);
    assert!(started.elapsed() < std::time::Duration::from_millis(50));
}

#[test]
// AC-RSP-084
fn pid_one_is_always_protected_even_without_process_name() {
    let introspector = MockIntrospector {
        children: HashMap::new(),
        names: HashMap::new(),
    };
    let sender = MockSignalSender::default();
    let protected = ProtectedList::default_linux();

    let err = kill_process_tree_with(1, &protected, &introspector, &sender)
        .expect_err("pid 1 must never be killed");
    assert!(matches!(err, ResponseError::ProtectedProcess(1)));
    assert!(sender.sent.borrow().is_empty());
}

#[test]
fn invalid_zero_pid_is_rejected() {
    let introspector = MockIntrospector {
        children: HashMap::new(),
        names: HashMap::new(),
    };
    let sender = MockSignalSender::default();
    let protected = ProtectedList::default_linux();

    let err = kill_process_tree_with(0, &protected, &introspector, &sender)
        .expect_err("zero pid should be rejected");
    assert!(matches!(err, ResponseError::InvalidInput(_)));
    assert!(sender.sent.borrow().is_empty());
}

#[test]
fn descendant_cycle_does_not_rekill_target_pid() {
    let introspector = MockIntrospector {
        children: HashMap::from([(700, vec![701]), (701, vec![700])]),
        names: HashMap::from([(700, "malware".to_string()), (701, "child".to_string())]),
    };
    let sender = MockSignalSender::default();
    let protected = ProtectedList::default_linux();

    let report =
        kill_process_tree_with(700, &protected, &introspector, &sender).expect("kill tree");
    assert_eq!(report.killed_pids, vec![701, 700]);
    assert_eq!(
        sender
            .sent
            .borrow()
            .iter()
            .filter(|(pid, sig)| *pid == 700 && *sig == Signal::SIGKILL)
            .count(),
        1
    );
}
