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

    fn process_start_time(&self, pid: u32) -> Option<u64> {
        Some(pid as u64)
    }
}

#[derive(Default)]
struct MockSignalSender {
    sent: RefCell<Vec<(u32, Signal)>>,
    failures: Vec<(u32, Signal)>,
    esrch: Vec<(u32, Signal)>,
}

impl SignalSender for MockSignalSender {
    fn send(&self, pid: u32, signal: Signal) -> ResponseResult<()> {
        self.sent.borrow_mut().push((pid, signal));
        if self.failures.contains(&(pid, signal)) {
            Err(ResponseError::Signal(
                "programmed signal failure".to_string(),
            ))
        } else if self.esrch.contains(&(pid, signal)) {
            // Match NixSignalSender's ESRCH normalization.
            Ok(())
        } else {
            Ok(())
        }
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
    assert_eq!(report.killed_pids, vec![103, 102, 101, 100]);

    assert_eq!(
        *sender.sent.borrow(),
        vec![
            (100, Signal::SIGSTOP),
            (103, Signal::SIGKILL),
            (102, Signal::SIGKILL),
            (101, Signal::SIGKILL),
            (100, Signal::SIGKILL),
        ]
    );
}

#[test]
fn unknown_name_is_skipped_as_protected_without_signalling() {
    let introspector = MockIntrospector {
        children: HashMap::from([(400, vec![401])]),
        names: HashMap::from([(400, "malware".to_string())]),
    };
    let sender = MockSignalSender::default();

    let report =
        kill_process_tree_with(400, &ProtectedList::default_linux(), &introspector, &sender)
            .expect("identified root remains killable");

    assert_eq!(report.killed_pids, vec![400]);
    assert_eq!(report.skipped_protected_pids, vec![401]);
    assert!(report.failed_pids.is_empty());
    assert!(!sender.sent.borrow().iter().any(|(pid, _)| *pid == 401));
}

#[test]
fn changed_start_time_is_failed_without_signalling_reused_pid() {
    struct ReusedChild {
        child_start_reads: std::cell::Cell<usize>,
    }

    impl ProcessIntrospector for ReusedChild {
        fn children_of(&self, pid: u32) -> Vec<u32> {
            if pid == 410 {
                vec![411]
            } else {
                Vec::new()
            }
        }

        fn process_name(&self, _pid: u32) -> Option<String> {
            Some("malware".to_string())
        }

        fn process_start_time(&self, pid: u32) -> Option<u64> {
            if pid == 411 {
                let reads = self.child_start_reads.get();
                self.child_start_reads.set(reads + 1);
                Some(if reads == 0 { 1 } else { 2 })
            } else {
                Some(1)
            }
        }
    }

    let introspector = ReusedChild {
        child_start_reads: std::cell::Cell::new(0),
    };
    let sender = MockSignalSender::default();
    let report =
        kill_process_tree_with(410, &ProtectedList::default_linux(), &introspector, &sender)
            .expect("reused child is isolated to the failure report");

    assert_eq!(report.killed_pids, vec![410]);
    assert_eq!(report.failed_pids, vec![411]);
    assert!(!sender.sent.borrow().iter().any(|(pid, _)| *pid == 411));
}

#[test]
fn failed_sigkill_is_reported_and_stopped_root_is_continued() {
    let introspector = MockIntrospector {
        children: HashMap::new(),
        names: HashMap::from([(420, "malware".to_string())]),
    };
    let sender = MockSignalSender {
        failures: vec![(420, Signal::SIGKILL)],
        ..MockSignalSender::default()
    };

    let report =
        kill_process_tree_with(420, &ProtectedList::default_linux(), &introspector, &sender)
            .expect("signal failure is represented in the report");

    assert!(report.killed_pids.is_empty());
    assert_eq!(report.failed_pids, vec![420]);
    assert_eq!(
        *sender.sent.borrow(),
        vec![
            (420, Signal::SIGSTOP),
            (420, Signal::SIGKILL),
            (420, Signal::SIGCONT),
        ]
    );
}

#[test]
fn successful_esrch_normalization_counts_as_terminated() {
    let introspector = MockIntrospector {
        children: HashMap::new(),
        names: HashMap::from([(430, "malware".to_string())]),
    };
    let sender = MockSignalSender {
        esrch: vec![(430, Signal::SIGKILL)],
        ..MockSignalSender::default()
    };

    let report =
        kill_process_tree_with(430, &ProtectedList::default_linux(), &introspector, &sender)
            .expect("normalized ESRCH is effectively terminated");

    assert_eq!(report.killed_pids, vec![430]);
    assert!(report.failed_pids.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn linux_start_time_parser_handles_spaces_and_parentheses_and_fails_closed() {
    let stat = "123 (name with ) parens) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242 20";
    assert_eq!(parse_linux_start_time(stat), Some(4242));

    let malformed =
        "123 (name with ) parens) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 invalid 20";
    assert_eq!(parse_linux_start_time(malformed), None);
}

#[test]
fn macos_pre_signal_name_check_uses_fresh_name_after_snapshot() {
    struct SnapshotThenFreshNames {
        children: HashMap<u32, Vec<u32>>,
        snapshot_names: HashMap<u32, String>,
        fresh_names: HashMap<u32, String>,
    }

    impl ProcessIntrospector for SnapshotThenFreshNames {
        fn children_of(&self, pid: u32) -> Vec<u32> {
            self.children.get(&pid).cloned().unwrap_or_default()
        }

        fn process_name(&self, pid: u32) -> Option<String> {
            self.snapshot_names.get(&pid).cloned()
        }

        fn process_name_before_signal(&self, pid: u32) -> Option<String> {
            self.fresh_names.get(&pid).cloned()
        }

        fn process_start_time(&self, pid: u32) -> Option<u64> {
            Some(pid as u64)
        }
    }

    let root = if matches!(std::process::id(), 440 | 441) {
        442
    } else {
        440
    };
    let protected = ProtectedList::default_linux();
    let protected_root = SnapshotThenFreshNames {
        children: HashMap::new(),
        snapshot_names: HashMap::from([(root, "malware".to_string())]),
        fresh_names: HashMap::from([(root, "systemd".to_string())]),
    };
    let root_sender = MockSignalSender::default();

    let err = kill_process_tree_with(root, &protected, &protected_root, &root_sender)
        .expect_err("root that execs into a protected name must not be signalled");
    assert!(matches!(err, ResponseError::ProtectedProcess(pid) if pid == root));
    assert!(root_sender.sent.borrow().is_empty());

    let child = root + 1;
    let protected_child = SnapshotThenFreshNames {
        children: HashMap::from([(root, vec![child])]),
        snapshot_names: HashMap::from([
            (root, "malware".to_string()),
            (child, "malware".to_string()),
        ]),
        fresh_names: HashMap::from([
            (root, "malware".to_string()),
            (child, "systemd".to_string()),
        ]),
    };
    let child_sender = MockSignalSender::default();

    let report = kill_process_tree_with(root, &protected, &protected_child, &child_sender)
        .expect("descendant that execs into a protected name is skipped");
    assert_eq!(report.killed_pids, vec![root]);
    assert_eq!(report.skipped_protected_pids, vec![child]);
    assert!(!child_sender
        .sent
        .borrow()
        .iter()
        .any(|(pid, _)| *pid == child));
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
    assert_eq!(report.killed_pids, vec![503, 502, 501, 500]);
    assert!(started.elapsed() < std::time::Duration::from_millis(50));
}

#[test]
fn pid_two_is_always_protected_before_identity_resolution() {
    struct PidTwoDescendant {
        root: u32,
    }

    impl ProcessIntrospector for PidTwoDescendant {
        fn children_of(&self, pid: u32) -> Vec<u32> {
            if pid == self.root {
                vec![2]
            } else {
                Vec::new()
            }
        }

        fn process_name(&self, pid: u32) -> Option<String> {
            assert_ne!(pid, 2, "pid 2 must be protected before name lookup");
            Some("malware".to_string())
        }

        fn process_start_time(&self, pid: u32) -> Option<u64> {
            assert_ne!(pid, 2, "pid 2 must be protected before identity lookup");
            Some(pid as u64)
        }
    }

    let root = if std::process::id() == 600 { 601 } else { 600 };
    let introspector = PidTwoDescendant { root };
    let sender = MockSignalSender::default();
    let protected = ProtectedList::default_linux();

    let err = kill_process_tree_with(2, &protected, &introspector, &sender)
        .expect_err("pid 2 root must never be killed");
    assert!(matches!(err, ResponseError::ProtectedProcess(2)));

    let report = kill_process_tree_with(root, &protected, &introspector, &sender)
        .expect("pid 2 descendant is skipped");
    assert_eq!(report.skipped_protected_pids, vec![2]);
    assert_eq!(report.killed_pids, vec![root]);
    assert!(!sender.sent.borrow().iter().any(|(pid, _)| *pid == 2));
}

#[test]
fn stopped_root_is_continued_when_post_stop_identity_read_fails() {
    struct FailingRevalidation {
        start_reads: std::cell::Cell<usize>,
    }

    impl ProcessIntrospector for FailingRevalidation {
        fn children_of(&self, _pid: u32) -> Vec<u32> {
            Vec::new()
        }

        fn process_name(&self, _pid: u32) -> Option<String> {
            Some("malware".to_string())
        }

        fn process_start_time(&self, _pid: u32) -> Option<u64> {
            let reads = self.start_reads.get();
            self.start_reads.set(reads + 1);
            (reads < 2).then_some(1)
        }
    }

    let root = if std::process::id() == 620 { 621 } else { 620 };
    let introspector = FailingRevalidation {
        start_reads: std::cell::Cell::new(0),
    };
    let sender = MockSignalSender::default();
    let report = kill_process_tree_with(
        root,
        &ProtectedList::default_linux(),
        &introspector,
        &sender,
    )
    .expect("failed revalidation is reported without leaving the root stopped");

    assert!(report.killed_pids.is_empty());
    assert_eq!(report.failed_pids, vec![root]);
    assert_eq!(
        *sender.sent.borrow(),
        vec![(root, Signal::SIGSTOP), (root, Signal::SIGCONT)]
    );
}

#[test]
fn descendant_self_pid_is_skipped_before_identity_resolution() {
    struct SelfDescendant {
        root: u32,
        self_pid: u32,
    }

    impl ProcessIntrospector for SelfDescendant {
        fn children_of(&self, pid: u32) -> Vec<u32> {
            if pid == self.root {
                vec![self.self_pid]
            } else {
                Vec::new()
            }
        }

        fn process_name(&self, pid: u32) -> Option<String> {
            assert_ne!(
                pid, self.self_pid,
                "self must be skipped before name lookup"
            );
            Some("malware".to_string())
        }

        fn process_start_time(&self, pid: u32) -> Option<u64> {
            assert_ne!(
                pid, self.self_pid,
                "self must be skipped before identity lookup"
            );
            Some(pid as u64)
        }
    }

    let self_pid = std::process::id();
    let root = if self_pid == 640 { 641 } else { 640 };
    let introspector = SelfDescendant { root, self_pid };
    let sender = MockSignalSender::default();
    let report = kill_process_tree_with(
        root,
        &ProtectedList::default_linux(),
        &introspector,
        &sender,
    )
    .expect("self descendant is skipped");

    assert_eq!(report.skipped_protected_pids, vec![self_pid]);
    assert_eq!(report.killed_pids, vec![root]);
    assert!(!sender.sent.borrow().iter().any(|(pid, _)| *pid == self_pid));
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
// A u32 above i32::MAX would wrap to a negative pid_t and become kill(-1, ...),
// a host-wide broadcast. It must be rejected before any signal is attempted.
fn out_of_range_pid_is_rejected_without_signals() {
    let introspector = MockIntrospector {
        children: HashMap::new(),
        names: HashMap::new(),
    };
    let sender = MockSignalSender::default();
    let protected = ProtectedList::default_linux();

    for pid in [u32::MAX, (i32::MAX as u32) + 1, 0x8000_0000] {
        let err = kill_process_tree_with(pid, &protected, &introspector, &sender)
            .expect_err("out-of-range pid must be rejected");
        assert!(matches!(err, ResponseError::InvalidInput(_)), "pid {pid}");
    }
    assert!(
        sender.sent.borrow().is_empty(),
        "no signal may be sent for an out-of-range pid"
    );
}

#[test]
// The agent must never be steered into killing itself, even when process-name
// resolution is unavailable (introspector returns no name for this pid).
fn self_pid_is_protected_without_signals() {
    let introspector = MockIntrospector {
        children: HashMap::new(),
        names: HashMap::new(),
    };
    let sender = MockSignalSender::default();
    let protected = ProtectedList::default_linux();

    let self_pid = std::process::id();
    let err = kill_process_tree_with(self_pid, &protected, &introspector, &sender)
        .expect_err("self pid must be protected");
    assert!(matches!(err, ResponseError::ProtectedProcess(pid) if pid == self_pid));
    assert!(sender.sent.borrow().is_empty());
}

#[cfg(unix)]
#[test]
fn real_esrch_is_counted_as_gone_not_failed() {
    let pid = i32::MAX as u32;
    let introspector = MockIntrospector {
        children: HashMap::new(),
        names: HashMap::from([(pid, "malware".to_string())]),
    };

    let report = kill_process_tree_with(
        pid,
        &ProtectedList::default_linux(),
        &introspector,
        &NixSignalSender,
    )
    .expect("ESRCH for a nonexistent valid pid is effectively terminated");

    assert_eq!(report.killed_pids, vec![pid]);
    assert!(report.failed_pids.is_empty());
}

#[cfg(unix)]
#[test]
// After the fix, the real Unix sender must refuse an out-of-range pid BEFORE it
// reaches kill(2) (proving no kill(-1) broadcast is ever issued).
fn nix_signal_sender_refuses_out_of_range_pid() {
    let sender = NixSignalSender;
    for pid in [0u32, u32::MAX, (i32::MAX as u32) + 1] {
        assert!(
            sender.send(pid, Signal::SIGSTOP).is_err(),
            "sender must refuse pid {pid} before the syscall"
        );
    }
}

#[test]
// One accepted root must not be able to signal an unbounded tree: exceeding the
// descendant cap fails closed with no signal emitted at all.
fn unix_tree_exceeding_descendant_cap_is_refused_without_signals() {
    let big: Vec<u32> = (10_000u32..15_001).collect(); // 5001 direct children > cap
    let mut children = HashMap::new();
    let _ = children.insert(50u32, big.clone());
    let mut names = HashMap::from([(50u32, "malware".to_string())]);
    for child in &big {
        let _ = names.insert(*child, "child".to_string());
    }
    let introspector = MockIntrospector { children, names };
    let sender = MockSignalSender::default();
    let protected = ProtectedList::default_linux();

    let err = kill_process_tree_with(50, &protected, &introspector, &sender)
        .expect_err("oversized tree must be refused");
    assert!(matches!(err, ResponseError::Signal(_)));
    assert!(
        sender.sent.borrow().is_empty(),
        "no signal may be emitted when the tree exceeds the descendant cap"
    );
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

fn process_entry(pid: u32, parent_pid: u32, creation_time: u64) -> WindowsProcessEntry {
    WindowsProcessEntry {
        pid,
        parent_pid,
        creation_time: Some(creation_time),
    }
}

#[test]
fn snapshot_topology_deduplicates_entries_and_orders_descendants() {
    let entries = vec![
        process_entry(800, 1, 800),
        process_entry(801, 800, 801),
        process_entry(801, 800, 801),
        process_entry(802, 800, 802),
        process_entry(803, 801, 803),
    ];
    let descendants = descendants_from_snapshot(800, &entries, 10).expect("valid topology");
    assert_eq!(descendants, vec![(801, 800), (802, 800), (803, 801)]);
}

#[test]
fn snapshot_topology_fails_closed_on_cycles_caps_and_identity_ambiguity() {
    let cycle = vec![process_entry(900, 901, 900), process_entry(901, 900, 901)];
    assert!(descendants_from_snapshot(900, &cycle, 10).is_err());

    let over_cap = vec![
        process_entry(910, 1, 910),
        process_entry(911, 910, 911),
        process_entry(912, 910, 912),
        process_entry(913, 910, 913),
    ];
    assert!(descendants_from_snapshot(910, &over_cap, 2).is_err());

    let ambiguous = vec![process_entry(920, 1, 920), process_entry(920, 1, 921)];
    assert!(descendants_from_snapshot(920, &ambiguous, 10).is_err());
}

#[cfg(target_os = "windows")]
#[derive(Default)]
struct MockWindowsApi {
    snapshot: Vec<WindowsProcessEntry>,
    validation_snapshot: Option<Vec<WindowsProcessEntry>>,
    snapshot_calls: std::cell::Cell<usize>,
    handles: HashMap<u32, u64>,
    creation_times: HashMap<u64, u64>,
    names: HashMap<u64, String>,
    denied_pids: std::collections::HashSet<u32>,
    time_denied_handles: std::collections::HashSet<u64>,
    name_denied_handles: std::collections::HashSet<u64>,
    critical_handles: std::collections::HashSet<u64>,
    critical_denied_handles: std::collections::HashSet<u64>,
    opened_pids: RefCell<Vec<u32>>,
    terminated_handles: RefCell<Vec<u64>>,
}

#[cfg(target_os = "windows")]
impl WindowsProcessApi for MockWindowsApi {
    type Handle = u64;

    fn process_snapshot(&self) -> ResponseResult<Vec<WindowsProcessEntry>> {
        let call = self.snapshot_calls.get();
        self.snapshot_calls.set(call + 1);
        Ok(if call > 0 {
            self.validation_snapshot
                .as_ref()
                .unwrap_or(&self.snapshot)
                .clone()
        } else {
            self.snapshot.clone()
        })
    }

    fn open_process(&self, pid: u32) -> ResponseResult<Self::Handle> {
        self.opened_pids.borrow_mut().push(pid);
        if self.denied_pids.contains(&pid) {
            return Err(ResponseError::Signal(format!("access denied for {pid}")));
        }
        self.handles
            .get(&pid)
            .copied()
            .ok_or_else(|| ResponseError::Signal(format!("unknown pid {pid}")))
    }

    fn process_creation_time(&self, handle: &Self::Handle) -> ResponseResult<u64> {
        if self.time_denied_handles.contains(handle) {
            return Err(ResponseError::Signal("time query denied".to_string()));
        }
        Ok(self.creation_times.get(handle).copied().unwrap_or(*handle))
    }

    fn process_name(&self, handle: &Self::Handle) -> ResponseResult<String> {
        if self.name_denied_handles.contains(handle) {
            return Err(ResponseError::Signal("image query denied".to_string()));
        }
        self.names
            .get(handle)
            .cloned()
            .ok_or_else(|| ResponseError::Signal("unknown image name".to_string()))
    }

    fn is_process_critical(&self, handle: &Self::Handle) -> ResponseResult<bool> {
        if self.critical_denied_handles.contains(handle) {
            return Err(ResponseError::Signal("critical query denied".to_string()));
        }
        Ok(self.critical_handles.contains(handle))
    }

    fn terminate_process(&self, handle: &Self::Handle) -> ResponseResult<()> {
        self.terminated_handles.borrow_mut().push(*handle);
        Ok(())
    }
}

#[cfg(target_os = "windows")]
#[test]
fn windows_os_critical_descendant_is_never_terminated() {
    // A descendant whose image name is NOT on the static list but which the OS
    // reports as critical must be skipped, while the non-critical root dies.
    let api = MockWindowsApi {
        snapshot: vec![
            process_entry(1700, 1, 5700),
            process_entry(1701, 1700, 5701),
        ],
        handles: HashMap::from([(1700, 5700), (1701, 5701)]),
        names: HashMap::from([
            (5700, "malware.exe".to_string()),
            (5701, "totally-not-critical.exe".to_string()),
        ]),
        critical_handles: std::collections::HashSet::from([5701]),
        ..MockWindowsApi::default()
    };

    let report = kill_process_tree_windows_with(1700, &ProtectedList::default_windows(), &api)
        .expect("root terminates while OS-critical child is skipped");
    assert_eq!(report.killed_pids, vec![1700]);
    assert_eq!(report.skipped_protected_pids, vec![1701]);
    assert_eq!(*api.terminated_handles.borrow(), vec![5700]);
}

#[cfg(target_os = "windows")]
#[test]
fn windows_failed_critical_query_on_root_fails_closed() {
    // If the OS critical query errors on the root, treat it as critical.
    let api = MockWindowsApi {
        handles: HashMap::from([(1800, 5800)]),
        names: HashMap::from([(5800, "malware.exe".to_string())]),
        critical_denied_handles: std::collections::HashSet::from([5800]),
        ..MockWindowsApi::default()
    };

    let err = kill_process_tree_windows_with(1800, &ProtectedList::default_windows(), &api)
        .expect_err("a failed critical query must fail closed");
    assert!(matches!(err, ResponseError::ProtectedProcess(1800)));
    assert!(api.terminated_handles.borrow().is_empty());
}

#[cfg(target_os = "windows")]
#[test]
fn windows_mixed_case_protected_target_is_never_terminated() {
    let api = MockWindowsApi {
        handles: HashMap::from([(1000, 5000)]),
        names: HashMap::from([(5000, "CSRSS.EXE".to_string())]),
        ..MockWindowsApi::default()
    };

    let err = kill_process_tree_windows_with(1000, &ProtectedList::default_windows(), &api)
        .expect_err("mixed-case protected image must fail closed");
    assert!(matches!(err, ResponseError::ProtectedProcess(1000)));
    assert!(api.terminated_handles.borrow().is_empty());
}

#[cfg(target_os = "windows")]
#[test]
fn windows_access_denied_and_unknown_identity_fail_closed() {
    let root_denied = MockWindowsApi {
        denied_pids: std::collections::HashSet::from([1100]),
        ..MockWindowsApi::default()
    };
    assert!(
        kill_process_tree_windows_with(1100, &ProtectedList::default_windows(), &root_denied)
            .is_err()
    );
    assert!(root_denied.terminated_handles.borrow().is_empty());

    // The root PID must not equal this test process's own id:
    // windows_pid_is_always_protected() treats pid == std::process::id() as protected,
    // and a hardcoded 1200 collides with the test-runner PID on some CI hosts (the
    // child PID never reaches that self-guard). The two branches are mutually
    // exclusive, so root_pid != std::process::id() deterministically.
    let root_pid = if std::process::id() == 1200 {
        1216
    } else {
        1200
    };
    let child_pid = root_pid + 1;
    let child_unknown = MockWindowsApi {
        snapshot: vec![
            process_entry(root_pid, 1, 5200),
            process_entry(child_pid, root_pid, 5201),
        ],
        handles: HashMap::from([(root_pid, 5200), (child_pid, 5201)]),
        names: HashMap::from([(5200, "malware.exe".to_string())]),
        ..MockWindowsApi::default()
    };
    let report =
        kill_process_tree_windows_with(root_pid, &ProtectedList::default_windows(), &child_unknown)
            .expect("unknown child is skipped while identified root is terminated");
    assert_eq!(report.killed_pids, vec![root_pid]);
    assert_eq!(report.failed_pids, vec![child_pid]);
    assert_eq!(*child_unknown.terminated_handles.borrow(), vec![5200]);
}

#[cfg(target_os = "windows")]
#[test]
fn windows_no_child_termination_uses_the_identified_handle() {
    let api = MockWindowsApi {
        snapshot: vec![process_entry(1300, 1, 0xfeed)],
        handles: HashMap::from([(1300, 0xfeed)]),
        names: HashMap::from([(0xfeed, "payload.exe".to_string())]),
        ..MockWindowsApi::default()
    };
    let report = kill_process_tree_windows_with(1300, &ProtectedList::default_windows(), &api)
        .expect("terminate root-only tree");

    assert_eq!(report.killed_pids, vec![1300]);
    assert!(report.failed_pids.is_empty());
    assert_eq!(*api.opened_pids.borrow(), vec![1300]);
    assert_eq!(*api.terminated_handles.borrow(), vec![0xfeed]);
}

#[cfg(target_os = "windows")]
#[test]
fn windows_changed_parent_snapshot_is_not_terminated() {
    let api = MockWindowsApi {
        snapshot: vec![
            process_entry(1400, 1, 5400),
            process_entry(1401, 1400, 5401),
        ],
        validation_snapshot: Some(vec![
            process_entry(1400, 1, 5400),
            process_entry(1401, 9999, 5401),
        ]),
        handles: HashMap::from([(1400, 5400), (1401, 5401)]),
        names: HashMap::from([
            (5400, "payload.exe".to_string()),
            (5401, "reused.exe".to_string()),
        ]),
        ..MockWindowsApi::default()
    };
    let report = kill_process_tree_windows_with(1400, &ProtectedList::default_windows(), &api)
        .expect("stale child snapshot should be skipped");

    assert_eq!(report.killed_pids, vec![1400]);
    assert_eq!(report.failed_pids, vec![1401]);
    assert_eq!(*api.terminated_handles.borrow(), vec![5400]);
}

#[cfg(target_os = "windows")]
#[test]
fn windows_root_first_snapshot_identity_mismatch_fails_closed() {
    let api = MockWindowsApi {
        snapshot: vec![process_entry(1450, 1, 99)],
        handles: HashMap::from([(1450, 5450)]),
        creation_times: HashMap::from([(5450, 100)]),
        names: HashMap::from([(5450, "payload.exe".to_string())]),
        ..MockWindowsApi::default()
    };

    assert!(kill_process_tree_windows_with(1450, &ProtectedList::default_windows(), &api).is_err());
    assert!(api.terminated_handles.borrow().is_empty());
}

#[cfg(target_os = "windows")]
#[test]
fn windows_creation_time_mismatch_is_not_terminated() {
    let api = MockWindowsApi {
        snapshot: vec![process_entry(1500, 1, 100), process_entry(1501, 1500, 200)],
        handles: HashMap::from([(1500, 5500), (1501, 5501)]),
        creation_times: HashMap::from([(5500, 100), (5501, 201)]),
        names: HashMap::from([
            (5500, "payload.exe".to_string()),
            (5501, "reused.exe".to_string()),
        ]),
        ..MockWindowsApi::default()
    };
    let report = kill_process_tree_windows_with(1500, &ProtectedList::default_windows(), &api)
        .expect("reused child identity should be skipped");

    assert_eq!(report.killed_pids, vec![1500]);
    assert_eq!(report.failed_pids, vec![1501]);
    assert_eq!(*api.terminated_handles.borrow(), vec![5500]);
}

#[cfg(target_os = "windows")]
#[test]
fn windows_child_older_than_parent_is_not_terminated() {
    let api = MockWindowsApi {
        snapshot: vec![process_entry(1600, 1, 300), process_entry(1601, 1600, 200)],
        handles: HashMap::from([(1600, 5600), (1601, 5601)]),
        creation_times: HashMap::from([(5600, 300), (5601, 200)]),
        names: HashMap::from([
            (5600, "payload.exe".to_string()),
            (5601, "stale-child.exe".to_string()),
        ]),
        ..MockWindowsApi::default()
    };
    let report = kill_process_tree_windows_with(1600, &ProtectedList::default_windows(), &api)
        .expect("impossible child age should be skipped");

    assert_eq!(report.killed_pids, vec![1600]);
    assert_eq!(report.failed_pids, vec![1601]);
    assert_eq!(*api.terminated_handles.borrow(), vec![5600]);
}

#[cfg(target_os = "windows")]
#[test]
fn windows_unreadable_creation_time_is_not_terminated() {
    let api = MockWindowsApi {
        snapshot: vec![process_entry(1700, 1, 100), process_entry(1701, 1700, 200)],
        handles: HashMap::from([(1700, 5700), (1701, 5701)]),
        creation_times: HashMap::from([(5700, 100)]),
        names: HashMap::from([
            (5700, "payload.exe".to_string()),
            (5701, "unknown.exe".to_string()),
        ]),
        time_denied_handles: std::collections::HashSet::from([5701]),
        ..MockWindowsApi::default()
    };
    let report = kill_process_tree_windows_with(1700, &ProtectedList::default_windows(), &api)
        .expect("unreadable child creation time should be skipped");

    assert_eq!(report.killed_pids, vec![1700]);
    assert_eq!(report.failed_pids, vec![1701]);
    assert_eq!(*api.terminated_handles.borrow(), vec![5700]);
}

#[cfg(target_os = "linux")]
#[test]
fn procfs_introspector_prefers_proc_exe_basename_when_available() {
    let introspector = ProcfsIntrospector;
    let expected = std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|s| s.to_string())
        })
        .expect("current executable basename");

    let observed = introspector
        .process_name(std::process::id())
        .expect("process name from procfs");

    assert_eq!(observed, expected);
}
