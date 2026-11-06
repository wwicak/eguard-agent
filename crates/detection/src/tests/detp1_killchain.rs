use super::*;

fn reverse_shell_engine() -> Layer4Engine {
    let mut engine = Layer4Engine::new(300);
    let mut stage = TemplatePredicate {
        process_any_of: Some(crate::util::set_of(["sh"])),
        uid_eq: None,
        uid_ne: None,
        require_network_non_web: false,
        require_module_loaded: false,
        require_sensitive_file_access: false,
        require_ransomware_write_burst: false,
        require_container_escape: false,
        require_privileged_container: false,
        require_ptrace_activity: false,
        require_userfaultfd_activity: false,
        require_execveat_activity: false,
        require_proc_mem_access: false,
        require_fileless_exec: false,
        ..Default::default()
    };
    let first = stage.clone();
    stage.process_any_of = None;
    stage.require_network_non_web = true;
    engine.add_template(KillChainTemplate {
        name: "killchain_reverse_shell".into(),
        stages: vec![first, stage],
        max_depth: 4,
        max_inter_stage_secs: 10,
    });
    engine
}

fn shell(ts: i64) -> TelemetryEvent {
    let mut e = event(ts, EventClass::ProcessExec, "sh", "service", 1000);
    e.pid = 10;
    e.ppid = 1;
    e
}

fn child(ts: i64, class: EventClass) -> TelemetryEvent {
    let mut e = event(ts, class, "python3", "sh", 1000);
    e.pid = 11;
    e.ppid = 10;
    if class == EventClass::NetworkConnect {
        e.dst_ip = Some("198.51.100.7".into());
        e.dst_port = Some(4444);
    }
    e
}

#[test]
fn detp1_killchain_fires_once_on_connection_not_imports_and_rearms_on_exec() {
    let mut engine = reverse_shell_engine();
    engine.observe(&shell(1));
    engine.observe(&child(2, EventClass::ProcessExec));
    let mut firings = engine.observe(&child(3, EventClass::NetworkConnect)).len();
    for i in 0..10 {
        let mut read = child(4, EventClass::FileOpen);
        read.file_path = Some(format!("/usr/lib/python3/module_{i}.py"));
        firings += engine.observe(&read).len();
    }
    firings += engine.observe(&child(5, EventClass::NetworkConnect)).len();
    assert_eq!(
        firings, 1,
        "one terminal transition per template/process instance/window"
    );
    engine.observe(&child(6, EventClass::ProcessExec));
    assert_eq!(
        engine.observe(&child(7, EventClass::NetworkConnect)).len(),
        1
    );
}

#[test]
fn detp1_killchain_rejects_stale_stage_despite_recent_file_activity() {
    let mut engine = reverse_shell_engine();
    engine.observe(&shell(1));
    engine.observe(&child(2, EventClass::ProcessExec));
    let mut read = shell(100);
    read.event_class = EventClass::FileOpen;
    engine.observe(&read);
    assert!(engine
        .observe(&child(101, EventClass::NetworkConnect))
        .is_empty());
}

#[test]
fn detp1_killchain_does_not_refire_a_sibling_chain_on_new_child_activity() {
    let mut engine = reverse_shell_engine();
    engine.observe(&shell(1));
    engine.observe(&child(2, EventClass::ProcessExec));
    assert_eq!(
        engine.observe(&child(3, EventClass::NetworkConnect)).len(),
        1
    );
    let mut sibling = child(4, EventClass::FileOpen);
    sibling.pid = 12;
    assert!(engine.observe(&sibling).is_empty());
    sibling.event_class = EventClass::NetworkConnect;
    sibling.dst_ip = Some("198.51.100.7".into());
    sibling.dst_port = Some(4444);
    assert_eq!(engine.observe(&sibling).len(), 1);
}

#[test]
fn rafix_old_parent_recent_child_uses_child_exec_as_network_window_anchor() {
    let mut engine = reverse_shell_engine();
    engine.observe(&shell(1));
    engine.observe(&child(200, EventClass::ProcessExec));
    assert_eq!(engine.observe(&child(201, EventClass::NetworkConnect)).len(), 1);
}

#[test]
fn rafix_killchain_walks_bounded_descendants_not_just_direct_children() {
    let mut engine = reverse_shell_engine();
    engine.observe(&shell(1));
    let mut intermediate = child(2, EventClass::ProcessExec);
    intermediate.process = "supervisor".into();
    engine.observe(&intermediate);
    let mut terminal = child(3, EventClass::NetworkConnect);
    terminal.pid = 12;
    terminal.ppid = 11;
    assert_eq!(engine.observe(&terminal).len(), 1);
}
