use super::*;

#[test]
// AC-RSP-112 AC-RSP-118 AC-RSP-119
fn parse_server_command_accepts_all_supported_literals_and_aliases() {
    assert_eq!(parse_server_command("isolate"), ServerCommand::Isolate);
    assert_eq!(parse_server_command("unisolate"), ServerCommand::Unisolate);
    assert_eq!(parse_server_command("scan"), ServerCommand::Scan);
    assert_eq!(parse_server_command("update"), ServerCommand::Update);
    assert_eq!(parse_server_command("forensics"), ServerCommand::Forensics);
    assert_eq!(
        parse_server_command("config_change"),
        ServerCommand::ConfigChange
    );
    assert_eq!(
        parse_server_command("restore_quarantine"),
        ServerCommand::RestoreQuarantine
    );
    assert_eq!(parse_server_command("uninstall"), ServerCommand::Uninstall);
    assert_eq!(
        parse_server_command("EMERGENCY_RULE_PUSH"),
        ServerCommand::EmergencyRulePush
    );
    assert_eq!(
        parse_server_command("push_emergency_rule"),
        ServerCommand::EmergencyRulePush
    );

    assert_eq!(
        parse_server_command("  emergency_rule_push  "),
        ServerCommand::EmergencyRulePush
    );
    assert_eq!(parse_server_command("unknown"), ServerCommand::Unknown);
}

#[test]
// AC-RSP-117 AC-RSP-118 AC-RSP-119
fn execute_server_commands_update_state_and_return_completed_status() {
    let mut state = HostControlState::default();

    let iso = execute_server_command_with_state(ServerCommand::Isolate, 101, &mut state);
    assert_eq!(iso.outcome, CommandOutcome::Applied);
    assert_eq!(iso.status, "completed");
    assert!(state.isolated);

    let uniso = execute_server_command_with_state(ServerCommand::Unisolate, 102, &mut state);
    assert_eq!(uniso.outcome, CommandOutcome::Applied);
    assert!(!state.isolated);

    let scan = execute_server_command_with_state(ServerCommand::Scan, 103, &mut state);
    assert_eq!(scan.status, "completed");
    assert_eq!(state.last_scan_unix, Some(103));

    let update = execute_server_command_with_state(ServerCommand::Update, 104, &mut state);
    assert_eq!(update.status, "completed");
    assert_eq!(state.last_update_unix, Some(104));

    let forensics = execute_server_command_with_state(ServerCommand::Forensics, 105, &mut state);
    assert_eq!(forensics.status, "completed");
    assert!(forensics.detail.contains("forensics snapshot"));

    let restore =
        execute_server_command_with_state(ServerCommand::RestoreQuarantine, 106, &mut state);
    assert_eq!(restore.status, "completed");
    assert!(restore.detail.contains("quarantine restore"));

    let uninstall = execute_server_command_with_state(ServerCommand::Uninstall, 107, &mut state);
    assert_eq!(uninstall.status, "completed");
    assert!(state.uninstall_requested);
}

#[test]
fn execute_server_command_unknown_maps_to_ignored_outcome() {
    assert_eq!(
        execute_server_command(ServerCommand::Unknown),
        CommandOutcome::Ignored
    );
}

#[test]
// AC-RSP-092
fn protected_process_matching_uses_regex_and_literal_exact_matching() {
    let protected = ProtectedList::default_linux();

    assert!(protected.is_protected_process("systemd"));
    assert!(protected.is_protected_process("systemd-logind"));
    assert!(protected.is_protected_process("journald"));

    // literal token "init" should not match unrelated prefixes/suffixes
    assert!(protected.is_protected_process("init"));
    assert!(!protected.is_protected_process("init-helper"));
    assert!(!protected.is_protected_process("my-init"));
}
