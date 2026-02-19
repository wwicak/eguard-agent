use super::*;

fn state(
    isolated: bool,
    last_scan_unix: Option<i64>,
    last_update_unix: Option<i64>,
    uninstall_requested: bool,
) -> HostControlState {
    HostControlState {
        isolated,
        last_scan_unix,
        last_update_unix,
        uninstall_requested,
        ..HostControlState::default()
    }
}

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
        parse_server_command("lock_device"),
        ServerCommand::LockDevice
    );
    assert_eq!(parse_server_command("wipe"), ServerCommand::WipeDevice);
    assert_eq!(parse_server_command("retire"), ServerCommand::RetireDevice);
    assert_eq!(
        parse_server_command("restart"),
        ServerCommand::RestartDevice
    );
    assert_eq!(parse_server_command("lost_mode"), ServerCommand::LostMode);
    assert_eq!(parse_server_command("locate"), ServerCommand::LocateDevice);
    assert_eq!(
        parse_server_command("install_app"),
        ServerCommand::InstallApp
    );
    assert_eq!(parse_server_command("remove_app"), ServerCommand::RemoveApp);
    assert_eq!(parse_server_command("update_app"), ServerCommand::UpdateApp);
    assert_eq!(
        parse_server_command("apply_profile"),
        ServerCommand::ApplyProfile
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
// AC-RSP-117 AC-RSP-118 AC-RSP-119
fn command_alias_table_maps_parse_and_execution_state_effects() {
    struct Case {
        raw: &'static str,
        now_unix: i64,
        initial_state: HostControlState,
        expected_command: ServerCommand,
        expected_state: HostControlState,
        expected_outcome: CommandOutcome,
        expected_status: &'static str,
        expected_detail_contains: &'static str,
    }

    let cases = [
        Case {
            raw: "isolate",
            now_unix: 100,
            initial_state: state(false, None, None, false),
            expected_command: ServerCommand::Isolate,
            expected_state: state(true, None, None, false),
            expected_outcome: CommandOutcome::Applied,
            expected_status: "completed",
            expected_detail_contains: "isolated mode",
        },
        Case {
            raw: "unisolate",
            now_unix: 101,
            initial_state: state(true, Some(7), Some(8), false),
            expected_command: ServerCommand::Unisolate,
            expected_state: state(false, Some(7), Some(8), false),
            expected_outcome: CommandOutcome::Applied,
            expected_status: "completed",
            expected_detail_contains: "isolation removed",
        },
        Case {
            raw: "scan",
            now_unix: 102,
            initial_state: state(false, Some(1), Some(8), false),
            expected_command: ServerCommand::Scan,
            expected_state: state(false, Some(102), Some(8), false),
            expected_outcome: CommandOutcome::Applied,
            expected_status: "completed",
            expected_detail_contains: "scan scheduled",
        },
        Case {
            raw: "update",
            now_unix: 103,
            initial_state: state(false, Some(1), Some(2), false),
            expected_command: ServerCommand::Update,
            expected_state: state(false, Some(1), Some(103), false),
            expected_outcome: CommandOutcome::Applied,
            expected_status: "completed",
            expected_detail_contains: "update check",
        },
        Case {
            raw: "forensics",
            now_unix: 104,
            initial_state: state(false, Some(1), Some(2), false),
            expected_command: ServerCommand::Forensics,
            expected_state: state(false, Some(1), Some(2), false),
            expected_outcome: CommandOutcome::Applied,
            expected_status: "completed",
            expected_detail_contains: "forensics snapshot",
        },
        Case {
            raw: "config_change",
            now_unix: 105,
            initial_state: state(false, Some(1), Some(2), false),
            expected_command: ServerCommand::ConfigChange,
            expected_state: state(false, Some(1), Some(2), false),
            expected_outcome: CommandOutcome::Applied,
            expected_status: "completed",
            expected_detail_contains: "configuration change",
        },
        Case {
            raw: "restore_quarantine",
            now_unix: 106,
            initial_state: state(false, Some(1), Some(2), false),
            expected_command: ServerCommand::RestoreQuarantine,
            expected_state: state(false, Some(1), Some(2), false),
            expected_outcome: CommandOutcome::Applied,
            expected_status: "completed",
            expected_detail_contains: "quarantine restore",
        },
        Case {
            raw: "uninstall",
            now_unix: 107,
            initial_state: state(false, Some(1), Some(2), false),
            expected_command: ServerCommand::Uninstall,
            expected_state: state(false, Some(1), Some(2), true),
            expected_outcome: CommandOutcome::Applied,
            expected_status: "completed",
            expected_detail_contains: "uninstall request",
        },
        Case {
            raw: "emergency_rule_push",
            now_unix: 108,
            initial_state: state(false, Some(1), Some(2), false),
            expected_command: ServerCommand::EmergencyRulePush,
            expected_state: state(false, Some(1), Some(2), false),
            expected_outcome: CommandOutcome::Applied,
            expected_status: "completed",
            expected_detail_contains: "emergency rule push",
        },
        Case {
            raw: " push_emergency_rule ",
            now_unix: 109,
            initial_state: state(false, Some(1), Some(2), false),
            expected_command: ServerCommand::EmergencyRulePush,
            expected_state: state(false, Some(1), Some(2), false),
            expected_outcome: CommandOutcome::Applied,
            expected_status: "completed",
            expected_detail_contains: "emergency rule push",
        },
    ];

    for case in cases {
        let parsed = parse_server_command(case.raw);
        assert_eq!(
            parsed, case.expected_command,
            "parsed command for {}",
            case.raw
        );

        let mut state = case.initial_state;
        let execution = execute_server_command_with_state(parsed, case.now_unix, &mut state);

        assert_eq!(
            execution.outcome, case.expected_outcome,
            "outcome for {}",
            case.raw
        );
        assert_eq!(
            execution.status, case.expected_status,
            "status for {}",
            case.raw
        );
        assert!(
            execution.detail.contains(case.expected_detail_contains),
            "detail for {} was {}",
            case.raw,
            execution.detail
        );
        assert_eq!(
            state.isolated, case.expected_state.isolated,
            "isolated mismatch for {}",
            case.raw
        );
        assert_eq!(
            state.last_scan_unix, case.expected_state.last_scan_unix,
            "last_scan_unix mismatch for {}",
            case.raw
        );
        assert_eq!(
            state.last_update_unix, case.expected_state.last_update_unix,
            "last_update_unix mismatch for {}",
            case.raw
        );
        assert_eq!(
            state.uninstall_requested, case.expected_state.uninstall_requested,
            "uninstall_requested mismatch for {}",
            case.raw
        );
    }
}

#[test]
fn execute_server_commands_update_mdm_state_fields() {
    let mut state = HostControlState::default();

    let lock = execute_server_command_with_state(ServerCommand::LockDevice, 201, &mut state);
    assert_eq!(lock.outcome, CommandOutcome::Applied);
    assert_eq!(state.last_lock_unix, Some(201));

    let wipe = execute_server_command_with_state(ServerCommand::WipeDevice, 202, &mut state);
    assert_eq!(wipe.outcome, CommandOutcome::Applied);
    assert_eq!(state.last_wipe_unix, Some(202));

    let retire = execute_server_command_with_state(ServerCommand::RetireDevice, 203, &mut state);
    assert_eq!(retire.outcome, CommandOutcome::Applied);
    assert_eq!(state.last_retire_unix, Some(203));

    let restart = execute_server_command_with_state(ServerCommand::RestartDevice, 204, &mut state);
    assert_eq!(restart.outcome, CommandOutcome::Applied);
    assert_eq!(state.last_restart_unix, Some(204));

    let lost = execute_server_command_with_state(ServerCommand::LostMode, 205, &mut state);
    assert_eq!(lost.outcome, CommandOutcome::Applied);
    assert!(state.lost_mode_enabled);

    let locate = execute_server_command_with_state(ServerCommand::LocateDevice, 206, &mut state);
    assert_eq!(locate.outcome, CommandOutcome::Applied);
    assert_eq!(state.last_locate_unix, Some(206));

    let install = execute_server_command_with_state(ServerCommand::InstallApp, 207, &mut state);
    assert_eq!(install.outcome, CommandOutcome::Applied);
    assert_eq!(state.last_app_action_unix, Some(207));

    let remove = execute_server_command_with_state(ServerCommand::RemoveApp, 208, &mut state);
    assert_eq!(remove.outcome, CommandOutcome::Applied);
    assert_eq!(state.last_app_action_unix, Some(208));

    let update = execute_server_command_with_state(ServerCommand::UpdateApp, 209, &mut state);
    assert_eq!(update.outcome, CommandOutcome::Applied);
    assert_eq!(state.last_app_action_unix, Some(209));

    let profile = execute_server_command_with_state(ServerCommand::ApplyProfile, 210, &mut state);
    assert_eq!(profile.outcome, CommandOutcome::Applied);
    assert_eq!(state.last_profile_apply_unix, Some(210));
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
