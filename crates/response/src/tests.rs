use super::*;
use std::path::Path;

#[test]
// AC-RSP-117
fn isolate_and_unisolate_change_state() {
    let mut state = HostControlState::default();

    let iso = execute_server_command_with_state(ServerCommand::Isolate, 1, &mut state);
    assert_eq!(iso.status, "completed");
    assert!(state.isolated);

    let uniso = execute_server_command_with_state(ServerCommand::Unisolate, 2, &mut state);
    assert_eq!(uniso.status, "completed");
    assert!(!state.isolated);
}

#[test]
fn unknown_command_is_failed() {
    let mut state = HostControlState::default();
    let result = execute_server_command_with_state(ServerCommand::Unknown, 3, &mut state);
    assert_eq!(result.outcome, CommandOutcome::Ignored);
    assert_eq!(result.status, "failed");
}

#[test]
// AC-RSP-110 AC-DET-162
fn emergency_rule_push_is_recognized() {
    let cmd = parse_server_command("emergency_rule_push");
    assert_eq!(cmd, ServerCommand::EmergencyRulePush);

    let mut state = HostControlState::default();
    let result = execute_server_command_with_state(cmd, 4, &mut state);
    assert_eq!(result.outcome, CommandOutcome::Applied);
    assert_eq!(result.status, "completed");
}

#[test]
// AC-RSP-001 AC-RSP-002 AC-RSP-003 AC-RSP-004 AC-RSP-049 AC-RSP-050 AC-RSP-101 AC-DET-066 AC-DET-067 AC-DET-068 AC-DET-069 AC-DET-070 AC-DET-071 AC-DET-092
fn default_policy_gates_autonomous_actions_by_confidence() {
    let mut cfg = ResponseConfig {
        autonomous_response: true,
        ..ResponseConfig::default()
    };

    assert_eq!(
        plan_action(Confidence::Definite, &cfg),
        PlannedAction::KillAndQuarantine
    );
    assert_eq!(
        plan_action(Confidence::VeryHigh, &cfg),
        PlannedAction::KillAndQuarantine
    );
    assert_eq!(
        plan_action(Confidence::High, &cfg),
        PlannedAction::CaptureScript
    );
    assert_eq!(
        plan_action(Confidence::Medium, &cfg),
        PlannedAction::AlertOnly
    );
    assert_eq!(plan_action(Confidence::Low, &cfg), PlannedAction::AlertOnly);

    cfg.autonomous_response = false;
    assert_eq!(
        plan_action(Confidence::Definite, &cfg),
        PlannedAction::AlertOnly
    );
}

#[test]
// AC-RSP-102 AC-RSP-103
fn dry_run_forces_alert_only() {
    let cfg = ResponseConfig {
        autonomous_response: true,
        dry_run: true,
        ..ResponseConfig::default()
    };

    assert_eq!(
        plan_action(Confidence::Definite, &cfg),
        PlannedAction::AlertOnly
    );
    assert_eq!(
        plan_action(Confidence::VeryHigh, &cfg),
        PlannedAction::AlertOnly
    );
}

#[test]
// AC-RSP-033 AC-RSP-094 AC-CFG-016
fn default_linux_protected_paths_match_acceptance_baseline() {
    let protected = ProtectedList::default_linux();

    assert!(protected.is_protected_path(Path::new("/usr/bin/ls")));
    assert!(protected.is_protected_path(Path::new("/usr/sbin/sshd")));
    assert!(protected.is_protected_path(Path::new("/usr/lib/libc.so")));
    assert!(protected.is_protected_path(Path::new("/lib/modules")));
    assert!(protected.is_protected_path(Path::new("/boot/vmlinuz")));
    assert!(protected.is_protected_path(Path::new("/usr/local/eg/agent")));
    assert!(!protected.is_protected_path(Path::new("/tmp/sample.bin")));
}

#[test]
// AC-RSP-033 AC-RSP-094
fn protected_paths_reject_parent_directory_escape_sequences() {
    let protected = ProtectedList::default_linux();

    assert!(!protected.is_protected_path(Path::new("/usr/local/eg/../tmp/malware.bin")));
    assert!(!protected.is_protected_path(Path::new("/usr/bin/../../opt/custom/dropper.sh")));
}

#[test]
// AC-RSP-033
fn protected_paths_accept_normalized_equivalents_inside_roots() {
    let protected = ProtectedList::default_linux();

    assert!(protected.is_protected_path(Path::new("/usr/local/eg/./agent")));
    assert!(protected.is_protected_path(Path::new("/usr/local/eg/runtime/../agentd")));
    assert!(protected.is_protected_path(Path::new("/usr/bin/./sh")));
}

#[test]
// AC-RSP-085 AC-RSP-086 AC-RSP-087 AC-RSP-088 AC-RSP-089 AC-RSP-090 AC-RSP-091 AC-RSP-092 AC-CFG-015
fn default_linux_protected_processes_match_acceptance_baseline() {
    let protected = ProtectedList::default_linux();
    assert!(protected.is_protected_process("init"));
    assert!(protected.is_protected_process("sshd"));
    assert!(protected.is_protected_process("systemd"));
    assert!(protected.is_protected_process("systemd-journald"));
    assert!(protected.is_protected_process("dbus-daemon"));
    assert!(protected.is_protected_process("journald"));
    assert!(protected.is_protected_process("eguard-agent"));
    assert!(protected.is_protected_process("containerd"));
    assert!(protected.is_protected_process("dockerd"));
    assert!(!protected.is_protected_process("python3"));
}

#[test]
// AC-RSP-080 AC-RSP-082
fn kill_rate_limiter_enforces_limit_and_expires_window() {
    let mut limiter = KillRateLimiter::new(2);
    let t0 = Instant::now();
    assert!(limiter.allow(t0));
    assert!(limiter.allow(t0 + Duration::from_secs(1)));
    assert!(!limiter.allow(t0 + Duration::from_secs(2)));
    assert!(limiter.allow(t0 + Duration::from_secs(61)));
}

#[test]
// AC-RSP-082 AC-TST-026 AC-VER-040
fn kill_rate_limiter_respects_default_rate_limit_window() {
    let max_per_minute = ResponseConfig::default().max_kills_per_minute;
    let mut limiter = KillRateLimiter::new(max_per_minute);
    let t0 = Instant::now();

    for i in 0..max_per_minute {
        assert!(limiter.allow(t0 + Duration::from_secs(i as u64)));
    }
    assert!(!limiter.allow(t0 + Duration::from_secs(59)));
    assert!(limiter.allow(t0 + Duration::from_secs(61)));
}

#[test]
fn scan_update_and_uninstall_commands_update_state() {
    let mut state = HostControlState::default();

    let scan = execute_server_command_with_state(ServerCommand::Scan, 123, &mut state);
    assert_eq!(scan.outcome, CommandOutcome::Applied);
    assert_eq!(state.last_scan_unix, Some(123));

    let update = execute_server_command_with_state(ServerCommand::Update, 456, &mut state);
    assert_eq!(update.outcome, CommandOutcome::Applied);
    assert_eq!(state.last_update_unix, Some(456));

    let uninstall = execute_server_command_with_state(ServerCommand::Uninstall, 789, &mut state);
    assert_eq!(uninstall.outcome, CommandOutcome::Applied);
    assert!(state.uninstall_requested);
}

#[test]
// AC-RSP-124 AC-RSP-126
fn auto_isolation_is_disabled_by_default() {
    let cfg = ResponseConfig::default();
    let mut state = AutoIsolationState::default();

    assert!(!cfg.auto_isolation.enabled);
    assert!(!evaluate_auto_isolation(
        Confidence::Definite,
        1_700_000_000,
        &cfg,
        &mut state,
    ));
}

#[test]
// AC-RSP-124 AC-RSP-125
fn auto_isolation_triggers_after_window_threshold_and_respects_hourly_cap() {
    let mut cfg = ResponseConfig {
        autonomous_response: true,
        ..ResponseConfig::default()
    };
    cfg.auto_isolation.enabled = true;
    cfg.auto_isolation.min_incidents_in_window = 3;
    cfg.auto_isolation.window_secs = 60;
    cfg.auto_isolation.max_isolations_per_hour = 1;

    let mut state = AutoIsolationState::default();

    assert!(!evaluate_auto_isolation(
        Confidence::VeryHigh,
        1_700_000_000,
        &cfg,
        &mut state,
    ));
    assert!(!evaluate_auto_isolation(
        Confidence::Definite,
        1_700_000_020,
        &cfg,
        &mut state,
    ));
    assert!(evaluate_auto_isolation(
        Confidence::VeryHigh,
        1_700_000_040,
        &cfg,
        &mut state,
    ));

    // Hourly cap reached.
    assert!(!evaluate_auto_isolation(
        Confidence::Definite,
        1_700_000_050,
        &cfg,
        &mut state,
    ));
    assert!(!evaluate_auto_isolation(
        Confidence::VeryHigh,
        1_700_000_060,
        &cfg,
        &mut state,
    ));
    assert!(!evaluate_auto_isolation(
        Confidence::Definite,
        1_700_000_070,
        &cfg,
        &mut state,
    ));

    // After one hour the cap window expires and a new threshold burst can isolate again.
    assert!(!evaluate_auto_isolation(
        Confidence::VeryHigh,
        1_700_003_700,
        &cfg,
        &mut state,
    ));
    assert!(!evaluate_auto_isolation(
        Confidence::Definite,
        1_700_003_710,
        &cfg,
        &mut state,
    ));
    assert!(evaluate_auto_isolation(
        Confidence::VeryHigh,
        1_700_003_720,
        &cfg,
        &mut state,
    ));
}

#[test]
// AC-RSP-124
fn auto_isolation_ignores_high_and_lower_confidence_events() {
    let mut cfg = ResponseConfig {
        autonomous_response: true,
        ..ResponseConfig::default()
    };
    cfg.auto_isolation.enabled = true;
    cfg.auto_isolation.min_incidents_in_window = 2;
    cfg.auto_isolation.window_secs = 120;
    cfg.auto_isolation.max_isolations_per_hour = 3;

    let mut state = AutoIsolationState::default();
    assert!(!evaluate_auto_isolation(
        Confidence::High,
        1_700_000_000,
        &cfg,
        &mut state,
    ));
    assert!(!evaluate_auto_isolation(
        Confidence::Medium,
        1_700_000_020,
        &cfg,
        &mut state,
    ));
    assert!(!evaluate_auto_isolation(
        Confidence::Low,
        1_700_000_030,
        &cfg,
        &mut state,
    ));

    // Two qualifying events still trigger as expected.
    assert!(!evaluate_auto_isolation(
        Confidence::VeryHigh,
        1_700_000_050,
        &cfg,
        &mut state,
    ));
    assert!(evaluate_auto_isolation(
        Confidence::Definite,
        1_700_000_060,
        &cfg,
        &mut state,
    ));
}

#[test]
fn default_macos_protected_paths_match_baseline() {
    let protected = ProtectedList::default_macos();

    assert!(protected.is_protected_path(Path::new("/System/Library/Frameworks")));
    assert!(protected.is_protected_path(Path::new("/Library/Application Support/eGuard")));
    assert!(protected.is_protected_path(Path::new("/usr/bin/ssh")));
    assert!(protected.is_protected_path(Path::new("/usr/sbin/sysctl")));
    assert!(protected.is_protected_path(Path::new("/usr/lib/dyld")));
    assert!(!protected.is_protected_path(Path::new("/tmp/sample.bin")));
}

#[test]
fn default_macos_protected_processes_match_baseline() {
    let protected = ProtectedList::default_macos();
    assert!(protected.is_protected_process("launchd"));
    assert!(protected.is_protected_process("kernel_task"));
    assert!(protected.is_protected_process("eguard-agent"));
    assert!(protected.is_protected_process("sshd"));
    assert!(protected.is_protected_process("WindowServer"));
    assert!(!protected.is_protected_process("python3"));
}

#[test]
#[cfg(target_os = "windows")]
fn default_windows_protected_paths_match_baseline() {
    let protected = ProtectedList::default_windows();

    assert!(protected.is_protected_path(Path::new(r"C:\Windows\System32\kernel32.dll")));
    assert!(protected.is_protected_path(Path::new(r"C:\Windows\SysWOW64\ntdll.dll")));
    assert!(protected.is_protected_path(Path::new(r"C:\ProgramData\eGuard\agent.conf")));
    assert!(!protected.is_protected_path(Path::new(r"C:\Users\Public\malware.exe")));
}

#[test]
fn default_windows_protected_processes_match_baseline() {
    let protected = ProtectedList::default_windows();
    assert!(protected.is_protected_process("csrss"));
    assert!(protected.is_protected_process("lsass"));
    assert!(protected.is_protected_process("svchost"));
    assert!(protected.is_protected_process("eguard-agent"));
    assert!(protected.is_protected_process("System"));
    assert!(!protected.is_protected_process("notepad"));
}
