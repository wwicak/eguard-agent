use super::*;
use std::path::{Path, PathBuf};

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
    let defaults = ResponseConfig::default();
    assert!(!defaults.autonomous_response);
    assert_eq!(
        plan_action(Confidence::Definite, &defaults),
        PlannedAction::AlertOnly
    );

    let cfg = ResponseConfig {
        autonomous_response: true,
        ..defaults
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
    assert_eq!(
        plan_action(Confidence::None, &cfg),
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

    for path in [
        "/usr/bin/ls",
        "/usr/sbin/sshd",
        "/usr/lib/libc.so",
        "/usr/libexec/openssh/sshd-session",
        "/lib/modules",
        "/boot/vmlinuz",
        "/etc/shadow",
        "/etc/fstab",
        "/usr/local/eg/agent",
        "/bin/systemctl",
        "/sbin/reboot",
        "/lib64/ld-linux-x86-64.so.2",
        "/usr/lib64/ld-linux-x86-64.so.2",
        "/usr/lib32/libc.so.6",
        "/usr/libx32/libc.so.6",
        "/root/.ssh/authorized_keys",
        "/var/lib/eguard-agent/quarantine/sample",
        "/var/lib/rpm/rpmdb.sqlite",
        "/var/lib/dnf/history.sqlite",
        "/var/lib/dpkg/status",
        "/var/lib/apt/lists/lock",
        "/var/lib/systemd/random-seed",
        "/var/lib/NetworkManager/NetworkManager.state",
        "/var/lib/dbus/machine-id",
        "/proc/1/exe",
        "/sys/kernel",
        "/dev/null",
        "/run/systemd/private",
        "/var/run/dbus/system_bus_socket",
    ] {
        assert!(
            protected.is_protected_path(Path::new(path)),
            "{path} should be protected"
        );
    }

    assert!(!protected.is_protected_path(Path::new("/tmp/sample.bin")));
    assert!(!protected.is_protected_path(Path::new("/var/tmp/sample.bin")));
    assert!(!protected.is_protected_path(Path::new("/home/user/sample.bin")));
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
#[cfg(unix)]
fn unix_protected_path_matching_remains_case_sensitive() {
    let protected = ProtectedList::default_linux();

    assert!(protected.is_protected_path(Path::new("/usr/bin/sh")));
    assert!(!protected.is_protected_path(Path::new("/USR/BIN/sh")));
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
    assert!(protected.is_protected_path(Path::new("/bin/sh")));
    assert!(protected.is_protected_path(Path::new("/sbin/mount")));
    assert!(protected.is_protected_path(Path::new("/usr/bin/ssh")));
    assert!(protected.is_protected_path(Path::new("/usr/sbin/sysctl")));
    assert!(protected.is_protected_path(Path::new("/usr/lib/dyld")));
    assert!(protected.is_protected_path(Path::new("/var/run/syslog")));
    assert!(protected.is_protected_path(Path::new("/private/var/run/syslog")));
    assert!(
        protected.is_protected_path(Path::new("/var/db/dslocal/nodes/Default/users/root.plist"))
    );
    assert!(protected.is_protected_path(Path::new(
        "/private/var/db/dslocal/nodes/Default/groups/admin.plist"
    )));
    assert!(protected.is_protected_path(Path::new("/etc/passwd")));
    assert!(protected.is_protected_path(Path::new("/Library/Keychains/System.keychain")));
    assert!(!protected.is_protected_path(Path::new(
        "/Library/LaunchDaemons/com.example.malware.plist"
    )));
    assert!(!protected.is_protected_path(Path::new("/tmp/sample.bin")));
}

// The /private<->/etc and /private/var<->/var firmlink aliasing is Unix
// path-grammar semantics (macOS/Linux). On Windows these POSIX-absolute paths
// are not valid protected roots, so this equivalence only applies on unix.
#[cfg(unix)]
#[test]
fn macos_private_path_spellings_match_protected_roots() {
    let protected = ProtectedList {
        process_patterns: Vec::new(),
        protected_paths: vec![
            PathBuf::from("/var/db/dslocal"),
            PathBuf::from("/private/etc"),
        ],
    };

    assert!(protected.is_protected_path(Path::new(
        "/private/var/db/dslocal/nodes/Default/users/root.plist"
    )));
    assert!(protected.is_protected_path(Path::new("/etc/passwd")));
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

    for path in [
        r"C:\Windows\explorer.exe",
        r"C:\Windows\System32\kernel32.dll",
        r"C:\Windows\System32\config\SAM",
        r"C:\Windows\SysWOW64\ntdll.dll",
        r"C:\Program Files\Common Files\system.dll",
        r"C:\Program Files (x86)\Common Files\system.dll",
        r"C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\key",
        r"C:\ProgramData\eGuard\agent.conf",
        r"C:\Boot\BCD",
    ] {
        assert!(
            protected.is_protected_path(Path::new(path)),
            "{path} should be protected"
        );
    }
    assert!(!protected.is_protected_path(Path::new(r"C:\Users\Public\malware.exe")));
}

#[test]
#[cfg(target_os = "windows")]
fn windows_protected_path_matching_is_case_insensitive_and_deverbatimized() {
    let protected = ProtectedList::default_windows();

    assert!(protected.is_protected_path(Path::new(r"\\?\c:\windows\system32\kernel32.dll")));
    assert!(protected.is_protected_path(Path::new(r"c:\program files\Common Files\system.dll")));
    assert_eq!(
        normalize_path(Path::new(r"\\?\UNC\server\share\folder\file.bin")),
        PathBuf::from(r"\\server\share\folder\file.bin")
    );
}

#[test]
fn default_windows_protected_processes_match_baseline() {
    let protected = ProtectedList::default_windows();
    // Bare names
    assert!(protected.is_protected_process("csrss"));
    assert!(protected.is_protected_process("lsass"));
    assert!(protected.is_protected_process("svchost"));
    assert!(protected.is_protected_process("eguard-agent"));
    assert!(protected.is_protected_process("System"));
    // .exe variants
    assert!(protected.is_protected_process("csrss.exe"));
    assert!(protected.is_protected_process("lsass.exe"));
    assert!(protected.is_protected_process("svchost.exe"));
    assert!(protected.is_protected_process("eguard-agent.exe"));
    // Windows image names are case-insensitive.
    assert!(protected.is_protected_process("CSRSS.EXE"));
    assert!(protected.is_protected_process("Csrss.Exe"));
    assert!(protected.is_protected_process("SYSTEM"));
    // Negatives
    assert!(!protected.is_protected_process("notepad"));
    assert!(!protected.is_protected_process("notepad.exe"));
}
