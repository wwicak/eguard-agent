use super::*;

fn snapshot_base(firewall_enabled: bool, kernel_version: &str) -> SystemSnapshot {
    SystemSnapshot::minimal(firewall_enabled, kernel_version)
}

#[test]
// AC-CMP-014 AC-CMP-015 AC-CMP-016
fn parse_policy_json_handles_extended_fields() {
    let raw = r#"{
            "firewall_required": true,
            "min_kernel_prefix": "6.",
            "os_version_prefix": "Ubuntu",
            "disk_encryption_required": true,
            "require_ssh_root_login_disabled": true,
            "required_packages": ["auditd"],
            "forbidden_packages": ["telnetd"]
        }"#;

    let policy = parse_policy_json(raw).expect("parse policy");
    assert!(policy.firewall_required);
    assert_eq!(policy.min_kernel_prefix.as_deref(), Some("6."));
    assert_eq!(policy.os_version_prefix.as_deref(), Some("Ubuntu"));
    assert!(policy.disk_encryption_required);
    assert!(policy.require_ssh_root_login_disabled);
    assert_eq!(policy.required_packages, vec!["auditd"]);
    assert_eq!(policy.forbidden_packages, vec!["telnetd"]);
}

#[test]
// AC-CMP-004 AC-CMP-005 AC-CMP-006 AC-CMP-030
fn evaluate_snapshot_reports_package_and_kernel_failures() {
    let policy = CompliancePolicy {
        firewall_required: true,
        min_kernel_prefix: Some("6.8".to_string()),
        required_packages: vec!["auditd".to_string()],
        forbidden_packages: vec!["telnetd".to_string()],
        ..CompliancePolicy::default()
    };

    let mut installed = HashSet::new();
    installed.insert("telnetd".to_string());

    let mut snapshot = snapshot_base(false, "6.1.0");
    snapshot.os_version = Some("Ubuntu 22.04".to_string());
    snapshot.root_fs_encrypted = Some(true);
    snapshot.ssh_root_login_permitted = Some(false);
    snapshot.installed_packages = Some(installed);

    let result = evaluate_snapshot(&policy, &snapshot);
    assert_eq!(result.status, "non_compliant");
    assert!(result.checks.iter().any(|check| {
        check.check_type == "firewall_required" && check.status == "non_compliant"
    }));
    assert!(result.checks.iter().any(|check| {
        check.check_type.starts_with("package_absent:") && check.status == "non_compliant"
    }));
}

#[test]
// AC-CMP-005
fn parse_dpkg_status_extracts_installed_packages() {
    let path = std::env::temp_dir().join(format!(
        "eguard-dpkg-status-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    fs::write(
            &path,
            "Package: auditd\nStatus: install ok installed\n\nPackage: telnetd\nStatus: purge ok not-installed\n",
        )
        .expect("write status file");

    let installed = parse_dpkg_status(path.to_string_lossy().as_ref()).expect("parse dpkg");
    assert!(installed.contains("auditd"));
    assert!(!installed.contains("telnetd"));

    let _ = fs::remove_file(path);
}

#[test]
// AC-CMP-020 AC-CMP-021 AC-CMP-023
fn plan_remediation_actions_covers_firewall_and_packages() {
    let policy = CompliancePolicy {
        firewall_required: true,
        required_packages: vec!["auditd".to_string()],
        forbidden_packages: vec!["telnetd".to_string()],
        ..CompliancePolicy::default()
    };

    let mut installed = HashSet::new();
    installed.insert("telnetd".to_string());

    let mut snapshot = snapshot_base(false, "6.8.0");
    snapshot.installed_packages = Some(installed);

    let actions = plan_remediation_actions(&policy, &snapshot);
    assert!(actions.iter().any(|a| a.action_id == "enable_firewall"));
    assert!(actions
        .iter()
        .any(|a| a.action_id == "install_package:auditd"));
    assert!(actions
        .iter()
        .any(|a| a.action_id == "remove_package:telnetd"));
}

#[test]
// AC-CMP-019
fn execute_remediation_actions_reports_failures() {
    #[derive(Default)]
    struct MockRunner;

    impl CommandRunner for MockRunner {
        fn run(&self, command: &str, _args: &[String]) -> std::io::Result<()> {
            if command == "ok" {
                Ok(())
            } else {
                Err(std::io::Error::other("boom"))
            }
        }
    }

    let actions = vec![
        RemediationAction {
            action_id: "a1".to_string(),
            command: "ok".to_string(),
            args: Vec::new(),
            reason: "test".to_string(),
            allowlist_id: String::new(),
            mode: String::new(),
        },
        RemediationAction {
            action_id: "a2".to_string(),
            command: "fail".to_string(),
            args: Vec::new(),
            reason: "test".to_string(),
            allowlist_id: String::new(),
            mode: String::new(),
        },
    ];

    let outcomes = execute_remediation_actions(&MockRunner, &actions);
    assert_eq!(outcomes.len(), 2);
    assert!(outcomes[0].success);
    assert!(!outcomes[1].success);
}

#[test]
// AC-CMP-014
fn parse_policy_json_rejects_invalid_input() {
    let err = parse_policy_json("{not-json").expect_err("invalid policy should fail");
    assert!(matches!(err, ComplianceError::PolicyParse(_)));
}

#[test]
// AC-CMP-001 AC-CMP-002 AC-CMP-026 AC-CMP-031
fn evaluate_snapshot_passes_when_all_checks_succeed() {
    let policy = CompliancePolicy {
        firewall_required: true,
        min_kernel_prefix: Some("6.8".to_string()),
        os_version_prefix: Some("Ubuntu".to_string()),
        disk_encryption_required: true,
        require_ssh_root_login_disabled: true,
        required_packages: vec!["auditd".to_string()],
        forbidden_packages: vec!["telnetd".to_string()],
        ..CompliancePolicy::default()
    };

    let mut installed = HashSet::new();
    installed.insert("auditd".to_string());

    let mut snapshot = snapshot_base(true, "6.8.12");
    snapshot.os_version = Some("Ubuntu 24.04".to_string());
    snapshot.root_fs_encrypted = Some(true);
    snapshot.ssh_root_login_permitted = Some(false);
    snapshot.installed_packages = Some(installed);

    let result = evaluate_snapshot(&policy, &snapshot);
    assert_eq!(result.status, "compliant");
    assert!(result.checks.iter().all(|c| c.status == "compliant"));
}

#[test]
// AC-CMP-028 AC-CMP-029
fn package_checks_are_case_insensitive() {
    let policy = CompliancePolicy {
        required_packages: vec!["AuditD".to_string()],
        forbidden_packages: vec!["TelNetD".to_string()],
        ..CompliancePolicy::default()
    };

    let mut installed = HashSet::new();
    installed.insert("auditd".to_string());
    installed.insert("telnetd".to_string());

    let mut snapshot = snapshot_base(true, "6.8.0");
    snapshot.installed_packages = Some(installed);

    let result = evaluate_snapshot(&policy, &snapshot);
    assert!(result.checks.iter().any(|c| {
        c.check_type == "package_present:AuditD" && c.status == "compliant"
    }));
    assert!(result.checks.iter().any(|c| {
        c.check_type == "package_absent:TelNetD" && c.status == "non_compliant"
    }));
}

#[test]
// AC-CMP-022
fn remediation_plan_includes_disabling_ssh_root_login() {
    let policy = CompliancePolicy {
        require_ssh_root_login_disabled: true,
        ..CompliancePolicy::default()
    };

    let mut snapshot = snapshot_base(true, "6.8.0");
    snapshot.os_version = Some("Ubuntu".to_string());
    snapshot.root_fs_encrypted = Some(true);
    snapshot.ssh_root_login_permitted = Some(true);

    let actions = plan_remediation_actions(&policy, &snapshot);
    assert!(actions
        .iter()
        .any(|a| a.action_id == "disable_ssh_root_login"));
}

#[test]
// AC-CMP-024
fn missing_probe_values_fail_strict_checks() {
    let policy = CompliancePolicy {
        disk_encryption_required: true,
        require_ssh_root_login_disabled: true,
        ..CompliancePolicy::default()
    };
    let snapshot = SystemSnapshot::minimal(true, "6.8.0");

    let result = evaluate_snapshot(&policy, &snapshot);
    assert_eq!(result.status, "non_compliant");
    assert!(result
        .checks
        .iter()
        .any(|c| c.check_type == "disk_encryption" && c.status == "non_compliant"));
    assert!(result
        .checks
        .iter()
        .any(|c| c.check_type == "ssh_root_login" && c.status == "non_compliant"));
}

#[test]
// AC-CMP-003
fn parse_root_fs_encrypted_from_mounts_detects_mapper_and_plain_devices() {
    let encrypted = "/dev/mapper/ubuntu--vg-root / ext4 rw,relatime 0 0\n";
    assert_eq!(parse_root_fs_encrypted_from_mounts(encrypted), Some(true));

    let luks_named = "/dev/nvme0n1p3_crypt / ext4 rw,relatime 0 0\n";
    assert_eq!(parse_root_fs_encrypted_from_mounts(luks_named), Some(true));

    let plain = "/dev/sda2 / ext4 rw,relatime 0 0\n";
    assert_eq!(parse_root_fs_encrypted_from_mounts(plain), Some(false));
}

#[test]
// AC-CMP-010
fn parse_ssh_root_login_from_config_honors_explicit_directive() {
    let allowed = r#"
# comment
PermitRootLogin yes
"#;
    assert_eq!(parse_ssh_root_login_from_config(allowed), Some(true));

    let disallowed = "PermitRootLogin no\n";
    assert_eq!(parse_ssh_root_login_from_config(disallowed), Some(false));

    let default_when_missing = "# no directive\n";
    assert_eq!(
        parse_ssh_root_login_from_config(default_when_missing),
        Some(false)
    );
}

#[test]
// AC-CMP-007
fn required_services_check_fails_when_service_not_running() {
    let policy = CompliancePolicy {
        required_services: vec!["sshd".to_string()],
        ..CompliancePolicy::default()
    };
    let mut snapshot = snapshot_base(true, "6.8.0");
    let mut services = HashSet::new();
    services.insert("cron".to_string());
    snapshot.running_services = Some(services);

    let result = evaluate_snapshot(&policy, &snapshot);
    assert!(result
        .checks
        .iter()
        .any(|c| c.check_type == "service_running:sshd" && c.status == "non_compliant"));
}

#[test]
// AC-CMP-008
fn password_policy_check_uses_hardened_probe_flag() {
    let policy = CompliancePolicy {
        password_policy_required: true,
        ..CompliancePolicy::default()
    };
    let mut snapshot = snapshot_base(true, "6.8.0");
    snapshot.password_policy_hardened = Some(true);

    let result = evaluate_snapshot(&policy, &snapshot);
    assert!(result
        .checks
        .iter()
        .any(|c| c.check_type == "password_policy" && c.status == "compliant"));
}

#[test]
// AC-CMP-009
fn screen_lock_check_uses_probe_flag() {
    let policy = CompliancePolicy {
        screen_lock_required: true,
        ..CompliancePolicy::default()
    };
    let mut snapshot = snapshot_base(true, "6.8.0");
    snapshot.screen_lock_enabled = Some(false);

    let result = evaluate_snapshot(&policy, &snapshot);
    assert!(result
        .checks
        .iter()
        .any(|c| c.check_type == "screen_lock_enabled" && c.status == "non_compliant"));
}

#[test]
// AC-CMP-011
fn auto_updates_check_uses_probe_flag() {
    let policy = CompliancePolicy {
        auto_updates_required: true,
        ..CompliancePolicy::default()
    };
    let mut snapshot = snapshot_base(true, "6.8.0");
    snapshot.auto_updates_enabled = Some(true);

    let result = evaluate_snapshot(&policy, &snapshot);
    assert!(result
        .checks
        .iter()
        .any(|c| c.check_type == "auto_updates" && c.status == "compliant"));
}

#[test]
// AC-CMP-012
fn agent_version_is_reported_from_package_metadata() {
    assert!(!current_agent_version().trim().is_empty());
}

#[test]
// AC-CMP-013
fn antivirus_check_uses_probe_flag() {
    let policy = CompliancePolicy {
        antivirus_required: true,
        ..CompliancePolicy::default()
    };
    let mut snapshot = snapshot_base(true, "6.8.0");
    snapshot.antivirus_running = Some(false);

    let result = evaluate_snapshot(&policy, &snapshot);
    assert!(result
        .checks
        .iter()
        .any(|c| c.check_type == "antivirus_running" && c.status == "non_compliant"));
}

#[test]
// AC-CMP-017 AC-CMP-018 AC-CMP-019
fn parse_policy_json_supports_runtime_timing_controls() {
    let policy = parse_policy_json(
        r#"{
            "check_interval_secs": 300,
            "grace_period_secs": 3600,
            "auto_remediate": false
        }"#,
    )
    .expect("parse policy timing");

    assert_eq!(policy.check_interval_secs, Some(300));
    assert_eq!(policy.grace_period_secs, Some(3600));
    assert_eq!(policy.auto_remediate, Some(false));
}

#[test]
// AC-CMP-025
fn os_version_gte_check_compares_numeric_prefix() {
    let policy = CompliancePolicy {
        min_os_version: Some("22.04".to_string()),
        ..CompliancePolicy::default()
    };
    let mut snapshot = snapshot_base(true, "6.8.0");
    snapshot.os_version = Some("Ubuntu 24.04.1 LTS".to_string());

    let result = evaluate_snapshot(&policy, &snapshot);
    assert!(result
        .checks
        .iter()
        .any(|c| c.check_type == "os_version_gte" && c.status == "compliant"));
}

#[test]
// AC-CMP-027
fn firewall_required_check_maps_to_expected_fail_and_remediation() {
    let policy = CompliancePolicy {
        firewall_required: true,
        ..CompliancePolicy::default()
    };
    let snapshot = snapshot_base(false, "6.8.0");
    let result = evaluate_snapshot(&policy, &snapshot);
    assert!(result
        .checks
        .iter()
        .any(|c| c.check_type == "firewall_required" && c.status == "non_compliant"));

    let actions = plan_remediation_actions(&policy, &snapshot);
    assert!(actions.iter().any(|a| a.action_id == "enable_firewall"));
}

#[test]
// AC-CMP-033 AC-GRP-036
fn default_runtime_settings_match_documented_values() {
    let (interval, auto_remediate) = default_runtime_settings();
    assert_eq!(interval, 300);
    assert!(!auto_remediate);
}

#[test]
// AC-CMP-007
fn parse_running_services_output_extracts_service_names() {
    let raw = "sshd.service loaded active running OpenSSH Daemon\ncron.service loaded active running Regular background program processing daemon\n";
    let parsed = parse_running_services_output(raw).expect("parse services");
    assert!(parsed.contains("sshd"));
    assert!(parsed.contains("cron"));
}

#[test]
// AC-CMP-008
fn parse_password_policy_requires_max_days_and_quality_module() {
    let login_defs = "PASS_MAX_DAYS 90\n";
    let pam = "password requisite pam_pwquality.so retry=3 minlen=12\n";
    assert_eq!(
        parse_password_policy(Some(login_defs), Some(pam)),
        Some(true)
    );

    let weak_login_defs = "PASS_MAX_DAYS 365\n";
    assert_eq!(
        parse_password_policy(Some(weak_login_defs), Some(pam)),
        Some(false)
    );
}
