use baseline::{BaselineStatus, BaselineStore};
use compliance::{
    evaluate_snapshot, parse_policy_json, plan_remediation_actions, CompliancePolicy,
    SystemSnapshot,
};
use detection::{confidence_policy, tau_delta, Confidence, DetectionSignals};
use grpc_client::{RetryPolicy, TransportMode, DEFAULT_BUFFER_CAP_BYTES};
use nac::{posture_from_compliance, Posture};
use platform_linux::platform_name;
use response::{plan_action, PlannedAction, ProtectedList, ResponseConfig};

#[test]
// AC-DET-060 AC-DET-061 AC-DET-062 AC-DET-063 AC-DET-064 AC-DET-065
fn ac_det_confidence_policy_matrix_executable() {
    let mut s = DetectionSignals {
        z1_exact_ioc: false,
        yara_hit: false,
        z2_temporal: false,
        z3_anomaly_high: false,
        z3_anomaly_med: false,
        z4_kill_chain: false,
        l1_prefilter_hit: false,
        exploit_indicator: false,
        kernel_integrity: false,
        tamper_indicator: false,
        ..Default::default()
    };

    s.z1_exact_ioc = true;
    assert_eq!(confidence_policy(&s), Confidence::Definite);

    s = DetectionSignals {
        z1_exact_ioc: false,
        yara_hit: false,
        z2_temporal: true,
        z3_anomaly_high: false,
        z3_anomaly_med: false,
        z4_kill_chain: false,
        l1_prefilter_hit: true,
        exploit_indicator: false,
        kernel_integrity: false,
        tamper_indicator: false,
        ..Default::default()
    };
    assert_eq!(confidence_policy(&s), Confidence::VeryHigh);

    s = DetectionSignals {
        z1_exact_ioc: false,
        yara_hit: false,
        z2_temporal: true,
        z3_anomaly_high: false,
        z3_anomaly_med: false,
        z4_kill_chain: false,
        l1_prefilter_hit: false,
        exploit_indicator: false,
        kernel_integrity: false,
        tamper_indicator: false,
        ..Default::default()
    };
    assert_eq!(confidence_policy(&s), Confidence::High);

    s = DetectionSignals {
        z1_exact_ioc: false,
        yara_hit: false,
        z2_temporal: false,
        z3_anomaly_high: true,
        z3_anomaly_med: false,
        z4_kill_chain: false,
        l1_prefilter_hit: false,
        exploit_indicator: false,
        kernel_integrity: false,
        tamper_indicator: false,
        ..Default::default()
    };
    assert_eq!(confidence_policy(&s), Confidence::Medium);

    s = DetectionSignals {
        z1_exact_ioc: false,
        yara_hit: false,
        z2_temporal: false,
        z3_anomaly_high: false,
        z3_anomaly_med: true,
        z4_kill_chain: false,
        l1_prefilter_hit: false,
        exploit_indicator: false,
        kernel_integrity: false,
        tamper_indicator: false,
        ..Default::default()
    };
    assert_eq!(confidence_policy(&s), Confidence::Low);
}

#[test]
// AC-DET-038
fn ac_det_tau_delta_reference_value_executable() {
    let tau = tau_delta(512, 12, 1e-6).expect("tau_delta");
    assert!((tau - 0.25).abs() < 0.03);
}

#[test]
// AC-RSP-001 AC-RSP-002 AC-RSP-003 AC-RSP-004 AC-RSP-100 AC-RSP-101 AC-RSP-102 AC-RSP-103
fn ac_rsp_policy_and_gating_executable() {
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

    cfg.autonomous_response = false;
    assert_eq!(
        plan_action(Confidence::Definite, &cfg),
        PlannedAction::AlertOnly
    );

    let dry = ResponseConfig {
        autonomous_response: true,
        dry_run: true,
        ..ResponseConfig::default()
    };
    assert_eq!(
        plan_action(Confidence::Definite, &dry),
        PlannedAction::AlertOnly
    );
}

#[test]
// AC-RSP-085 AC-RSP-086 AC-RSP-087 AC-RSP-088 AC-RSP-089 AC-RSP-090 AC-RSP-091 AC-RSP-092 AC-RSP-033
fn ac_rsp_protected_defaults_executable() {
    let protected = ProtectedList::default_linux();

    assert!(protected.is_protected_process("sshd"));
    assert!(protected.is_protected_process("systemd-journald"));
    assert!(protected.is_protected_process("dbus-daemon"));
    assert!(protected.is_protected_process("eguard-agent"));
    assert!(protected.is_protected_process("containerd"));
    assert!(protected.is_protected_process("dockerd"));
    assert!(!protected.is_protected_process("python3"));

    assert!(protected.is_protected_path(std::path::Path::new("/usr/bin/ls")));
    assert!(protected.is_protected_path(std::path::Path::new("/usr/sbin/sshd")));
    assert!(protected.is_protected_path(std::path::Path::new("/usr/lib/libc.so")));
    assert!(protected.is_protected_path(std::path::Path::new("/lib/modules")));
    assert!(protected.is_protected_path(std::path::Path::new("/boot/vmlinuz")));
    assert!(protected.is_protected_path(std::path::Path::new("/usr/local/eg/agent")));
}

#[test]
// AC-GRP-080
fn ac_grp_retry_policy_backoff_executable() {
    let policy = RetryPolicy::default();
    assert!(policy.next_delay(0).as_millis() > 0);
    assert!(policy.next_delay(99) <= policy.max_backoff);
}

#[test]
// AC-GRP-082 AC-EBP-044 AC-CFG-020
fn ac_grp_offline_buffer_cap_executable() {
    assert_eq!(DEFAULT_BUFFER_CAP_BYTES, 100 * 1024 * 1024);
}

#[test]
// AC-GRP-090
fn ac_grp_transport_mode_parse_executable() {
    assert!(matches!(TransportMode::parse("grpc"), TransportMode::Grpc));
    assert!(matches!(TransportMode::parse("tonic"), TransportMode::Grpc));
    assert!(matches!(TransportMode::parse("http"), TransportMode::Http));
}

#[test]
// AC-CMP-014 AC-CMP-015 AC-CMP-016
fn ac_cmp_policy_parse_executable() {
    let policy = parse_policy_json(
        r#"{
            "firewall_required": true,
            "required_packages": ["auditd"],
            "forbidden_packages": ["telnetd"]
        }"#,
    )
    .expect("parse policy");

    assert!(policy.firewall_required);
    assert_eq!(policy.required_packages, vec!["auditd"]);
    assert_eq!(policy.forbidden_packages, vec!["telnetd"]);
}

#[test]
// AC-CMP-004 AC-CMP-005 AC-CMP-006 AC-CMP-020 AC-CMP-021 AC-CMP-024
fn ac_cmp_eval_and_remediation_executable() {
    let policy = CompliancePolicy {
        firewall_required: true,
        required_packages: vec!["auditd".to_string()],
        forbidden_packages: vec!["telnetd".to_string()],
        ..CompliancePolicy::default()
    };

    let mut installed = std::collections::HashSet::new();
    installed.insert("telnetd".to_string());

    let mut snapshot = SystemSnapshot::minimal(false, "6.8.0");
    snapshot.os_version = Some("Ubuntu 24.04".to_string());
    snapshot.root_fs_encrypted = Some(true);
    snapshot.ssh_root_login_permitted = Some(false);
    snapshot.installed_packages = Some(installed);

    let result = evaluate_snapshot(&policy, &snapshot);
    assert!(
        result.status == "non_compliant" || result.status == "fail",
        "unexpected compliance status: {}",
        result.status
    );

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
// AC-NAC-005 AC-NAC-006 AC-NAC-007 AC-NAC-008
fn ac_nac_posture_mapping_executable() {
    assert_eq!(posture_from_compliance("pass"), Posture::Compliant);
    assert_eq!(posture_from_compliance("compliant"), Posture::Compliant);
    assert_eq!(posture_from_compliance("fail"), Posture::NonCompliant);
    assert_eq!(
        posture_from_compliance("non_compliant"),
        Posture::NonCompliant
    );
    assert_eq!(posture_from_compliance("unknown"), Posture::Unknown);
}

#[test]
// AC-EBP-022
fn ac_ebp_platform_identity_executable() {
    assert_eq!(platform_name(), "linux");
}

#[test]
// AC-BSL-004 AC-BSL-005 AC-BSL-039
fn ac_bsl_state_transitions_executable() {
    let path = std::env::temp_dir().join(format!(
        "eguard-ac-bsl-{}.bin",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let mut store = BaselineStore::new(&path).expect("new store");
    let t_learn_done = store.learning_started_unix + 7 * 24 * 3600 + 1;
    let learn_transition = store.check_transition_with_now(t_learn_done);
    assert_eq!(
        learn_transition,
        Some(baseline::BaselineTransition::LearningComplete)
    );
    assert_eq!(store.status, BaselineStatus::Active);

    store.last_refresh_unix = 0;
    let stale_transition = store.check_transition_with_now(30 * 24 * 3600 + 1);
    assert_eq!(
        stale_transition,
        Some(baseline::BaselineTransition::BecameStale)
    );
    assert_eq!(store.status, BaselineStatus::Stale);

    let _ = std::fs::remove_file(path);
}
