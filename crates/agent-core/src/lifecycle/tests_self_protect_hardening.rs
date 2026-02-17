use super::*;
use crate::config::AgentConfig;
use ::self_protect::{
    apply_linux_hardening, capability_number, default_retained_capabilities, LinuxHardeningConfig,
    LinuxHardeningStepStatus,
};

#[test]
fn hardening_with_all_controls_disabled_reports_skipped_steps_without_failures() {
    let config = LinuxHardeningConfig {
        set_dumpable_zero: false,
        restrict_ptrace: false,
        set_no_new_privs: false,
        drop_capability_bounding_set: false,
        retained_capability_names: default_retained_capabilities(),
        enable_seccomp_strict: false,
    };
    let report = apply_linux_hardening(&config);

    #[cfg(target_os = "linux")]
    {
        assert_eq!(report.steps.len(), 5);
        assert!(!report.has_failures());
        assert_eq!(report.dropped_capability_count, 0);
        assert!(report
            .steps
            .iter()
            .all(|step| step.status == LinuxHardeningStepStatus::Skipped));
    }

    #[cfg(not(target_os = "linux"))]
    {
        assert_eq!(report.steps.len(), 1);
        assert_eq!(report.steps[0].name, "platform");
        assert_eq!(report.steps[0].status, LinuxHardeningStepStatus::Skipped);
    }
}

#[test]
fn unknown_retained_capability_name_surfaces_failure_in_drop_caps_step() {
    let config = LinuxHardeningConfig {
        set_dumpable_zero: false,
        restrict_ptrace: false,
        set_no_new_privs: false,
        drop_capability_bounding_set: true,
        retained_capability_names: vec!["CAP_FAKE_123".to_string()],
        enable_seccomp_strict: false,
    };
    let report = apply_linux_hardening(&config);

    #[cfg(target_os = "linux")]
    {
        assert!(report.has_failures());
        assert!(report
            .failed_step_names()
            .contains(&"capability_bounding_set"));
        let step = report
            .steps
            .iter()
            .find(|s| s.name == "capability_bounding_set")
            .expect("capability step present");
        assert_eq!(step.status, LinuxHardeningStepStatus::Failed);
        assert_eq!(
            step.detail,
            "unknown retained capability names: CAP_FAKE_123"
        );
    }

    #[cfg(not(target_os = "linux"))]
    {
        assert_eq!(report.steps[0].name, "platform");
        assert_eq!(report.steps[0].status, LinuxHardeningStepStatus::Skipped);
    }
}

#[test]
fn default_retained_capabilities_resolve_to_known_numeric_ids() {
    let retained = default_retained_capabilities();
    assert!(!retained.is_empty());
    for cap in retained {
        assert!(
            capability_number(&cap).is_some(),
            "unknown capability: {cap}"
        );
    }
}

#[test]
fn runtime_initialization_succeeds_with_uninstall_protection_on_and_off() {
    let mut cfg_disabled = AgentConfig::default();
    cfg_disabled.offline_buffer_backend = "memory".to_string();
    cfg_disabled.self_protection_prevent_uninstall = false;
    let runtime_disabled = AgentRuntime::new(cfg_disabled).expect("runtime with protection off");
    assert!(!runtime_disabled.is_forced_degraded());

    let mut cfg_enabled = AgentConfig::default();
    cfg_enabled.offline_buffer_backend = "memory".to_string();
    cfg_enabled.self_protection_prevent_uninstall = true;
    let runtime_enabled = AgentRuntime::new(cfg_enabled).expect("runtime with protection on");
    assert!(!runtime_enabled.is_forced_degraded());
}
