use self_protect::{
    apply_linux_hardening, capability_number, default_retained_capabilities, LinuxHardeningConfig,
    LinuxHardeningStepStatus,
};

#[test]
fn default_retained_capabilities_include_required_linux_set() {
    let retained = default_retained_capabilities();
    assert!(retained.iter().any(|name| name == "CAP_BPF"));
    assert!(retained.iter().any(|name| name == "CAP_SYS_ADMIN"));
    assert!(retained.iter().any(|name| name == "CAP_NET_ADMIN"));
    assert!(retained.iter().any(|name| name == "CAP_DAC_READ_SEARCH"));
}

#[test]
fn capability_name_mapping_is_case_insensitive_for_known_values() {
    assert_eq!(capability_number("cap_bpf"), Some(39));
    assert_eq!(capability_number("CAP_SYS_ADMIN"), Some(21));
    assert_eq!(capability_number("Cap_Net_Admin"), Some(12));
    assert_eq!(capability_number("missing"), None);
}

#[test]
fn hardening_can_be_disabled_per_step_for_non_privileged_execution_paths() {
    let config = LinuxHardeningConfig {
        set_dumpable_zero: false,
        restrict_ptrace: false,
        set_no_new_privs: false,
        drop_capability_bounding_set: false,
        retained_capability_names: default_retained_capabilities(),
        enable_seccomp_strict: false,
    };

    let report = apply_linux_hardening(&config);
    assert!(report.steps.iter().all(|step| {
        matches!(
            step.status,
            LinuxHardeningStepStatus::Skipped | LinuxHardeningStepStatus::Applied
        )
    }));
}
