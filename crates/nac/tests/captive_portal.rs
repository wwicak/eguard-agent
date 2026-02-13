use nac::{build_captive_portal_install, detect_install_target, InstallTarget};

#[test]
// AC-NAC-002
fn captive_portal_auto_detects_os_and_preserves_enrollment_token() {
    assert_eq!(
        detect_install_target("Mozilla/5.0 (X11; Linux x86_64; Ubuntu 24.04)"),
        InstallTarget::LinuxDeb
    );
    assert_eq!(
        detect_install_target("Mozilla/5.0 (X11; Linux x86_64; Fedora 41)"),
        InstallTarget::LinuxRpm
    );

    let install = build_captive_portal_install(
        "Mozilla/5.0 (X11; Linux x86_64; Ubuntu 24.04)",
        "token-abc-123",
    );
    assert_eq!(install.target, InstallTarget::LinuxDeb);
    assert_eq!(install.install_endpoint, "/api/v1/agent-install/linux-deb");
    assert_eq!(install.enrollment_token, "token-abc-123");
}
