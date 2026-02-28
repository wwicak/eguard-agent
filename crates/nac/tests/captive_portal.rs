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
    assert_eq!(
        detect_install_target("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
        InstallTarget::WindowsExe
    );
    assert_eq!(
        detect_install_target("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1)"),
        InstallTarget::MacosPkg
    );

    let install = build_captive_portal_install(
        "Mozilla/5.0 (X11; Linux x86_64; Ubuntu 24.04)",
        "token-abc-123",
    );
    assert_eq!(install.target, InstallTarget::LinuxDeb);
    assert_eq!(install.install_endpoint, "/api/v1/agent-install/linux-deb");
    assert_eq!(install.enrollment_token, "token-abc-123");

    let windows_install =
        build_captive_portal_install("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "token-win-999");
    assert_eq!(windows_install.target, InstallTarget::WindowsExe);
    assert_eq!(
        windows_install.install_endpoint,
        "/api/v1/agent-install/windows-exe"
    );
    assert_eq!(windows_install.enrollment_token, "token-win-999");

    let macos_install = build_captive_portal_install(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1)",
        "token-mac-333",
    );
    assert_eq!(macos_install.target, InstallTarget::MacosPkg);
    assert_eq!(
        macos_install.install_endpoint,
        "/api/v1/agent-install/macos"
    );
    assert_eq!(macos_install.enrollment_token, "token-mac-333");
}
