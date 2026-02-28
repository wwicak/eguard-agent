use super::command_utils::{extract_server_host, resolve_allowed_server_ips};
use super::payloads::{
    format_device_action_context, parse_device_action_payload, parse_locate_payload,
    DeviceActionPayload,
};
use super::sanitize::{
    sanitize_apt_package_name, sanitize_apt_package_version, sanitize_profile_id,
};

#[cfg(any(test, target_os = "windows"))]
use super::sanitize::{sanitize_windows_package_name, sanitize_windows_package_version};

#[cfg(any(test, target_os = "macos"))]
use super::sanitize::{sanitize_macos_package_name, sanitize_macos_package_version};

#[test]
fn device_action_payload_parser_extracts_force_and_reason() {
    let payload = parse_device_action_payload(r#"{"force":true,"reason":"incident-42"}"#);
    assert!(payload.force);
    assert_eq!(payload.reason, "incident-42");
}

#[test]
fn device_action_payload_parser_defaults_on_invalid_json() {
    let payload = parse_device_action_payload("{not-json");
    assert!(!payload.force);
    assert!(payload.reason.is_empty());
}

#[test]
fn format_device_action_context_omits_empty_reason() {
    let payload = DeviceActionPayload {
        force: false,
        reason: "  ".to_string(),
    };
    assert_eq!(format_device_action_context(&payload), "force=false");
}

#[test]
fn locate_payload_parser_reads_high_accuracy_flag() {
    let payload = parse_locate_payload(r#"{"high_accuracy":true}"#);
    assert!(payload.high_accuracy);
}

#[test]
fn sanitize_profile_id_rejects_path_traversal_sequences() {
    assert!(sanitize_profile_id("../../etc/cron.d/backdoor").is_err());
    assert!(sanitize_profile_id("corp/../default").is_err());
    assert!(sanitize_profile_id("corp\\..\\default").is_err());
}

#[test]
fn sanitize_profile_id_accepts_safe_identifier() {
    let profile_id = sanitize_profile_id("corp-prod_01.v2").expect("safe profile id");
    assert_eq!(profile_id, "corp-prod_01.v2");
}

#[test]
fn sanitize_apt_package_name_rejects_option_injection_tokens() {
    assert!(sanitize_apt_package_name("pkg -o APT::Update").is_err());
    assert!(sanitize_apt_package_name("pkg;touch /tmp/x").is_err());
}

#[test]
fn sanitize_apt_package_version_rejects_option_injection_tokens() {
    assert!(sanitize_apt_package_version("1.0 -o Acquire::http::Proxy").is_err());
    assert!(sanitize_apt_package_version("1.0;rm -rf /").is_err());
}

#[test]
fn sanitize_apt_package_fields_accept_valid_values() {
    assert_eq!(
        sanitize_apt_package_name("libssl3").expect("valid package"),
        "libssl3"
    );
    assert_eq!(
        sanitize_apt_package_version("1:3.0.2-0ubuntu1~22.04.1").expect("valid version"),
        "1:3.0.2-0ubuntu1~22.04.1"
    );
}

#[test]
fn extract_server_host_parses_host_port_and_ipv6_forms() {
    assert_eq!(extract_server_host("127.0.0.1:50052"), "127.0.0.1");
    assert_eq!(extract_server_host("[2001:db8::1]:50052"), "2001:db8::1");
    assert_eq!(extract_server_host("eguard-server"), "eguard-server");
}

#[test]
fn resolve_allowed_server_ips_merges_payload_and_server_literal_ip() {
    let allowed = resolve_allowed_server_ips(
        "[2001:db8::10]:50052",
        &["203.0.113.4".to_string(), "not-an-ip".to_string()],
    );

    assert_eq!(
        allowed,
        vec!["203.0.113.4".to_string(), "2001:db8::10".to_string()]
    );
}

#[test]
fn sanitize_macos_package_fields_reject_injection_and_accept_safe_values() {
    assert!(sanitize_macos_package_name("brew;rm -rf /").is_err());
    assert!(sanitize_macos_package_version("1.0 && whoami").is_err());

    assert_eq!(
        sanitize_macos_package_name("google-chrome").expect("valid package name"),
        "google-chrome"
    );
    assert_eq!(
        sanitize_macos_package_version("124.0.2478").expect("valid package version"),
        "124.0.2478"
    );
}

#[test]
fn sanitize_windows_package_fields_reject_injection_and_accept_safe_values() {
    assert!(sanitize_windows_package_name("winget;calc").is_err());
    assert!(sanitize_windows_package_version("1.0 && whoami").is_err());

    assert_eq!(
        sanitize_windows_package_name("Microsoft.Edge").expect("valid package id"),
        "Microsoft.Edge"
    );
    assert_eq!(
        sanitize_windows_package_version("124.0.2478.67").expect("valid package version"),
        "124.0.2478.67"
    );
}
