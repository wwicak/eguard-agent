use response::ServerCommand;

use super::command_utils::{extract_server_host, resolve_allowed_server_ips};
use super::payloads::{
    format_device_action_context, parse_device_action_payload, parse_locate_payload,
    parse_update_payload, DeviceActionPayload, ForensicsPayload,
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
        true,
    );

    assert_eq!(
        allowed,
        vec!["203.0.113.4".to_string(), "2001:db8::10".to_string()]
    );
}

#[test]
fn resolve_allowed_server_ips_respects_allow_server_connection_flag() {
    let allowed = resolve_allowed_server_ips(
        "103.132.18.221:50053",
        &["192.168.122.25".to_string()],
        false,
    );

    assert_eq!(allowed, vec!["192.168.122.25".to_string()]);
}

#[test]
fn reconcile_isolation_state_restores_previous_value_on_failed_isolate() {
    let reconciled = super::reconcile_isolation_state_after_command(
        ServerCommand::Isolate,
        false,
        "failed",
        true,
    );
    assert!(!reconciled);
}

#[test]
fn reconcile_isolation_state_restores_previous_value_on_failed_unisolate() {
    let reconciled = super::reconcile_isolation_state_after_command(
        ServerCommand::Unisolate,
        true,
        "failed",
        false,
    );
    assert!(reconciled);
}

#[test]
fn reconcile_isolation_state_keeps_successful_transition() {
    let reconciled = super::reconcile_isolation_state_after_command(
        ServerCommand::Isolate,
        false,
        "completed",
        true,
    );
    assert!(reconciled);
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

#[test]
fn forensics_payload_merges_legacy_pid_and_target_pids() {
    let payload: ForensicsPayload =
        serde_json::from_str(r#"{"pid":123,"target_pids":[456,123,0],"memory_dump":true}"#)
            .expect("valid payload");

    assert!(payload.memory_dump);
    assert_eq!(payload.effective_target_pids(), vec![456, 123]);
}

#[test]
fn forensics_payload_defaults_to_snapshot_when_flags_missing() {
    let payload: ForensicsPayload = serde_json::from_str("{}").expect("valid empty payload");

    assert!(!payload.memory_dump);
    assert!(!payload.wants_snapshot());
    assert!(payload.effective_target_pids().is_empty());
}

#[test]
fn update_payload_parser_supports_grpc_alias_fields() {
    let payload = parse_update_payload(
        r#"{"target_version":"0.2.11","download_url":"https://example.local/eguard-agent_0.2.11_amd64.deb","checksum":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#,
    );

    assert_eq!(payload.version, "0.2.11");
    assert_eq!(
        payload.package_url,
        "https://example.local/eguard-agent_0.2.11_amd64.deb"
    );
    assert_eq!(
        payload.checksum_sha256,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    );
}

#[test]
fn update_payload_parser_supports_rest_fields() {
    let payload = parse_update_payload(
        r#"{"version":"0.2.11","package_url":"https://example.local/eguard-agent.exe","checksum_sha256":"feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface","package_format":"exe"}"#,
    );

    assert_eq!(payload.version, "0.2.11");
    assert_eq!(
        payload.package_url,
        "https://example.local/eguard-agent.exe"
    );
    assert_eq!(
        payload.checksum_sha256,
        "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface"
    );
    assert_eq!(payload.package_format, "exe");
}

// --- P0-2: server kill_process command must honor the same safety boundary as
// local detections (self-guard + shared rate limiter) and bound its blast
// radius (target-vector ceiling). ---

fn kill_command_runtime(max_kills_per_minute: usize) -> super::AgentRuntime {
    let mut cfg = crate::config::AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();
    cfg.self_protection_integrity_check_interval_secs = 0;
    cfg.response.max_kills_per_minute = max_kills_per_minute;
    cfg.response.max_quarantines_per_minute = 1;
    let mut runtime = super::AgentRuntime::new(cfg).expect("runtime");
    let path = std::env::temp_dir().join(format!(
        "eguard-command-breaker-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    runtime.breaker = crate::lifecycle::circuit_breaker::CircuitBreaker::load_from_path(
        path,
        crate::lifecycle::circuit_breaker::BREAKER_MAX_BLAST_UNITS,
    );
    runtime
}

fn fresh_kill_exec() -> response::CommandExecution {
    response::CommandExecution {
        outcome: response::CommandOutcome::Applied,
        status: "completed",
        detail: String::new(),
    }
}

#[test]
fn command_pipeline_circuit_breaker_denies_wipe_and_remove_app() {
    let mut runtime = kill_command_runtime(1);
    let now = crate::lifecycle::now_unix().max(0) as u64;
    runtime.breaker.check_and_charge(
        crate::lifecycle::circuit_breaker::DestructiveKind::Kill,
        crate::lifecycle::circuit_breaker::BREAKER_MAX_BLAST_UNITS,
        now,
    );
    runtime.breaker.check_and_charge(
        crate::lifecycle::circuit_breaker::DestructiveKind::Kill,
        1,
        now,
    );

    for (kind, units, expected) in [
        (
            crate::lifecycle::circuit_breaker::DestructiveKind::DeviceWipe,
            32,
            "wipe_device_skipped:circuit_open",
        ),
        (
            crate::lifecycle::circuit_breaker::DestructiveKind::AppRemove,
            8,
            "remove_app_skipped:circuit_open",
        ),
    ] {
        let mut exec = fresh_kill_exec();
        assert!(!runtime.allow_destructive_command(kind, units, now as i64, expected, &mut exec,));
        assert_eq!(exec.outcome, response::CommandOutcome::Ignored);
        assert_eq!(exec.status, "failed");
        assert_eq!(exec.detail, expected);
    }
}

#[test]
fn command_kill_rejects_oversized_target_vector() {
    let mut runtime = kill_command_runtime(1000);
    // 65 targets exceeds MAX_KILL_COMMAND_TARGETS (64): reject the whole command.
    let pids: Vec<u32> = (100_000u32..100_065).collect();
    assert_eq!(pids.len(), 65);
    let payload = serde_json::json!({ "target_pids": pids }).to_string();
    let mut exec = fresh_kill_exec();

    runtime.apply_kill_process(&payload, &mut exec);

    assert_eq!(exec.status, "failed");
    assert!(exec.detail.contains("too many targets"), "{}", exec.detail);
    // Rejected before the loop, so no rate-limiter quota was consumed.
    assert!(
        runtime.limiter.allow(std::time::Instant::now()),
        "limiter must be untouched after an oversized-vector rejection"
    );
}

#[test]
fn command_kill_rejects_self_pid() {
    let mut runtime = kill_command_runtime(1000);
    let payload = serde_json::json!({ "pid": std::process::id() }).to_string();
    let mut exec = fresh_kill_exec();

    runtime.apply_kill_process(&payload, &mut exec);

    assert_eq!(exec.status, "partial");
    assert!(exec.detail.contains("agent self pid"), "{}", exec.detail);
}

#[test]
fn command_kill_rejects_oversized_payload_before_parsing() {
    let mut runtime = kill_command_runtime(1000);
    // ~80 KiB payload, larger than MAX_KILL_PAYLOAD_BYTES (64 KiB): rejected
    // before JSON deserialization so it cannot force a large allocation.
    let payload = format!("{{\"target_pids\":[{}]}}", "1,".repeat(40_000));
    assert!(payload.len() > 64 * 1024);
    let mut exec = fresh_kill_exec();

    runtime.apply_kill_process(&payload, &mut exec);

    assert_eq!(exec.status, "failed");
    assert!(exec.detail.contains("payload too large"), "{}", exec.detail);
}

#[test]
fn command_kill_consumes_shared_rate_limiter() {
    // Only one kill per minute is allowed; two distinct (non-existent) targets
    // means the second must be refused by the SAME limiter local detections use.
    let mut runtime = kill_command_runtime(1);
    let payload = serde_json::json!({ "target_pids": [999_001u32, 999_002u32] }).to_string();
    let mut exec = fresh_kill_exec();

    runtime.apply_kill_process(&payload, &mut exec);

    assert!(exec.detail.contains("rate limited"), "{}", exec.detail);
    // The single token was spent by the command path.
    assert!(
        !runtime.limiter.allow(std::time::Instant::now()),
        "command kills must consume the shared kill limiter"
    );
}

#[test]
fn command_pipeline_circuit_breaker_denies_kill_without_consuming_limiter() {
    let _guard = crate::test_support::env_lock().lock().expect("env lock");
    let dir = std::env::temp_dir().join(format!(
        "eguard-command-circuit-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create breaker state dir");
    std::env::set_var("EGUARD_AGENT_DATA_DIR", &dir);

    let mut cfg = crate::config::AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();
    cfg.self_protection_integrity_check_interval_secs = 0;
    cfg.response.max_kills_per_minute = 1;
    cfg.response.max_quarantines_per_minute = 1;
    let mut runtime = super::AgentRuntime::new(cfg).expect("runtime");
    let now = crate::lifecycle::now_unix().max(0) as u64;
    assert!(matches!(
        runtime.breaker.check_and_charge(
            crate::lifecycle::circuit_breaker::DestructiveKind::Kill,
            crate::lifecycle::circuit_breaker::BREAKER_MAX_BLAST_UNITS,
            now,
        ),
        crate::lifecycle::circuit_breaker::BreakerDecision::Allow
    ));
    assert!(matches!(
        runtime.breaker.check_and_charge(
            crate::lifecycle::circuit_breaker::DestructiveKind::Kill,
            1,
            now,
        ),
        crate::lifecycle::circuit_breaker::BreakerDecision::Deny { .. }
    ));

    let payload = serde_json::json!({ "pid": 999_003u32 }).to_string();
    let mut exec = fresh_kill_exec();
    runtime.apply_kill_process(&payload, &mut exec);

    assert_eq!(exec.status, "partial");
    assert!(exec.detail.contains("circuit_open"), "{}", exec.detail);
    assert!(
        runtime.limiter.allow(std::time::Instant::now()),
        "circuit-open kill must not consume limiter quota"
    );

    std::env::remove_var("EGUARD_AGENT_DATA_DIR");
    let _ = std::fs::remove_dir_all(dir);
}
