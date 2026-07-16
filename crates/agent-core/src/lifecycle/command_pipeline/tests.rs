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
fn forensics_collection_hardens_permissions_and_reports_upload_ready_artifacts() {
    let _guard = crate::test_support::env_lock().lock().expect("env lock");
    let dir = std::env::temp_dir().join(format!(
        "eguard-forensics-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create data dir");
    std::env::set_var("EGUARD_AGENT_DATA_DIR", &dir);

    let mut cfg = crate::config::AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();
    cfg.self_protection_integrity_check_interval_secs = 0;
    let runtime = super::AgentRuntime::new(cfg).expect("runtime");

    let mut exec = response::CommandExecution {
        outcome: response::CommandOutcome::Applied,
        status: "completed",
        detail: String::new(),
    };

    let artifacts = runtime.apply_forensics_collection("{}", &mut exec);

    assert_eq!(exec.status, "completed", "{}", exec.detail);
    assert_eq!(artifacts.len(), 1, "{}", exec.detail);
    assert_eq!(artifacts[0].artifact_type, "forensics_snapshot");
    assert!(
        exec.detail.contains("forensics snapshot captured on"),
        "detail must name the capture host: {}",
        exec.detail
    );
    assert!(
        exec.detail.contains("sha256="),
        "detail must carry tamper-evidence hash: {}",
        exec.detail
    );

    let path = std::path::Path::new(&artifacts[0].path);
    assert!(path.exists(), "snapshot file must exist at {:?}", path);

    // The hash in the detail must match the bytes on disk (chain of custody).
    let body = std::fs::read(path).expect("read snapshot");
    let sha = super::forensics::sha256_hex(&body);
    assert!(
        exec.detail.contains(&sha),
        "detail sha must match stored file: {}",
        exec.detail
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file_mode = std::fs::metadata(path)
            .expect("snapshot metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600, "snapshot must not be world-readable");
        let dir_mode = std::fs::metadata(path.parent().expect("forensics dir"))
            .expect("forensics dir metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "forensics dir must be root-only");
    }

    std::env::remove_var("EGUARD_AGENT_DATA_DIR");
    let _ = std::fs::remove_dir_all(dir);
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

fn uninstall_command_runtime(allow_remote_uninstall: bool) -> super::AgentRuntime {
    let mut cfg = crate::config::AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();
    cfg.self_protection_integrity_check_interval_secs = 0;
    cfg.response.allow_remote_uninstall = allow_remote_uninstall;
    super::AgentRuntime::new(cfg).expect("runtime")
}

#[test]
fn remote_uninstall_flag_off_preserves_honest_ack() {
    let _guard = crate::test_support::env_lock().lock().expect("env lock");
    let mut runtime = uninstall_command_runtime(false);
    let mut state = response::HostControlState::default();
    let mut exec =
        response::execute_server_command_with_state(ServerCommand::Uninstall, 1, &mut state);
    let before = (exec.outcome, exec.status, exec.detail.clone());

    runtime.apply_uninstall("{}", &mut exec);

    assert_eq!(exec.outcome, before.0);
    assert_eq!(exec.status, before.1);
    assert_eq!(exec.detail, before.2);
    assert!(exec.detail.contains("not executed"));
}

#[cfg(target_os = "linux")]
fn uninstall_test_dir(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "eguard-uninstall-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ))
}

#[cfg(target_os = "linux")]
fn write_uninstall_test_tool(path: &std::path::Path, contents: &str) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::write(path, contents).expect("write fake uninstall tool");
    let mut permissions = std::fs::metadata(path)
        .expect("fake uninstall tool metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).expect("make fake uninstall tool executable");
}

#[cfg(target_os = "linux")]
#[test]
fn remote_uninstall_dry_run_marks_completion_without_teardown() {
    let _guard = crate::test_support::env_lock().lock().expect("env lock");
    let dir = uninstall_test_dir("dry-run");
    let bin_dir = dir.join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create fake package tools dir");
    for tool in ["dpkg", "apt-get"] {
        write_uninstall_test_tool(&bin_dir.join(tool), "#!/bin/sh\nexit 0\n");
    }

    let original_path = std::env::var_os("PATH");
    let original_data_dir = std::env::var_os("EGUARD_AGENT_DATA_DIR");
    let original_dry_run = std::env::var_os("EGUARD_UNINSTALL_DRY_RUN");
    std::env::set_var("EGUARD_AGENT_DATA_DIR", &dir);
    std::env::set_var("PATH", &bin_dir);
    std::env::set_var("EGUARD_UNINSTALL_DRY_RUN", "1");
    let mut runtime = uninstall_command_runtime(true);
    let mut state = response::HostControlState::default();
    let mut exec =
        response::execute_server_command_with_state(ServerCommand::Uninstall, 1, &mut state);

    runtime.apply_uninstall("{}", &mut exec);

    assert_eq!(exec.status, "completed", "{}", exec.detail);
    assert_eq!(exec.outcome, response::CommandOutcome::Applied);
    assert!(exec.detail.contains("systemd-run"), "{}", exec.detail);
    assert!(exec.detail.contains("--collect"), "{}", exec.detail);
    assert!(
        exec.detail.contains("apt-get -y purge eguard-agent"),
        "{}",
        exec.detail
    );
    assert!(
        !exec.detail.contains("systemctl disable"),
        "{}",
        exec.detail
    );
    assert!(!dir.join("uninstalling").exists());

    for (name, original) in [
        ("PATH", original_path),
        ("EGUARD_AGENT_DATA_DIR", original_data_dir),
        ("EGUARD_UNINSTALL_DRY_RUN", original_dry_run),
    ] {
        if let Some(value) = original {
            std::env::set_var(name, value);
        } else {
            std::env::remove_var(name);
        }
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(target_os = "linux")]
#[test]
fn remote_uninstall_schedules_transient_purge_unit() {
    let _guard = crate::test_support::env_lock().lock().expect("env lock");
    let dir = uninstall_test_dir("systemd-run");
    let bin_dir = dir.join("bin");
    let capture = dir.join("systemd-run.argv");
    std::fs::create_dir_all(&bin_dir).expect("create fake package tools dir");
    for tool in ["dpkg", "apt-get"] {
        write_uninstall_test_tool(&bin_dir.join(tool), "#!/bin/sh\nexit 0\n");
    }
    write_uninstall_test_tool(
        &bin_dir.join("systemd-run"),
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >> '{}'\nexit 0\n",
            capture.display()
        ),
    );

    let original_path = std::env::var_os("PATH");
    let original_home = std::env::var_os("HOME");
    let original_data_dir = std::env::var_os("EGUARD_AGENT_DATA_DIR");
    let original_dry_run = std::env::var_os("EGUARD_UNINSTALL_DRY_RUN");
    std::env::set_var("PATH", &bin_dir);
    std::env::set_var("HOME", &dir);
    std::env::set_var("EGUARD_AGENT_DATA_DIR", &dir);
    std::env::remove_var("EGUARD_UNINSTALL_DRY_RUN");
    let mut runtime = uninstall_command_runtime(true);
    let mut state = response::HostControlState::default();
    let mut exec =
        response::execute_server_command_with_state(ServerCommand::Uninstall, 1, &mut state);

    runtime.apply_uninstall("{}", &mut exec);

    assert_eq!(exec.status, "completed", "{}", exec.detail);
    assert_eq!(exec.outcome, response::CommandOutcome::Applied);
    let captured = std::fs::read_to_string(&capture).expect("read captured systemd-run argv");
    assert!(captured.lines().any(|arg| arg == "--collect"), "{captured}");
    assert!(
        captured.lines().any(|arg| arg == "--service-type=exec"),
        "{captured}"
    );
    assert!(
        captured.contains("--unit=eguard-agent-uninstall-"),
        "{captured}"
    );
    assert!(
        captured.contains("apt-get -y purge eguard-agent"),
        "{captured}"
    );
    assert!(!captured.contains("systemctl disable"), "{captured}");

    for (name, original) in [
        ("PATH", original_path),
        ("HOME", original_home),
        ("EGUARD_AGENT_DATA_DIR", original_data_dir),
        ("EGUARD_UNINSTALL_DRY_RUN", original_dry_run),
    ] {
        if let Some(value) = original {
            std::env::set_var(name, value);
        } else {
            std::env::remove_var(name);
        }
    }
    let _ = std::fs::remove_dir_all(dir);
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
fn command_pipeline_circuit_breaker_denies_update_and_restart_device() {
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

    for expected in [
        "update_skipped:circuit_open",
        "restart_device_skipped:circuit_open",
    ] {
        let mut exec = fresh_kill_exec();
        assert!(!runtime.allow_destructive_command(
            crate::lifecycle::circuit_breaker::DestructiveKind::RestartOrUpdate,
            4,
            now as i64,
            expected,
            &mut exec,
        ));
        assert_eq!(exec.outcome, response::CommandOutcome::Ignored);
        assert_eq!(exec.status, "failed");
        assert_eq!(exec.detail, expected);
    }
}

#[tokio::test]
async fn command_pipeline_dispatch_denies_update_and_restart_on_tripped_breaker() {
    let mut runtime = kill_command_runtime(1);
    runtime.client.set_online(false);
    let path = std::env::temp_dir().join(format!(
        "eguard-command-dispatch-breaker-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    runtime.breaker = crate::lifecycle::circuit_breaker::CircuitBreaker::load_from_path(
        path.clone(),
        crate::lifecycle::circuit_breaker::BREAKER_MAX_BLAST_UNITS,
    );
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

    for (command_type, expected) in [
        ("update", "update_skipped:circuit_open"),
        ("restart_device", "restart_device_skipped:circuit_open"),
    ] {
        let exec = runtime
            .handle_command(
                grpc_client::CommandEnvelope {
                    command_id: format!("cmd-{command_type}"),
                    command_type: command_type.to_string(),
                    payload_json: "{}".to_string(),
                },
                now as i64,
            )
            .await;
        assert_eq!(exec.outcome, response::CommandOutcome::Ignored);
        assert_eq!(exec.status, "failed");
        assert_eq!(exec.detail, expected);

        let persisted: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&path).expect("read persisted breaker accounting"),
        )
        .expect("parse persisted breaker accounting");
        assert_eq!(persisted["tripped"], true);
        assert_eq!(
            persisted["blast_units"],
            crate::lifecycle::circuit_breaker::BREAKER_MAX_BLAST_UNITS
        );
        assert_eq!(persisted["alerted"], true);
    }

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn command_pipeline_circuit_breaker_allows_single_update_on_healthy_breaker() {
    let mut runtime = kill_command_runtime(1);
    runtime.client.set_online(false);
    let path = std::env::temp_dir().join(format!(
        "eguard-command-healthy-breaker-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    runtime.breaker = crate::lifecycle::circuit_breaker::CircuitBreaker::load_from_path(
        path.clone(),
        crate::lifecycle::circuit_breaker::BREAKER_MAX_BLAST_UNITS,
    );
    let now = crate::lifecycle::now_unix().max(0) as i64;

    let exec = runtime
        .handle_command(
            grpc_client::CommandEnvelope {
                command_id: "cmd-healthy-update".to_string(),
                command_type: "update".to_string(),
                payload_json: "{}".to_string(),
            },
            now,
        )
        .await;

    assert_eq!(exec.outcome, response::CommandOutcome::Ignored);
    assert_eq!(exec.status, "failed");
    assert_eq!(
        exec.detail,
        "invalid update payload: version is required and must be a safe token"
    );
    assert_ne!(exec.detail, "update_skipped:circuit_open");

    let persisted: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read persisted breaker accounting"))
            .expect("parse persisted breaker accounting");
    assert_eq!(persisted["tripped"], false);
    assert_eq!(persisted["blast_units"], 4);

    let _ = std::fs::remove_file(path);
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
    // Only one kill per minute is allowed; two distinct REAL targets means the
    // first consumes the single token and the second must be refused by the SAME
    // limiter local detections use. Real children are required because a
    // non-existent PID now fail-closes as protected (P1-1 identity binding)
    // before the limiter is ever consulted.
    let mut runtime = kill_command_runtime(1);
    let mut child_a = std::process::Command::new("sleep")
        .arg("300")
        .spawn()
        .expect("spawn child_a");
    let mut child_b = std::process::Command::new("sleep")
        .arg("300")
        .spawn()
        .expect("spawn child_b");
    let payload = serde_json::json!({ "target_pids": [child_a.id(), child_b.id()] }).to_string();
    let mut exec = fresh_kill_exec();

    runtime.apply_kill_process(&payload, &mut exec);

    assert!(exec.detail.contains("rate limited"), "{}", exec.detail);
    // The single token was spent by the command path.
    assert!(
        !runtime.limiter.allow(std::time::Instant::now()),
        "command kills must consume the shared kill limiter"
    );

    let _ = child_a.kill();
    let _ = child_a.wait();
    let _ = child_b.kill();
    let _ = child_b.wait();
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

    // Target a REAL, non-protected child so the kill reaches the breaker budget
    // gate. A non-existent PID now fail-closes as "protected" before the gate
    // (P1-1 identity binding), which would never exercise the circuit-open path.
    let mut child = std::process::Command::new("sleep")
        .arg("300")
        .spawn()
        .expect("spawn sleep child");
    let payload = serde_json::json!({ "pid": child.id() }).to_string();
    let mut exec = fresh_kill_exec();
    runtime.apply_kill_process(&payload, &mut exec);

    assert_eq!(exec.status, "partial", "{}", exec.detail);
    assert!(exec.detail.contains("circuit_open"), "{}", exec.detail);
    assert!(
        runtime.limiter.allow(std::time::Instant::now()),
        "circuit-open kill must not consume limiter quota"
    );
    // The tripped breaker must abort BEFORE any signal: the child is untouched.
    assert!(
        matches!(child.try_wait(), Ok(None)),
        "circuit-open kill must not signal the target process"
    );

    let _ = child.kill();
    let _ = child.wait();
    std::env::remove_var("EGUARD_AGENT_DATA_DIR");
    let _ = std::fs::remove_dir_all(dir);
}

// --- Phase C: adversarial storm fault-injection (director §5). Drives the REAL
// integrated AgentRuntime through a destructive command storm and proves the
// host cannot be bricked: hostile kills against protected identities do nothing,
// the circuit breaker trips BEFORE crossing its ceiling, every destructive
// command is then denied, recovery stays available, the trip survives a full
// process restart, and the canary process tree survives untouched. ---
#[tokio::test]
#[ignore = "Phase C storm fault-injection: spawns real canary processes and reloads the runtime; run explicitly with --ignored"]
async fn storm_fault_injection_no_brick_under_destructive_command_storm() {
    let _guard = crate::test_support::env_lock().lock().expect("env lock");
    let dir = std::env::temp_dir().join(format!(
        "eguard-storm-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create storm data dir");
    std::env::set_var("EGUARD_AGENT_DATA_DIR", &dir);

    let build_runtime = || {
        let mut cfg = crate::config::AgentConfig::default();
        cfg.offline_buffer_backend = "memory".to_string();
        cfg.server_addr = "127.0.0.1:1".to_string();
        cfg.self_protection_integrity_check_interval_secs = 0;
        // Large rate limits so the shared limiter never masks the breaker: the
        // breaker (attempted-blast-unit accounting) must be the thing that stops
        // the storm, not the per-minute limiter.
        cfg.response.max_kills_per_minute = 100_000;
        cfg.response.max_quarantines_per_minute = 100_000;
        let mut rt = super::AgentRuntime::new(cfg).expect("runtime");
        rt.client.set_online(false);
        rt
    };
    let mut runtime = build_runtime();
    let now = crate::lifecycle::now_unix().max(0) as i64;

    // A real canary process tree we will PROVE survives the entire storm.
    let mut canaries: Vec<std::process::Child> = (0..4)
        .map(|_| {
            std::process::Command::new("sleep")
                .arg("300")
                .spawn()
                .expect("spawn canary")
        })
        .collect();
    let self_pid = std::process::id();

    // ---- Phase 1: hostile kill flood against protected / critical / fake
    // identities. Every one must be refused with NOTHING signalled (fail-closed
    // identity binding); the agent itself and the canaries are untouched. ----
    let hostile: Vec<u32> = vec![
        self_pid,
        1,
        2,
        u32::MAX,
        u32::MAX - 1,
        999_001,
        999_002,
        999_003,
        4_000_000,
        4_000_001,
        4_000_002,
        4_000_003,
        4_000_004,
        4_000_005,
    ];
    for pid in &hostile {
        let payload = serde_json::json!({ "pid": pid }).to_string();
        let mut exec = fresh_kill_exec();
        runtime.apply_kill_process(&payload, &mut exec);
        assert!(
            !exec.detail.contains("killed=1")
                && !exec.detail.contains("killed=2")
                && exec.status != "completed",
            "hostile kill against protected/fake pid {pid} must not report a real kill: {}",
            exec.detail
        );
    }
    assert!(
        matches!(canaries[0].try_wait(), Ok(None)),
        "canary must survive the hostile-identity kill flood"
    );
    // The hostile-identity kill storm itself charges attempted blast units
    // (protected-guard violations) and may already have tripped the breaker -
    // that is a correct defensive outcome. Reset to a healthy breaker so the
    // next phase can prove the trip-before-crossing boundary deterministically.
    let state_path = dir.join("breaker_state.json");
    let _ = std::fs::remove_file(&state_path);
    runtime.breaker = crate::lifecycle::circuit_breaker::CircuitBreaker::load_from_path(
        state_path.clone(),
        crate::lifecycle::circuit_breaker::BREAKER_MAX_BLAST_UNITS,
    );

    // ---- Phase 2: destructive command storm that trips the breaker. Each
    // `update` attempt charges 4 attempted blast units before its payload is even
    // validated; the storm must trip BEFORE crossing the 128u ceiling. ----
    let mut tripped_at = None;
    for i in 0..64u32 {
        let exec = runtime
            .handle_command(
                grpc_client::CommandEnvelope {
                    command_id: format!("storm-update-{i}"),
                    command_type: "update".to_string(),
                    payload_json: "{}".to_string(),
                },
                now,
            )
            .await;
        if exec.detail == "update_skipped:circuit_open" {
            tripped_at = Some(i);
            break;
        }
    }
    let tripped_at = tripped_at.expect("destructive command storm must trip the breaker");
    // 128u ceiling / 4u per update => trips on the ~33rd attempt, never unbounded.
    assert!(
        (30..=34).contains(&tripped_at),
        "breaker must trip BEFORE crossing the ceiling (attempt {tripped_at})"
    );

    // Breaker state must be persisted as tripped at exactly the ceiling.
    let persisted: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_path).expect("read persisted breaker"))
            .expect("parse persisted breaker");
    assert_eq!(persisted["tripped"], true);
    assert_eq!(
        persisted["blast_units"],
        crate::lifecycle::circuit_breaker::BREAKER_MAX_BLAST_UNITS
    );

    // ---- Phase 3: with the breaker tripped, EVERY destructive command is denied
    // and the host survives. A real canary targeted by a kill command is not
    // signalled. ----
    for (ct, expected) in [
        ("update", "update_skipped:circuit_open"),
        ("restart_device", "restart_device_skipped:circuit_open"),
    ] {
        let exec = runtime
            .handle_command(
                grpc_client::CommandEnvelope {
                    command_id: format!("storm-post-{ct}"),
                    command_type: ct.to_string(),
                    payload_json: "{}".to_string(),
                },
                now,
            )
            .await;
        assert_eq!(exec.detail, expected, "post-trip {ct} must be denied");
    }
    let payload = serde_json::json!({ "pid": canaries[1].id() }).to_string();
    let mut exec = fresh_kill_exec();
    runtime.apply_kill_process(&payload, &mut exec);
    assert!(
        exec.detail.contains("circuit_open"),
        "post-trip kill must be denied: {}",
        exec.detail
    );
    assert!(
        matches!(canaries[1].try_wait(), Ok(None)),
        "tripped-breaker kill must not signal the real canary target"
    );

    // ---- Phase 4: recovery must stay available while the breaker is tripped. A
    // restore_quarantine command is routed to its handler, never breaker-denied. ----
    let exec = runtime
        .handle_command(
            grpc_client::CommandEnvelope {
                command_id: "storm-recovery".to_string(),
                command_type: "restore_quarantine".to_string(),
                payload_json: "{}".to_string(),
            },
            now,
        )
        .await;
    assert!(
        !exec.detail.contains("circuit_open"),
        "recovery (restore_quarantine) must never be gated by the breaker: {}",
        exec.detail
    );

    // ---- Phase 5: the trip must survive a full agent restart (crash aftermath). ----
    drop(runtime);
    let mut reloaded = build_runtime();
    let exec = reloaded
        .handle_command(
            grpc_client::CommandEnvelope {
                command_id: "storm-reload-update".to_string(),
                command_type: "update".to_string(),
                payload_json: "{}".to_string(),
            },
            now,
        )
        .await;
    assert_eq!(
        exec.detail, "update_skipped:circuit_open",
        "breaker trip must persist across a full runtime restart"
    );

    // ---- No brick: the agent itself and every canary are still alive. ----
    for (i, c) in canaries.iter_mut().enumerate() {
        assert!(
            matches!(c.try_wait(), Ok(None)),
            "canary {i} was killed by the storm -> host damage"
        );
    }

    for mut c in canaries {
        let _ = c.kill();
        let _ = c.wait();
    }
    std::env::remove_var("EGUARD_AGENT_DATA_DIR");
    let _ = std::fs::remove_dir_all(dir);
}
