use super::*;
use std::io::Write;
use std::sync::{Mutex, OnceLock};

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn clear_env() {
    let vars = [
        "EGUARD_AGENT_CONFIG",
        "EGUARD_BOOTSTRAP_CONFIG",
        "EGUARD_AGENT_ID",
        "EGUARD_SERVER_ADDR",
        "EGUARD_SERVER",
        "EGUARD_AGENT_MODE",
        "EGUARD_TRANSPORT_MODE",
        "EGUARD_ENROLLMENT_TOKEN",
        "EGUARD_TENANT_ID",
        "EGUARD_AUTONOMOUS_RESPONSE",
        "EGUARD_RESPONSE_DRY_RUN",
        "EGUARD_RESPONSE_MAX_KILLS_PER_MINUTE",
        "EGUARD_BUFFER_BACKEND",
        "EGUARD_BUFFER_PATH",
        "EGUARD_BUFFER_CAP_MB",
        "EGUARD_TLS_CERT",
        "EGUARD_TLS_KEY",
        "EGUARD_TLS_CA",
    ];
    for v in vars {
        std::env::remove_var(v);
    }
}

#[test]
// AC-CFG-004 AC-CFG-010 AC-CFG-013 AC-CFG-017 AC-CFG-020
fn file_config_is_loaded() {
    let _guard = env_lock().lock().expect("env lock");
    clear_env();

    let path = std::env::temp_dir().join(format!(
        "eguard-agent-config-{}.toml",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let mut f = std::fs::File::create(&path).expect("create file");
    writeln!(
            f,
            "[agent]\nserver_addr=\"10.0.0.1:50051\"\nmode=\"active\"\n[transport]\nmode=\"grpc\"\n[response]\nautonomous_response=true\ndry_run=true\n[response.high]\nkill=true\nquarantine=false\ncapture_script=true\n[response.rate_limit]\nmax_kills_per_minute=21\n[storage]\nbackend=\"memory\"\ncap_mb=10"
        )
        .expect("write file");

    std::env::set_var("EGUARD_AGENT_CONFIG", &path);
    let cfg = AgentConfig::load().expect("load config");

    assert_eq!(cfg.server_addr, "10.0.0.1:50051");
    assert!(matches!(cfg.mode, AgentMode::Active));
    assert!(cfg.response.autonomous_response);
    assert!(cfg.response.dry_run);
    assert!(cfg.response.high.kill);
    assert!(!cfg.response.high.quarantine);
    assert!(cfg.response.high.capture_script);
    assert_eq!(cfg.response.max_kills_per_minute, 21);
    assert_eq!(cfg.transport_mode, "grpc");
    assert_eq!(cfg.offline_buffer_backend, "memory");
    assert_eq!(cfg.offline_buffer_cap_bytes, 10 * 1024 * 1024);

    clear_env();
    let _ = std::fs::remove_file(path);
}

#[test]
// AC-CFG-004
fn env_overrides_file_config() {
    let _guard = env_lock().lock().expect("env lock");
    clear_env();

    let path = std::env::temp_dir().join(format!(
        "eguard-agent-config-{}.toml",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let mut f = std::fs::File::create(&path).expect("create file");
    writeln!(f, "[agent]\nserver_addr=\"10.0.0.1:50051\"").expect("write file");

    std::env::set_var("EGUARD_AGENT_CONFIG", &path);
    std::env::set_var("EGUARD_SERVER_ADDR", "10.9.9.9:50051");
    std::env::set_var("EGUARD_TRANSPORT_MODE", "http");
    std::env::set_var("EGUARD_AUTONOMOUS_RESPONSE", "true");
    let cfg = AgentConfig::load().expect("load config");

    assert_eq!(cfg.server_addr, "10.9.9.9:50051");
    assert_eq!(cfg.transport_mode, "http");
    assert!(cfg.response.autonomous_response);

    clear_env();
    let _ = std::fs::remove_file(path);
}

#[test]
// AC-CFG-001 AC-CFG-002 AC-GRP-006
fn bootstrap_config_is_used_when_agent_config_missing() {
    let _guard = env_lock().lock().expect("env lock");
    clear_env();

    let path = std::env::temp_dir().join(format!(
        "eguard-bootstrap-config-{}.conf",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let mut f = std::fs::File::create(&path).expect("create bootstrap file");
    writeln!(
            f,
            "[server]\naddress = 10.11.12.13\ngrpc_port = 50051\nenrollment_token = abc123def456\ntenant_id = default"
        )
        .expect("write bootstrap file");

    std::env::set_var("EGUARD_BOOTSTRAP_CONFIG", &path);
    let cfg = AgentConfig::load().expect("load config");

    assert_eq!(cfg.server_addr, "10.11.12.13:50051");
    assert_eq!(cfg.transport_mode, "grpc");
    assert_eq!(cfg.enrollment_token.as_deref(), Some("abc123def456"));
    assert_eq!(cfg.tenant_id.as_deref(), Some("default"));
    assert_eq!(cfg.bootstrap_config_path.as_deref(), Some(path.as_path()));

    clear_env();
    let _ = std::fs::remove_file(path);
}

#[test]
// AC-CFG-002
fn format_server_addr_handles_ipv6_without_port() {
    assert_eq!(
        format_server_addr("2001:db8::1", Some(50051)),
        "[2001:db8::1]:50051"
    );
    assert_eq!(
        format_server_addr("[2001:db8::1]:50051", Some(50052)),
        "[2001:db8::1]:50051"
    );
    assert_eq!(
        format_server_addr("eguard.example.com", Some(50051)),
        "eguard.example.com:50051"
    );
}

#[test]
// AC-CFG-010
fn parse_bool_accepts_expected_truthy_values() {
    assert!(parse_bool("1"));
    assert!(parse_bool("true"));
    assert!(parse_bool("YES"));
    assert!(parse_bool("enabled"));
    assert!(!parse_bool("0"));
    assert!(!parse_bool("false"));
}

#[test]
// AC-CFG-020
fn parse_cap_mb_handles_invalid_values() {
    assert_eq!(parse_cap_mb("10"), Some(10 * 1024 * 1024));
    assert_eq!(parse_cap_mb("not-a-number"), None);
}

#[test]
// AC-CFG-002
fn has_explicit_port_detects_ipv4_and_ipv6_forms() {
    assert!(has_explicit_port("127.0.0.1:50051"));
    assert!(has_explicit_port("[2001:db8::1]:50051"));
    assert!(!has_explicit_port("eguard.example.com"));
    assert!(!has_explicit_port("2001:db8::1"));
}

#[test]
// AC-CFG-001 AC-CFG-002
fn parse_bootstrap_config_ignores_comments_and_other_sections() {
    let cfg = parse_bootstrap_config(
        r#"
[misc]
address = ignored.example

[server]
address = 10.1.2.3 ; inline comment
grpc_port = 50051 # inline comment
enrollment_token = "tok-123"
tenant_id = 'tenant-a'
"#,
    )
    .expect("parse bootstrap");

    assert_eq!(cfg.address.as_deref(), Some("10.1.2.3"));
    assert_eq!(cfg.grpc_port, Some(50051));
    assert_eq!(cfg.enrollment_token.as_deref(), Some("tok-123"));
    assert_eq!(cfg.tenant_id.as_deref(), Some("tenant-a"));
}

#[test]
// AC-CFG-004
fn resolve_config_path_fails_for_missing_explicit_env_path() {
    let _guard = env_lock().lock().expect("env lock");
    clear_env();
    std::env::set_var(
        "EGUARD_AGENT_CONFIG",
        "/tmp/eguard-agent-config-should-not-exist.toml",
    );

    let err = resolve_config_path().expect_err("missing explicit config path should fail");
    assert!(err.to_string().contains("does not exist"));
    clear_env();
}

#[test]
// AC-CFG-010 AC-CFG-011 AC-CFG-012 AC-CFG-013 AC-CFG-014
fn apply_response_policy_updates_only_provided_fields() {
    let mut dst = ResponsePolicy {
        kill: false,
        quarantine: false,
        capture_script: false,
    };
    let src = FileResponsePolicy {
        kill: Some(true),
        quarantine: None,
        capture_script: Some(true),
    };

    apply_response_policy(&mut dst, Some(src));
    assert!(dst.kill);
    assert!(!dst.quarantine);
    assert!(dst.capture_script);
}

#[test]
// AC-CFG-007 AC-CFG-008 AC-CFG-009 AC-CFG-010 AC-CFG-011 AC-CFG-012 AC-CFG-013 AC-CFG-014 AC-CFG-018 AC-CFG-019 AC-CFG-020 AC-CFG-021 AC-GRP-015 AC-GRP-027
fn default_config_matches_expected_baseline_values() {
    let cfg = AgentConfig::default();
    assert!(matches!(cfg.mode, AgentMode::Learning));
    assert_eq!(cfg.transport_mode, "http");
    assert_eq!(cfg.offline_buffer_backend, "sqlite");
    assert_eq!(
        cfg.offline_buffer_path,
        "/var/lib/eguard-agent/offline-events.db"
    );
    assert_eq!(cfg.offline_buffer_cap_bytes, 100 * 1024 * 1024);
    assert_eq!(cfg.heartbeat_interval_secs, 30);
    assert_eq!(cfg.reconnect_backoff_max_secs, 300);
    assert!(cfg.telemetry_process_exec);
    assert!(cfg.telemetry_file_events);
    assert!(cfg.telemetry_network_connections);
    assert!(cfg.telemetry_dns_queries);
    assert!(cfg.telemetry_module_loads);
    assert!(cfg.telemetry_user_logins);
    assert_eq!(cfg.telemetry_flush_interval_ms, 100);
    assert_eq!(cfg.telemetry_max_batch_size, 100);
    assert_eq!(cfg.detection_max_file_scan_size_mb, 100);
    assert!(cfg.detection_scan_on_create);
    assert_eq!(cfg.compliance_check_interval_secs, 300);
    assert!(!cfg.compliance_auto_remediate);
    assert_eq!(cfg.baseline_learning_period_days, 7);
    assert_eq!(cfg.baseline_refresh_interval_days, 7);
    assert_eq!(cfg.baseline_stale_after_days, 30);
    assert_eq!(cfg.self_protection_integrity_check_interval_secs, 60);
    assert!(cfg.self_protection_prevent_uninstall);
    assert!(!cfg.response.autonomous_response);
    assert!(!cfg.response.dry_run);
}

#[test]
// AC-CFG-005 AC-CFG-006 AC-CFG-007 AC-CFG-008 AC-CFG-009 AC-CFG-018 AC-CFG-019 AC-CFG-021 AC-GRP-097
fn file_config_loads_extended_sections() {
    let _guard = env_lock().lock().expect("env lock");
    clear_env();

    let path = std::env::temp_dir().join(format!(
        "eguard-agent-config-extended-{}.toml",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));

    let mut f = std::fs::File::create(&path).expect("create file");
    writeln!(
        f,
        "[agent]\nid=\"agent-123\"\nmachine_id=\"machine-xyz\"\n\
         [server]\naddress=\"10.20.30.40\"\ngrpc_port=50051\ncert_file=\"/tmp/agent.crt\"\nkey_file=\"/tmp/agent.key\"\nca_file=\"/tmp/ca.crt\"\n\
         [heartbeat]\ninterval_secs=45\nreconnect_backoff_max_secs=120\n\
         [telemetry]\nprocess_exec=true\nfile_events=false\nnetwork_connections=true\ndns_queries=false\nmodule_loads=true\nuser_logins=false\nflush_interval_ms=250\nmax_batch_size=64\n\
         [detection]\nsigma_rules_dir=\"/opt/rules/sigma\"\nyara_rules_dir=\"/opt/rules/yara\"\nioc_dir=\"/opt/rules/ioc\"\nscan_on_create=false\nmax_file_scan_size_mb=42\n\
         [compliance]\ncheck_interval_secs=900\nauto_remediate=true\n\
         [baseline]\nlearning_period_days=10\nrefresh_interval_days=14\nstale_after_days=40\n\
         [self_protection]\nintegrity_check_interval_secs=90\nprevent_uninstall=false"
    )
    .expect("write file");

    std::env::set_var("EGUARD_AGENT_CONFIG", &path);
    let cfg = AgentConfig::load().expect("load config");

    assert_eq!(cfg.agent_id, "agent-123");
    assert_eq!(cfg.machine_id.as_deref(), Some("machine-xyz"));
    assert_eq!(cfg.server_addr, "10.20.30.40:50051");
    assert_eq!(cfg.tls_cert_path.as_deref(), Some("/tmp/agent.crt"));
    assert_eq!(cfg.tls_key_path.as_deref(), Some("/tmp/agent.key"));
    assert_eq!(cfg.tls_ca_path.as_deref(), Some("/tmp/ca.crt"));
    assert_eq!(cfg.heartbeat_interval_secs, 45);
    assert_eq!(cfg.reconnect_backoff_max_secs, 120);
    assert!(cfg.telemetry_process_exec);
    assert!(!cfg.telemetry_file_events);
    assert!(cfg.telemetry_network_connections);
    assert!(!cfg.telemetry_dns_queries);
    assert!(cfg.telemetry_module_loads);
    assert!(!cfg.telemetry_user_logins);
    assert_eq!(cfg.telemetry_flush_interval_ms, 250);
    assert_eq!(cfg.telemetry_max_batch_size, 64);
    assert_eq!(cfg.detection_sigma_rules_dir, "/opt/rules/sigma");
    assert_eq!(cfg.detection_yara_rules_dir, "/opt/rules/yara");
    assert_eq!(cfg.detection_ioc_dir, "/opt/rules/ioc");
    assert!(!cfg.detection_scan_on_create);
    assert_eq!(cfg.detection_max_file_scan_size_mb, 42);
    assert_eq!(cfg.compliance_check_interval_secs, 900);
    assert!(cfg.compliance_auto_remediate);
    assert_eq!(cfg.baseline_learning_period_days, 10);
    assert_eq!(cfg.baseline_refresh_interval_days, 14);
    assert_eq!(cfg.baseline_stale_after_days, 40);
    assert_eq!(cfg.self_protection_integrity_check_interval_secs, 90);
    assert!(!cfg.self_protection_prevent_uninstall);

    clear_env();
    let _ = std::fs::remove_file(path);
}

#[test]
// AC-CFG-004
fn eguard_server_fallback_env_is_used_when_primary_is_absent() {
    let _guard = env_lock().lock().expect("env lock");
    clear_env();
    std::env::set_var("EGUARD_SERVER", "10.2.3.4:50051");

    let mut cfg = AgentConfig::default();
    cfg.apply_env_overrides();
    assert_eq!(cfg.server_addr, "10.2.3.4:50051");

    clear_env();
}

#[test]
// AC-CFG-004
fn eguard_server_addr_takes_precedence_over_eguard_server() {
    let _guard = env_lock().lock().expect("env lock");
    clear_env();
    std::env::set_var("EGUARD_SERVER", "10.2.3.4:50051");
    std::env::set_var("EGUARD_SERVER_ADDR", "10.9.9.9:50051");

    let mut cfg = AgentConfig::default();
    cfg.apply_env_overrides();
    assert_eq!(cfg.server_addr, "10.9.9.9:50051");

    clear_env();
}

#[test]
// AC-CFG-001
fn resolve_bootstrap_path_fails_for_missing_explicit_env_path() {
    let _guard = env_lock().lock().expect("env lock");
    clear_env();
    std::env::set_var(
        "EGUARD_BOOTSTRAP_CONFIG",
        "/tmp/eguard-bootstrap-config-should-not-exist.conf",
    );

    let err = resolve_bootstrap_path().expect_err("missing explicit bootstrap path should fail");
    assert!(err.to_string().contains("does not exist"));

    clear_env();
}

#[test]
// AC-CFG-003
fn remove_bootstrap_config_deletes_existing_file() {
    let path = std::env::temp_dir().join(format!(
        "eguard-bootstrap-remove-{}.conf",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::write(&path, "test=true\n").expect("write bootstrap");
    assert!(path.exists());

    remove_bootstrap_config(&path).expect("remove bootstrap");
    assert!(!path.exists());
}

#[test]
// AC-CFG-022
fn expected_config_files_match_documented_layout() {
    let expected = expected_config_files();
    assert!(expected.contains(&"/etc/eguard-agent/bootstrap.conf"));
    assert!(expected.contains(&"/etc/eguard-agent/agent.conf"));
    assert!(expected.contains(&"/etc/eguard-agent/certs/agent.crt"));
    assert!(expected.contains(&"/etc/eguard-agent/certs/agent.key"));
    assert!(expected.contains(&"/etc/eguard-agent/certs/ca.crt"));
}

#[test]
// AC-CFG-023
fn expected_data_paths_match_documented_layout() {
    let expected = expected_data_paths();
    assert!(expected.contains(&"/var/lib/eguard-agent/buffer.db"));
    assert!(expected.contains(&"/var/lib/eguard-agent/baselines.bin"));
    assert!(expected.contains(&"/var/lib/eguard-agent/rules/sigma/"));
    assert!(expected.contains(&"/var/lib/eguard-agent/rules/yara/"));
    assert!(expected.contains(&"/var/lib/eguard-agent/rules/ioc/"));
    assert!(expected.contains(&"/var/lib/eguard-agent/quarantine/"));
    assert!(expected.contains(&"/var/lib/eguard-agent/rules-staging/"));
}
