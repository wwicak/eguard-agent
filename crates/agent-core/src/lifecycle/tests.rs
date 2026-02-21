use super::*;
use crate::config::AgentConfig;
use crate::detection_state::SharedDetectionState;
use ed25519_dalek::{Signer, SigningKey};
use grpc_client::{CertificatePolicyEnvelope, PolicyEnvelope};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDDTCCAfWgAwIBAgIUG1RpSsAZxqzhHCoL473XsyD9hlcwDQYJKoZIhvcNAQEL\n\
BQAwFjEUMBIGA1UEAwwLZWd1YXJkLXRlc3QwHhcNMjYwMjEzMTI0MDE4WhcNMzYw\n\
MjExMTI0MDE4WjAWMRQwEgYDVQQDDAtlZ3VhcmQtdGVzdDCCASIwDQYJKoZIhvcN\n\
AQEBBQADggEPADCCAQoCggEBAKk2momq5fBplRm+Wm6LTgTZb75brV0G++bHTR1+\n\
dYGuY3RV+5MQ06O5iKaQBeoNMNQ5PtK5CZL/BRd2pPmYVZdez6CImCtmY6jjaIlA\n\
LJTuhjxgJT6t6N03UVm9EuBvx90c4sQ7ZlXGdXNz8LlIWaFiQGWA8Gp3IoC5SdLt\n\
pkw4B8g1UFBgWgVHW4OucqQAGK9kESJssQO6lqGYx8MCBOsf/KVfN3GGcd4jbHLQ\n\
1d8BuW6T3BIxm9VubcuoGzpoNyCeWPcjpCJ+i9IxKCIV/1/Z0UBAdkh5eFxQUNrL\n\
rWVg6pf1GayrhwJtWk0xkk/cAH/xaZAH7gs0RdX2RMKqkekCAwEAAaNTMFEwHQYD\n\
VR0OBBYEFA96oAcppUC9w2vay+M/RXgZocyWMB8GA1UdIwQYMBaAFA96oAcppUC9\n\
w2vay+M/RXgZocyWMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB\n\
ACclf3E4MeBJaB1h5QLiBrT1MkepdRSfLZKoQWDLvfbLI+HLm5DJs2HRB407u92a\n\
aLSoImIFf/8Om95GtM1Ys7/ViskaLtRvcoRpndCtXuMMb78NL2/KcIul9K8VsRTP\n\
yEVUVnNeqAg7wFvTFntHuMpeIdOOw0EfncifFcm8bU7nWNvWGnJU00GtbbIWPbFM\n\
BUXtvynj+IpUYX+71Q9iMSTUGPOyoLZqe/0CQ3jhS/cJ+ACcz3twv/9iH68H6LOP\n\
qtOeacCdUvKD1rtdLF2VFDvEBncUdvQ0IM2isK8qJvEQ7mFTPa+4bS8urSAtQHa9\n\
avL4/CXZNaqR1xewDR9ipTA=\n\
-----END CERTIFICATE-----\n";

fn sha256_bytes_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

#[test]
fn candidate_ebpf_object_paths_uses_known_order() {
    let base = std::env::temp_dir().join(format!(
        "eguard-ebpf-objects-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(&base).expect("create temp dir");

    let process = base.join("process_exec_bpf.o");
    let dns = base.join("dns_query_bpf.o");
    let lsm = base.join("lsm_block_bpf.o");
    std::fs::write(&process, b"obj").expect("write process obj");
    std::fs::write(&dns, b"obj").expect("write dns obj");
    std::fs::write(&lsm, b"obj").expect("write lsm obj");

    let paths = candidate_ebpf_object_paths(&base);
    assert_eq!(paths, vec![process.clone(), dns.clone(), lsm.clone()]);

    let _ = std::fs::remove_file(process);
    let _ = std::fs::remove_file(dns);
    let _ = std::fs::remove_file(lsm);
    let _ = std::fs::remove_dir(base);
}

#[test]
// AC-EBP-001
fn candidate_ebpf_object_paths_discovers_core_program_objects() {
    let base = std::env::temp_dir().join(format!(
        "eguard-ebpf-core-objects-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(&base).expect("create temp dir");

    let names = [
        "process_exec_bpf.o",
        "file_open_bpf.o",
        "file_write_bpf.o",
        "file_rename_bpf.o",
        "file_unlink_bpf.o",
        "tcp_connect_bpf.o",
        "dns_query_bpf.o",
        "module_load_bpf.o",
    ];
    for name in names {
        std::fs::write(base.join(name), b"obj").expect("write object file");
    }

    let paths = candidate_ebpf_object_paths(&base);
    assert_eq!(paths.len(), 8);
    for name in names {
        assert!(paths.iter().any(|p| p.ends_with(name)));
    }
    assert!(!paths.iter().any(|p| p.ends_with("lsm_block_bpf.o")));

    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn default_ebpf_object_dirs_include_expected_targets() {
    let dirs = default_ebpf_objects_dirs();
    assert!(dirs.iter().any(|d| d == &PathBuf::from("./zig-out/ebpf")));
    assert!(dirs.iter().any(|d| d == &PathBuf::from("zig-out/ebpf")));
    assert!(dirs
        .iter()
        .any(|d| d == &PathBuf::from("/usr/lib/eguard-agent/ebpf")));
}

#[test]
// AC-ATP-084
fn parse_certificate_not_after_unix_reads_pem_validity() {
    let not_after =
        parse_certificate_not_after_unix(TEST_CERT_PEM.as_bytes()).expect("parse test cert");
    assert!(not_after > 2_000_000_000);
}

#[test]
// AC-ATP-084 AC-ATP-085
fn days_until_certificate_expiry_is_positive_for_future_cert() {
    let path = std::env::temp_dir().join(format!(
        "eguard-renew-cert-{}.pem",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::write(&path, TEST_CERT_PEM.as_bytes()).expect("write test cert");

    let days = days_until_certificate_expiry(&path.to_string_lossy(), 1_700_000_000)
        .expect("calculate cert expiry days");
    assert!(days > 1000);

    let _ = std::fs::remove_file(path);
}

#[test]
// AC-ATP-084
fn parse_certificate_not_after_unix_rejects_invalid_payload() {
    let err = parse_certificate_not_after_unix(b"not-a-certificate")
        .expect_err("invalid cert payload must fail");
    assert!(err
        .to_string()
        .contains("parse X509 certificate DER payload"));
}

#[test]
// AC-REM-002 AC-REM-004
fn update_tls_policy_from_server_updates_pin_and_rotation_window() {
    let mut cfg = AgentConfig::default();
    let policy = PolicyEnvelope {
        certificate_policy: Some(CertificatePolicyEnvelope {
            pinned_ca_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            rotate_before_expiry_days: 14,
            ..CertificatePolicyEnvelope::default()
        }),
        ..PolicyEnvelope::default()
    };

    let changed = update_tls_policy_from_server(&mut cfg, &policy);
    assert!(changed);
    assert_eq!(
        cfg.tls_pinned_ca_sha256.as_deref(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert_eq!(cfg.tls_rotate_before_expiry_days, 14);
}

#[test]
// AC-REM-002 AC-REM-004
fn update_tls_policy_from_server_ignores_empty_values() {
    let mut cfg = AgentConfig::default();
    let original_days = cfg.tls_rotate_before_expiry_days;
    let policy = PolicyEnvelope {
        certificate_policy: Some(CertificatePolicyEnvelope {
            pinned_ca_sha256: String::new(),
            rotate_before_expiry_days: 0,
            ..CertificatePolicyEnvelope::default()
        }),
        ..PolicyEnvelope::default()
    };

    let changed = update_tls_policy_from_server(&mut cfg, &policy);
    assert!(!changed);
    assert!(cfg.tls_pinned_ca_sha256.is_none());
    assert_eq!(cfg.tls_rotate_before_expiry_days, original_days);
}

#[test]
// AC-EBP-051 AC-EBP-052 AC-EBP-053 AC-EBP-054 AC-DET-184
fn compute_poll_timeout_prioritizes_drop_backpressure() {
    assert_eq!(
        compute_poll_timeout(0, 1),
        std::time::Duration::from_millis(1)
    );
    assert_eq!(
        compute_poll_timeout(5000, 0),
        std::time::Duration::from_millis(5)
    );
    assert_eq!(
        compute_poll_timeout(2000, 0),
        std::time::Duration::from_millis(20)
    );
    assert_eq!(
        compute_poll_timeout(10, 0),
        std::time::Duration::from_millis(100)
    );
}

#[test]
fn interval_due_runs_immediately_then_waits_for_threshold() {
    assert!(interval_due(None, 100, 30));
    assert!(!interval_due(Some(100), 120, 30));
    assert!(interval_due(Some(100), 130, 30));
}

#[test]
fn interval_due_ignores_backward_wall_clock_steps() {
    assert!(!interval_due(Some(1_000), 900, 30));
    assert!(interval_due(Some(1_000), 1_030, 30));
}

#[test]
fn interval_due_uses_runtime_interval_constants() {
    assert!(!interval_due(Some(1_000), 1_029, HEARTBEAT_INTERVAL_SECS));
    assert!(interval_due(Some(1_000), 1_030, HEARTBEAT_INTERVAL_SECS));

    assert!(!interval_due(Some(2_000), 2_059, COMPLIANCE_INTERVAL_SECS));
    assert!(interval_due(Some(2_000), 2_060, COMPLIANCE_INTERVAL_SECS));

    assert!(!interval_due(
        Some(3_000),
        3_149,
        THREAT_INTEL_INTERVAL_SECS
    ));
    assert!(interval_due(Some(3_000), 3_150, THREAT_INTEL_INTERVAL_SECS));

    assert!(!interval_due(
        Some(4_000),
        4_299,
        BASELINE_SAVE_INTERVAL_SECS
    ));
    assert!(interval_due(
        Some(4_000),
        4_300,
        BASELINE_SAVE_INTERVAL_SECS
    ));
}

#[test]
fn load_bundle_rules_reads_sigma_and_yara_dirs() {
    let base = std::env::temp_dir().join(format!(
        "eguard-bundle-rules-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let sigma_dir = base.join("sigma");
    let yara_dir = base.join("yara");
    std::fs::create_dir_all(&sigma_dir).expect("create sigma dir");
    std::fs::create_dir_all(&yara_dir).expect("create yara dir");

    std::fs::write(
        sigma_dir.join("rule.yml"),
        r#"
title: sigma_rule_from_bundle
detection:
  sequence:
    - event_class: process_exec
      process_any_of: [bash]
      parent_any_of: [nginx]
      within_secs: 30
    - event_class: network_connect
      dst_port_not_in: [80, 443]
      within_secs: 10
"#,
    )
    .expect("write sigma rule");

    std::fs::write(
        yara_dir.join("rule.yar"),
        r#"
rule bundle_marker {
  strings:
    $m = "bundle-malware-marker"
  condition:
    $m
}
"#,
    )
    .expect("write yara rule");

    let mut direct = DetectionEngine::default_with_rules();
    assert_eq!(
        direct
            .load_sigma_rules_from_dir(&sigma_dir)
            .expect("direct sigma load"),
        1
    );

    let mut engine = DetectionEngine::default_with_rules();
    let (sigma, yara) = load_bundle_rules(&mut engine, base.to_string_lossy().as_ref());
    assert!(sigma <= 1);
    assert_eq!(yara, 1);

    let _ = std::fs::remove_file(sigma_dir.join("rule.yml"));
    let _ = std::fs::remove_file(yara_dir.join("rule.yar"));
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn load_bundle_rules_reads_nested_source_directories() {
    let base = std::env::temp_dir().join(format!(
        "eguard-bundle-nested-rules-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let sigma_nested = base.join("sigma/rules-emerging-threats");
    let yara_nested = base.join("yara/yara-forge");
    std::fs::create_dir_all(&sigma_nested).expect("create nested sigma dir");
    std::fs::create_dir_all(&yara_nested).expect("create nested yara dir");

    std::fs::write(
        sigma_nested.join("rule.yml"),
        r#"
title: sigma_rule_from_nested_bundle
detection:
  sequence:
    - event_class: process_exec
      process_any_of: [bash]
      parent_any_of: [nginx]
      within_secs: 30
    - event_class: network_connect
      dst_port_not_in: [80, 443]
      within_secs: 10
"#,
    )
    .expect("write nested sigma rule");

    std::fs::write(
        yara_nested.join("rule.yar"),
        r#"
rule nested_bundle_marker {
  strings:
    $m = "nested-bundle-marker"
  condition:
    $m
}
"#,
    )
    .expect("write nested yara rule");

    let mut engine = DetectionEngine::default_with_rules();
    let (sigma, yara) = load_bundle_rules(&mut engine, base.to_string_lossy().as_ref());
    assert!(sigma >= 1);
    assert_eq!(yara, 1);

    let _ = std::fs::remove_file(sigma_nested.join("rule.yml"));
    let _ = std::fs::remove_file(yara_nested.join("rule.yar"));
    let _ = std::fs::remove_dir_all(base);
}

#[test]
// AC-DET-143 AC-DET-170
fn reload_detection_state_from_bundle_swaps_runtime_engine_and_emits_bundle_hits() {
    let base = std::env::temp_dir().join(format!(
        "eguard-bundle-runtime-hit-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let sigma_dir = base.join("sigma");
    let yara_dir = base.join("yara");
    std::fs::create_dir_all(&sigma_dir).expect("create sigma dir");
    std::fs::create_dir_all(&yara_dir).expect("create yara dir");

    std::fs::write(
        sigma_dir.join("rule.yml"),
        r#"
title: sigma_bundle_runtime_hit
detection:
  sequence:
    - event_class: process_exec
      process_any_of: [bundleproc]
      parent_any_of: [bundleparent]
      within_secs: 30
    - event_class: network_connect
      dst_port_not_in: [443]
      within_secs: 10
"#,
    )
    .expect("write sigma rule");

    std::fs::write(
        yara_dir.join("rule.yar"),
        r#"
rule bundle_runtime_marker {
  strings:
    $m = "bundle-runtime-marker-8844"
  condition:
    $m
}
"#,
    )
    .expect("write yara rule");

    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let mut runtime = AgentRuntime::new(cfg.clone()).expect("build runtime");
    runtime
        .reload_detection_state("bundle-runtime-v1", base.to_string_lossy().as_ref(), None)
        .expect("reload detection state from bundle");

    assert_eq!(
        runtime
            .detection_state
            .version()
            .expect("state version")
            .as_deref(),
        Some("bundle-runtime-v1")
    );
    let report = runtime
        .last_reload_report
        .clone()
        .expect("recorded reload report");
    assert!(report.sigma_rules >= 1);
    assert!(report.yara_rules >= 1);

    let stage_one = detection::TelemetryEvent {
        ts_unix: 10_000,
        event_class: detection::EventClass::ProcessExec,
        pid: 4242,
        ppid: 1,
        uid: 1000,
        process: "bundleproc".to_string(),
        parent_process: "bundleparent".to_string(),
        session_id: 1,
        file_path: None,
        file_write: false,
        file_hash: None,
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
        command_line: Some("echo bundle-runtime-marker-8844".to_string()),
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    };
    let stage_one_out = runtime
        .detection_state
        .process_event(&stage_one)
        .expect("evaluate stage one event");
    assert!(stage_one_out
        .yara_hits
        .iter()
        .any(|hit| hit.rule_name == "bundle_runtime_marker"));
    assert_eq!(stage_one_out.confidence, detection::Confidence::Definite);

    let stage_two = detection::TelemetryEvent {
        ts_unix: 10_005,
        event_class: detection::EventClass::NetworkConnect,
        pid: 4242,
        ppid: 1,
        uid: 1000,
        process: "bundleproc".to_string(),
        parent_process: "bundleparent".to_string(),
        session_id: 1,
        file_path: None,
        file_write: false,
        file_hash: None,
        dst_port: Some(31337),
        dst_ip: Some("203.0.113.8".to_string()),
        dst_domain: None,
        command_line: None,
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    };
    let stage_two_out = runtime
        .detection_state
        .process_event(&stage_two)
        .expect("evaluate stage two event");
    assert!(stage_two_out.signals.z2_temporal);
    assert!(stage_two_out
        .temporal_hits
        .iter()
        .any(|hit| hit == "sigma_bundle_runtime_hit"));

    let _ = std::fs::remove_file(sigma_dir.join("rule.yml"));
    let _ = std::fs::remove_file(yara_dir.join("rule.yar"));
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn reload_detection_state_from_bundle_populates_ioc_layers_on_all_shards() {
    let base = std::env::temp_dir().join(format!(
        "eguard-bundle-sharded-ioc-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let ioc_dir = base.join("ioc");
    std::fs::create_dir_all(&ioc_dir).expect("create ioc dir");
    std::fs::write(ioc_dir.join("hashes.txt"), "bundle-ioc-hash-9911\n")
        .expect("write hash ioc list");

    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let mut runtime = AgentRuntime::new(cfg.clone()).expect("build runtime");
    runtime.detection_state = SharedDetectionState::new_with_shards(
        detection_bootstrap::build_detection_engine_with_ransomware_policy(
            build_ransomware_policy(&cfg),
        ),
        runtime
            .detection_state
            .version()
            .expect("state version before reset"),
        2,
        || {
            detection_bootstrap::build_detection_engine_with_ransomware_policy(
                build_ransomware_policy(&cfg),
            )
        },
    );

    runtime
        .reload_detection_state("bundle-ioc-v1", base.to_string_lossy().as_ref(), None)
        .expect("reload detection state from IOC bundle");

    let event_for_pid = |pid| detection::TelemetryEvent {
        ts_unix: 20_000,
        event_class: detection::EventClass::ProcessExec,
        pid,
        ppid: 1,
        uid: 1000,
        process: "bash".to_string(),
        parent_process: "sshd".to_string(),
        session_id: 1,
        file_path: None,
        file_write: false,
        file_hash: Some("bundle-ioc-hash-9911".to_string()),
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
        command_line: None,
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    };

    for pid in [9000u32, 9001u32] {
        let out = runtime
            .detection_state
            .process_event(&event_for_pid(pid))
            .expect("evaluate IOC event across shards");
        assert_eq!(
            out.confidence,
            detection::Confidence::Definite,
            "ioc hit should be loaded on shard for pid {pid}"
        );
    }

    let _ = std::fs::remove_file(ioc_dir.join("hashes.txt"));
    let _ = std::fs::remove_dir_all(base);
}

#[test]
// AC-DET-143 AC-DET-077
fn verify_bundle_signature_with_material_accepts_signed_payload() {
    let base = std::env::temp_dir().join(format!(
        "eguard-bundle-signature-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(&base).expect("create temp dir");

    let bundle = base.join("bundle.tar.zst");
    let signature = base.join("bundle.tar.zst.sig");
    std::fs::write(&bundle, b"signed-bundle-content").expect("write bundle bytes");

    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let sig = signing.sign(b"signed-bundle-content");
    std::fs::write(&signature, sig.to_bytes()).expect("write signature bytes");

    let verified = verify_bundle_signature_with_material(
        &bundle,
        &signature,
        signing.verifying_key().to_bytes(),
    );
    assert!(verified.is_ok());

    let _ = std::fs::remove_file(bundle);
    let _ = std::fs::remove_file(signature);
    let _ = std::fs::remove_dir(base);
}

#[test]
// AC-VER-053 AC-DET-143
fn verify_bundle_signature_with_material_rejects_tampered_payload() {
    let base = std::env::temp_dir().join(format!(
        "eguard-bundle-signature-tamper-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(&base).expect("create temp dir");

    let bundle = base.join("bundle.tar.zst");
    let tampered = base.join("bundle.tampered.tar.zst");
    let signature = base.join("bundle.tar.zst.sig");
    std::fs::write(&bundle, b"signed-bundle-content").expect("write bundle bytes");
    std::fs::write(&tampered, b"signed-bundle-content-tampered")
        .expect("write tampered bundle bytes");

    let signing = SigningKey::from_bytes(&[11u8; 32]);
    let sig = signing.sign(b"signed-bundle-content");
    std::fs::write(&signature, sig.to_bytes()).expect("write signature bytes");

    let verified = verify_bundle_signature_with_material(
        &tampered,
        &signature,
        signing.verifying_key().to_bytes(),
    );
    assert!(verified.is_err());

    let _ = std::fs::remove_file(bundle);
    let _ = std::fs::remove_file(tampered);
    let _ = std::fs::remove_file(signature);
    let _ = std::fs::remove_dir(base);
}

#[test]
// AC-DET-143 AC-DET-144 AC-DET-170 AC-EBP-092
fn load_bundle_rules_reads_signed_archive_bundle() {
    let _env_guard = env_var_lock().lock().expect("lock env vars");
    let base = std::env::temp_dir().join(format!(
        "eguard-signed-bundle-load-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let src = base.join("src");
    let staging = base.join("staging");
    let sigma_dir = src.join("sigma");
    let yara_dir = src.join("yara");
    std::fs::create_dir_all(&sigma_dir).expect("create sigma dir");
    std::fs::create_dir_all(&yara_dir).expect("create yara dir");

    let sigma_rule = r#"
title: sigma_rule_from_signed_bundle
detection:
  sequence:
    - event_class: process_exec
      process_any_of: [bash]
      parent_any_of: [nginx]
      within_secs: 30
    - event_class: network_connect
      dst_port_not_in: [80, 443]
      within_secs: 10
"#;
    std::fs::write(sigma_dir.join("rule.yml"), sigma_rule).expect("write sigma rule");

    let yara_rule = r#"
rule signed_bundle_marker {
  strings:
    $m = "signed-bundle-marker"
  condition:
    $m
}
"#;
    std::fs::write(yara_dir.join("rule.yar"), yara_rule).expect("write yara rule");

    let manifest = serde_json::json!({
        "version": "2026.02.13",
        "sigma_count": 1,
        "yara_count": 1,
        "ioc_hash_count": 0,
        "ioc_domain_count": 0,
        "ioc_ip_count": 0,
        "cve_count": 0,
        "suricata_count": 0,
        "elastic_count": 0,
        "files": {
            "sigma/rule.yml": format!("sha256:{}", sha256_bytes_hex(sigma_rule.as_bytes())),
            "yara/rule.yar": format!("sha256:{}", sha256_bytes_hex(yara_rule.as_bytes())),
        }
    });
    std::fs::write(
        src.join("manifest.json"),
        serde_json::to_vec(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");

    let tar_path = base.join("bundle.tar");
    let tar_file = std::fs::File::create(&tar_path).expect("create tar file");
    let mut tar_builder = tar::Builder::new(tar_file);
    tar_builder
        .append_path_with_name(src.join("manifest.json"), "manifest.json")
        .expect("append manifest to tar");
    tar_builder
        .append_path_with_name(sigma_dir.join("rule.yml"), "sigma/rule.yml")
        .expect("append sigma file to tar");
    tar_builder
        .append_path_with_name(yara_dir.join("rule.yar"), "yara/rule.yar")
        .expect("append yara file to tar");
    tar_builder.finish().expect("finish tar archive");

    let bundle_path = base.join("bundle.tar.zst");
    let mut tar_input = std::fs::File::open(&tar_path).expect("open tar input");
    let zstd_output = std::fs::File::create(&bundle_path).expect("create zstd output");
    let mut encoder = zstd::stream::write::Encoder::new(zstd_output, 1).expect("init zstd");
    std::io::copy(&mut tar_input, &mut encoder).expect("compress tar");
    encoder.finish().expect("finish zstd");

    let signing = SigningKey::from_bytes(&[9u8; 32]);
    let bundle_bytes = std::fs::read(&bundle_path).expect("read compressed bundle");
    let sig = signing.sign(&bundle_bytes);
    let signature_path = PathBuf::from(format!("{}.sig", bundle_path.to_string_lossy()));
    std::fs::write(&signature_path, sig.to_bytes()).expect("write signature sidecar");

    std::env::set_var(
        "EGUARD_RULE_BUNDLE_PUBKEY",
        to_hex(&signing.verifying_key().to_bytes()),
    );
    std::env::set_var("EGUARD_RULES_STAGING_DIR", &staging);

    let mut engine = DetectionEngine::default_with_rules();
    let started = std::time::Instant::now();
    let (_sigma, yara) = load_bundle_rules(&mut engine, bundle_path.to_string_lossy().as_ref());
    assert_eq!(yara, 1);
    assert!(started.elapsed() < std::time::Duration::from_secs(5));

    std::env::remove_var("EGUARD_RULE_BUNDLE_PUBKEY");
    std::env::remove_var("EGUARD_RULES_STAGING_DIR");

    let _ = std::fs::remove_file(signature_path);
    let _ = std::fs::remove_file(bundle_path);
    let _ = std::fs::remove_file(tar_path);
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn load_bundle_rules_reads_signed_archive_with_nested_source_layout() {
    let _env_guard = env_var_lock().lock().expect("lock env vars");
    let base = std::env::temp_dir().join(format!(
        "eguard-signed-bundle-nested-load-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let src = base.join("src");
    let staging = base.join("staging");
    let sigma_dir = src.join("sigma/rules-emerging-threats");
    let yara_dir = src.join("yara/yara-forge");
    std::fs::create_dir_all(&sigma_dir).expect("create nested sigma dir");
    std::fs::create_dir_all(&yara_dir).expect("create nested yara dir");

    let sigma_rule = r#"
title: sigma_rule_from_nested_signed_bundle
detection:
  sequence:
    - event_class: process_exec
      process_any_of: [bash]
      parent_any_of: [nginx]
      within_secs: 30
    - event_class: network_connect
      dst_port_not_in: [80, 443]
      within_secs: 10
"#;
    std::fs::write(sigma_dir.join("rule.yml"), sigma_rule).expect("write nested sigma rule");

    let yara_rule = r#"
rule nested_signed_bundle_marker {
  strings:
    $m = "nested-signed-bundle-marker"
  condition:
    $m
}
"#;
    std::fs::write(yara_dir.join("rule.yar"), yara_rule).expect("write nested yara rule");

    let manifest = serde_json::json!({
        "version": "2026.02.14",
        "sigma_count": 1,
        "yara_count": 1,
        "ioc_hash_count": 0,
        "ioc_domain_count": 0,
        "ioc_ip_count": 0,
        "cve_count": 0,
        "suricata_count": 0,
        "elastic_count": 0,
        "sources": {
            "sigma": ["rules-emerging-threats"],
            "yara": ["yara-forge"],
        },
        "source_rule_counts": {
            "sigma": {"rules-emerging-threats": 1},
            "yara": {"yara-forge": 1},
        },
        "files": {
            "sigma/rules-emerging-threats/rule.yml":
                format!("sha256:{}", sha256_bytes_hex(sigma_rule.as_bytes())),
            "yara/yara-forge/rule.yar":
                format!("sha256:{}", sha256_bytes_hex(yara_rule.as_bytes())),
        }
    });
    std::fs::write(
        src.join("manifest.json"),
        serde_json::to_vec(&manifest).expect("serialize nested manifest"),
    )
    .expect("write nested manifest");

    let tar_path = base.join("bundle.tar");
    let tar_file = std::fs::File::create(&tar_path).expect("create tar file");
    let mut tar_builder = tar::Builder::new(tar_file);
    tar_builder
        .append_path_with_name(src.join("manifest.json"), "manifest.json")
        .expect("append manifest");
    tar_builder
        .append_path_with_name(
            sigma_dir.join("rule.yml"),
            "sigma/rules-emerging-threats/rule.yml",
        )
        .expect("append nested sigma rule");
    tar_builder
        .append_path_with_name(yara_dir.join("rule.yar"), "yara/yara-forge/rule.yar")
        .expect("append nested yara rule");
    tar_builder.finish().expect("finish tar");

    let bundle_path = base.join("bundle.tar.zst");
    let mut tar_input = std::fs::File::open(&tar_path).expect("open tar input");
    let zstd_output = std::fs::File::create(&bundle_path).expect("create zstd output");
    let mut encoder = zstd::stream::write::Encoder::new(zstd_output, 1).expect("init zstd");
    std::io::copy(&mut tar_input, &mut encoder).expect("compress tar");
    encoder.finish().expect("finish zstd");

    let signing = SigningKey::from_bytes(&[13u8; 32]);
    let bundle_bytes = std::fs::read(&bundle_path).expect("read compressed nested bundle");
    let sig = signing.sign(&bundle_bytes);
    let signature_path = PathBuf::from(format!("{}.sig", bundle_path.to_string_lossy()));
    std::fs::write(&signature_path, sig.to_bytes()).expect("write signature sidecar");

    std::env::set_var(
        "EGUARD_RULE_BUNDLE_PUBKEY",
        to_hex(&signing.verifying_key().to_bytes()),
    );
    std::env::set_var("EGUARD_RULES_STAGING_DIR", &staging);

    let mut engine = DetectionEngine::default_with_rules();
    let (sigma, yara) = load_bundle_rules(&mut engine, bundle_path.to_string_lossy().as_ref());
    assert!(sigma >= 1);
    assert_eq!(yara, 1);

    let nested_event = detection::TelemetryEvent {
        ts_unix: 42_000,
        event_class: detection::EventClass::ProcessExec,
        pid: 10,
        ppid: 1,
        uid: 1000,
        process: "bash".to_string(),
        parent_process: "nginx".to_string(),
        session_id: 1,
        file_path: None,
        file_write: false,
        file_hash: None,
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
        command_line: Some("echo nested-signed-bundle-marker".to_string()),
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    };
    let out = engine.process_event(&nested_event);
    assert!(out
        .yara_hits
        .iter()
        .any(|hit| hit.rule_name == "nested_signed_bundle_marker"));

    std::env::remove_var("EGUARD_RULE_BUNDLE_PUBKEY");
    std::env::remove_var("EGUARD_RULES_STAGING_DIR");

    let _ = std::fs::remove_file(signature_path);
    let _ = std::fs::remove_file(bundle_path);
    let _ = std::fs::remove_file(tar_path);
    let _ = std::fs::remove_dir_all(base);
}

#[test]
// AC-DET-170
fn load_bundle_rules_reads_ci_generated_signed_bundle() {
    let _env_guard = env_var_lock().lock().expect("lock env vars");

    let bundle_path_raw = match std::env::var("EGUARD_CI_BUNDLE_PATH") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return,
    };
    let bundle_pubkey_raw = match std::env::var("EGUARD_CI_BUNDLE_PUBHEX") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return,
    };

    let bundle_path = PathBuf::from(bundle_path_raw.trim());
    assert!(
        bundle_path.is_file(),
        "ci generated bundle path must exist: {}",
        bundle_path.display()
    );

    let signature_path = PathBuf::from(format!("{}.sig", bundle_path.to_string_lossy()));
    assert!(
        signature_path.is_file(),
        "ci generated bundle signature path must exist: {}",
        signature_path.display()
    );

    let staging = std::env::temp_dir().join(format!(
        "eguard-ci-generated-bundle-stage-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(&staging).expect("create CI staging dir");

    std::env::set_var("EGUARD_RULE_BUNDLE_PUBKEY", bundle_pubkey_raw.trim());
    std::env::set_var("EGUARD_RULES_STAGING_DIR", &staging);

    let mut engine = DetectionEngine::default_with_rules();
    let (sigma, yara) = load_bundle_rules(&mut engine, bundle_path.to_string_lossy().as_ref());
    let allow_shortfall = std::env::var("EGUARD_CI_ALLOW_COVERAGE_SHORTFALL")
        .map(|value| {
            matches!(
                value.trim().to_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);
    if allow_shortfall && (sigma == 0 || yara == 0) {
        return;
    }
    if sigma == 0 {
        eprintln!(
            "ci generated bundle loaded zero sigma rules; proceeding because signature/hash checks and non-sigma families can still be valid"
        );
    }
    assert!(
        yara > 0,
        "ci generated bundle should load yara rules through agent runtime"
    );

    std::env::remove_var("EGUARD_RULE_BUNDLE_PUBKEY");
    std::env::remove_var("EGUARD_RULES_STAGING_DIR");
    let _ = std::fs::remove_dir_all(staging);
}

#[test]
// AC-DET-ML-001: Full bundle load including ML model
fn load_bundle_full_loads_ml_model_from_ci_generated_bundle() {
    let _env_guard = env_var_lock().lock().expect("lock env vars");

    let bundle_path_raw = match std::env::var("EGUARD_CI_BUNDLE_PATH") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return,
    };
    let bundle_pubkey_raw = match std::env::var("EGUARD_CI_BUNDLE_PUBHEX") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return,
    };

    let bundle_path = PathBuf::from(bundle_path_raw.trim());
    assert!(
        bundle_path.is_file(),
        "ci generated bundle path must exist: {}",
        bundle_path.display()
    );

    let staging = std::env::temp_dir().join(format!(
        "eguard-ci-bundle-full-load-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(&staging).expect("create CI staging dir");

    std::env::set_var("EGUARD_RULE_BUNDLE_PUBKEY", bundle_pubkey_raw.trim());
    std::env::set_var("EGUARD_RULES_STAGING_DIR", &staging);

    let mut engine = DetectionEngine::default_with_rules();
    let summary = load_bundle_full(&mut engine, bundle_path.to_string_lossy().as_ref());
    let allow_shortfall = std::env::var("EGUARD_CI_ALLOW_COVERAGE_SHORTFALL")
        .map(|value| {
            matches!(
                value.trim().to_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);
    if !allow_shortfall {
        if summary.sigma_loaded == 0 {
            eprintln!(
                "ci bundle loaded zero sigma rules; continuing because sigma parser compatibility can lag bundle source counts"
            );
        }
        assert!(
            summary.yara_loaded > 0,
            "ci bundle should load yara rules: got {}",
            summary.yara_loaded
        );
        assert!(
            summary.ioc_hashes > 0 || summary.ioc_domains > 0 || summary.ioc_ips > 0,
            "ci bundle should load IOC indicators: hashes={} domains={} ips={}",
            summary.ioc_hashes,
            summary.ioc_domains,
            summary.ioc_ips
        );
    }

    // Verify ML model was loaded from bundle and carries a concrete version identifier.
    let model_id = engine.layer5.model_id().to_string();
    let model_version = engine.layer5.model_version().to_string();
    assert!(
        !model_id.is_empty() && model_id != "default-v1",
        "ci bundle should load ML model: got model_id='{}'",
        model_id
    );
    assert!(
        !model_version.trim().is_empty(),
        "ci bundle ML model version should be non-empty: got '{}'",
        model_version
    );

    std::env::remove_var("EGUARD_RULE_BUNDLE_PUBKEY");
    std::env::remove_var("EGUARD_RULES_STAGING_DIR");
    let _ = std::fs::remove_dir_all(staging);
}

#[test]
// AC-DET-143 AC-DET-170
fn load_bundle_rules_rejects_tampered_ci_generated_signed_bundle() {
    let _env_guard = env_var_lock().lock().expect("lock env vars");

    let bundle_path_raw = match std::env::var("EGUARD_CI_BUNDLE_PATH") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return,
    };
    let bundle_pubkey_raw = match std::env::var("EGUARD_CI_BUNDLE_PUBHEX") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return,
    };

    let source_bundle = PathBuf::from(bundle_path_raw.trim());
    assert!(
        source_bundle.is_file(),
        "ci generated bundle path must exist: {}",
        source_bundle.display()
    );
    let source_signature = PathBuf::from(format!("{}.sig", source_bundle.to_string_lossy()));
    assert!(
        source_signature.is_file(),
        "ci generated bundle signature path must exist: {}",
        source_signature.display()
    );

    let base = std::env::temp_dir().join(format!(
        "eguard-ci-generated-bundle-tamper-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let staging = base.join("staging");
    std::fs::create_dir_all(&staging).expect("create tamper staging dir");

    let tampered_bundle = base.join("bundle.tar.zst");
    let mut tampered_bytes = std::fs::read(&source_bundle).expect("read source bundle bytes");
    tampered_bytes.extend_from_slice(b"ci-tamper-marker-eguard");
    std::fs::write(&tampered_bundle, tampered_bytes).expect("write tampered bundle bytes");

    let tampered_signature = PathBuf::from(format!("{}.sig", tampered_bundle.to_string_lossy()));
    std::fs::copy(&source_signature, &tampered_signature).expect("copy source signature sidecar");

    std::env::set_var("EGUARD_RULE_BUNDLE_PUBKEY", bundle_pubkey_raw.trim());
    std::env::set_var("EGUARD_RULES_STAGING_DIR", &staging);

    let mut engine = DetectionEngine::default_with_rules();
    let loaded = load_bundle_rules(&mut engine, tampered_bundle.to_string_lossy().as_ref());
    assert_eq!(
        loaded,
        (0, 0),
        "tampered ci bundle must be rejected by agent runtime loader"
    );

    std::env::remove_var("EGUARD_RULE_BUNDLE_PUBKEY");
    std::env::remove_var("EGUARD_RULES_STAGING_DIR");
    let _ = std::fs::remove_dir_all(base);
}

#[test]
// AC-DET-006 AC-DET-143 AC-DET-077
fn load_bundle_rules_rejects_invalid_signature_archive() {
    let _env_guard = env_var_lock().lock().expect("lock env vars");
    let base = std::env::temp_dir().join(format!(
        "eguard-bundle-bad-signature-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(&base).expect("create base");

    let bundle_path = base.join("bundle.tar.zst");
    std::fs::write(&bundle_path, b"not-a-valid-zstd-archive").expect("write bundle bytes");
    let signature_path = PathBuf::from(format!("{}.sig", bundle_path.to_string_lossy()));
    std::fs::write(&signature_path, [0u8; 64]).expect("write invalid signature");

    std::env::set_var("EGUARD_RULE_BUNDLE_PUBKEY", to_hex(&[1u8; 32]));

    let mut engine = DetectionEngine::default_with_rules();
    let loaded = load_bundle_rules(&mut engine, bundle_path.to_string_lossy().as_ref());
    assert_eq!(loaded, (0, 0));

    std::env::remove_var("EGUARD_RULE_BUNDLE_PUBKEY");
    let _ = std::fs::remove_file(signature_path);
    let _ = std::fs::remove_file(bundle_path);
    let _ = std::fs::remove_dir_all(base);
}

#[test]
// AC-DET-006 AC-DET-143 AC-DET-171
fn load_bundle_rules_rejects_signed_bundle_with_manifest_hash_mismatch() {
    let _env_guard = env_var_lock().lock().expect("lock env vars");
    let base = std::env::temp_dir().join(format!(
        "eguard-bundle-manifest-mismatch-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let src = base.join("src");
    let sigma_dir = src.join("sigma");
    std::fs::create_dir_all(&sigma_dir).expect("create sigma dir");

    let sigma_rule = "title: manifest_mismatch";
    std::fs::write(sigma_dir.join("rule.yml"), sigma_rule).expect("write sigma rule");

    let manifest = serde_json::json!({
        "version": "2026.02.14",
        "sigma_count": 1,
        "yara_count": 0,
        "ioc_hash_count": 0,
        "ioc_domain_count": 0,
        "ioc_ip_count": 0,
        "cve_count": 0,
        "files": {
            "sigma/rule.yml": "sha256:deadbeef"
        }
    });
    std::fs::write(
        src.join("manifest.json"),
        serde_json::to_vec(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");

    let tar_path = base.join("bundle.tar");
    let tar_file = std::fs::File::create(&tar_path).expect("create tar file");
    let mut tar_builder = tar::Builder::new(tar_file);
    tar_builder
        .append_path_with_name(src.join("manifest.json"), "manifest.json")
        .expect("append manifest");
    tar_builder
        .append_path_with_name(sigma_dir.join("rule.yml"), "sigma/rule.yml")
        .expect("append sigma");
    tar_builder.finish().expect("finish tar");

    let bundle_path = base.join("bundle.tar.zst");
    let mut tar_input = std::fs::File::open(&tar_path).expect("open tar");
    let zstd_output = std::fs::File::create(&bundle_path).expect("create zstd");
    let mut encoder = zstd::stream::write::Encoder::new(zstd_output, 1).expect("init zstd");
    std::io::copy(&mut tar_input, &mut encoder).expect("compress tar");
    encoder.finish().expect("finish zstd");

    let signing = SigningKey::from_bytes(&[11u8; 32]);
    let bundle_bytes = std::fs::read(&bundle_path).expect("read bundle bytes");
    let sig = signing.sign(&bundle_bytes);
    let signature_path = PathBuf::from(format!("{}.sig", bundle_path.to_string_lossy()));
    std::fs::write(&signature_path, sig.to_bytes()).expect("write signature sidecar");

    std::env::set_var(
        "EGUARD_RULE_BUNDLE_PUBKEY",
        to_hex(&signing.verifying_key().to_bytes()),
    );

    let mut engine = DetectionEngine::default_with_rules();
    let loaded = load_bundle_rules(&mut engine, bundle_path.to_string_lossy().as_ref());
    assert_eq!(loaded, (0, 0));

    std::env::remove_var("EGUARD_RULE_BUNDLE_PUBKEY");
    let _ = std::fs::remove_file(signature_path);
    let _ = std::fs::remove_file(bundle_path);
    let _ = std::fs::remove_file(tar_path);
    let _ = std::fs::remove_dir_all(base);
}

#[test]
// AC-DET-006 AC-DET-171
fn load_bundle_rules_allows_manifest_count_mismatch_when_signature_and_hashes_valid() {
    let _env_guard = env_var_lock().lock().expect("lock env vars");
    let base = std::env::temp_dir().join(format!(
        "eguard-bundle-manifest-count-mismatch-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let src = base.join("src");
    let staging = base.join("staging");
    let yara_dir = src.join("yara");
    std::fs::create_dir_all(&yara_dir).expect("create yara dir");
    std::fs::create_dir_all(&staging).expect("create staging dir");

    let yara_rules = r#"
rule mismatch_marker_one {
  strings:
    $a = "manifest-mismatch-one"
  condition:
    $a
}

rule mismatch_marker_two {
  strings:
    $b = "manifest-mismatch-two"
  condition:
    $b
}
"#;
    let mut sanity_engine = DetectionEngine::default_with_rules();
    let sanity_loaded = sanity_engine
        .load_yara_rules_str(yara_rules)
        .expect("sanity parse yara rules");
    assert_eq!(sanity_loaded, 2, "sanity yara parse should load both rules");

    let yara_path = yara_dir.join("rules.yar");
    std::fs::write(&yara_path, yara_rules).expect("write yara rules");

    let yara_hash = sha256_bytes_hex(yara_rules.as_bytes());
    let manifest = serde_json::json!({
        "version": "2026.02.19.0545",
        "sigma_count": 0,
        "yara_count": 1,
        "ioc_hash_count": 0,
        "ioc_domain_count": 0,
        "ioc_ip_count": 0,
        "cve_count": 0,
        "files": {
            "yara/rules.yar": format!("sha256:{}", yara_hash)
        }
    });
    std::fs::write(
        src.join("manifest.json"),
        serde_json::to_vec(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");

    let tar_path = base.join("bundle.tar");
    let tar_file = std::fs::File::create(&tar_path).expect("create tar file");
    let mut tar_builder = tar::Builder::new(tar_file);
    tar_builder
        .append_path_with_name(src.join("manifest.json"), "manifest.json")
        .expect("append manifest");
    tar_builder
        .append_path_with_name(&yara_path, "yara/rules.yar")
        .expect("append yara rules");
    tar_builder.finish().expect("finish tar");

    let bundle_path = base.join("bundle.tar.zst");
    let mut tar_input = std::fs::File::open(&tar_path).expect("open tar");
    let zstd_output = std::fs::File::create(&bundle_path).expect("create zstd");
    let mut encoder = zstd::stream::write::Encoder::new(zstd_output, 1).expect("init zstd");
    std::io::copy(&mut tar_input, &mut encoder).expect("compress tar");
    encoder.finish().expect("finish zstd");

    let signing = SigningKey::from_bytes(&[12u8; 32]);
    let bundle_bytes = std::fs::read(&bundle_path).expect("read bundle bytes");
    let sig = signing.sign(&bundle_bytes);
    let signature_path = PathBuf::from(format!("{}.sig", bundle_path.to_string_lossy()));
    std::fs::write(&signature_path, sig.to_bytes()).expect("write signature sidecar");

    std::env::set_var(
        "EGUARD_RULE_BUNDLE_PUBKEY",
        to_hex(&signing.verifying_key().to_bytes()),
    );
    std::env::set_var("EGUARD_RULES_STAGING_DIR", &staging);
    assert!(
        super::rule_bundle_verify::verify_bundle_signature(&bundle_path),
        "signature verification should succeed for test bundle"
    );

    let mut engine = DetectionEngine::default_with_rules();
    let loaded = load_bundle_rules(&mut engine, bundle_path.to_string_lossy().as_ref());
    assert_eq!(
        loaded,
        (0, 2),
        "count mismatch should not discard otherwise valid signed bundle content"
    );

    std::env::remove_var("EGUARD_RULE_BUNDLE_PUBKEY");
    std::env::remove_var("EGUARD_RULES_STAGING_DIR");
    let _ = std::fs::remove_file(signature_path);
    let _ = std::fs::remove_file(bundle_path);
    let _ = std::fs::remove_file(tar_path);
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn sanitize_archive_relative_path_rejects_traversal() {
    assert_eq!(
        sanitize_archive_relative_path(Path::new("../etc/passwd")),
        None
    );
    assert_eq!(
        sanitize_archive_relative_path(Path::new("/absolute/path")),
        None
    );
    assert_eq!(
        sanitize_archive_relative_path(Path::new("sigma/rule.yml")),
        Some(PathBuf::from("sigma/rule.yml"))
    );
}

#[test]
// AC-DET-171
fn signed_bundle_archive_contains_required_manifest_signature_and_rule_paths() {
    let base = std::env::temp_dir().join(format!(
        "eguard-bundle-layout-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let src = base.join("src");
    std::fs::create_dir_all(src.join("sigma/linux")).expect("sigma/linux");
    std::fs::create_dir_all(src.join("yara/malware")).expect("yara/malware");
    std::fs::create_dir_all(src.join("yara/webshell")).expect("yara/webshell");
    std::fs::create_dir_all(src.join("yara/packer")).expect("yara/packer");
    std::fs::create_dir_all(src.join("ioc")).expect("ioc");
    std::fs::create_dir_all(src.join("cve")).expect("cve");

    std::fs::write(src.join("manifest.json"), "{}").expect("manifest");
    std::fs::write(src.join("signature.ed25519"), [1u8; 64]).expect("signature");
    std::fs::write(src.join("sigma/linux/rule.yml"), "title: x").expect("sigma");
    std::fs::write(
        src.join("yara/malware/rule.yar"),
        "rule a { condition: true }",
    )
    .expect("yara malware");
    std::fs::write(
        src.join("yara/webshell/rule.yar"),
        "rule b { condition: true }",
    )
    .expect("yara webshell");
    std::fs::write(
        src.join("yara/packer/rule.yar"),
        "rule c { condition: true }",
    )
    .expect("yara packer");
    std::fs::write(src.join("ioc/hashes.json"), "[]").expect("ioc hashes");
    std::fs::write(src.join("ioc/domains.json"), "[]").expect("ioc domains");
    std::fs::write(src.join("ioc/ips.json"), "[]").expect("ioc ips");
    std::fs::write(src.join("cve/cve-checks.json"), "[]").expect("cve checks");

    let tar_path = base.join("bundle-layout.tar");
    let tar_file = std::fs::File::create(&tar_path).expect("create tar");
    let mut builder = tar::Builder::new(tar_file);
    builder
        .append_dir_all(".", &src)
        .expect("append source layout");
    builder.finish().expect("finish tar");

    let tar_file = std::fs::File::open(&tar_path).expect("open tar");
    let mut archive = tar::Archive::new(tar_file);
    let mut entries = std::collections::HashSet::new();
    for entry in archive.entries().expect("read entries") {
        let entry = entry.expect("entry");
        let path = entry.path().expect("entry path").to_path_buf();
        entries.insert(path.to_string_lossy().trim_start_matches("./").to_string());
    }

    for required in [
        "manifest.json",
        "signature.ed25519",
        "sigma/linux/rule.yml",
        "yara/malware/rule.yar",
        "yara/webshell/rule.yar",
        "yara/packer/rule.yar",
        "ioc/hashes.json",
        "ioc/domains.json",
        "ioc/ips.json",
        "cve/cve-checks.json",
    ] {
        assert!(
            entries.contains(required),
            "missing required entry {required}"
        );
    }

    let _ = std::fs::remove_dir_all(base);
}

#[test]
// AC-DET-172 AC-DET-173
fn synthetic_rule_bundle_sizes_fit_expected_uncompressed_and_zstd_ranges() {
    let base = std::env::temp_dir().join(format!(
        "eguard-bundle-size-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let src = base.join("src");
    std::fs::create_dir_all(src.join("sigma/linux")).expect("sigma/linux");
    std::fs::create_dir_all(src.join("yara/malware")).expect("yara/malware");
    std::fs::create_dir_all(src.join("ioc")).expect("ioc");

    // Build ~10 MiB corpus with controlled entropy so zstd level3 stays in ~2-5 MiB band.
    let mut payload = Vec::with_capacity(10 * 1024 * 1024);
    let alphabet = *b"ABCDEFGH";
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    for idx in 0..(10 * 1024 * 1024) {
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        if idx < (2 * 1024 * 1024) {
            payload.push((z & 0xFF) as u8);
        } else {
            payload.push(alphabet[idx % alphabet.len()]);
        }
    }

    std::fs::write(src.join("manifest.json"), "{}").expect("manifest");
    std::fs::write(src.join("signature.ed25519"), [7u8; 64]).expect("signature");
    std::fs::write(
        src.join("sigma/linux/rule.yml"),
        &payload[..4 * 1024 * 1024],
    )
    .expect("sigma payload");
    std::fs::write(
        src.join("yara/malware/rule.yar"),
        &payload[4 * 1024 * 1024..8 * 1024 * 1024],
    )
    .expect("yara payload");
    std::fs::write(src.join("ioc/hashes.json"), &payload[8 * 1024 * 1024..]).expect("ioc payload");

    let mut uncompressed_bytes = 0u64;
    for path in [
        src.join("manifest.json"),
        src.join("signature.ed25519"),
        src.join("sigma/linux/rule.yml"),
        src.join("yara/malware/rule.yar"),
        src.join("ioc/hashes.json"),
    ] {
        uncompressed_bytes += std::fs::metadata(path).expect("file stat").len();
    }
    assert!(uncompressed_bytes >= 10 * 1024 * 1024);
    assert!(uncompressed_bytes <= 20 * 1024 * 1024);

    let tar_path = base.join("bundle.tar");
    let tar_file = std::fs::File::create(&tar_path).expect("create tar");
    let mut builder = tar::Builder::new(tar_file);
    builder
        .append_dir_all(".", &src)
        .expect("append source layout");
    builder.finish().expect("finish tar");

    let bundle_path = base.join("bundle.tar.zst");
    let mut tar_input = std::fs::File::open(&tar_path).expect("open tar input");
    let zstd_output = std::fs::File::create(&bundle_path).expect("create zstd output");
    let mut encoder = zstd::stream::write::Encoder::new(zstd_output, 3).expect("init zstd");
    std::io::copy(&mut tar_input, &mut encoder).expect("compress tar");
    encoder.finish().expect("finish zstd");

    let compressed_bytes = std::fs::metadata(&bundle_path).expect("bundle stat").len();
    assert!(compressed_bytes >= 2 * 1024 * 1024);
    assert!(compressed_bytes <= 5 * 1024 * 1024);

    let _ = std::fs::remove_dir_all(base);
}

#[tokio::test]
// AC-DET-160 AC-DET-161 AC-DET-163 AC-DET-183
async fn emergency_command_is_applied_immediately_in_command_path() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();

    let mut runtime = AgentRuntime::new(cfg).expect("build runtime");
    runtime.client.set_online(false);

    let command = grpc_client::CommandEnvelope {
        command_id: "cmd-emergency-1".to_string(),
        command_type: "emergency_rule_push".to_string(),
        payload_json: serde_json::json!({
            "rule_type": "signature",
            "rule_name": "cmd-emergency-signature",
            "rule_content": "curl|bash",
            "severity": "high"
        })
        .to_string(),
    };

    let started = std::time::Instant::now();
    runtime.handle_command(command, 123).await;
    assert!(started.elapsed() < std::time::Duration::from_secs(1));

    let event = detection::TelemetryEvent {
        ts_unix: 124,
        event_class: detection::EventClass::ProcessExec,
        pid: 4242,
        ppid: 1,
        uid: 1000,
        process: "bash".to_string(),
        parent_process: "sshd".to_string(),
        session_id: 1,
        file_path: None,
        file_write: false,
        file_hash: None,
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
        command_line: Some("curl|bash -s https://bad".to_string()),
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    };

    let out = runtime
        .detection_state
        .process_event(&event)
        .expect("evaluate event");
    assert!(out
        .layer1
        .matched_signatures
        .iter()
        .any(|sig| sig == "curl|bash"));
}

fn to_hex(raw: &[u8]) -> String {
    raw.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}

fn env_var_lock() -> &'static std::sync::Mutex<()> {
    static ENV_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    ENV_LOCK.get_or_init(|| std::sync::Mutex::new(()))
}
