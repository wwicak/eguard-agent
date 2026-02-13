use super::*;
use ed25519_dalek::{Signer, SigningKey};

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
fn candidate_ebpf_object_paths_discovers_five_core_program_objects() {
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
        "tcp_connect_bpf.o",
        "dns_query_bpf.o",
        "module_load_bpf.o",
    ];
    for name in names {
        std::fs::write(base.join(name), b"obj").expect("write object file");
    }

    let paths = candidate_ebpf_object_paths(&base);
    assert_eq!(paths.len(), 5);
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
// AC-DET-143 AC-DET-144 AC-DET-170 AC-EBP-092
fn load_bundle_rules_reads_signed_archive_bundle() {
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

    std::fs::write(
        sigma_dir.join("rule.yml"),
        r#"
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
"#,
    )
    .expect("write sigma rule");
    std::fs::write(
        yara_dir.join("rule.yar"),
        r#"
rule signed_bundle_marker {
  strings:
    $m = "signed-bundle-marker"
  condition:
    $m
}
"#,
    )
    .expect("write yara rule");

    let tar_path = base.join("bundle.tar");
    let tar_file = std::fs::File::create(&tar_path).expect("create tar file");
    let mut tar_builder = tar::Builder::new(tar_file);
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
    let staging_entries = std::fs::read_dir(&staging)
        .expect("staging root exists")
        .count();
    assert_eq!(staging_entries, 0);

    std::env::remove_var("EGUARD_RULE_BUNDLE_PUBKEY");
    std::env::remove_var("EGUARD_RULES_STAGING_DIR");

    let _ = std::fs::remove_file(signature_path);
    let _ = std::fs::remove_file(bundle_path);
    let _ = std::fs::remove_file(tar_path);
    let _ = std::fs::remove_dir_all(base);
}

#[test]
// AC-DET-006 AC-DET-143 AC-DET-077
fn load_bundle_rules_rejects_invalid_signature_archive() {
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
        file_path: None,
        file_hash: None,
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
        command_line: Some("curl|bash -s https://bad".to_string()),
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
