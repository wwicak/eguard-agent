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
fn default_ebpf_object_dirs_include_expected_targets() {
    let dirs = default_ebpf_objects_dirs();
    assert!(dirs.iter().any(|d| d == &PathBuf::from("./zig-out/ebpf")));
    assert!(dirs.iter().any(|d| d == &PathBuf::from("zig-out/ebpf")));
    assert!(dirs
        .iter()
        .any(|d| d == &PathBuf::from("/usr/lib/eguard-agent/ebpf")));
}

#[test]
// AC-EBP-051 AC-EBP-052 AC-EBP-053 AC-EBP-054
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
// AC-DET-143 AC-DET-144 AC-DET-170
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
    let (_sigma, yara) = load_bundle_rules(&mut engine, bundle_path.to_string_lossy().as_ref());
    assert_eq!(yara, 1);
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

fn to_hex(raw: &[u8]) -> String {
    raw.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}
