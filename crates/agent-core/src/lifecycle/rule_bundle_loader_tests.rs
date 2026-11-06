use super::*;
use detection::DetectionEngine;

#[test]
fn yara_files_load_without_per_file_sleep() {
    let dir = std::env::temp_dir().join(format!("eguard-rafix-yara-load-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for i in 0..3 {
        std::fs::write(dir.join(format!("{i}.yar")), format!("rule eguard_fixture_{i} {{\n strings:\n  $x = \"fixture\"\n condition:\n  $x at 0 and filesize <= 128\n}}\n")).unwrap();
    }
    let mut engine = DetectionEngine::default_with_rules();
    let start = std::time::Instant::now();
    assert_eq!(load_yara_rules_recursive(&mut engine, &dir), 3);
    let elapsed = start.elapsed();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "three trivial files took {elapsed:?}"
    );
}

struct SignedFixture {
    base: PathBuf,
    source: PathBuf,
    archive: PathBuf,
}

impl Drop for SignedFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn signed_fixture(sigma: Option<&str>, yara: Option<&str>, extra_sigma: usize) -> SignedFixture {
    use ed25519_dalek::{Signer, SigningKey};
    let base = std::env::temp_dir().join(format!(
        "eguard-rafix-corrob-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let source = base.join("source");
    fs::create_dir_all(source.join("ioc")).unwrap();
    fs::write(
        source.join("ioc/hashes.txt"),
        format!("{}\n", "a".repeat(64)),
    )
    .unwrap();
    let mut paths = vec!["ioc/hashes.txt"];
    if let Some(rule) = sigma {
        fs::create_dir_all(source.join("sigma")).unwrap();
        fs::write(source.join("sigma/foreign.yml"), rule).unwrap();
        paths.push("sigma/foreign.yml");
    }
    if let Some(rule) = yara {
        fs::create_dir_all(source.join("yara")).unwrap();
        fs::write(source.join("yara/community.yar"), rule).unwrap();
        paths.push("yara/community.yar");
    }
    let hashes: HashMap<_, _> = paths
        .iter()
        .map(|path| {
            (
                path.to_string(),
                format!("sha256:{}", sha256_file_hex(&source.join(path)).unwrap()),
            )
        })
        .collect();
    let manifest = serde_json::json!({"version":"fixture","sigma_count":usize::from(sigma.is_some())+extra_sigma,
        "yara_count":usize::from(yara.is_some()),"ioc_hash_count":1,"ioc_domain_count":0,"ioc_ip_count":0,"cve_count":0,"files":hashes});
    fs::write(
        source.join("manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    paths.push("manifest.json");
    let archive = base.join("fixture.tar.zst");
    let encoder =
        zstd::stream::write::Encoder::new(fs::File::create(&archive).unwrap(), 1).unwrap();
    let mut tar = tar::Builder::new(encoder);
    for path in paths {
        tar.append_path_with_name(source.join(path), path).unwrap();
    }
    let encoder = tar.into_inner().unwrap();
    encoder.finish().unwrap();
    // Public, deterministic TEST material only. No production key files are read.
    let signing = SigningKey::from_bytes(&[42; 32]);
    let signature = signing.sign(&fs::read(&archive).unwrap());
    fs::write(format!("{}.sig", archive.display()), signature.to_bytes()).unwrap();
    let public: String = signing
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    std::env::remove_var("EGUARD_RULE_BUNDLE_PUBKEY_PATH");
    std::env::set_var("EGUARD_RULE_BUNDLE_PUBKEY", public);
    std::env::set_var("EGUARD_RULES_STAGING_DIR", base.join("staging"));
    std::env::set_var("EGUARD_IOC_EXACT_STORE", "false");
    SignedFixture {
        base,
        source,
        archive,
    }
}

const FOREIGN: &str = "title: foreign_fixture\nid: foreign_fixture\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains: synthetic_payload\n  condition: selection\n";

#[test]
#[cfg(target_os = "linux")]
fn foreign_platform_signed_fixture_preserves_other_layers_and_corroborates_files() {
    let _env = crate::test_support::TestEnvGuard::new(&[
        "EGUARD_RULE_BUNDLE_PUBKEY_PATH",
        "EGUARD_RULE_BUNDLE_PUBKEY",
        "EGUARD_RULES_STAGING_DIR",
        "EGUARD_IOC_EXACT_STORE",
    ]);
    let fixture = signed_fixture(Some(FOREIGN), None, 0);
    let manifest = read_bundle_manifest(&fixture.source).unwrap();
    verify_manifest_file_hashes(&fixture.source, &manifest).unwrap();
    let mut engine = DetectionEngine::default_with_rules();
    let summary = load_signed_bundle_archive_full(&mut engine, &fixture.archive);
    assert_eq!(summary.sigma_loaded, 0);
    assert_eq!(summary.ioc_hashes, 1);
    let counts = load_sigma_rules_recursive(
        &mut DetectionEngine::default_with_rules(),
        &fixture.source.join("sigma"),
    );
    assert_eq!(
        (counts.loaded, counts.platform_skipped, counts.failed),
        (0, 1, 0)
    );
    assert!(corroborate_summary_against_manifest(&summary, &manifest, &fixture.source).is_ok());
}

#[test]
#[cfg(target_os = "linux")]
fn physical_sigma_count_mismatch_warns_without_discarding_summary() {
    let _env = crate::test_support::TestEnvGuard::new(&[
        "EGUARD_RULE_BUNDLE_PUBKEY_PATH",
        "EGUARD_RULE_BUNDLE_PUBKEY",
        "EGUARD_RULES_STAGING_DIR",
        "EGUARD_IOC_EXACT_STORE",
    ]);
    let fixture = signed_fixture(Some(FOREIGN), None, 1);
    let manifest = read_bundle_manifest(&fixture.source).unwrap();
    let mut engine = DetectionEngine::default_with_rules();
    let before = load_bundle_all_layers(&mut engine, &fixture.source);
    let error = corroborate_summary_against_manifest(&before, &manifest, &fixture.source)
        .expect_err("physical + 1 must mismatch");
    assert!(error.contains("sigma_count"), "{error}");
    let mut next = DetectionEngine::default_with_rules();
    assert_eq!(
        load_signed_bundle_archive_full(&mut next, &fixture.archive),
        before,
        "count mismatch must remain warn-only"
    );
}

#[test]
fn rejected_yara_file_count_does_not_claim_loaded_rules() {
    let _env = crate::test_support::TestEnvGuard::new(&[
        "EGUARD_RULE_BUNDLE_PUBKEY_PATH",
        "EGUARD_RULE_BUNDLE_PUBKEY",
        "EGUARD_RULES_STAGING_DIR",
        "EGUARD_IOC_EXACT_STORE",
    ]);
    let yara = "rule vendor_fixture {\n strings:\n  $a = \"payload\"\n condition:\n  undefined_fixture_identifier\n}\n";
    let fixture = signed_fixture(None, Some(yara), 0);
    let manifest = read_bundle_manifest(&fixture.source).unwrap();
    let mut engine = DetectionEngine::default_with_rules();
    let summary = load_signed_bundle_archive_full(&mut engine, &fixture.archive);
    assert_eq!(summary.yara_loaded, 0);
    assert_eq!(summary.ioc_hashes, 1);
    assert!(corroborate_summary_against_manifest(&summary, &manifest, &fixture.source).is_ok());
}
