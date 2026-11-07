#![cfg(feature = "yara-x")]
#[path = "support/yara_fixtures.rs"]
mod fixtures;
use detection::{Confidence, YaraEngine};
#[test]
fn exact_curated_ids_and_every_family_positive_and_near_negative() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/yara");
    let mut engine = YaraEngine::new();
    assert_eq!(engine.load_rules_from_dir(&root).unwrap(), 10);
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("../../../threat-intel/yara-v1.json")).unwrap();
    let mut expected = manifest["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rule| rule["id"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    expected.push("eguard_eicar_test_file".into());
    expected.sort();
    assert_eq!(engine.rule_names(), expected);
    for (name, positive, negative) in fixtures::cases() {
        let hits = engine.scan_bytes(name, &positive);
        assert!(
            hits.iter()
                .any(|hit| hit.rule_name == name && hit.severity == Confidence::High),
            "missing {name}: {hits:?}"
        );
        assert!(
            engine.scan_bytes("near-negative", &negative).is_empty(),
            "near-negative matched {name}"
        );
        assert!(engine.take_incomplete().is_empty());
    }
}
#[test]
fn score_boundaries_are_real_rule_metadata_not_a_global_demotion() {
    for (metadata, expected) in [
        ("", Confidence::Medium),
        ("meta: score = 50", Confidence::Medium),
        ("meta: score = 69", Confidence::Medium),
        ("meta: score = 70", Confidence::High),
        ("meta: score = 100", Confidence::High),
        ("meta: score = 99.9", Confidence::Medium),
    ] {
        let mut engine = YaraEngine::new();
        engine
            .load_rules_str(&format!(
                "rule score {{ {metadata} condition: uint16(0) == 0x5A4D }}"
            ))
            .unwrap();
        assert_eq!(
            engine.scan_bytes("x", b"MZ")[0].severity,
            expected,
            "{metadata}"
        );
    }
}
