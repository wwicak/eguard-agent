use self_protect::{
    measure_self_integrity, DebuggerCheckConfig, SelfProtectConfig, SelfProtectEngine,
    SelfProtectViolation,
};

#[test]
fn measure_self_integrity_hashes_text_and_rodata_sections() {
    let measurement = measure_self_integrity().expect("measure self integrity");
    let sections = measurement
        .section_digests
        .iter()
        .map(|item| item.section.as_str())
        .collect::<Vec<_>>();

    assert_eq!(sections, vec![".text", ".rodata"]);
    assert_eq!(measurement.combined_sha256_hex.len(), 64);
}

#[test]
fn engine_reports_integrity_mismatch_when_expected_hash_differs() {
    let config = SelfProtectConfig {
        expected_integrity_sha256_hex: Some(
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        ),
        debugger: DebuggerCheckConfig {
            enable_tracer_pid_probe: false,
            enable_timing_probe: false,
            ..DebuggerCheckConfig::default()
        },
    };
    let engine = SelfProtectEngine::new(config);
    let report = engine.evaluate();

    assert!(report
        .violations
        .iter()
        .any(|violation| matches!(violation, SelfProtectViolation::IntegrityMismatch { .. })));
}

#[test]
fn engine_accepts_matching_integrity_hash() {
    let measurement = measure_self_integrity().expect("measure self integrity");
    let config = SelfProtectConfig {
        expected_integrity_sha256_hex: Some(measurement.combined_sha256_hex),
        debugger: DebuggerCheckConfig {
            enable_tracer_pid_probe: false,
            enable_timing_probe: false,
            ..DebuggerCheckConfig::default()
        },
    };
    let engine = SelfProtectEngine::new(config);
    let report = engine.evaluate();

    assert!(report
        .violations
        .iter()
        .all(|violation| !matches!(violation, SelfProtectViolation::IntegrityMismatch { .. })));
}
