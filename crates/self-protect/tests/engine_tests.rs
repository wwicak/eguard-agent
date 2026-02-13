use self_protect::{
    normalize_sha256_hex, DebuggerCheckConfig, SelfProtectConfig, SelfProtectEngine,
    SelfProtectReport, SelfProtectViolation,
};
use std::sync::{Mutex, OnceLock};

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[test]
// AC-ATP-001
fn normalize_sha256_hex_accepts_trimmed_uppercase_and_rejects_invalid() {
    let upper = "  ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD  ";
    let normalized = normalize_sha256_hex(upper).expect("normalize valid hex");
    assert_eq!(normalized.len(), 64);
    assert!(normalized.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(normalized.chars().all(|c| !c.is_ascii_uppercase()));

    assert!(normalize_sha256_hex("abc").is_none());
    assert!(normalize_sha256_hex(&"g".repeat(64)).is_none());
}

#[test]
// AC-ATP-003 AC-ATP-004 AC-ATP-005
fn report_summary_and_violation_codes_include_debugger_signal_suffix() {
    let report = SelfProtectReport {
        integrity_measurement: None,
        debugger_observation: Default::default(),
        violations: vec![
            SelfProtectViolation::IntegrityProbeFailed {
                detail: "probe failed".to_string(),
            },
            SelfProtectViolation::DebuggerSignal {
                code: "timing_anomaly".to_string(),
                detail: "timing exceeded".to_string(),
            },
        ],
    };

    assert!(!report.is_clean());
    let codes = report.violation_codes();
    assert!(codes.contains(&"integrity_probe_failed".to_string()));
    assert!(codes.contains(&"debugger_detected:timing_anomaly".to_string()));
    assert!(report.summary().contains("probe failed"));
    assert!(report.summary().contains("timing_anomaly"));
}

#[test]
// AC-ATP-003
fn invalid_expected_hash_generates_integrity_probe_failed_violation() {
    let engine = SelfProtectEngine::new(SelfProtectConfig {
        expected_integrity_sha256_hex: Some("invalid".to_string()),
        debugger: DebuggerCheckConfig {
            enable_tracer_pid_probe: false,
            enable_timing_probe: false,
            ..DebuggerCheckConfig::default()
        },
    });

    let report = engine.evaluate();
    assert!(report
        .violations
        .iter()
        .any(|v| matches!(v, SelfProtectViolation::IntegrityProbeFailed { .. })));
}

#[test]
// AC-ATP-002
fn from_env_prefers_env_hash_and_normalizes_case() {
    let _guard = env_lock().lock().expect("env lock");
    std::env::remove_var("EGUARD_SELF_PROTECT_EXPECTED_SHA256");
    std::env::remove_var("EGUARD_SELF_PROTECT_EXPECTED_SHA256_FILE");

    std::env::set_var(
        "EGUARD_SELF_PROTECT_EXPECTED_SHA256",
        "ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD",
    );

    let engine = SelfProtectEngine::from_env();
    let cfg = engine.config();
    assert_eq!(
        cfg.expected_integrity_sha256_hex.as_deref(),
        Some("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd")
    );

    std::env::remove_var("EGUARD_SELF_PROTECT_EXPECTED_SHA256");
    std::env::remove_var("EGUARD_SELF_PROTECT_EXPECTED_SHA256_FILE");
}

#[test]
// AC-ATP-002
fn from_env_uses_file_when_env_hash_is_invalid() {
    let _guard = env_lock().lock().expect("env lock");
    std::env::remove_var("EGUARD_SELF_PROTECT_EXPECTED_SHA256");
    std::env::remove_var("EGUARD_SELF_PROTECT_EXPECTED_SHA256_FILE");

    let tmp = std::env::temp_dir().join(format!(
        "eguard-self-protect-hash-{}.txt",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::write(
        &tmp,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
    )
    .expect("write expected hash file");

    std::env::set_var("EGUARD_SELF_PROTECT_EXPECTED_SHA256", "not-a-sha256");
    std::env::set_var("EGUARD_SELF_PROTECT_EXPECTED_SHA256_FILE", &tmp);

    let engine = SelfProtectEngine::from_env();
    assert_eq!(
        engine.config().expected_integrity_sha256_hex.as_deref(),
        Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    );

    std::env::remove_var("EGUARD_SELF_PROTECT_EXPECTED_SHA256");
    std::env::remove_var("EGUARD_SELF_PROTECT_EXPECTED_SHA256_FILE");
    let _ = std::fs::remove_file(tmp);
}
