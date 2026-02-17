use super::*;
use crate::config::{AgentConfig, AgentMode};
use ::self_protect::{SelfProtectReport, SelfProtectViolation};
use std::sync::{Mutex, OnceLock};

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct EnvGuard {
    name: String,
    previous: Option<String>,
}

impl EnvGuard {
    fn set(name: &str, value: &str) -> Self {
        let previous = std::env::var(name).ok();
        std::env::set_var(name, value);
        Self {
            name: name.to_string(),
            previous,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.as_ref() {
            std::env::set_var(&self.name, previous);
        } else {
            std::env::remove_var(&self.name);
        }
    }
}

#[test]
fn self_protect_violation_forces_sticky_degraded_mode() {
    let _guard = env_lock().lock().expect("env lock");
    let _expected = EnvGuard::set(
        "EGUARD_SELF_PROTECT_EXPECTED_SHA256",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let _tracer = EnvGuard::set("EGUARD_SELF_PROTECT_ENABLE_TRACER_PID", "0");
    let _timing = EnvGuard::set("EGUARD_SELF_PROTECT_ENABLE_TIMING", "0");

    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.self_protection_integrity_check_interval_secs = 1;

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.client.set_online(false);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async {
        runtime
            .run_self_protection_if_due(1)
            .await
            .expect("self protection check");
    });

    assert!(runtime.tamper_forced_degraded);
    assert!(runtime.is_forced_degraded());
    assert!(matches!(runtime.runtime_mode, AgentMode::Degraded));
    assert!(runtime.buffer.pending_count() >= 1);
}

#[test]
// AC-ATP-100
fn self_protect_alert_payload_includes_tampered_paths() {
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.self_protection_integrity_check_interval_secs = 0;

    let runtime = AgentRuntime::new(cfg).expect("runtime");
    let report = SelfProtectReport {
        integrity_measurement: None,
        debugger_observation: Default::default(),
        violations: vec![SelfProtectViolation::RuntimeIntegrityMismatch {
            path: "/proc/self/exe".to_string(),
            expected_sha256: "a".repeat(64),
            observed_sha256: "b".repeat(64),
        }],
    };

    let payload = runtime.self_protect_alert_payload(&report, 123);
    let value: serde_json::Value = serde_json::from_str(&payload).expect("valid json");
    let paths = value["tampered_paths"]
        .as_array()
        .expect("tampered_paths array");
    assert!(paths.iter().any(|p| p == "/proc/self/exe"));

    let indicators = value["tamper_indicators"]
        .as_array()
        .expect("tamper_indicators array");
    assert!(indicators
        .iter()
        .any(|p| p == "self_protect:/proc/self/exe"));
}
