//! Real tick regression: fallback must recover without restarting the agent.
#![cfg(target_os = "linux")]
use super::*;
use crate::config::{AgentConfig, AgentMode};
use grpc_client::EventBuffer;

struct Fixture {
    root: std::path::PathBuf,
    env: Vec<(&'static str, Option<std::ffi::OsString>)>,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "eguard-runtime-buffer-recovery-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let mut fixture = Self {
            root,
            env: Vec::new(),
        };
        for (key, relative) in [
            ("EGUARD_AGENT_DATA_DIR", "data"),
            ("EGUARD_LOG_DIR", "logs"),
            ("EGUARD_QUARANTINE_DIR", "quarantine"),
            ("EGUARD_BASELINE_PATH", "baseline.bin"),
            ("EGUARD_RULES_STAGING_DIR", "staging"),
            ("EGUARD_COMPLIANCE_POLICY_PATH", "policy.json"),
            ("EGUARD_SELF_PROTECT_RUNTIME_INTEGRITY_PATHS", "integrity"),
            ("EGUARD_SELF_PROTECT_RUNTIME_CONFIG_PATHS", "config"),
            ("EGUARD_EBPF_REPLAY_PATH", "replay"),
        ] {
            fixture.env.push((key, std::env::var_os(key)));
            std::env::set_var(key, fixture.root.join(relative));
        }
        std::fs::write(fixture.root.join("replay"), "").unwrap();
        fixture
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for (key, old) in self.env.drain(..).rev() {
            match old {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn runtime_tick_recovers_sqlite_fallback_fifo_after_path_repair() {
    let _guard = shared_env_var_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new();
    let parent = fixture.root.join("blocked");
    std::fs::write(&parent, "not a directory").unwrap();
    let db = parent.join("events.db");
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "sqlite".into();
    cfg.offline_buffer_path = db.to_string_lossy().into_owned();
    cfg.offline_buffer_cap_bytes = 1_000_000;
    cfg.server_addr = "127.0.0.1:1".into();
    cfg.mode = AgentMode::Degraded;
    cfg.self_protection_prevent_uninstall = false;
    cfg.self_protection_integrity_check_interval_secs = 0;
    cfg.detection_sigma_rules_dir = fixture.root.join("sigma").to_string_lossy().into_owned();
    cfg.detection_yara_rules_dir = fixture.root.join("yara").to_string_lossy().into_owned();
    cfg.detection_ioc_dir = fixture.root.join("ioc").to_string_lossy().into_owned();
    cfg.detection_bundle_path = fixture.root.join("bundle").to_string_lossy().into_owned();
    cfg.bootstrap_config_path = Some(fixture.root.join("bootstrap.conf"));
    cfg.tls_cert_path = None;
    cfg.tls_key_path = None;
    cfg.tls_ca_path = None;
    cfg.tls_ca_pin_path = Some(fixture.root.join("ca.pin").to_string_lossy().into_owned());
    let mut runtime = AgentRuntime::new(cfg).unwrap();
    runtime.client.set_online(false);
    runtime.ebpf_engine = crate::platform::EbpfEngine::disabled();
    assert!(matches!(runtime.buffer, EventBuffer::Memory(_)));
    for seq in 1..=3 {
        runtime
            .buffer
            .enqueue(EventEnvelope::info(
                "test".into(),
                "test".into(),
                seq.to_string(),
                seq,
            ))
            .unwrap();
    }
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for now in [1_700_000_000, 1_700_000_060] {
        // Suppress unrelated periodic work, especially the unconfigurable /etc
        // permission sweep. Recovery itself is driven only by production tick.
        runtime.last_config_permission_check_unix = Some(now);
        runtime.last_self_protect_check_unix = Some(now);
        runtime.last_recovery_probe_unix = Some(now);
        runtime.last_heartbeat_attempt_unix = Some(now);
        runtime.last_compliance_attempt_unix = Some(now);
        runtime.last_inventory_attempt_unix = Some(now);
        runtime.last_baseline_save_unix = Some(now);
        runtime.last_baseline_upload_unix = Some(now);
        runtime.last_fleet_baseline_fetch_unix = Some(now);
        runtime.last_memory_scan_unix = Some(now);
        runtime.last_ioc_signal_upload_unix = Some(now);
        runtime.last_campaign_fetch_unix = Some(now);
        runtime.last_kernel_integrity_scan_unix = Some(now);
        runtime.last_command_fetch_attempt_unix = Some(now);
        runtime.last_policy_fetch_unix = Some(now);
        runtime.last_threat_intel_refresh_unix = Some(now);
        executor.block_on(runtime.tick(now)).unwrap();
        if now == 1_700_000_000 {
            assert!(matches!(runtime.buffer, EventBuffer::Memory(_)));
            assert_eq!(runtime.buffer.pending_count(), 3);
            std::fs::remove_file(&parent).unwrap();
        }
    }
    assert!(
        matches!(runtime.buffer, EventBuffer::Sqlite(_)),
        "real tick must retry the volatile fallback"
    );
    drop(runtime);
    let reopened = EventBuffer::sqlite(db.to_str().unwrap(), 1_000_000).unwrap();
    let events = reopened
        .peek_batch(10)
        .unwrap()
        .into_iter()
        .map(|(_, e)| e.payload_json)
        .collect::<Vec<_>>();
    assert_eq!(
        events,
        ["1", "2", "3"],
        "fallback events must survive restart in FIFO order"
    );
}
