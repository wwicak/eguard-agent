use super::*;
use crate::config::AgentMode;
use self_protect::{DebuggerCheckConfig, SelfProtectConfig, SelfProtectEngine};

struct Fixture {
    root: PathBuf,
    previous: Option<std::ffi::OsString>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous {
            std::env::set_var("EGUARD_AGENT_CONFIG", previous);
        } else {
            std::env::remove_var("EGUARD_AGENT_CONFIG");
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn enrolled_after_baseline() -> (Fixture, AgentRuntime) {
    enroll_with_initial_config(true)
}

fn enroll_with_initial_config(config_exists: bool) -> (Fixture, AgentRuntime) {
    let root = std::env::temp_dir().join(format!(
        "eguard-enroll-race-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("agent.conf");
    let bootstrap = root.join("bootstrap.conf");
    if config_exists {
        std::fs::write(&path, "[agent]\nid = \"before-enrollment\"\n").unwrap();
    }
    std::fs::write(&bootstrap, "bootstrap credential").unwrap();
    let fixture = Fixture {
        root,
        previous: std::env::var_os("EGUARD_AGENT_CONFIG"),
    };
    std::env::set_var("EGUARD_AGENT_CONFIG", &path);
    let config = AgentConfig {
        agent_id: "enrolled-agent".into(),
        mode: AgentMode::Active,
        offline_buffer_backend: "memory".into(),
        bootstrap_config_path: Some(bootstrap.clone()),
        self_protection_integrity_check_interval_secs: 1,
        ..AgentConfig::default()
    };
    let mut runtime = AgentRuntime::new(config).unwrap();
    runtime.client.set_online(false);
    runtime.self_protect_engine = SelfProtectEngine::new(SelfProtectConfig {
        expected_integrity_sha256_hex: None,
        debugger: DebuggerCheckConfig {
            enable_tracer_pid_probe: false,
            enable_timing_probe: false,
            ..DebuggerCheckConfig::default()
        },
        runtime_integrity_paths: Vec::new(),
        runtime_config_paths: vec![path.to_string_lossy().into_owned()],
    });
    assert!(runtime.self_protect_engine.evaluate().is_clean());
    // Enrollment runs after the eager (or lazy first-evaluation) baseline.
    runtime.consume_bootstrap_config();
    assert!(
        !bootstrap.exists(),
        "successful persistence must consume bootstrap"
    );
    assert!(std::fs::read_to_string(path)
        .unwrap()
        .contains("enrolled-agent"));
    (fixture, runtime)
}

fn check(runtime: &mut AgentRuntime, now: i64) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(runtime.run_self_protection_if_due(now))
        .unwrap();
}

#[test]
fn enrollment_after_baseline_does_not_alert_or_degrade() {
    let _lock = crate::test_support::env_lock().lock().unwrap();
    let (_fixture, mut runtime) = enrolled_after_baseline();
    check(&mut runtime, 1);
    assert!(
        !runtime.tamper_forced_degraded,
        "our enrollment write is authorized, not tampering"
    );
    assert!(matches!(runtime.runtime_mode, AgentMode::Active));
    assert_eq!(runtime.buffer.pending_count(), 0, "no agent_tamper alert");
}

#[test]
fn external_edit_after_enrollment_still_alerts_and_degrades() {
    let _lock = crate::test_support::env_lock().lock().unwrap();
    let (fixture, mut runtime) = enrolled_after_baseline();
    check(&mut runtime, 1);
    assert!(
        !runtime.tamper_forced_degraded,
        "must not already be degraded by enrollment"
    );
    let path = fixture.root.join("agent.conf");
    std::fs::write(&path, "[agent]\nid = \"external-edit\"\n").unwrap();
    assert!(runtime
        .self_protect_engine
        .evaluate()
        .violation_codes()
        .contains(&"runtime_config_tamper".to_string()));
    check(&mut runtime, 2);
    assert!(
        runtime.tamper_forced_degraded,
        "baseline refresh must not disable future checks"
    );
    assert!(matches!(runtime.runtime_mode, AgentMode::Degraded));
    assert_eq!(runtime.buffer.pending_count(), 1);
}

#[test]
fn enrollment_created_config_is_protected_against_external_edits() {
    let _lock = crate::test_support::env_lock().lock().unwrap();
    let (fixture, mut runtime) = enroll_with_initial_config(false);
    check(&mut runtime, 1);
    assert!(!runtime.tamper_forced_degraded);
    std::fs::write(fixture.root.join("agent.conf"), "external replacement").unwrap();
    check(&mut runtime, 2);
    assert!(
        runtime.tamper_forced_degraded,
        "a fresh-install config must become monitored when enrollment creates it"
    );
    assert_eq!(runtime.buffer.pending_count(), 1);
}

#[test]
fn enrollment_cannot_bless_preexisting_external_edit() {
    let _lock = crate::test_support::env_lock().lock().unwrap();
    let (fixture, mut runtime) = enrolled_after_baseline();
    let path = fixture.root.join("agent.conf");
    let bootstrap = fixture.root.join("bootstrap.conf");
    std::fs::write(&bootstrap, "retry credential").unwrap();
    let external = "[agent]\nid = \"external-edit\"\n";
    std::fs::write(&path, external).unwrap();
    runtime.consume_bootstrap_config();
    assert!(
        bootstrap.exists(),
        "reject rather than legitimize preexisting tampering during an authorized write"
    );
    assert_eq!(std::fs::read_to_string(path).unwrap(), external);
    check(&mut runtime, 1);
    assert!(runtime.tamper_forced_degraded);
}
