use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "eguard-update-window-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let fixture = Self(root);
        std::fs::create_dir(fixture.0.join("update-restart")).unwrap();
        std::fs::set_permissions(
            fixture.0.join("update-restart"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fixture.write(1800);
        fixture
    }
    fn path(&self) -> PathBuf {
        self.0.join("update-restart/window.json")
    }
    fn write(&self, expires_at: i64) {
        std::fs::write(
            self.path(),
            format!(
                r#"{{"command_id":"cmd-123","target_version":"15.0.31","expires_at":{expires_at}}}"#
            ),
        )
        .unwrap();
        std::fs::set_permissions(self.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn read(&self, now: i64) -> Option<UpdateWindow> {
        read(&self.0, now, unsafe { libc::geteuid() })
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn event(window: Option<UpdateWindow>) -> EventEnvelope {
    let mut event = EventEnvelope {
        agent_id: "agent-test".into(), event_type: "alert".into(), severity: "critical".into(), rule_name: "agent_stop_tamper".into(),
        payload_json: serde_json::json!({"rule_name":"agent_stop_tamper", "severity":"critical", "timestamp":1000, "signal":"sigterm", "detail":"agent received termination signal; restart is expected under self-protection"}).to_string(), created_at_unix: 1000,
    };
    classify(&mut event, window);
    event
}
fn assert_critical(window: Option<UpdateWindow>) {
    let actual = event(window);
    assert_eq!(actual.rule_name, "agent_stop_tamper");
    assert_eq!(actual.severity, "critical");
    assert_eq!(actual.event_type, "alert");
    let payload: serde_json::Value = serde_json::from_str(&actual.payload_json).unwrap();
    assert_eq!(payload["severity"], "critical");
}
#[test]
fn valid_window_reports_both_update_stops_as_info() {
    let fixture = Fixture::new();
    for now in [1000, 1001] {
        let actual = event(fixture.read(now));
        assert_eq!(actual.rule_name, "agent_update_restart");
        assert_eq!(actual.severity, "info");
        assert_eq!(actual.event_type, "alert");
        let payload: serde_json::Value = serde_json::from_str(&actual.payload_json).unwrap();
        assert_eq!(payload["command_id"], "cmd-123");
        assert_eq!(payload["target_version"], "15.0.31");
        assert_eq!(payload["severity"], "info");
        assert_eq!(payload["signal"], "sigterm");
    }
    assert!(fixture.path().exists(), "window is not single-use");
}
#[test]
fn missing_expired_future_malformed_and_oversized_windows_stay_critical() {
    let fixture = Fixture::new();
    for expires in [999, 1000, 1901, i64::MAX] {
        fixture.write(expires);
        assert_critical(fixture.read(1000));
    }
    for contents in [
        "{}".to_string(),
        "not json".into(),
        "x".repeat(1025),
        r#"{"command_id":"","target_version":"15.0.31","expires_at":1800}"#.into(),
        r#"{"command_id":"cmd-123","target_version":"bad\nversion","expires_at":1800}"#.into(),
    ] {
        std::fs::write(fixture.path(), contents).unwrap();
        assert_critical(fixture.read(1000));
    }
    std::fs::remove_file(fixture.path()).unwrap();
    assert_critical(fixture.read(1000));
}
#[test]
fn untrusted_permissions_owners_symlinks_and_nonregular_files_stay_critical() {
    let fixture = Fixture::new();
    for (path, bad, good) in [
        (fixture.0.clone(), 0o777, 0o700),
        (fixture.0.join("update-restart"), 0o755, 0o700),
        (fixture.path(), 0o644, 0o600),
    ] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(bad)).unwrap();
        assert_critical(fixture.read(1000));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(good)).unwrap();
    }
    assert_critical(read(
        &fixture.0,
        1000,
        unsafe { libc::geteuid() }.wrapping_add(1),
    ));
    let real_dir = fixture.0.join("real-dir");
    std::fs::rename(fixture.0.join("update-restart"), &real_dir).unwrap();
    symlink(&real_dir, fixture.0.join("update-restart")).unwrap();
    assert_critical(fixture.read(1000));
    std::fs::remove_file(fixture.0.join("update-restart")).unwrap();
    std::fs::rename(real_dir, fixture.0.join("update-restart")).unwrap();
    let real_file = fixture.0.join("real-file");
    std::fs::rename(fixture.path(), &real_file).unwrap();
    symlink(&real_file, fixture.path()).unwrap();
    assert_critical(fixture.read(1000));
    std::fs::remove_file(fixture.path()).unwrap();
    std::fs::create_dir(fixture.path()).unwrap();
    assert_critical(fixture.read(1000));
}
#[tokio::test]
#[allow(clippy::await_holding_lock)] // Serialize process-wide environment throughout the report.
async fn runtime_reports_production_owner_checked_window_and_cleans_expired_at_startup() {
    let _lock = crate::test_support::env_lock().lock().unwrap();
    let fixture = Fixture::new();
    let old = std::env::var_os("EGUARD_AGENT_DATA_DIR");
    std::env::set_var("EGUARD_AGENT_DATA_DIR", &fixture.0);
    let config = crate::config::AgentConfig {
        offline_buffer_backend: "memory".into(),
        server_addr: "127.0.0.1:1".into(),
        ..Default::default()
    };
    let now = crate::lifecycle::now_unix();
    fixture.write(now + 800);
    let mut runtime = crate::lifecycle::AgentRuntime::new(config.clone()).unwrap();
    for _ in 0..2 {
        runtime
            .report_shutdown_tamper(now, "sigterm")
            .await
            .unwrap();
    }
    let events = runtime.buffer.peek_batch(10).unwrap();
    assert_eq!(events.len(), 2);
    for (_, actual) in events {
        let expected = if unsafe { libc::geteuid() } == 0 {
            "agent_update_restart"
        } else {
            "agent_stop_tamper"
        };
        assert_eq!(actual.rule_name, expected);
    }
    assert!(fixture.path().exists());
    fixture.write(now - 1);
    let _runtime = crate::lifecycle::AgentRuntime::new(config).unwrap();
    assert_eq!(fixture.path().exists(), unsafe { libc::geteuid() } != 0);
    match old {
        Some(value) => std::env::set_var("EGUARD_AGENT_DATA_DIR", value),
        None => std::env::remove_var("EGUARD_AGENT_DATA_DIR"),
    }
}

#[test]
fn linux_writer_enforces_root_only_and_emits_bounded_window() {
    let fixture = Fixture::new();
    std::fs::remove_file(fixture.path()).unwrap();
    let source = include_str!("../command_pipeline/update_agent/worker_linux.rs");
    let function = source
        .split_once("write_update_window() (")
        .unwrap()
        .1
        .split_once("\n)\n")
        .unwrap()
        .0;
    let script = format!("write_update_window() ({function}\n)\nwrite_update_window");
    let run = |authenticated: bool| {
        std::process::Command::new("bash")
            .args(["-c", &script])
            .env("UPDATE_DIR", fixture.0.join("update"))
            .env("AUTHENTICATED_COMMAND", authenticated.to_string())
            .env("COMMAND_ID", "cmd-123")
            .env("VERSION", "15.0.31")
            .status()
            .unwrap()
    };
    let now = crate::lifecycle::now_unix();
    assert!(!run(false).success());
    assert!(
        !fixture.path().exists(),
        "plaintext update must not arm a window"
    );
    assert_critical(fixture.read(now));
    if unsafe { libc::geteuid() } == 0 {
        assert!(run(true).success());
        let after = crate::lifecycle::now_unix();
        let window = read(&fixture.0, after, 0).expect("trusted actual writer output");
        assert_eq!(window.command_id, "cmd-123");
        assert_eq!(window.target_version, "15.0.31");
        assert!(window.expires_at >= now + 900 && window.expires_at <= after + 900);
        let contents = std::fs::read(fixture.path()).unwrap();
        std::fs::set_permissions(
            fixture.0.join("update-restart"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(!run(true).success());
        assert_eq!(std::fs::read(fixture.path()).unwrap(), contents);
    } else {
        assert!(!run(true).success());
        assert!(!fixture.path().exists());
    }
}

#[test]
fn linux_worker_arms_only_after_checksum_and_before_package_or_rollback_stop() {
    let source = include_str!("../command_pipeline/update_agent/worker_linux.rs");
    let initial = source
        .find("write_update_window || echo \"agent update: could not record update window\"")
        .unwrap();
    assert!(source.find("sha256sum --check --status").unwrap() < initial);
    assert!(initial < source.find("dpkg -i --force-confdef").unwrap());
    let rollback = source
        .find("write_update_window || echo \"agent update: could not record rollback window\"")
        .unwrap();
    assert!(
        source[rollback..]
            .find("systemctl kill --kill-who=main -s TERM")
            .unwrap()
            < 200
    );
    assert!(source.contains("$(date +%s) + 900"));
}

#[test]
fn startup_keeps_valid_window_and_removes_expired_without_extension() {
    let fixture = Fixture::new();
    let owner = unsafe { libc::geteuid() };
    let before = std::fs::read(fixture.path()).unwrap();
    cleanup(&fixture.0, 1000, owner);
    assert_eq!(std::fs::read(fixture.path()).unwrap(), before);
    cleanup(&fixture.0, 1800, owner);
    assert!(!fixture.path().exists());
    assert_critical(fixture.read(1800));
}
