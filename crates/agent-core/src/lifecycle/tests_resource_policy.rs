use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use super::*;
use crate::config::{AgentConfig, AgentMode};
use platform_linux::EbpfEngine;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn write_executable(path: &std::path::Path, body: &str) {
    std::fs::write(path, body).expect("write script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path).expect("stat script").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).expect("chmod script");
    }
}

fn lock_package_names(lock: &str) -> Vec<String> {
    lock.lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("name = \""))
        .filter_map(|tail| tail.strip_suffix('"'))
        .map(ToOwned::to_owned)
        .collect()
}

#[test]
// AC-RES-008
fn runtime_dependency_set_excludes_ml_frameworks_and_keeps_zig_build_path() {
    let root = workspace_root();
    let lock = std::fs::read_to_string(root.join("Cargo.lock")).expect("read Cargo.lock");
    let package_names: Vec<String> = lock_package_names(&lock)
        .into_iter()
        .map(|name| name.to_ascii_lowercase())
        .collect();

    for banned in [
        "tensorflow",
        "pytorch",
        "onnxruntime",
        "xgboost",
        "lightgbm",
        "scikit",
        "numpy",
    ] {
        assert!(
            !package_names
                .iter()
                .any(|name| name == banned || name.starts_with(&format!("{banned}-"))),
            "unexpected external ML dependency in lockfile: {banned}"
        );
    }

    assert!(
        root.join("build.zig").exists(),
        "expected zig build entrypoint"
    );
}

#[test]
// AC-RES-009 AC-OPT-005
fn runtime_loop_progresses_without_busy_wait_under_offline_conditions() {
    let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
    let mut cfg = AgentConfig::default();
    cfg.offline_buffer_backend = "memory".to_string();
    cfg.server_addr = "127.0.0.1:1".to_string();
    cfg.self_protection_integrity_check_interval_secs = 0;

    let temp = std::env::temp_dir().join(format!(
        "eguard-res-policy-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let bin_dir = temp.join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create mock bin");
    write_executable(
        &bin_dir.join("systemctl"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexit 0\n",
    );
    let old_path = std::env::var("PATH").unwrap_or_default();
    let path = format!("{}:{}", bin_dir.display(), old_path);
    std::env::set_var("PATH", path);

    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.client.set_online(false);
    runtime.runtime_mode = AgentMode::Degraded;
    runtime.last_recovery_probe_unix = Some(1_700_000_000);
    runtime.last_self_protect_check_unix = Some(1_700_000_000);
    runtime.ebpf_engine = EbpfEngine::disabled();

    let start = std::time::Instant::now();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async {
        runtime.tick(1_700_000_000).await.expect("tick");
    });
    let elapsed = start.elapsed();

    std::env::set_var("PATH", old_path);
    let _ = std::fs::remove_dir_all(&temp);

    assert!(
        elapsed < Duration::from_secs(20),
        "tick took too long: {elapsed:?}"
    );
    assert!(runtime.buffer.pending_count() <= 1);
}

#[test]
// AC-RES-009
fn disabled_ebpf_engine_poll_and_forward_return_immediately_without_errors() {
    let mut engine = EbpfEngine::disabled();
    let start = std::time::Instant::now();
    let events = engine
        .poll_once(Duration::from_millis(0))
        .expect("disabled poll");
    let elapsed_poll = start.elapsed();
    assert!(events.is_empty());
    assert!(elapsed_poll < Duration::from_millis(50));

    let (tx, rx) = std::sync::mpsc::channel();
    let start_forward = std::time::Instant::now();
    let forwarded = engine
        .poll_and_forward(Duration::from_millis(0), &tx)
        .expect("disabled poll and forward");
    let elapsed_forward = start_forward.elapsed();
    drop(tx);

    assert_eq!(forwarded, 0);
    assert!(elapsed_forward < Duration::from_millis(50));
    assert!(rx.try_recv().is_err());
}
