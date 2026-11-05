#![cfg(target_os = "linux")]

use super::*;
use crate::config::AgentConfig;

struct Fixture {
    root: std::path::PathBuf,
    env: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "eguard-kernel-scan-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("sys_module")).unwrap();
        std::fs::create_dir_all(root.join("bpffs")).unwrap();
        for name in ["proc_modules", "kprobes", "tracer", "lsm"] {
            std::fs::write(root.join(name), "").unwrap();
        }
        std::fs::write(root.join("filter"), "sys_execve\n").unwrap();
        let mut fixture = Self { root, env: vec![] };
        for (key, relative) in [
            ("EGUARD_AGENT_DATA_DIR", "data"),
            ("EGUARD_LOG_DIR", "logs"),
            ("EGUARD_BASELINE_PATH", "baseline.bin"),
            ("EGUARD_RULES_STAGING_DIR", "staging"),
            ("EGUARD_COMPLIANCE_POLICY_PATH", "policy.json"),
            ("EGUARD_EBPF_REPLAY_PATH", "replay"),
            ("EGUARD_KERNEL_INTEGRITY_PROC_MODULES_PATH", "proc_modules"),
            ("EGUARD_KERNEL_INTEGRITY_SYS_MODULES_PATH", "sys_module"),
            ("EGUARD_KERNEL_INTEGRITY_KPROBE_EVENTS_PATH", "kprobes"),
            ("EGUARD_KERNEL_INTEGRITY_TRACER_PATH", "tracer"),
            ("EGUARD_KERNEL_INTEGRITY_FTRACE_FILTER_PATH", "filter"),
            ("EGUARD_KERNEL_INTEGRITY_LSM_PATH", "lsm"),
            ("EGUARD_KERNEL_INTEGRITY_BPF_FS_PATH", "bpffs"),
        ] {
            fixture.env.push((key, std::env::var_os(key)));
            std::env::set_var(key, fixture.root.join(relative));
        }
        std::fs::write(fixture.root.join("replay"), "").unwrap();
        fixture.env.push((
            "EGUARD_DETECTION_SHARDS",
            std::env::var_os("EGUARD_DETECTION_SHARDS"),
        ));
        std::env::set_var("EGUARD_DETECTION_SHARDS", "1");
        fixture
    }

    fn runtime(&self) -> AgentRuntime {
        AgentRuntime::new(AgentConfig {
            offline_buffer_backend: "memory".into(),
            server_addr: "127.0.0.1:1".into(),
            detection_kernel_integrity_enabled: true,
            detection_kernel_integrity_interval_secs: 300,
            detection_sigma_rules_dir: self.root.join("sigma").to_string_lossy().into_owned(),
            detection_yara_rules_dir: self.root.join("yara").to_string_lossy().into_owned(),
            detection_ioc_dir: self.root.join("ioc").to_string_lossy().into_owned(),
            detection_bundle_path: self.root.join("bundle").to_string_lossy().into_owned(),
            bootstrap_config_path: Some(self.root.join("bootstrap.conf")),
            ..Default::default()
        })
        .unwrap()
    }

    fn filter(&self, value: &str) {
        std::fs::write(self.root.join("filter"), value).unwrap();
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
fn identical_kernel_integrity_scans_emit_once_with_indicators() {
    let _guard = shared_env_var_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new();
    let mut runtime = fixture.runtime();
    runtime.run_kernel_integrity_scan_if_due(1_700_000_000);
    runtime.run_kernel_integrity_scan_if_due(1_700_000_300);
    assert_eq!(runtime.buffer.pending_count(), 1);
    let events = runtime.buffer.peek_batch(10).unwrap();
    let payload: serde_json::Value = serde_json::from_str(&events[0].1.payload_json).unwrap();
    assert_eq!(payload["event"]["process"], "kernel_integrity_scan");
    assert_eq!(
        payload["detection"]["kernel_integrity_indicators"][0],
        "ftrace_filter_count:1"
    );
}

#[test]
fn kernel_integrity_unordered_results_do_not_repeat_or_reorder_payload() {
    let _guard = shared_env_var_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new();
    for name in ["z_hidden", "a_hidden", "m_hidden"] {
        let module = fixture.root.join("sys_module").join(name);
        std::fs::create_dir(&module).unwrap();
        std::fs::write(module.join("initstate"), "live").unwrap();
        std::fs::create_dir(fixture.root.join("bpffs").join(name)).unwrap();
    }
    let mut runtime = fixture.runtime();
    for scan in 0..16 {
        runtime.run_kernel_integrity_scan_if_due(1_700_000_000 + scan * 300);
    }
    assert_eq!(runtime.buffer.pending_count(), 1);
    let events = runtime.buffer.peek_batch(1).unwrap();
    let payload: serde_json::Value = serde_json::from_str(&events[0].1.payload_json).unwrap();
    // The scanner emits hidden modules before ftrace and bpffs indicators.
    // Sorting the emitted list (rather than a comparison copy) changes rule selection.
    assert!(payload["detection"]["kernel_integrity_indicators"][0]
        .as_str()
        .unwrap()
        .starts_with("hidden_module_sysfs:"));
    assert!(events[0]
        .1
        .rule_name
        .starts_with("kernel:hidden_module_sysfs:"));
}

#[test]
fn changed_kernel_integrity_indicators_emit_again() {
    let _guard = shared_env_var_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new();
    let mut runtime = fixture.runtime();
    runtime.run_kernel_integrity_scan_if_due(1_700_000_000);
    fixture.filter("sys_execve\nsys_open\n");
    runtime.run_kernel_integrity_scan_if_due(1_700_000_300);
    assert_eq!(runtime.buffer.pending_count(), 2);
    runtime.run_kernel_integrity_scan_if_due(1_700_000_600);
    assert_eq!(runtime.buffer.pending_count(), 2);
}

#[test]
fn changed_kernel_integrity_report_values_emit_again() {
    let _guard = shared_env_var_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new();
    let mut runtime = fixture.runtime();
    runtime.run_kernel_integrity_scan_if_due(1_700_000_000);
    // A built-in module changes the report count without changing indicators.
    std::fs::create_dir(fixture.root.join("sys_module/builtin")).unwrap();
    runtime.run_kernel_integrity_scan_if_due(1_700_000_300);
    assert_eq!(runtime.buffer.pending_count(), 2);
    runtime.run_kernel_integrity_scan_if_due(1_700_000_600);
    assert_eq!(runtime.buffer.pending_count(), 2);
}

#[test]
fn kernel_integrity_a_b_a_emits_each_transition() {
    let _guard = shared_env_var_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new();
    let mut runtime = fixture.runtime();
    runtime.run_kernel_integrity_scan_if_due(1_700_000_000);
    fixture.filter("sys_execve\nsys_open\n");
    runtime.run_kernel_integrity_scan_if_due(1_700_000_300);
    fixture.filter("sys_execve\n");
    runtime.run_kernel_integrity_scan_if_due(1_700_000_600);
    assert_eq!(runtime.buffer.pending_count(), 3);
}

#[test]
fn fresh_kernel_integrity_runtime_emits_first_scan() {
    let _guard = shared_env_var_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new();
    let mut runtime = fixture.runtime();
    runtime.run_kernel_integrity_scan_if_due(1_700_000_000);
    assert_eq!(runtime.buffer.pending_count(), 1);
    drop(runtime);
    let mut restarted = fixture.runtime();
    restarted.run_kernel_integrity_scan_if_due(1_700_000_300);
    assert_eq!(restarted.buffer.pending_count(), 1);
}

#[test]
fn kernel_integrity_clean_transition_stays_silent_and_resets_result() {
    let _guard = shared_env_var_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new();
    let mut runtime = fixture.runtime();
    fixture.filter("");
    runtime.run_kernel_integrity_scan_if_due(1_700_000_000);
    assert_eq!(runtime.buffer.pending_count(), 0);
    fixture.filter("sys_execve\n");
    runtime.run_kernel_integrity_scan_if_due(1_700_000_300);
    fixture.filter("");
    runtime.run_kernel_integrity_scan_if_due(1_700_000_600);
    runtime.run_kernel_integrity_scan_if_due(1_700_000_900);
    assert_eq!(runtime.buffer.pending_count(), 1);
    fixture.filter("sys_execve\n");
    runtime.run_kernel_integrity_scan_if_due(1_700_001_200);
    assert_eq!(runtime.buffer.pending_count(), 2);
}

#[test]
fn kernel_integrity_scan_interval_and_disabled_setting_are_preserved() {
    let _guard = shared_env_var_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new();
    let mut runtime = fixture.runtime();
    runtime.run_kernel_integrity_scan_if_due(1_700_000_000);
    fixture.filter("sys_execve\nsys_open\n");
    runtime.run_kernel_integrity_scan_if_due(1_700_000_299);
    assert_eq!(runtime.buffer.pending_count(), 1);
    runtime.run_kernel_integrity_scan_if_due(1_700_000_300);
    assert_eq!(runtime.buffer.pending_count(), 2);
    runtime.config.detection_kernel_integrity_enabled = false;
    fixture.filter("sys_execve\n");
    runtime.run_kernel_integrity_scan_if_due(1_700_000_600);
    assert_eq!(runtime.buffer.pending_count(), 2);
}
