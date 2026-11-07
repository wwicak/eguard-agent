//! Isolated full AgentRuntime RSS measurement; never starts the daemon or contacts a server.
#[path = "../../../detection/tests/support/yara_metrics.rs"]
mod memory;
use super::AgentRuntime;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};

#[test]
#[ignore = "local/CI resource qualification; run explicitly with --nocapture --test-threads=1"]
fn full_agent_yara_idle_and_scan_burst_rss() {
    let _guard = crate::test_support::TestEnvGuard::new(&[
        "EGUARD_BASELINE_PATH",
        "EGUARD_COMPLIANCE_POLICY_PATH",
        "EGUARD_COMPLIANCE_POLICY_JSON",
        "EGUARD_POLICY_PUBKEY_PATH",
        "EGUARD_EBPF_REPLAY_PATH",
        "EGUARD_DETECTION_SHARDS",
    ]);
    let root = std::env::temp_dir().join(format!(
        "eguard-yara-rss-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(root.clone());
    std::env::set_var("EGUARD_BASELINE_PATH", root.join("baseline"));
    std::env::set_var("EGUARD_COMPLIANCE_POLICY_PATH", root.join("missing-policy"));
    std::env::remove_var("EGUARD_COMPLIANCE_POLICY_JSON");
    std::env::remove_var("EGUARD_POLICY_PUBKEY_PATH");
    std::env::set_var("EGUARD_DETECTION_SHARDS", "1");
    #[cfg(target_os = "linux")]
    {
        let replay = root.join("empty-replay");
        std::fs::write(&replay, b"").unwrap();
        std::env::set_var("EGUARD_EBPF_REPLAY_PATH", replay);
    }
    let mut config = crate::config::AgentConfig::default();
    config.offline_buffer_backend = "memory".into();
    config.server_addr = "127.0.0.1:1".into();
    config.detection_bundle_path.clear();
    config.detection_sigma_rules_dir = "rules/sigma".into();
    config.detection_yara_rules_dir = "rules/yara".into();
    config.detection_ioc_dir = "rules/ioc".into();
    config.detection_memory_scan_enabled = false;
    let before = memory::rss_kib().expect("RSS available");
    let runtime = AgentRuntime::new(config).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(100));
    let idle = memory::rss_kib().unwrap();
    let file = root.join("image");
    let mut data = vec![0; 4 * 1024 * 1024];
    data[..4].copy_from_slice(b"\x7fELF");
    std::fs::write(&file, &data).unwrap();
    drop(data);
    let stop = Arc::new(AtomicBool::new(false));
    let peak = Arc::new(AtomicU64::new(idle));
    let sampler_stop = Arc::clone(&stop);
    let sampler_peak = Arc::clone(&peak);
    let sampler = std::thread::spawn(move || {
        while !sampler_stop.load(Ordering::Relaxed) {
            if let Some(rss) = memory::rss_kib() {
                sampler_peak.fetch_max(rss, Ordering::Relaxed);
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    });
    let mut elapsed = Vec::new();
    for index in 0..30 {
        let event:detection::TelemetryEvent=serde_json::from_value(serde_json::json!({"ts_unix":123+index,"event_class":"FileOpen","pid":424242,"ppid":1,"uid":1000,"process":"synthetic","parent_process":"synthetic","session_id":1,"file_path":file,"file_write":true,"container_escape":false,"container_privileged":false})).unwrap();
        let started = std::time::Instant::now();
        runtime.detection_state.process_event(&event).unwrap();
        elapsed.push(started.elapsed().as_micros());
    }
    #[cfg(feature = "yara-x")]
    runtime.detection_state.drain_yara_for_tests();
    stop.store(true, Ordering::Relaxed);
    sampler.join().unwrap();
    elapsed.sort();
    println!(
        "YARA_AGENT_RSS {}",
        serde_json::json!({"before_kib":before,"idle_kib":idle,"burst_peak_kib":peak.load(Ordering::Relaxed),"burst_final_kib":memory::rss_kib(),"events":30,"event_p50_us":elapsed[15],"event_p99_us":elapsed[29],"file_mib":4,"memory_scanning_enabled":false})
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "loaded-file tick qualification; run explicitly, no daemon/server"]
fn loaded_executable_write_tick_p99() {
    use platform_linux::{EventType, RawEvent, RawEventFields};
    let _guard = crate::test_support::TestEnvGuard::new(&[
        "EGUARD_BASELINE_PATH",
        "EGUARD_EBPF_REPLAY_PATH",
        "EGUARD_DETECTION_SHARDS",
    ]);
    let root = std::env::temp_dir().join(format!(
        "eguard-yara-tick-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    struct Cleanup(std::path::PathBuf, u32);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::process::Command::new("kill")
                .arg(self.1.to_string())
                .status();
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let output = std::process::Command::new("sh")
        .args(["-c", "sleep 120 >/dev/null 2>&1 & echo $!"])
        .output()
        .unwrap();
    let pid: u32 = String::from_utf8(output.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let _cleanup = Cleanup(root.clone(), pid);
    let replay = root.join("replay");
    std::fs::write(&replay, b"").unwrap();
    std::env::set_var("EGUARD_EBPF_REPLAY_PATH", replay);
    std::env::set_var("EGUARD_BASELINE_PATH", root.join("baseline"));
    std::env::set_var("EGUARD_DETECTION_SHARDS", "1");
    let path = root.join("image");
    let mut bytes = vec![0; 4 * 1024 * 1024];
    bytes[..4].copy_from_slice(b"\x7fELF");
    std::fs::write(&path, &bytes).unwrap();
    drop(bytes);
    let mut config = crate::config::AgentConfig::default();
    config.offline_buffer_backend = "memory".into();
    config.server_addr = "127.0.0.1:1".into();
    config.detection_bundle_path.clear();
    config.detection_sigma_rules_dir = "rules/sigma".into();
    config.detection_yara_rules_dir = "rules/yara".into();
    config.detection_ioc_dir = "rules/ioc".into();
    config.detection_memory_scan_enabled = false;
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    executor.block_on(async {
        let mut runtime=AgentRuntime::new(config).unwrap();
        runtime.ebpf_engine=platform_linux::EbpfEngine::disabled();runtime.runtime_mode=crate::config::AgentMode::Degraded;runtime.baseline_store.status=baseline::BaselineStatus::Active;runtime.deferred_bundle_bootstrap_pending=false;
        let now=1_800_000_000;
        runtime.last_recovery_probe_unix=Some(now);
        runtime.last_kernel_integrity_scan_unix=Some(now);
        runtime.last_memory_scan_unix=Some(now);
        runtime.last_self_protect_check_unix=Some(now);
        runtime.last_config_permission_check_unix=Some(now);
        runtime.last_storage_hygiene_unix=Some(now);
        runtime.last_isolation_failsafe_check_unix=Some(now);
        runtime.last_heartbeat_attempt_unix=Some(now);
        runtime.last_compliance_attempt_unix=Some(now);
        runtime.last_inventory_attempt_unix=Some(now);
        runtime.last_command_fetch_attempt_unix=Some(now);
        runtime.last_policy_fetch_unix=Some(now);
        runtime.last_threat_intel_refresh_unix=Some(now);
        runtime.last_baseline_save_unix=Some(now);
        runtime.last_baseline_upload_unix=Some(now);
        runtime.last_fleet_baseline_fetch_unix=Some(now);
        runtime.last_ioc_signal_upload_unix=Some(now);
        runtime.last_campaign_fetch_unix=Some(now);
        runtime.last_enrollment_attempt_unix=Some(now);
        let status=std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();let ppid:u32=status.lines().find_map(|line|line.strip_prefix("PPid:")).unwrap().trim().parse().unwrap();assert_ne!(ppid,std::process::id());
        let comm=std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap().trim().to_string();let parent_comm=std::fs::read_to_string(format!("/proc/{ppid}/comm")).unwrap().trim().to_string();
        let mut times=Vec::new();let mut consumed=0;
        for index in 0..320u64 {
            runtime.raw_event_backlog.push_back(RawEvent{event_type:EventType::FileOpen,pid,uid:1000,ts_ns:1_000_000_000+index*100_000_000,pid_start_ns:None,ppid_start_ns:None,payload:format!("path={};flags=577;ppid={ppid};comm={comm};parent_comm={parent_comm}",path.display()),fields:RawEventFields{path:Some(path.to_string_lossy().into()),flags:Some(577),ppid:Some(ppid),comm:Some(comm.clone()),parent_comm:Some(parent_comm.clone()),..Default::default()}});
            let started=std::time::Instant::now();runtime.tick(now).await.unwrap();assert!(runtime.raw_event_backlog.is_empty());consumed+=1;if index>=20{times.push(started.elapsed().as_micros());}
        }
        #[cfg(feature="yara-x")] runtime.detection_state.drain_yara_for_tests();
        #[cfg(feature="yara-x")] let yara_health=runtime.detection_state.yara_health();
        #[cfg(not(feature="yara-x"))] let yara_health="baseline FileKey-only fallback".to_string();
        times.sort();println!("YARA_TICK {}",serde_json::json!({"events":times.len(),"consumed":consumed,"file_mib":4,"p50_us":times[times.len()/2],"p99_us":times[(times.len()*99).div_ceil(100)-1],"buffered_events":runtime.buffer.pending_count(),"yara_health":yara_health,"scope":"executable-magic file writes; no RPC/daemon"}));
    });
}
