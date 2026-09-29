//! Portable to 9cdb193 with the cfg(test) bench_ingest_polled forwarding shim.
//! No server/eBPF input; /proc enrichment and local file reads remain real.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "local CPU benchmark; run explicitly with --nocapture --test-threads=1"]
fn bench_eval_throughput() {
    use super::AgentRuntime;
    use crate::config::{AgentConfig, AgentMode};
    use platform_linux::{EbpfEngine, EventType, RawEvent};
    use std::{path::PathBuf, process::Command, time::Instant};

    struct Fixture {
        children: Vec<u32>,
        directory: PathBuf,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            for pid in &self.children {
                let _ = Command::new("kill")
                    .args(["-KILL", &pid.to_string()])
                    .status();
            }
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }
    fn parameter(name: &str, default: usize) -> usize {
        let value = std::env::var(name)
            .map(|s| s.parse().expect("positive integer parameter"))
            .unwrap_or(default);
        assert!(value > 0, "{name} must be positive");
        value
    }
    let batch = parameter("EG_BENCH_BATCH", 50);
    let ticks = parameter("EG_BENCH_TICKS", 300);
    let test_pid = std::process::id();
    let mut fixture = Fixture {
        children: Vec::new(),
        directory: PathBuf::from(format!("/tmp/eg-bench/{test_pid}")),
    };
    std::fs::create_dir_all(&fixture.directory).expect("fixture directory");
    for _ in 0..4 {
        // Direct children are intentionally suppressed as agent-internal events.
        // Reparent each sleep before reading its real lineage, rather than forging PPid.
        let output = Command::new("sh")
            .args(["-c", "sleep 600 >/dev/null 2>&1 & echo $!"])
            .output()
            .expect("detached sleep");
        assert!(output.status.success());
        fixture.children.push(
            String::from_utf8(output.stdout)
                .expect("PID output")
                .trim()
                .parse()
                .expect("sleep PID"),
        );
    }
    let lineage: Vec<(u32, String, String)> = fixture
        .children
        .iter()
        .map(|pid| {
            let status =
                std::fs::read_to_string(format!("/proc/{pid}/status")).expect("sleep status");
            let ppid: u32 = status
                .lines()
                .find_map(|line| line.strip_prefix("PPid:"))
                .expect("PPid")
                .trim()
                .parse()
                .expect("parent PID");
            assert_ne!(ppid, test_pid, "sleep must not be an agent-internal child");
            let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).expect("sleep comm");
            let parent_comm =
                std::fs::read_to_string(format!("/proc/{ppid}/comm")).expect("parent comm");
            (
                ppid,
                comm.trim().to_string(),
                parent_comm.trim().to_string(),
            )
        })
        .collect();
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    executor.block_on(async {
        let mut cfg = AgentConfig::default();
        cfg.offline_buffer_backend = "memory".to_string();
        cfg.server_addr = "127.0.0.1:1".to_string();
        cfg.self_protection_integrity_check_interval_secs = 0;
        let mut runtime = AgentRuntime::new(cfg).expect("agent runtime");
        runtime.ebpf_engine = EbpfEngine::disabled();
        runtime.runtime_mode = AgentMode::Degraded;
        runtime.deferred_bundle_bootstrap_pending = false;
        let now = 1_700_000_000;
        runtime.last_recovery_probe_unix = Some(now);
        runtime.last_kernel_integrity_scan_unix = Some(now);
        runtime.last_memory_scan_unix = Some(now);
        runtime.last_self_protect_check_unix = Some(now);
        runtime.last_config_permission_check_unix = Some(now);
        runtime.last_storage_hygiene_unix = Some(now);
        runtime.last_isolation_failsafe_check_unix = Some(now);
        runtime.last_heartbeat_attempt_unix = Some(now);
        runtime.last_compliance_attempt_unix = Some(now);
        runtime.last_inventory_attempt_unix = Some(now);
        runtime.last_command_fetch_attempt_unix = Some(now);
        runtime.last_policy_fetch_unix = Some(now);
        runtime.last_threat_intel_refresh_unix = Some(now);
        runtime.last_baseline_save_unix = Some(now);
        runtime.last_baseline_upload_unix = Some(now);
        runtime.last_fleet_baseline_fetch_unix = Some(now);
        runtime.last_ioc_signal_upload_unix = Some(now);
        runtime.last_campaign_fetch_unix = Some(now);
        runtime.last_enrollment_attempt_unix = Some(now);
        let (mut ppid, mut comm, mut parent_comm) = lineage[0].clone();
        // Warm compliance as in tick_drains_queued_events_past_a_filtered_event.
        runtime.raw_event_backlog.push_back(RawEvent {
            fields: Default::default(),
            pid_start_ns: None,
            ppid_start_ns: None,
            event_type: EventType::ProcessExec, pid: fixture.children[0], uid: 1000, ts_ns: 1,
            payload: format!("path=/bin/true;cmdline=/bin/true;ppid={ppid};cgroup_id=0;comm={comm};parent_comm={parent_comm}"),
        });
        runtime.evaluate_tick(now).expect("warm evaluation");
        assert!(runtime.raw_event_backlog.is_empty());
        let mut seed = 0x4d595df4d0f33173_u64;
        let mut pid = fixture.children[0];
        let mut durations = Vec::with_capacity(ticks);
        let mut combined_durations = Vec::with_capacity(ticks);
        let mut ingest_us = 0.0;
        let mut dropped = 0usize;
        let mut consumed = 0usize;
        for tick in 0..ticks {
            let mut events = Vec::with_capacity(batch);
            for index in 0..batch {
                let n = tick * batch + index;
                let path = fixture.directory.join((n / 4).to_string());
                let path = path.display();
                let (event_type, payload) = match n % 4 {
                    0 => {
                        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
                        let actor = (seed % 4) as usize;
                        pid = fixture.children[actor];
                        (ppid, comm, parent_comm) = lineage[actor].clone();
                        std::fs::write(path.to_string(), b"eguard deterministic benchmark fixture\n").expect("fixture file");
                        (EventType::ProcessExec, format!("path=/bin/true;cmdline=/bin/true;ppid={ppid};cgroup_id=0;comm={comm};parent_comm={parent_comm}"))
                    }
                    1 => (EventType::FileOpen, format!("path={path};flags=577;mode=420;ppid={ppid};cgroup_id=0;comm={comm};parent_comm={parent_comm}")),
                    2 => (EventType::FileOpen, format!("path={path};flags=0;mode=0;ppid={ppid};cgroup_id=0;comm={comm};parent_comm={parent_comm}")),
                    _ => (EventType::FileUnlink, format!("path={path}")),
                };
                events.push(RawEvent { fields: Default::default(), pid_start_ns: None, ppid_start_ns: None, event_type, pid, uid: 1000,
                    ts_ns: 1_000_000_000 + tick as u64 * 100_000_000 + index as u64, payload });
            }
            // Keep files alive so delayed baseline events can still stat/hash them.
            let before = runtime.raw_event_backlog.len();
            let ingest_started = Instant::now();
            runtime.bench_ingest_polled(events);
            let this_ingest_us = ingest_started.elapsed().as_secs_f64() * 1_000_000.0;
            ingest_us += this_ingest_us;
            let after_enqueue = runtime.raw_event_backlog.len();
            dropped += before + batch - after_enqueue;
            let started = Instant::now();
            runtime.tick(now).await.expect("benchmark tick");
            let tick_us = started.elapsed().as_secs_f64() * 1_000_000.0;
            durations.push(tick_us);
            combined_durations.push(this_ingest_us + tick_us);
            consumed += after_enqueue - runtime.raw_event_backlog.len();
        }
        assert!(consumed > 0);
        assert!(runtime.buffer.pending_count() > 0, "fixture must produce telemetry");
        let total_us: f64 = durations.iter().sum();
        durations.sort_by(f64::total_cmp);
        combined_durations.sort_by(f64::total_cmp);
        let percentile = |p: usize| durations[(ticks * p).div_ceil(100).saturating_sub(1)];
        println!("BENCH_JSON {}", serde_json::json!({
            "batch": batch, "total_ticks": ticks, "events_enqueued": ticks * batch,
            // Backlog accounting includes pre-enqueue filtering/coalescing as well as caps.
            "overflow_dropped_at_enqueue": dropped,
            "cap_overflow_dropped": runtime.metrics.telemetry_raw_backlog_dropped_total,
            "events_consumed": consumed,
            "final_backlog": runtime.raw_event_backlog.len(), "buffer_pending": runtime.buffer.pending_count(),
            "tick_wall_time_us": total_us, "mean_tick_us": total_us / ticks as f64,
            "p50_tick_us": percentile(50), "p99_tick_us": percentile(99),
            "us_per_consumed_event": total_us / consumed as f64,
            "ingest_wall_us": ingest_us,
            "ingest_us_per_enqueued_event": ingest_us / (ticks * batch) as f64,
            "total_us_per_consumed_event": (ingest_us + total_us) / consumed as f64,
            "total_cpu_events_per_sec": consumed as f64 * 1_000_000.0 / (ingest_us + total_us),
            "total_p99_tick_us": combined_durations[(ticks * 99).div_ceil(100).saturating_sub(1)],
            "sustainable_events_per_sec_at_100ms_ticks": consumed as f64 / (ticks as f64 * 0.1)
        }));
    });
}
