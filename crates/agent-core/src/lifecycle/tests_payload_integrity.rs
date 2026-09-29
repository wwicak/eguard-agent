use super::*;

fn runtime() -> AgentRuntime {
    AgentRuntime::new(crate::config::AgentConfig {
        offline_buffer_backend: "memory".into(),
        server_addr: "127.0.0.1:1".into(),
        ..Default::default()
    })
    .unwrap()
}

#[test]
fn delayed_event_cannot_bind_reused_pid_generation() {
    let mut runtime = runtime();
    // At consumption /proc already describes a replacement, not the emitted child.
    runtime.internal_process_start_time_reader = Some(|_| Some(200));
    let mut event = RawEvent {
        fields: Default::default(),
        pid_start_ns: Some(1_000_000_001),
        ppid_start_ns: None,
        pid: 4_000_020,
        uid: 1000,
        ts_ns: 1,
        event_type: crate::platform::EventType::FileOpen,
        payload: format!("ppid={};path=/tmp/internal", std::process::id()),
    };
    assert!(runtime.should_suppress_internal_process_event(&event));
    event.payload = "path=/tmp/replacement".into();
    // Even generations within the same clock tick must stay distinct.
    event.pid_start_ns = Some(1_000_000_002);
    assert!(!runtime.should_suppress_internal_process_event(&event));
}

#[test]
fn delayed_parent_event_requires_emitted_parent_generation() {
    let mut runtime = runtime();
    runtime.internal_process_start_time_reader = Some(|_| Some(200));
    let mut event = RawEvent {
        fields: Default::default(),
        pid_start_ns: Some(1_000_000_001),
        ppid_start_ns: None,
        pid: 4_000_021,
        uid: 1000,
        ts_ns: 1,
        event_type: crate::platform::EventType::FileOpen,
        payload: format!("ppid={}", std::process::id()),
    };
    assert!(runtime.should_suppress_internal_process_event(&event));
    event.pid = 4_000_022;
    event.pid_start_ns = Some(3_000_000_000);
    event.ppid_start_ns = Some(1_000_000_002);
    event.payload = "ppid=4000021;path=/tmp/unrelated".into();
    assert!(!runtime.should_suppress_internal_process_event(&event));
}

#[cfg(target_os = "linux")]
#[test]
fn event_generation_fallback_compares_proc_at_clock_tick_granularity() {
    let mut runtime = runtime();
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
    runtime.internal_process_start_time_reader =
        Some(|_| Some(2 * unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64));
    let mut event = RawEvent {
        fields: Default::default(),
        pid_start_ns: Some(2_000_000_001),
        ppid_start_ns: Some(2_000_000_001),
        pid: 4_000_023,
        uid: 1000,
        ts_ns: 1,
        event_type: crate::platform::EventType::FileOpen,
        payload: format!("ppid={}", std::process::id()),
    };
    assert!(hz > 0);
    assert!(runtime.should_suppress_internal_process_event(&event));
    // A legacy event can validate the nanosecond identity via /proc ticks.
    event.pid_start_ns = None;
    event.payload = "path=/tmp/legacy".into();
    assert!(runtime.should_suppress_internal_process_event(&event));
    event.pid = 4_000_024;
    event.pid_start_ns = Some(2_000_000_001);
    event.ppid_start_ns = Some(3_000_000_001);
    event.payload = format!("ppid={}", std::process::id());
    assert!(!runtime.should_suppress_internal_process_event(&event));
}

#[test]
fn internal_process_pid_reuse_requires_same_generation() {
    let mut runtime = runtime();
    runtime.internal_process_start_time_reader = Some(|_| Some(100));
    runtime.track_internal_process_pid(4_000_001, 1, None);
    assert!(runtime.is_tracked_internal_process(4_000_001, 2, None));
    runtime.internal_process_start_time_reader = Some(|_| Some(200));
    assert!(!runtime.is_tracked_internal_process(4_000_001, 3, None));
    assert!(!runtime
        .suppressed_internal_process_pids
        .contains_key(&4_000_001));
    runtime.internal_process_start_time_reader = Some(|_| Some(100));
    runtime.track_internal_process_pid(4_000_001, 3, None);
    runtime.internal_process_start_time_reader = Some(|_| Some(200));
    let descendant = RawEvent {
        fields: Default::default(),
        pid_start_ns: None,
        ppid_start_ns: None,
        pid: 4_000_005,
        uid: 1000,
        ts_ns: 4,
        event_type: crate::platform::EventType::FileOpen,
        payload: "path=/tmp/child;ppid=4000001".into(),
    };
    assert!(!runtime.should_suppress_internal_process_event(&descendant));
    assert!(!runtime
        .suppressed_internal_process_pids
        .contains_key(&4_000_001));
    runtime.internal_process_start_time_reader =
        Some(|_| panic!("untracked PID must not read proc"));
    assert!(!runtime.is_tracked_internal_process(4_000_001, 4, None));
}

#[cfg(target_os = "linux")]
#[test]
fn payload_module_fallback_preserves_server_visible_text() {
    let mut enriched = platform_linux::enrich_event(RawEvent {
        fields: Default::default(),
        pid_start_ns: None,
        ppid_start_ns: None,
        pid: 4_000_004,
        uid: 1000,
        ts_ns: 1,
        event_type: crate::platform::EventType::ModuleLoad,
        payload: "module=evil%3Bppid%3D1".into(),
    });
    enriched.file_path = None;
    let event = crate::lifecycle::detection_event::to_detection_event(&enriched, 1);
    assert_eq!(event.file_path.as_deref(), Some("module=evil;ppid=1"));
}

#[test]
fn internal_process_stat_uses_last_parenthesis() {
    let stat = format!("123 (a ) b (c)) S {} 98765 0", vec!["0"; 18].join(" "));
    assert_eq!(parse_process_start_time(&stat), Some(98765));
    assert_eq!(parse_process_start_time("123 (bad) S"), None);
}

#[test]
fn payload_json_fallback_cannot_forge_suppression_ancestry() {
    let mut runtime = runtime();
    runtime.internal_process_start_time_reader = Some(|_| Some(100));
    let event = RawEvent {
        fields: Default::default(),
        pid_start_ns: None,
        ppid_start_ns: None,
        pid: 4_000_006,
        uid: 1000,
        ts_ns: 1,
        event_type: crate::platform::EventType::FileOpen,
        payload: format!(r#"{{"unknown":"x;ppid={};x"}}"#, std::process::id()),
    };
    assert!(!runtime.should_suppress_internal_process_event(&event));
    runtime.track_internal_process_pid(event.pid, 1, None);
    assert!(runtime.should_suppress_internal_process_event(&event));
}

#[test]
fn payload_duplicate_security_fields_never_suppress() {
    let mut runtime = runtime();
    runtime.internal_process_start_time_reader = Some(|_| Some(100));
    let pid = 4_000_002;
    for key in ["ppid", "pid", "uid", "cgroup_id"] {
        let payload = if key == "ppid" {
            format!("ppid={};ppid=1", std::process::id())
        } else {
            format!("ppid={};{key}=1;{key}=2", std::process::id())
        };
        let event = RawEvent {
            fields: Default::default(),
            pid_start_ns: None,
            ppid_start_ns: None,
            pid,
            uid: 1000,
            ts_ns: 1,
            event_type: crate::platform::EventType::FileOpen,
            payload,
        };
        assert!(!runtime.should_track_internal_process_event(&event, 1));
        runtime.track_internal_process_pid(pid, 1, None);
        assert!(!runtime.should_suppress_internal_process_event(&event));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn payload_codec_injection_survives_ingest_but_direct_child_is_suppressed() {
    let mut runtime = runtime();
    let filename = format!("/tmp/x;ppid={}", std::process::id());
    let replay_path = std::env::temp_dir().join(format!(
        "eguard-payload-{}-{}.ndjson",
        std::process::id(),
        unix_now_ns()
    ));
    std::fs::write(
        &replay_path,
        serde_json::json!({
            "event_type": "file_open", "pid": 4_000_003, "ppid": 1,
            "file_path": filename, "comm": "attacker", "parent_comm": "other", "ts_ns": 1
        })
        .to_string()
            + "\n",
    )
    .unwrap();
    let mut engine = platform_linux::EbpfEngine::from_replay(&replay_path).unwrap();
    let events = engine.poll_once(std::time::Duration::ZERO).unwrap();
    std::fs::remove_file(replay_path).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(
        parse_payload_field(&events[0].payload, "path"),
        Some(filename.clone())
    );
    assert_eq!(payload_parent_pid(&events[0].payload), Some(1));
    runtime.ingest_polled_raw_events(events);
    assert_eq!(runtime.raw_event_backlog.len(), 1);
    let raw = runtime.raw_event_backlog.pop_front().unwrap();
    let enriched = platform_linux::enrich_event(raw);
    assert_eq!(enriched.file_path.as_deref(), Some(filename.as_str()));

    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let event = RawEvent {
        fields: Default::default(),
        pid_start_ns: None,
        ppid_start_ns: None,
        pid: child.id(),
        uid: 1000,
        ts_ns: 2,
        event_type: crate::platform::EventType::FileOpen,
        payload: format!("path=/tmp/normal;ppid={}", std::process::id()),
    };
    runtime.ingest_polled_raw_events(vec![event]);
    let _ = child.kill();
    let _ = child.wait();
    assert!(runtime.raw_event_backlog.is_empty());
}

#[test]
fn windows_live_generation_rejects_reuse_and_missing_even_with_stale_event() {
    let mut runtime = runtime();
    runtime.windows_process_generations = true;
    runtime.internal_process_start_time_reader = Some(|_| Some(100));
    runtime.track_internal_process_pid(4_000_050, 1, Some(100));
    assert!(runtime.is_tracked_internal_process(4_000_050, 2, Some(100)));
    // A dropped ProcessStop must not let a queued old identity authenticate reuse.
    runtime.internal_process_start_time_reader = Some(|_| Some(200));
    assert!(!runtime.is_tracked_internal_process(4_000_050, 3, Some(100)));
    assert!(!runtime
        .suppressed_internal_process_pids
        .contains_key(&4_000_050));
    runtime.internal_process_start_time_reader = Some(|_| Some(100));
    runtime.track_internal_process_pid(4_000_050, 4, Some(100));
    runtime.internal_process_start_time_reader = Some(|_| None);
    assert!(!runtime.is_tracked_internal_process(4_000_050, 5, Some(100)));
    assert!(!runtime
        .suppressed_internal_process_pids
        .contains_key(&4_000_050));
}

#[test]
fn windows_unknown_parent_generation_cannot_authenticate_ancestry() {
    let mut runtime = runtime();
    runtime.windows_process_generations = true;
    runtime.internal_process_start_time_reader = Some(|_| Some(100));
    let mut event = RawEvent {
        fields: Default::default(),
        pid_start_ns: Some(100),
        ppid_start_ns: None,
        pid: 4_000_051,
        uid: 0,
        ts_ns: 1,
        event_type: crate::platform::EventType::ProcessExec,
        payload: format!("ppid={}", std::process::id()),
    };
    // A PID alone cannot authenticate a parent when ingest could not query it.
    assert!(!runtime.should_suppress_internal_process_event(&event));
    event.ppid_start_ns = Some(100);
    assert!(runtime.should_suppress_internal_process_event(&event));
    event.pid = 4_000_052;
    event.payload = "ppid=4000051".into();
    event.ppid_start_ns = None;
    assert!(!runtime.should_suppress_internal_process_event(&event));
    event.ppid_start_ns = Some(100);
    assert!(runtime.should_suppress_internal_process_event(&event));
    event.pid = 4_000_053;
    event.pid_start_ns = Some(99);
    assert!(!runtime.should_suppress_internal_process_event(&event));
}

#[test]
fn windows_ordinary_events_do_not_query_live_processes() {
    let mut runtime = runtime();
    runtime.windows_process_generations = true;
    runtime.internal_process_start_time_reader =
        Some(|_| panic!("unauthenticated telemetry must not open process handles"));
    let event = RawEvent {
        fields: Default::default(),
        pid_start_ns: None,
        ppid_start_ns: None,
        pid: 4_000_054,
        uid: 0,
        ts_ns: 1,
        event_type: crate::platform::EventType::ProcessExec,
        payload: "ppid=4000055".into(),
    };
    assert!(!runtime.should_suppress_internal_process_event(&event));
    assert!(!runtime.should_suppress_internal_process_event(&event));
}
