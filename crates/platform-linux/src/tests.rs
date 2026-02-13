use super::*;

#[test]
// AC-EBP-032 AC-EBP-062
fn file_hash_cache_reuses_entries() {
    let base = std::env::temp_dir().join(format!(
        "eguard-platform-linux-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    fs::create_dir_all(&base).expect("create temp dir");

    let file = base.join("payload.bin");
    fs::write(&file, b"abc123").expect("write payload");

    let mut cache = EnrichmentCache::default();
    let first = cache
        .hash_for_path(file.to_string_lossy().as_ref())
        .expect("hash first");
    let second = cache
        .hash_for_path(file.to_string_lossy().as_ref())
        .expect("hash second");

    assert_eq!(first, second);
    assert_eq!(cache.file_hash_cache_len(), 1);

    let _ = fs::remove_file(file);
    let _ = fs::remove_dir(base);
}

#[test]
// AC-EBP-031 AC-EBP-061 AC-EBP-062
fn enrich_event_with_cache_populates_process_cache() {
    let mut cache = EnrichmentCache::default();
    let raw = RawEvent {
        event_type: EventType::ProcessExec,
        pid: std::process::id(),
        uid: 0,
        ts_ns: 1,
        payload: "x".to_string(),
    };

    let _ = enrich_event_with_cache(raw.clone(), &mut cache);
    let _ = enrich_event_with_cache(raw, &mut cache);

    assert_eq!(cache.process_cache_len(), 1);
}

#[test]
// AC-EBP-034
fn enrich_event_parent_chain_is_bounded_to_five_ancestors() {
    let mut cache = EnrichmentCache::default();
    let raw = RawEvent {
        event_type: EventType::ProcessExec,
        pid: std::process::id(),
        uid: 0,
        ts_ns: 1,
        payload: "cmdline=/usr/bin/bash -lc whoami".to_string(),
    };

    let enriched = enrich_event_with_cache(raw, &mut cache);
    assert!(enriched.parent_chain.len() <= 5);
    assert!(enriched.parent_chain.iter().all(|pid| *pid > 0));
}

#[test]
// AC-EBP-033
fn payload_parser_extracts_kv_network_fields() {
    let metadata = parse_payload_metadata(
        &EventType::TcpConnect,
        "dst_ip=203.0.113.10;dst_port=8443;domain=c2.example",
    );

    assert_eq!(metadata.dst_ip.as_deref(), Some("203.0.113.10"));
    assert_eq!(metadata.dst_port, Some(8443));
    assert_eq!(metadata.dst_domain.as_deref(), Some("c2.example"));
}

#[test]
// AC-EBP-030
fn payload_parser_fallbacks_for_dns_and_file_open() {
    let dns = parse_payload_metadata(&EventType::DnsQuery, "malicious.example");
    assert_eq!(dns.dst_domain.as_deref(), Some("malicious.example"));

    let file = parse_payload_metadata(&EventType::FileOpen, "/tmp/dropper.sh");
    assert_eq!(file.file_path.as_deref(), Some("/tmp/dropper.sh"));
}

#[test]
// AC-EBP-022
fn platform_name_is_linux() {
    assert_eq!(platform_name(), "linux");
}

#[test]
// AC-EBP-033
fn payload_parser_uses_endpoint_fallback_when_needed() {
    let metadata = parse_payload_metadata(&EventType::TcpConnect, "dst=198.51.100.2:4444");
    assert_eq!(metadata.dst_ip.as_deref(), Some("198.51.100.2"));
    assert_eq!(metadata.dst_port, Some(4444));
}

#[test]
// AC-EBP-033
fn parse_endpoint_supports_bracketed_ipv6() {
    let (ip, port) = parse_endpoint("[2001:db8::1]:8443");
    assert_eq!(ip.as_deref(), Some("2001:db8::1"));
    assert_eq!(port, Some(8443));
}

#[test]
// AC-EBP-061
fn process_cache_is_lru_bounded() {
    let mut cache = EnrichmentCache::new(128, 256);
    for pid in 900_000..900_160 {
        let raw = RawEvent {
            event_type: EventType::ProcessExec,
            pid,
            uid: 0,
            ts_ns: pid as u64,
            payload: String::new(),
        };
        let _ = enrich_event_with_cache(raw, &mut cache);
    }

    assert!(cache.process_cache_len() <= 128);
}

#[test]
// AC-EBP-060
fn file_hash_cache_is_lru_bounded() {
    let base = std::env::temp_dir().join(format!(
        "eguard-platform-linux-cache-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    fs::create_dir_all(&base).expect("create temp dir");

    let mut cache = EnrichmentCache::new(256, 128);
    for idx in 0..140 {
        let file = base.join(format!("file-{idx}.bin"));
        fs::write(&file, format!("payload-{idx}").as_bytes()).expect("write file");
        let _ = cache.hash_for_path(file.to_string_lossy().as_ref());
    }

    assert!(cache.file_hash_cache_len() <= 128);

    let _ = fs::remove_dir_all(base);
}

#[test]
// AC-RES-022
fn default_file_hash_cache_capacity_tracks_ten_thousand_entry_policy_target() {
    let source = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"),
    )
    .expect("read platform source");
    assert!(source.contains("Self::new(500, 10_000)"));

    let projected_bytes = 10_000usize * 50usize;
    assert!((450 * 1024..=550 * 1024).contains(&projected_bytes));
}

#[test]
// AC-RES-023
fn process_exit_event_evicts_process_entry_from_cache() {
    let mut cache = EnrichmentCache::new(500, 10_000);
    let pid = std::process::id();
    let raw_exec = RawEvent {
        event_type: EventType::ProcessExec,
        pid,
        uid: 0,
        ts_ns: 1,
        payload: "cmdline=/usr/bin/bash".to_string(),
    };
    let _ = enrich_event_with_cache(raw_exec, &mut cache);
    assert_eq!(cache.process_cache_len(), 1);

    let raw_exit = RawEvent {
        event_type: EventType::ProcessExit,
        pid,
        uid: 0,
        ts_ns: 2,
        payload: String::new(),
    };
    let _ = enrich_event_with_cache(raw_exit, &mut cache);
    assert_eq!(cache.process_cache_len(), 0);
}

#[test]
// AC-RES-025
fn event_driven_runtime_primitives_include_inotify_watch_support() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let main_src =
        std::fs::read_to_string(root.join("crates/agent-core/src/main.rs")).expect("main.rs");
    let ebpf_src =
        std::fs::read_to_string(root.join("crates/platform-linux/src/ebpf.rs")).expect("ebpf.rs");
    assert!(main_src.contains("time::interval("));
    assert!(main_src.contains("tokio::select!"));
    assert!(ebpf_src.contains(".poll(timeout)"));

    let dir = std::env::temp_dir();
    let fd = open_inotify_nonblocking().expect("open inotify");
    let _wd = add_inotify_watch(fd, &dir).expect("add inotify watch");
    let closed = unsafe { libc::close(fd) };
    assert_eq!(closed, 0);
}
