use super::*;
#[cfg(target_os = "linux")]
use std::os::unix::fs::symlink;
#[cfg(target_os = "linux")]
use std::process::Command;

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
fn enrich_event_parent_chain_is_bounded_to_max_depth() {
    let mut cache = EnrichmentCache::default();
    let raw = RawEvent {
        event_type: EventType::ProcessExec,
        pid: std::process::id(),
        uid: 0,
        ts_ns: 1,
        payload: "cmdline=/usr/bin/bash -lc whoami".to_string(),
    };

    let enriched = enrich_event_with_cache(raw, &mut cache);
    assert!(enriched.parent_chain.len() <= super::MAX_PARENT_CHAIN_DEPTH);
    assert!(enriched.parent_chain.iter().all(|pid| *pid > 0));
}

#[cfg(target_os = "linux")]
#[test]
fn primed_process_exec_metadata_survives_short_lived_process_exit() {
    let mut child = Command::new("/bin/sh")
        .args(["-c", "sleep 0.2"])
        .spawn()
        .expect("spawn short-lived child");
    let pid = child.id();

    let mut cache = EnrichmentCache::default();
    let raw = RawEvent {
        event_type: EventType::ProcessExec,
        pid,
        uid: 0,
        ts_ns: 1,
        payload: "ppid=1;parent_comm=sh;comm=sh;path=/bin/sh;cmdline=sh".to_string(),
    };

    cache.prime_process_metadata(&raw);
    child.wait().expect("wait for child exit");

    let enriched = enrich_event_with_cache(raw, &mut cache);
    let cmdline = enriched.process_cmdline.expect("cached cmdline");
    assert!(cmdline.contains("sleep 0.2"), "cmdline was {cmdline:?}");
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
fn process_exec_payload_parent_hint_backfills_parent_process_when_proc_lookup_fails() {
    let mut cache = EnrichmentCache::default();
    let raw = RawEvent {
        event_type: EventType::ProcessExec,
        pid: 999_999,
        uid: 0,
        ts_ns: 1,
        payload: "ppid=1;parent_comm=systemd;comm=bash;path=/usr/bin/bash;cmdline=bash -lc whoami"
            .to_string(),
    };

    let enriched = enrich_event_with_cache(raw, &mut cache);
    assert_eq!(enriched.parent_process.as_deref(), Some("systemd"));
    assert_eq!(enriched.parent_chain.first().copied(), Some(1));
}

#[test]
// AC-EBP-030
fn payload_parser_fallbacks_for_dns_and_file_open() {
    let dns = parse_payload_metadata(&EventType::DnsQuery, "malicious.example");
    assert_eq!(dns.dst_domain.as_deref(), Some("malicious.example"));

    let file = parse_payload_metadata(&EventType::FileOpen, "/tmp/dropper.sh");
    assert_eq!(file.file_path.as_deref(), Some("/tmp/dropper.sh"));

    let unlink = parse_payload_metadata(&EventType::FileUnlink, "/tmp/old");
    assert_eq!(unlink.file_path.as_deref(), Some("/tmp/old"));
}

#[test]
// AC-EBP-033
fn payload_parser_extracts_module_load_name() {
    let module = parse_payload_metadata(&EventType::ModuleLoad, "module=fake_rootkit");
    assert_eq!(module.file_path.as_deref(), Some("fake_rootkit"));

    let fallback = parse_payload_metadata(&EventType::ModuleLoad, "bare_module");
    assert_eq!(fallback.file_path.as_deref(), Some("bare_module"));
}

#[test]
// AC-EBP-022
fn platform_name_is_linux() {
    assert_eq!(platform_name(), "linux");
}

#[test]
fn parse_process_start_time_ticks_extracts_field_22_from_proc_stat() {
    let raw = "1234 (cmd with space) R 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242 20";
    assert_eq!(parse_process_start_time_ticks(raw), Some(424_242));
}

#[test]
fn parse_process_start_time_ticks_rejects_short_or_malformed_records() {
    assert!(parse_process_start_time_ticks("1234 (bash) R 1 2 3").is_none());
    assert!(parse_process_start_time_ticks("totally malformed").is_none());
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
fn default_file_hash_cache_capacity_is_bounded_to_ten_thousand_under_churn() {
    let base = std::env::temp_dir().join(format!(
        "eguard-platform-linux-default-cache-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    fs::create_dir_all(&base).expect("create temp dir");

    let mut cache = EnrichmentCache::default();
    let mut first_path = String::new();
    let mut latest_path = String::new();

    for idx in 0..10_128usize {
        let file = base.join(format!("file-{idx}.bin"));
        fs::write(&file, [idx as u8]).expect("write file");
        let path = file.to_string_lossy().into_owned();
        if idx == 0 {
            first_path = path.clone();
        }
        latest_path = path.clone();
        let _ = cache.hash_for_path(&path).expect("hash path");
        assert!(
            cache.file_hash_cache_len() <= 10_000,
            "default cache exceeded ten-thousand cap at index {idx}"
        );
    }

    assert_eq!(cache.file_hash_cache_len(), 10_000);
    assert!(
        !cache.file_hash_cache_contains_path(&first_path),
        "oldest file path should be evicted under churn"
    );
    assert!(
        cache.file_hash_cache_contains_path(&latest_path),
        "most recent file path should remain cached"
    );

    let _ = fs::remove_dir_all(base);
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

#[cfg(target_os = "linux")]
#[test]
fn native_forensics_collector_reads_procfs_fixture() {
    let base = std::env::temp_dir().join(format!(
        "eguard-platform-linux-forensics-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let proc_root = base.join("proc");
    let net_root = proc_root.join("net");
    fs::create_dir_all(proc_root.join("1/fd")).expect("create fd dir");
    fs::create_dir_all(&net_root).expect("create net dir");

    fs::write(
        proc_root.join("1/status"),
        "Name:\tbash\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\n",
    )
    .expect("write status");
    fs::write(proc_root.join("1/comm"), "bash\n").expect("write comm");
    fs::write(proc_root.join("1/cmdline"), b"/usr/bin/bash\0-lc\0whoami\0").expect("write cmdline");
    symlink("/usr/bin/bash", proc_root.join("1/exe")).expect("symlink exe");
    symlink("/tmp/test.txt", proc_root.join("1/fd/3")).expect("symlink fd");

    let header = "  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
    fs::write(
        net_root.join("tcp"),
        format!(
            "{header}   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345 1 0000000000000000 100 0 0 10 0\n"
        ),
    )
    .expect("write tcp");
    fs::write(net_root.join("tcp6"), header).expect("write tcp6");
    fs::write(net_root.join("udp"), header).expect("write udp");
    fs::write(net_root.join("udp6"), header).expect("write udp6");

    let modules_path = base.join("modules");
    fs::write(&modules_path, "dm_mod 123 0 - Live 0x0\n").expect("write modules");

    let collector = ForensicsCollector::with_paths(proc_root.clone(), modules_path);
    let snapshot = collector.collect_full_snapshot(true, true, true, true);

    assert!(snapshot.processes.contains("pid=1"));
    assert!(snapshot
        .processes
        .contains("cmdline=/usr/bin/bash -lc whoami"));
    assert!(snapshot.network.contains("proto=tcp"));
    assert!(snapshot.network.contains("local=127.0.0.1:22"));
    assert!(snapshot.open_files.contains("target=/tmp/test.txt"));
    assert!(snapshot.loaded_modules.contains("dm_mod"));

    let _ = fs::remove_dir_all(base);
}

#[cfg(target_os = "linux")]
#[test]
fn native_forensics_collector_enforces_snapshot_limits() {
    let base = std::env::temp_dir().join(format!(
        "eguard-platform-linux-forensics-limits-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let proc_root = base.join("proc");
    let net_root = proc_root.join("net");
    fs::create_dir_all(proc_root.join("1/fd")).expect("create fd dir 1");
    fs::create_dir_all(proc_root.join("2/fd")).expect("create fd dir 2");
    fs::create_dir_all(&net_root).expect("create net dir");

    for pid in ["1", "2"] {
        fs::write(
            proc_root.join(pid).join("status"),
            format!("Name:\tproc{pid}\nPPid:\t1\nUid:\t0\t0\t0\t0\n"),
        )
        .expect("write status");
        fs::write(proc_root.join(pid).join("comm"), format!("proc{pid}\n")).expect("write comm");
        fs::write(
            proc_root.join(pid).join("cmdline"),
            format!("proc{pid}\0").as_bytes(),
        )
        .expect("write cmdline");
        symlink("/bin/true", proc_root.join(pid).join("exe")).expect("symlink exe");
        symlink("/tmp/fixture", proc_root.join(pid).join("fd/0")).expect("symlink fd");
    }

    let header = "  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
    fs::write(
        net_root.join("tcp"),
        format!(
            "{header}   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 111 1 0000000000000000 100 0 0 10 0\n   1: 0100007F:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 222 1 0000000000000000 100 0 0 10 0\n"
        ),
    )
    .expect("write tcp");
    fs::write(net_root.join("tcp6"), header).expect("write tcp6");
    fs::write(net_root.join("udp"), header).expect("write udp");
    fs::write(net_root.join("udp6"), header).expect("write udp6");

    let modules_path = base.join("modules");
    fs::write(&modules_path, "mod_a 1 0 - Live 0x0\n").expect("write modules");

    let collector =
        ForensicsCollector::with_paths(proc_root.clone(), modules_path).with_limits(1, 1, 1, 1);
    let snapshot = collector.collect_full_snapshot(true, true, true, true);

    assert!(snapshot.processes.contains("truncated"));
    assert!(snapshot.network.contains("truncated"));
    assert!(snapshot.open_files.contains("truncated"));

    let _ = fs::remove_dir_all(base);
}

#[test]
// AC-RES-025
fn event_driven_runtime_primitives_include_inotify_watch_support() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let main_src =
        std::fs::read_to_string(root.join("crates/agent-core/src/main.rs")).expect("main.rs");
    let ebpf_backend_src =
        std::fs::read_to_string(root.join("crates/platform-linux/src/ebpf/libbpf_backend.rs"))
            .expect("libbpf_backend.rs");
    assert!(main_src.contains("time::interval("));
    assert!(main_src.contains("tokio::select!"));
    assert!(ebpf_backend_src.contains(".poll(timeout)"));

    let dir = std::env::temp_dir();
    let fd = open_inotify_nonblocking().expect("open inotify");
    let _wd = add_inotify_watch(fd, &dir).expect("add inotify watch");
    let closed = unsafe { libc::close(fd) };
    assert_eq!(closed, 0);
}

#[test]
// AC-OPT-003 AC-OPT-004
fn enrichment_cache_uses_ootb_o1_lru_implementation_for_recency_updates() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let src = std::fs::read_to_string(root.join("crates/platform-linux/src/lib.rs"))
        .expect("platform-linux lib.rs");
    assert!(src.contains("LruCache<u32, ProcessCacheEntry>"));
    assert!(src.contains("LruCache<String, FileHashCacheEntry>"));
}

#[test]
fn churn_aware_hashing_delays_rehash_until_finalize_window_passes() {
    let base = std::env::temp_dir().join(format!(
        "eguard-platform-linux-hash-delay-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    fs::create_dir_all(&base).expect("create temp dir");

    let file = base.join("payload.bin");
    fs::write(&file, b"version-1").expect("write v1");
    let path = file.to_string_lossy().to_string();

    let mut cache = EnrichmentCache::new(128, 128);
    cache.set_hash_finalize_delay_ms(5_000);

    let stable_hash = cache.hash_for_path(&path).expect("initial hash");

    fs::write(&file, b"version-2-with-more-bytes").expect("write v2");
    let deferred_hash = cache
        .hash_for_path_churn_aware(&path)
        .expect("deferred hash returns previous stable value");
    assert_eq!(deferred_hash, stable_hash);

    cache.set_hash_finalize_delay_ms(0);
    let finalized_hash = cache
        .hash_for_path_churn_aware(&path)
        .expect("finalized hash");
    assert_ne!(finalized_hash, stable_hash);

    let _ = fs::remove_file(file);
    let _ = fs::remove_dir(base);
}

#[test]
fn file_open_hashes_newly_written_file_immediately_even_when_write_event_is_pending() {
    let base = std::env::temp_dir().join(format!(
        "eguard-platform-linux-file-open-hash-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    fs::create_dir_all(&base).expect("create temp dir");

    let file = base.join("eicar.com");
    let payload = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    fs::write(&file, payload).expect("write test file");

    let expected_hash = compute_sha256_file(file.to_string_lossy().as_ref()).expect("hash file");

    let mut cache = EnrichmentCache::new(128, 128);
    cache.set_hash_finalize_delay_ms(60_000);

    let write_raw = RawEvent {
        event_type: EventType::FileWrite,
        pid: std::process::id(),
        uid: 0,
        ts_ns: 1,
        payload: format!(
            "path={};fd=3;size={}",
            file.to_string_lossy(),
            payload.len()
        ),
    };
    let write_enriched = enrich_event_with_cache(write_raw, &mut cache);
    assert!(write_enriched.file_sha256.is_none());

    let open_raw = RawEvent {
        event_type: EventType::FileOpen,
        pid: std::process::id(),
        uid: 0,
        ts_ns: 2,
        payload: format!("path={};flags=0", file.to_string_lossy()),
    };
    let open_enriched = enrich_event_with_cache(open_raw, &mut cache);
    assert_eq!(
        open_enriched.file_sha256.as_deref(),
        Some(expected_hash.as_str())
    );

    let _ = fs::remove_dir_all(base);
}

#[test]
fn pseudo_and_device_paths_skip_file_hashing() {
    let mut cache = EnrichmentCache::new(128, 128);

    let proc_raw = RawEvent {
        event_type: EventType::FileOpen,
        pid: std::process::id(),
        uid: 0,
        ts_ns: 1,
        payload: "path=/proc/self/stat;fd=3;size=0".to_string(),
    };
    let proc_enriched = enrich_event_with_cache(proc_raw, &mut cache);
    assert!(proc_enriched.file_sha256.is_none());

    let dev_raw = RawEvent {
        event_type: EventType::FileOpen,
        pid: std::process::id(),
        uid: 0,
        ts_ns: 2,
        payload: "path=/dev/null;fd=3;size=0".to_string(),
    };
    let dev_enriched = enrich_event_with_cache(dev_raw, &mut cache);
    assert!(dev_enriched.file_sha256.is_none());
}

#[test]
fn expensive_check_exclusions_skip_file_hash_on_noisy_paths() {
    let base = std::env::temp_dir().join(format!(
        "eguard-platform-linux-noisy-cache-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    fs::create_dir_all(&base).expect("create temp dir");

    let noisy_dir = base.join("build-cache");
    fs::create_dir_all(&noisy_dir).expect("create noisy dir");
    let file = noisy_dir.join("artifact.tmp");
    fs::write(&file, b"payload").expect("write file");

    let mut cache = EnrichmentCache::new(128, 128);
    cache.set_expensive_check_exclusions(vec!["build-cache".to_string()], Vec::new());

    let raw = RawEvent {
        event_type: EventType::FileWrite,
        pid: std::process::id(),
        uid: 0,
        ts_ns: 1,
        payload: format!("path={};fd=3;size=7", file.to_string_lossy()),
    };
    let enriched = enrich_event_with_cache(raw, &mut cache);
    assert!(enriched.file_sha256.is_none());

    let _ = fs::remove_dir_all(base);
}

#[test]
fn strict_budget_mode_keeps_hash_for_high_value_tmp_file_open() {
    let base = std::env::temp_dir().join(format!(
        "eguard-platform-linux-strict-budget-high-value-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    fs::create_dir_all(&base).expect("create temp dir");

    let file = base.join("eicar-proof.bin");
    fs::write(&file, b"payload").expect("write file");
    let expected_hash = compute_sha256_file(file.to_string_lossy().as_ref()).expect("hash file");

    let mut cache = EnrichmentCache::new(128, 128);
    cache.set_budget_mode(true);

    let raw = RawEvent {
        event_type: EventType::FileOpen,
        pid: std::process::id(),
        uid: 0,
        ts_ns: 1,
        payload: format!("path={};fd=3;size=7", file.to_string_lossy()),
    };
    let enriched = enrich_event_with_cache(raw, &mut cache);
    assert_eq!(
        enriched.file_sha256.as_deref(),
        Some(expected_hash.as_str())
    );

    let _ = fs::remove_dir_all(base);
}
