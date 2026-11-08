//! Loopback regressions for R-FIRST-TICK-CONTROL-PLANE-20S.
use super::*;
use crate::config::{AgentConfig, AgentMode};
use crate::lifecycle::PendingControlPlaneTask;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const NOW: i64 = 1_700_000_500;

fn runtime(addr: String) -> AgentRuntime {
    let cfg = AgentConfig {
        agent_id: "cpstall-test".into(),
        transport_mode: "http".into(),
        server_addr: addr,
        offline_buffer_backend: "memory".into(),
        self_protection_integrity_check_interval_secs: 0,
        self_protection_prevent_uninstall: false,
        detection_kernel_integrity_enabled: false,
        detection_memory_scan_enabled: false,
        ..AgentConfig::default()
    };
    let mut runtime = AgentRuntime::new(cfg).expect("runtime");
    runtime.ebpf_engine = platform_linux::EbpfEngine::disabled();
    runtime.runtime_mode = AgentMode::Active;
    runtime.enrolled = true;
    runtime.deferred_bundle_bootstrap_pending = false;
    runtime.last_heartbeat_attempt_unix = Some(NOW);
    runtime.last_compliance_attempt_unix = Some(NOW);
    runtime.last_inventory_attempt_unix = Some(NOW);
    runtime.last_threat_intel_refresh_unix = Some(NOW);
    runtime.last_command_fetch_attempt_unix = Some(NOW);
    runtime.last_baseline_save_unix = Some(NOW);
    runtime.last_memory_scan_unix = Some(NOW);
    runtime.baseline_upload_enabled = true;
    runtime.baseline_upload_canary_percent = 100;
    runtime.fleet_seed_enabled = true;
    runtime.fleet_seed_canary_percent = 100;
    assert_eq!(runtime.buffer.pending_count(), 0);
    assert!(runtime.raw_event_backlog.is_empty());
    assert!(!runtime.strict_budget_mode);
    assert_eq!(runtime.consecutive_send_failures, 0);
    runtime
}

#[tokio::test]
async fn cpstall_refused_first_tick_finishes_within_one_second() {
    // Reserve a loopback port before closing it, rather than relying on a host service.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let mut runtime = runtime(addr.to_string());
    assert!(runtime.policy_refresh_due(NOW));
    assert!(runtime.baseline_upload_due(NOW));
    assert!(runtime.fleet_baseline_fetch_due(NOW));
    assert!(runtime.campaign_fetch_due(NOW));
    let started = Instant::now();
    runtime.tick(NOW).await.unwrap();
    let elapsed = started.elapsed();
    eprintln!("CPSTALL refused tick0_ms={}", elapsed.as_millis());
    assert_eq!(runtime.consecutive_send_failures, 0);
    assert_eq!(runtime.metrics.degraded_due_to_send_failures, 0);
    assert!(elapsed <= Duration::from_secs(1), "refused tick stalled: {elapsed:?}");
}

#[tokio::test]
async fn cpstall_unresponsive_first_three_ticks_share_one_bound() {
    // Keep the listener alive without accepting: TCP connects, HTTP never answers.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut runtime = runtime(listener.local_addr().unwrap().to_string());
    let started = Instant::now();
    for offset in 0..3 {
        let tick_started = Instant::now();
        runtime.tick(NOW + offset).await.unwrap();
        eprintln!("CPSTALL blackhole tick{offset}_ms={}", tick_started.elapsed().as_millis());
    }
    let elapsed = started.elapsed();
    assert_eq!(runtime.consecutive_send_failures, 0);
    assert_eq!(runtime.metrics.degraded_due_to_send_failures, 0);
    assert!(elapsed <= Duration::from_millis(5_500), "three ticks stalled: {elapsed:?}");
}

#[tokio::test]
async fn cpstall_failed_ioc_upload_is_retained_and_retried_after_recovery() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let mut runtime = runtime(addr.to_string());
    runtime.buffer_ioc_signal("example.test".into(), "domain".into(), "high", NOW);
    runtime.try_enqueue_control_plane_task(ControlPlaneTaskKind::IocSignalUpload, NOW);
    runtime.execute_control_plane_task_budget(NOW).await.unwrap();
    let retained_after_failure = runtime.ioc_signal_buffer.len();

    let listener = TcpListener::bind(addr).await.unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        loop {
            let mut bytes = [0u8; 4096];
            let n = stream.read(&mut bytes).await.unwrap();
            assert_ne!(n, 0, "request ended before body");
            request.extend_from_slice(&bytes[..n]);
            if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&request[..end]).to_lowercase();
                let len: usize = headers.lines().find_map(|line| line.strip_prefix("content-length: "))
                    .expect("content length").parse().unwrap();
                if request.len() >= end + 4 + len { break; }
            }
        }
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
        String::from_utf8(request).unwrap()
    });
    // Failed attempts retain their current interval semantics; recovery is a later due window.
    let later = NOW + 3_600;
    runtime.try_enqueue_control_plane_task(ControlPlaneTaskKind::IocSignalUpload, later);
    runtime.execute_control_plane_task_budget(later).await.unwrap();
    let request = tokio::time::timeout(Duration::from_millis(250), server).await;
    assert_eq!(retained_after_failure, 1, "failed upload lost its IOC payload");
    let request = request.expect("recovered upload reached server").unwrap();
    assert!(request.starts_with("POST /api/v1/endpoint/threat-intel/ioc-signals"));
    assert!(request.contains("example.test"));
    assert!(runtime.ioc_signal_buffer.is_empty());
    assert_eq!(runtime.last_ioc_signal_upload_unix, Some(later));
    assert_eq!(runtime.consecutive_send_failures, 0);
}

#[tokio::test]
async fn cpstall_timed_out_ioc_upload_retains_payload() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut runtime = runtime(listener.local_addr().unwrap().to_string());
    runtime.buffer_ioc_signal("timeout.test".into(), "domain".into(), "high", NOW);
    runtime.pending_control_plane_tasks.push_back(PendingControlPlaneTask {
        kind: ControlPlaneTaskKind::IocSignalUpload,
        enqueued_at_unix: NOW,
    });
    runtime.execute_control_plane_task_budget(NOW).await.unwrap();
    assert_eq!(runtime.ioc_signal_buffer.len(), 1, "cancellation lost IOC payload");
}
