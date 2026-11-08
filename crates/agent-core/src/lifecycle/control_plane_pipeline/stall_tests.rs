//! Loopback regressions for R-FIRST-TICK-CONTROL-PLANE-20S.
use super::*;
use crate::config::{AgentConfig, AgentMode};
use crate::lifecycle::PendingControlPlaneTask;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const NOW: i64 = 1_700_000_500;

fn maintenance_tasks() -> Vec<ControlPlaneTaskKind> {
    vec![
        ControlPlaneTaskKind::PolicySync,
        ControlPlaneTaskKind::ThreatIntelRefresh,
        ControlPlaneTaskKind::BaselineUpload,
        ControlPlaneTaskKind::FleetBaselineFetch,
        ControlPlaneTaskKind::IocSignalUpload,
        ControlPlaneTaskKind::CampaignFetch,
    ]
}

struct ResponsiveServer {
    task: tokio::task::JoinHandle<()>,
    requests: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl Drop for ResponsiveServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn responsive_server(listener: TcpListener) -> ResponsiveServer {
    let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured = requests.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut bytes = [0u8; 4096];
                let n = stream.read(&mut bytes).await.unwrap();
                assert_ne!(n, 0);
                request.extend_from_slice(&bytes[..n]);
                if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..end]).to_lowercase();
                    let len: usize = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .unwrap_or("0")
                        .parse()
                        .unwrap();
                    if request.len() >= end + 4 + len {
                        break;
                    }
                }
            }
            let request = String::from_utf8(request).unwrap();
            let path = request
                .split_whitespace()
                .nth(1)
                .unwrap()
                .split('?')
                .next()
                .unwrap()
                .to_string();
            let body = match path.as_str() {
                "/api/v1/endpoint/threat-intel/version" => "{\"versions\":[]}",
                "/api/v1/endpoint/baseline/fleet" => "{\"fleet_baselines\":[]}",
                "/api/v1/endpoint/threat-intel/campaigns" => "{\"campaigns\":[]}",
                _ => "{}",
            };
            captured.lock().unwrap().push(path);
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).as_bytes()).await.unwrap();
        }
    });
    ResponsiveServer { task, requests }
}

#[tokio::test]
async fn cpstall_reachable_six_tasks_keep_order_budget_and_timestamps() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut runtime = runtime(listener.local_addr().unwrap().to_string());
    let server = responsive_server(listener);
    runtime.last_threat_intel_refresh_unix = None;
    runtime.buffer_ioc_signal("reachable.test".into(), "domain".into(), "high", NOW);
    runtime.tick(NOW).await.unwrap();
    assert_eq!(
        *server.requests.lock().unwrap(),
        vec![
            "/api/v1/endpoint/policy",
            "/api/v1/endpoint/threat-intel/version",
            "/api/v1/endpoint/baseline/batch",
            "/api/v1/endpoint/baseline/fleet",
            "/api/v1/endpoint/threat-intel/ioc-signals",
            "/api/v1/endpoint/threat-intel/campaigns",
        ]
    );
    assert_eq!(runtime.metrics.last_control_plane_execute_count, 6);
    assert_eq!(runtime.pending_control_plane_tasks.len(), 1);
    assert!(matches!(
        runtime.pending_control_plane_tasks[0].kind,
        ControlPlaneTaskKind::CommandSync
    ));
    assert_eq!(runtime.maintenance_retry_after_unix, None);
    assert_eq!(runtime.last_policy_fetch_unix, Some(NOW));
    assert_eq!(runtime.last_threat_intel_refresh_unix, Some(NOW));
    assert_eq!(runtime.last_baseline_upload_unix, Some(NOW));
    assert_eq!(runtime.last_fleet_baseline_fetch_unix, Some(NOW));
    assert_eq!(runtime.last_ioc_signal_upload_unix, Some(NOW));
    assert_eq!(runtime.last_campaign_fetch_unix, Some(NOW));
    assert!(runtime.ioc_signal_buffer.is_empty());
    assert!(runtime.dirty_baseline_keys.is_empty());
}

#[tokio::test]
async fn cpstall_deferred_tasks_recover_in_order_at_next_window() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let mut runtime = runtime(addr.to_string());
    runtime.tick(NOW).await.unwrap();
    assert_eq!(runtime.last_policy_fetch_unix, Some(NOW));
    assert_eq!(runtime.last_baseline_upload_unix, None);
    assert_eq!(runtime.last_fleet_baseline_fetch_unix, None);
    assert_eq!(runtime.last_campaign_fetch_unix, None);
    let server = responsive_server(TcpListener::bind(addr).await.unwrap());
    runtime.tick(NOW + 1).await.unwrap();
    assert!(server.requests.lock().unwrap().is_empty());
    runtime.last_heartbeat_attempt_unix = Some(NOW + 30);
    runtime.last_compliance_attempt_unix = Some(NOW + 30);
    runtime.last_inventory_attempt_unix = Some(NOW + 30);
    runtime.last_command_fetch_attempt_unix = Some(NOW + 30);
    runtime.tick(NOW + 30).await.unwrap();
    assert_eq!(
        *server.requests.lock().unwrap(),
        vec![
            "/api/v1/endpoint/baseline/batch",
            "/api/v1/endpoint/baseline/fleet",
            "/api/v1/endpoint/threat-intel/campaigns",
        ]
    );
    assert_eq!(
        runtime.last_policy_fetch_unix,
        Some(NOW),
        "failed attempt keeps its interval"
    );
    assert_eq!(runtime.last_baseline_upload_unix, Some(NOW + 30));
    assert_eq!(runtime.last_fleet_baseline_fetch_unix, Some(NOW + 30));
    assert_eq!(runtime.last_campaign_fetch_unix, Some(NOW + 30));
    assert_eq!(runtime.consecutive_send_failures, 0);
    assert_eq!(runtime.metrics.degraded_due_to_send_failures, 0);
}

#[tokio::test]
async fn cpstall_gate_retains_all_maintenance_without_starving_critical_tasks() {
    let mut runtime = runtime("127.0.0.1:1".into());
    runtime.maintenance_retry_after_unix = Some(NOW + 30);
    runtime.last_heartbeat_attempt_unix = None;
    runtime.last_compliance_attempt_unix = None;
    runtime.last_inventory_attempt_unix = None;
    for kind in maintenance_tasks() {
        runtime.try_enqueue_control_plane_task(kind, NOW - 10);
    }
    runtime.enqueue_due_control_plane_tasks(NOW, None);
    let executed = runtime
        .execute_control_plane_task_budget(NOW)
        .await
        .unwrap();
    assert_eq!(
        executed, 4,
        "skips must not consume the six-task execution budget"
    );
    assert_eq!(
        runtime
            .pending_control_plane_tasks
            .iter()
            .map(|task| task.kind.clone())
            .collect::<Vec<_>>(),
        maintenance_tasks()
    );
    assert!(runtime
        .pending_control_plane_tasks
        .iter()
        .all(|task| task.enqueued_at_unix == NOW - 10));
    assert_eq!(runtime.last_policy_fetch_unix, None);
    assert_eq!(runtime.last_baseline_upload_unix, None);
    assert_eq!(runtime.last_fleet_baseline_fetch_unix, None);
    assert_eq!(runtime.last_campaign_fetch_unix, None);
    assert_eq!(runtime.last_heartbeat_attempt_unix, Some(NOW));
    assert_eq!(runtime.last_compliance_attempt_unix, Some(NOW));
    assert_eq!(runtime.last_inventory_attempt_unix, Some(NOW));
    assert_eq!(runtime.pending_control_plane_sends.len(), 3);
    // Scheduler must not enqueue new maintenance while the gate is closed either.
    runtime.pending_control_plane_tasks.clear();
    runtime.enqueue_due_control_plane_tasks(NOW, None);
    assert!(runtime
        .pending_control_plane_tasks
        .iter()
        .all(|task| !task.kind.is_bounded_maintenance()));
}

#[test]
fn cpstall_gate_expires_at_boundary_and_on_backward_clock_jump() {
    let mut runtime = runtime("127.0.0.1:1".into());
    assert!(!runtime.maintenance_transport_deferred(NOW));
    runtime.maintenance_retry_after_unix = Some(NOW + 30);
    assert!(runtime.maintenance_transport_deferred(NOW));
    assert!(runtime.maintenance_transport_deferred(NOW + 29));
    assert!(!runtime.maintenance_transport_deferred(NOW + 30));
    assert!(
        !runtime.maintenance_transport_deferred(NOW - 1),
        "backward clock jump must expire gate"
    );
}

#[tokio::test]
async fn cpstall_each_maintenance_transport_failure_sets_gate() {
    for kind in maintenance_tasks() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let mut runtime = runtime(addr.to_string());
        runtime.last_threat_intel_refresh_unix = None;
        runtime.buffer_ioc_signal("failed.test".into(), "domain".into(), "high", NOW);
        runtime.try_enqueue_control_plane_task(kind.clone(), NOW);
        assert_eq!(
            runtime
                .execute_control_plane_task_budget(NOW)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            runtime.maintenance_retry_after_unix,
            Some(NOW + 30),
            "{} must set gate",
            kind.kind_name()
        );
    }
}

#[tokio::test]
async fn cpstall_repeated_ioc_failures_remain_bounded() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let mut runtime = runtime(addr.to_string());
    for round in 0..3 {
        let now = NOW + round * 3_600;
        for i in 0..(crate::lifecycle::IOC_SIGNAL_BUFFER_CAP + 32) {
            runtime.buffer_ioc_signal(format!("{round}-{i}.test"), "domain".into(), "high", now);
        }
        runtime.try_enqueue_control_plane_task(ControlPlaneTaskKind::IocSignalUpload, now);
        runtime
            .execute_control_plane_task_budget(now)
            .await
            .unwrap();
        assert_eq!(
            runtime.ioc_signal_buffer.len(),
            crate::lifecycle::IOC_SIGNAL_BUFFER_CAP
        );
    }
}

#[tokio::test]
async fn cpstall_nontransport_error_does_not_set_gate() {
    let mut runtime = runtime("127.0.0.1:1".into());
    runtime.client.set_online(false);
    runtime.try_enqueue_control_plane_task(ControlPlaneTaskKind::BaselineUpload, NOW);
    runtime
        .execute_control_plane_task_budget(NOW)
        .await
        .unwrap();
    assert_eq!(runtime.maintenance_retry_after_unix, None);
}

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
    assert!(
        elapsed <= Duration::from_secs(1),
        "refused tick stalled: {elapsed:?}"
    );
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
        eprintln!(
            "CPSTALL blackhole tick{offset}_ms={}",
            tick_started.elapsed().as_millis()
        );
    }
    let elapsed = started.elapsed();
    assert_eq!(runtime.consecutive_send_failures, 0);
    assert_eq!(runtime.metrics.degraded_due_to_send_failures, 0);
    assert!(
        elapsed <= Duration::from_millis(5_500),
        "three ticks stalled: {elapsed:?}"
    );
}

#[tokio::test]
async fn cpstall_failed_ioc_upload_is_retained_and_retried_after_recovery() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let mut runtime = runtime(addr.to_string());
    runtime.buffer_ioc_signal("example.test".into(), "domain".into(), "high", NOW);
    runtime.try_enqueue_control_plane_task(ControlPlaneTaskKind::IocSignalUpload, NOW);
    runtime
        .execute_control_plane_task_budget(NOW)
        .await
        .unwrap();
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
                let len: usize = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .expect("content length")
                    .parse()
                    .unwrap();
                if request.len() >= end + 4 + len {
                    break;
                }
            }
        }
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
        String::from_utf8(request).unwrap()
    });
    // Failed attempts retain their current interval semantics; recovery is a later due window.
    let later = NOW + 3_600;
    runtime.try_enqueue_control_plane_task(ControlPlaneTaskKind::IocSignalUpload, later);
    runtime
        .execute_control_plane_task_budget(later)
        .await
        .unwrap();
    let request = tokio::time::timeout(Duration::from_millis(250), server).await;
    assert_eq!(
        retained_after_failure, 1,
        "failed upload lost its IOC payload"
    );
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
    runtime
        .pending_control_plane_tasks
        .push_back(PendingControlPlaneTask {
            kind: ControlPlaneTaskKind::IocSignalUpload,
            enqueued_at_unix: NOW,
        });
    runtime
        .execute_control_plane_task_budget(NOW)
        .await
        .unwrap();
    assert_eq!(
        runtime.ioc_signal_buffer.len(),
        1,
        "cancellation lost IOC payload"
    );
}
