use super::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tonic::{Request, Response, Status};

#[test]
// AC-GRP-090
fn url_scheme_defaults_to_http_without_tls() {
    let c = Client::new("10.0.0.1:50051".to_string());
    let u = c.url_for("/api/v1/endpoint/ping");
    assert!(u.starts_with("http://"));
}

#[test]
// AC-GRP-090 AC-GRP-091 AC-GRP-097
fn url_scheme_switches_to_https_with_tls() {
    let base = std::env::temp_dir().join(format!(
        "eguard-agent-tls-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let _ = std::fs::create_dir_all(&base);

    let cert = base.join("agent.crt");
    let key = base.join("agent.key");
    let ca = base.join("ca.crt");
    let _ = std::fs::write(&cert, b"x");
    let _ = std::fs::write(&key, b"x");
    let _ = std::fs::write(&ca, b"x");

    let mut c = Client::new("10.0.0.1:50051".to_string());
    c.configure_tls(TlsConfig {
        cert_path: cert.to_string_lossy().into_owned(),
        key_path: key.to_string_lossy().into_owned(),
        ca_path: ca.to_string_lossy().into_owned(),
    })
    .expect("configure tls");

    let u = c.url_for("/api/v1/endpoint/ping");
    assert!(u.starts_with("https://"));

    let _ = std::fs::remove_file(cert);
    let _ = std::fs::remove_file(key);
    let _ = std::fs::remove_file(ca);
    let _ = std::fs::remove_dir(base);
}

#[test]
// AC-GRP-097
fn configure_tls_rejects_missing_files() {
    let mut c = Client::new("10.0.0.1:50051".to_string());
    let err = c
        .configure_tls(TlsConfig {
            cert_path: "/tmp/definitely-missing-cert.pem".to_string(),
            key_path: "/tmp/definitely-missing-key.pem".to_string(),
            ca_path: "/tmp/definitely-missing-ca.pem".to_string(),
        })
        .expect_err("missing tls files must fail");
    assert!(err.to_string().contains("TLS file does not exist"));
}

#[test]
// AC-GRP-090 AC-GRP-096
fn grpc_base_url_adds_default_scheme() {
    let c = Client::new("127.0.0.1:50051".to_string());
    assert_eq!(c.grpc_base_url(), "http://127.0.0.1:50051");
}

#[test]
// AC-GRP-090
fn grpc_base_url_preserves_existing_scheme() {
    let c = Client::new("https://agent.example:50051".to_string());
    assert_eq!(c.grpc_base_url(), "https://agent.example:50051");
}

#[test]
// AC-GRP-095
fn grpc_max_receive_message_size_matches_contract() {
    assert_eq!(MAX_GRPC_RECV_MSG_SIZE_BYTES, 16 << 20);
}

#[test]
// AC-EBP-071 AC-EBP-091
fn heartbeat_payload_size_and_compressed_overhead_stay_within_budget() {
    let heartbeat = serde_json::json!({
        "agent_id": "agent-1234",
        "agent_version": "0.1.0",
        "compliance_status": "compliant",
    });
    let raw = serde_json::to_vec(&heartbeat).expect("serialize heartbeat");
    assert!(raw.len() <= 200);

    let compressed =
        zstd::encode_all(std::io::Cursor::new(&raw), 3).expect("zstd level3 heartbeat encode");
    assert!(compressed.len() <= 150);
}

#[test]
// AC-GRP-080 AC-GRP-081
fn ensure_online_returns_error_when_offline() {
    let mut c = Client::new("10.0.0.1:50051".to_string());
    c.set_online(false);
    let err = c.ensure_online().expect_err("offline client should fail");
    assert!(err.to_string().contains("server unreachable"));
}

#[test]
// AC-GRP-042
fn protobuf_command_conversion_preserves_fields() {
    let pb_command = pb::AgentCommand {
        command_id: "cmd-1".to_string(),
        command_type: "scan".to_string(),
        payload_json: "{\"scope\":\"quick\"}".to_string(),
        issued_by: "server".to_string(),
        status: "pending".to_string(),
    };
    let converted = from_pb_agent_command(pb_command);
    assert_eq!(converted.command_id, "cmd-1");
    assert_eq!(converted.command_type, "scan");
    assert_eq!(converted.payload_json, "{\"scope\":\"quick\"}");
}

#[tokio::test]
// AC-GRP-020
async fn send_events_empty_batch_returns_without_network() {
    let c = Client::new("127.0.0.1:1".to_string());
    c.send_events(&[])
        .await
        .expect("empty batch should be no-op");
}

#[tokio::test]
// AC-GRP-028 AC-GRP-081
async fn send_events_offline_returns_error() {
    let mut c = Client::new("127.0.0.1:1".to_string());
    c.set_online(false);
    let started = std::time::Instant::now();
    let err = c
        .send_events(&[EventEnvelope {
            agent_id: "a1".to_string(),
            event_type: "alert".to_string(),
            payload_json: "{}".to_string(),
            created_at_unix: 1,
        }])
        .await
        .expect_err("offline send should fail");
    assert!(err.to_string().contains("server unreachable"));
    assert!(started.elapsed() < std::time::Duration::from_millis(20));
}

#[test]
// AC-GRP-029 AC-EBP-070
fn zstd_level3_compresses_process_event_payload_close_to_target_ratio() {
    let mut uncompressed = Vec::new();
    for i in 0..240 {
        let line = format!(
            "{{\"event_type\":\"process_exec\",\"pid\":{},\"ppid\":1,\"uid\":1000,\"comm\":\"python3\",\"cmdline\":\"python3 /tmp/task-{} --arg test --flag --alpha 111 --beta 222 --gamma 333 --delta 444\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"env\":\"PATH=/usr/bin:/bin;HOME=/tmp;LANG=C\",\"cgroup\":\"/system.slice/eguard.service\"}}\n",
            10_000 + i,
            i
        );
        uncompressed.extend_from_slice(line.as_bytes());
    }

    let compressed =
        zstd::encode_all(std::io::Cursor::new(&uncompressed), 3).expect("zstd level3 encode");
    assert!(uncompressed.len() >= 50_000);
    assert!(compressed.len() * 10 <= uncompressed.len());
}

#[tokio::test]
// AC-GRP-040 AC-GRP-081
async fn fetch_commands_offline_returns_error() {
    let mut c = Client::new("127.0.0.1:1".to_string());
    c.set_online(false);
    let err = c
        .fetch_commands("agent-1", &[], 10)
        .await
        .expect_err("offline command fetch should fail");
    assert!(err.to_string().contains("server unreachable"));
}

#[tokio::test]
// AC-GRP-001 AC-GRP-081
async fn enroll_offline_returns_error() {
    let mut c = Client::new("127.0.0.1:1".to_string());
    c.set_online(false);
    let err = c
        .enroll(&EnrollmentEnvelope {
            agent_id: "agent-1".to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            hostname: "host-a".to_string(),
            enrollment_token: Some("tok".to_string()),
            tenant_id: Some("default".to_string()),
        })
        .await
        .expect_err("offline enroll should fail");
    assert!(err.to_string().contains("server unreachable"));
}

#[tokio::test]
// AC-GRP-010 AC-GRP-081
async fn send_heartbeat_offline_returns_error() {
    let mut c = Client::new("127.0.0.1:1".to_string());
    c.set_online(false);
    let err = c
        .send_heartbeat("agent-1", "compliant")
        .await
        .expect_err("offline heartbeat should fail");
    assert!(err.to_string().contains("server unreachable"));
}

#[tokio::test]
// AC-GRP-030 AC-CMP-032 AC-GRP-081
async fn send_compliance_offline_returns_error() {
    let mut c = Client::new("127.0.0.1:1".to_string());
    c.set_online(false);
    let err = c
        .send_compliance(&ComplianceEnvelope {
            agent_id: "agent-1".to_string(),
            policy_id: "policy-1".to_string(),
            check_type: "firewall_enabled".to_string(),
            status: "fail".to_string(),
            detail: "firewall off".to_string(),
            expected_value: "true".to_string(),
            actual_value: "false".to_string(),
        })
        .await
        .expect_err("offline compliance should fail");
    assert!(err.to_string().contains("server unreachable"));
}

#[tokio::test]
// AC-GRP-050 AC-GRP-081
async fn send_response_offline_returns_error() {
    let mut c = Client::new("127.0.0.1:1".to_string());
    c.set_online(false);
    let err = c
        .send_response(&ResponseEnvelope {
            agent_id: "agent-1".to_string(),
            action_type: "kill".to_string(),
            confidence: "definite".to_string(),
            success: true,
            error_message: String::new(),
        })
        .await
        .expect_err("offline response report should fail");
    assert!(err.to_string().contains("server unreachable"));
}

#[tokio::test]
// AC-GRP-060 AC-GRP-081
async fn fetch_latest_threat_intel_offline_returns_error() {
    let mut c = Client::new("127.0.0.1:1".to_string());
    c.set_online(false);
    let err = c
        .fetch_latest_threat_intel()
        .await
        .expect_err("offline threat-intel query should fail");
    assert!(err.to_string().contains("server unreachable"));
}

#[tokio::test]
// AC-GRP-040 AC-GRP-041
async fn stream_command_channel_zero_limit_is_empty() {
    let c = Client::new("127.0.0.1:1".to_string());
    let out = c
        .stream_command_channel("agent-1", &["cmd-1".to_string()], 0)
        .await
        .expect("zero limit should short-circuit");
    assert!(out.is_empty());
}

#[tokio::test]
// AC-GRP-042 AC-GRP-081
async fn ack_command_offline_returns_error() {
    let mut c = Client::new("127.0.0.1:1".to_string());
    c.set_online(false);
    let err = c
        .ack_command("cmd-1", "completed")
        .await
        .expect_err("offline ack should fail");
    assert!(err.to_string().contains("server unreachable"));
}

#[test]
// AC-GRP-061
fn resolve_bundle_download_url_accepts_absolute_url() {
    let c = Client::new("10.0.0.1:50051".to_string());
    let resolved = c
        .resolve_bundle_download_url("https://downloads.example/rules.tar.zst")
        .expect("resolve absolute url");
    assert_eq!(resolved, "https://downloads.example/rules.tar.zst");
}

#[test]
// AC-GRP-061
fn resolve_bundle_download_url_expands_api_relative_path() {
    let c = Client::new("10.0.0.1:50051".to_string());
    let resolved = c
        .resolve_bundle_download_url("/api/v1/endpoint/threat-intel/bundle/rules-v1")
        .expect("resolve relative api path");
    assert_eq!(
        resolved,
        "http://10.0.0.1:50051/api/v1/endpoint/threat-intel/bundle/rules-v1"
    );
}

#[derive(Clone)]
struct EnrollmentTokenRecord {
    expires_at_unix: i64,
    max_uses: u32,
    used: u32,
}

#[derive(Default)]
struct EnrollmentMockState {
    token_table: HashMap<String, EnrollmentTokenRecord>,
    endpoint_agents: Vec<String>,
    last_enrollment_token: Option<String>,
    last_csr_len: Option<usize>,
}

#[derive(Clone)]
struct MockAgentControlService {
    state: Arc<Mutex<EnrollmentMockState>>,
}

#[tonic::async_trait]
impl pb::agent_control_service_server::AgentControlService for MockAgentControlService {
    async fn ping(
        &self,
        _request: Request<pb::PingRequest>,
    ) -> Result<Response<pb::PingResponse>, Status> {
        Ok(Response::new(pb::PingResponse {
            status: "ok".to_string(),
        }))
    }

    async fn enroll(
        &self,
        request: Request<pb::EnrollRequest>,
    ) -> Result<Response<pb::EnrollResponse>, Status> {
        let req = request.into_inner();
        let mut guard = self.state.lock().expect("state lock");

        let token = guard
            .token_table
            .get_mut(&req.enrollment_token)
            .ok_or_else(|| Status::unauthenticated("token not found"))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or_default();
        if token.expires_at_unix <= now {
            return Err(Status::permission_denied("token expired"));
        }
        if token.max_uses > 0 && token.used >= token.max_uses {
            return Err(Status::resource_exhausted("token usage exceeded"));
        }
        if req.csr.is_empty() {
            return Err(Status::invalid_argument("missing csr"));
        }

        token.used += 1;
        guard.last_enrollment_token = Some(req.enrollment_token);
        guard.last_csr_len = Some(req.csr.len());
        guard.endpoint_agents.push(req.hostname);

        Ok(Response::new(pb::EnrollResponse {
            agent_id: "agent-created-1".to_string(),
            signed_certificate: b"signed-by-scep-ca".to_vec(),
            ca_certificate: b"ca-cert".to_vec(),
            initial_policy: "{}".to_string(),
            initial_rules: "{}".to_string(),
            status: "ok".to_string(),
            issued_profile: "default".to_string(),
        }))
    }

    async fn heartbeat(
        &self,
        _request: Request<pb::HeartbeatRequest>,
    ) -> Result<Response<pb::HeartbeatResponse>, Status> {
        Ok(Response::new(pb::HeartbeatResponse {
            heartbeat_interval_secs: 30,
            policy_update: None,
            rule_update: None,
            pending_commands: Vec::new(),
            fleet_baseline: None,
            status: "ok".to_string(),
            server_time: String::new(),
        }))
    }

    async fn get_latest_threat_intel(
        &self,
        _request: Request<pb::ThreatIntelRequest>,
    ) -> Result<Response<pb::ThreatIntelVersion>, Status> {
        Ok(Response::new(pb::ThreatIntelVersion {
            version: String::new(),
            bundle_path: String::new(),
            sigma_count: 0,
            yara_count: 0,
            ioc_count: 0,
            cve_count: 0,
            published_at_unix: 0,
            custom_rule_count: 0,
            custom_rule_version_hash: String::new(),
        }))
    }
}

fn free_local_addr() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    addr
}

async fn spawn_mock_agent_control(
    state: Arc<Mutex<EnrollmentMockState>>,
) -> (std::net::SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let addr = free_local_addr();
    let svc = MockAgentControlService { state };
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(pb::agent_control_service_server::AgentControlServiceServer::new(svc))
            .serve_with_shutdown(addr, async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("serve mock agent-control");
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr, shutdown_tx)
}

#[tokio::test]
// AC-GRP-007 AC-GRP-008 AC-GRP-009 AC-ENR-001 AC-ENR-002
async fn enroll_grpc_validates_token_issues_cert_and_tracks_endpoint_agent_record() {
    let state = Arc::new(Mutex::new(EnrollmentMockState::default()));
    state.lock().expect("state lock").token_table.insert(
        "tok-valid".to_string(),
        EnrollmentTokenRecord {
            expires_at_unix: i64::MAX,
            max_uses: 2,
            used: 0,
        },
    );

    let (addr, shutdown_tx) = spawn_mock_agent_control(state.clone()).await;

    let client = Client::with_mode(addr.to_string(), TransportMode::Grpc);
    client
        .enroll(&EnrollmentEnvelope {
            agent_id: "agent-1".to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            hostname: "host-a".to_string(),
            enrollment_token: Some("tok-valid".to_string()),
            tenant_id: Some("default".to_string()),
        })
        .await
        .expect("enroll must succeed for valid token");

    let guard = state.lock().expect("state lock");
    let token = guard
        .token_table
        .get("tok-valid")
        .expect("existing token record");
    assert_eq!(token.used, 1);
    assert_eq!(guard.endpoint_agents.len(), 1);
    assert_eq!(guard.endpoint_agents[0], "host-a");
    assert_eq!(guard.last_enrollment_token.as_deref(), Some("tok-valid"));
    assert!(guard.last_csr_len.unwrap_or_default() > 0);
    drop(guard);

    let _ = shutdown_tx.send(());
}

#[tokio::test]
// AC-GRP-007 AC-ENR-006
async fn enroll_grpc_rejects_expired_or_exhausted_tokens() {
    let state = Arc::new(Mutex::new(EnrollmentMockState::default()));
    {
        let mut guard = state.lock().expect("state lock");
        guard.token_table.insert(
            "tok-expired".to_string(),
            EnrollmentTokenRecord {
                expires_at_unix: 1,
                max_uses: 1,
                used: 0,
            },
        );
        guard.token_table.insert(
            "tok-maxed".to_string(),
            EnrollmentTokenRecord {
                expires_at_unix: i64::MAX,
                max_uses: 1,
                used: 1,
            },
        );
    }

    let (addr, shutdown_tx) = spawn_mock_agent_control(state.clone()).await;
    let client = Client::with_mode(addr.to_string(), TransportMode::Grpc);

    let expired_err = client
        .enroll(&EnrollmentEnvelope {
            agent_id: "agent-exp".to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            hostname: "host-exp".to_string(),
            enrollment_token: Some("tok-expired".to_string()),
            tenant_id: None,
        })
        .await
        .expect_err("expired token must fail");
    assert!(expired_err
        .to_string()
        .contains("operation enroll_grpc failed"));

    let maxed_err = client
        .enroll(&EnrollmentEnvelope {
            agent_id: "agent-max".to_string(),
            mac: "00:11:22:33:44:66".to_string(),
            hostname: "host-max".to_string(),
            enrollment_token: Some("tok-maxed".to_string()),
            tenant_id: None,
        })
        .await
        .expect_err("maxed token must fail");
    assert!(maxed_err
        .to_string()
        .contains("operation enroll_grpc failed"));

    let guard = state.lock().expect("state lock");
    assert!(guard.endpoint_agents.is_empty());
    assert_eq!(
        guard
            .token_table
            .get("tok-expired")
            .expect("expired token")
            .used,
        0
    );
    assert_eq!(
        guard
            .token_table
            .get("tok-maxed")
            .expect("maxed token")
            .used,
        1
    );
    drop(guard);

    let _ = shutdown_tx.send(());
}

#[tokio::test]
// AC-ENR-006
async fn enroll_grpc_allows_unlimited_token_when_max_uses_zero() {
    let state = Arc::new(Mutex::new(EnrollmentMockState::default()));
    state.lock().expect("state lock").token_table.insert(
        "tok-unlimited".to_string(),
        EnrollmentTokenRecord {
            expires_at_unix: i64::MAX,
            max_uses: 0,
            used: 0,
        },
    );

    let (addr, shutdown_tx) = spawn_mock_agent_control(state.clone()).await;
    let client = Client::with_mode(addr.to_string(), TransportMode::Grpc);
    for i in 0..3 {
        client
            .enroll(&EnrollmentEnvelope {
                agent_id: format!("agent-{i}"),
                mac: "00:11:22:33:44:77".to_string(),
                hostname: format!("host-{i}"),
                enrollment_token: Some("tok-unlimited".to_string()),
                tenant_id: None,
            })
            .await
            .expect("unlimited token should not be usage-capped");
    }

    let guard = state.lock().expect("state lock");
    let token = guard
        .token_table
        .get("tok-unlimited")
        .expect("unlimited token");
    assert_eq!(token.used, 3);
    drop(guard);

    let _ = shutdown_tx.send(());
}
