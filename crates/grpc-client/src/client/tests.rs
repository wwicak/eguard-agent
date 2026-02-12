use super::*;

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
// AC-GRP-090
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
// AC-GRP-081
async fn send_events_offline_returns_error() {
    let mut c = Client::new("127.0.0.1:1".to_string());
    c.set_online(false);
    let err = c
        .send_events(&[EventEnvelope {
            agent_id: "a1".to_string(),
            event_type: "process_exec".to_string(),
            payload_json: "{}".to_string(),
            created_at_unix: 1,
        }])
        .await
        .expect_err("offline send should fail");
    assert!(err.to_string().contains("server unreachable"));
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
