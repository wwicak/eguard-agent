use super::*;
use crate::types::ComplianceCheckEnvelope;
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_stream::{wrappers::ReceiverStream, StreamExt};
use tonic::{Request, Response, Status};

const TEST_TLS_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUNW78K5A0KsY4c5O6JVr75ReDAnIwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDIyMDA2NTMwNloXDTI2MDIy
MTA2NTMwNlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAuN/5w2cRH6AkHgXAlzrIfRNVtPe9eK6xZKAOhDc1ebgL
8asqY2iEs8x70r+hqpAhpJ/iTrUqec4zs6Dzdl3kLaDKq3kt045qLn4n4qGZgSl6
dlat1xyah5fJNzFJDrGep/MOHZSqMJS36DCFlNDs9itj3vv+P8G656Yh0puFyEhF
8+fnJMtJ32mj5CtHxZm1KiB3CdCN9bIfhUlHfL8MhlU28d/2hzeo0pJ2OLEDKoxs
OLSPMl7YfIRl0hj8AbNxaexilm9CH8AkiCFQHP2HKm9Bkgv9UEHvzHJOEsLVjwKr
BrLvF5eVeSBfvXXUEAwD9/ZLizkknxDmDnQwwhz1jwIDAQABo1MwUTAdBgNVHQ4E
FgQUgH6ot7HcWgm4lLWdRZ3192D9lXEwHwYDVR0jBBgwFoAUgH6ot7HcWgm4lLWd
RZ3192D9lXEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAmwQW
g889YDQJDAcW/bT5X7YKU2EDiPbpfb2ftqYZwr2IeEihHc+Su5IuVd39c5p05VqC
wwuowQqHXWTAiG/Kx1jI2oyc9jxdKnTDvcYuY1puQ3OoVliANjKdK29Y/YFyQZpT
5stU1NAHbXepjlsJjytg/v3ne2ZwtSVRpXZWFjMZsUE20EQVwIcoORvypo6Zpd7O
LdVIRgJR/8LRIPei1UbjHRwGllt198wUsO6Eu4LVm2bbFqF7d2dA11xqXRS+y2Hn
UghqcxBJf/cGPUkoGu63ZSG9hk7sY8st2r++EmuI+14qLzS3OFc06pbTHObJLieQ
hbIMPyekKYTMzyJipg==
-----END CERTIFICATE-----
"#;

const TEST_TLS_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC43/nDZxEfoCQe
BcCXOsh9E1W09714rrFkoA6ENzV5uAvxqypjaISzzHvSv6GqkCGkn+JOtSp5zjOz
oPN2XeQtoMqreS3TjmoufifioZmBKXp2Vq3XHJqHl8k3MUkOsZ6n8w4dlKowlLfo
MIWU0Oz2K2Pe+/4/wbrnpiHSm4XISEXz5+cky0nfaaPkK0fFmbUqIHcJ0I31sh+F
SUd8vwyGVTbx3/aHN6jSknY4sQMqjGw4tI8yXth8hGXSGPwBs3Fp7GKWb0IfwCSI
IVAc/Ycqb0GSC/1QQe/Mck4SwtWPAqsGsu8Xl5V5IF+9ddQQDAP39kuLOSSfEOYO
dDDCHPWPAgMBAAECggEACEi7r7kt7UAxyMlH3f7w/kR1h2G/3b6GOGoWUcUKN7q6
3ki7N4Uhcnpr5KpYRi+l3PNFIshqGiyBPeqtE4AVj23bEbVLtmUf9kFfltTYRLoP
wL8VlG61sJ8T5yM65iuos6ySf1oqs3lBMb2q3rDrTVntubo0+bURTlFaxqMtatIE
BzpJ9eKlj0MyiReFMplro7+TCge9zCluiNNgZDLSTD87+TWlJ9jQuxrpHG7RCjep
qz8Ro4GSWVR0+AaaEvvuLk2G2Min48VV+pAvbt85K876OvmMrId4r1c/2DWapOf0
5xaKUNpgcOaxSda2YZdAU+fSq8T/Ab0PPlxHMLpV4QKBgQDrTHuBr7ugjzwkBka+
szPfhCKk0ul0WtjaFgQIZ1jKt9hZQzxWrSZdVtdCvGBnBR2iGHrO1pWTgxBwODBF
ubrvKHJ5J9uM5twrGYoC20puTa9h9dEoy67fimd/0HHSn9rrATvQqwq0eeVF35xU
YTmacHjDgBI648vG300M+k1rGQKBgQDJI9JYE1DMp872dLLDWgArU02ahBIQBjKX
tEL9cyaTtv3dHtX6nWWvzE+cJrd2dIZz3GX1Xjzf1R5UK+7r9UWG4nt/OjMtT3Ln
ImMOV2CvaJAoM3db+phN5/fuU/k9h07g8KZ6ICA0sETZFE3TzuAxWMCL+QyE1iv9
ASq5V0gi5wKBgQDlX+56MuR2FYtsFs46MplbyAS5pn08Fx+UIagWxSBSpbt68MdO
O4bNsM0xWk+jveHwVWrKXXb8kOSicLPmFLN9VnGZV9h318lDHqdiN4GsW4CfvzEB
UuWLNvHEMF/1Ei4nr1EvDr3lx3pQjjZoL0snGYMwGZYr4EqS+LW09AAqaQKBgHSg
QKaxDHieFHLy13ROCysT8jtVuONxtIQiEXXD/upHgItmBcx61ytH3CE+kcItbohf
kv7i1YkzmZJUpwRKAzZivBjZNjNfjdBXL/hw0a7jgjLNJLhAZW9GwYt/RVVXz3S+
FMlbN1FVo5X7H+VgXr4+J+cBUTD0vizFMHCnGzyhAoGAXFxacR0KfHtfu2IS61Km
4LVn/nh8kFNBT7e6yyTywU2vZ6kGLOTBqZLPyFf1ptaijJvZ4tF3CNAXIhB0Jiro
4+EqX8kvtz4qyfqJAKWt7kgjHDvifQvSJDha8l/ZQxD4zVmOY1IHAct+WBHoykWa
Mx21PUEshgiUdUGJej+L4+w=
-----END PRIVATE KEY-----
"#;

fn write_test_tls_materials(cert: &std::path::Path, key: &std::path::Path, ca: &std::path::Path) {
    std::fs::write(cert, TEST_TLS_CERT_PEM).expect("write test cert");
    std::fs::write(key, TEST_TLS_KEY_PEM).expect("write test key");
    std::fs::write(ca, TEST_TLS_CERT_PEM).expect("write test ca");
}

#[test]
// AC-GRP-090
fn url_scheme_defaults_to_http_without_tls() {
    let c = Client::new("10.0.0.1:50052".to_string());
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
    write_test_tls_materials(&cert, &key, &ca);

    let mut c = Client::new("10.0.0.1:50052".to_string());
    c.configure_tls(TlsConfig {
        cert_path: cert.to_string_lossy().into_owned(),
        key_path: key.to_string_lossy().into_owned(),
        ca_path: ca.to_string_lossy().into_owned(),
        pinned_ca_sha256: None,
        ca_pin_path: None,
    })
    .expect("configure tls");

    let u = c.url_for("/api/v1/endpoint/ping");
    assert!(u.starts_with("https://"));

    let _ = std::fs::remove_file(cert);
    let _ = std::fs::remove_file(key);
    let _ = std::fs::remove_file(ca);
    let _ = std::fs::remove_dir_all(base);
}

#[test]
// AC-ATP-082
fn configure_tls_persists_ca_pin_on_first_use() {
    let base = std::env::temp_dir().join(format!(
        "eguard-agent-tls-pin-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let _ = std::fs::create_dir_all(&base);

    let cert = base.join("agent.crt");
    let key = base.join("agent.key");
    let ca = base.join("ca.crt");
    write_test_tls_materials(&cert, &key, &ca);

    let mut c = Client::new("10.0.0.1:50052".to_string());
    c.configure_tls(TlsConfig {
        cert_path: cert.to_string_lossy().into_owned(),
        key_path: key.to_string_lossy().into_owned(),
        ca_path: ca.to_string_lossy().into_owned(),
        pinned_ca_sha256: None,
        ca_pin_path: None,
    })
    .expect("configure tls should persist CA pin");

    let pin_path = resolve_pin_path(&ca.to_string_lossy(), None);
    let pin_raw = std::fs::read_to_string(&pin_path).expect("read persisted pin");
    assert_eq!(pin_raw.trim().len(), 64);
    assert!(pin_raw.trim().chars().all(|c| c.is_ascii_hexdigit()));

    let _ = std::fs::remove_dir_all(base);
}

#[test]
// AC-ATP-083
fn configure_tls_rejects_changed_ca_when_pin_exists() {
    let base = std::env::temp_dir().join(format!(
        "eguard-agent-tls-pin-mismatch-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let _ = std::fs::create_dir_all(&base);

    let cert = base.join("agent.crt");
    let key = base.join("agent.key");
    let ca = base.join("ca.crt");
    write_test_tls_materials(&cert, &key, &ca);

    let mut first_client = Client::new("10.0.0.1:50052".to_string());
    first_client
        .configure_tls(TlsConfig {
            cert_path: cert.to_string_lossy().into_owned(),
            key_path: key.to_string_lossy().into_owned(),
            ca_path: ca.to_string_lossy().into_owned(),
            pinned_ca_sha256: None,
            ca_pin_path: None,
        })
        .expect("initial configure should persist pin");

    let _ = std::fs::write(&ca, b"ca-v2");

    let mut second_client = Client::new("10.0.0.1:50052".to_string());
    let err = second_client
        .configure_tls(TlsConfig {
            cert_path: cert.to_string_lossy().into_owned(),
            key_path: key.to_string_lossy().into_owned(),
            ca_path: ca.to_string_lossy().into_owned(),
            pinned_ca_sha256: None,
            ca_pin_path: None,
        })
        .expect_err("changed CA should be rejected by pin check");
    assert!(err.to_string().contains("TLS CA pin mismatch"));

    let _ = std::fs::remove_dir_all(base);
}

#[test]
// AC-ATP-082 AC-ATP-083
fn configure_tls_rejects_mismatched_explicit_pinned_hash() {
    let base = std::env::temp_dir().join(format!(
        "eguard-agent-tls-explicit-pin-mismatch-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let _ = std::fs::create_dir_all(&base);

    let cert = base.join("agent.crt");
    let key = base.join("agent.key");
    let ca = base.join("ca.crt");
    write_test_tls_materials(&cert, &key, &ca);

    let mut c = Client::new("10.0.0.1:50052".to_string());
    let err = c
        .configure_tls(TlsConfig {
            cert_path: cert.to_string_lossy().into_owned(),
            key_path: key.to_string_lossy().into_owned(),
            ca_path: ca.to_string_lossy().into_owned(),
            pinned_ca_sha256: Some(
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ),
            ca_pin_path: None,
        })
        .expect_err("mismatched explicit pinned hash should fail");
    assert!(err
        .to_string()
        .contains("TLS CA pin mismatch from TLS config"));

    let _ = std::fs::remove_dir_all(base);
}

#[test]
// AC-ATP-082
fn configure_tls_persists_pin_to_explicit_path() {
    let base = std::env::temp_dir().join(format!(
        "eguard-agent-tls-explicit-pin-path-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let _ = std::fs::create_dir_all(&base);

    let cert = base.join("agent.crt");
    let key = base.join("agent.key");
    let ca = base.join("ca.crt");
    let pin_path = base.join("custom-ca.pin.sha256");
    write_test_tls_materials(&cert, &key, &ca);

    let mut c = Client::new("10.0.0.1:50052".to_string());
    c.configure_tls(TlsConfig {
        cert_path: cert.to_string_lossy().into_owned(),
        key_path: key.to_string_lossy().into_owned(),
        ca_path: ca.to_string_lossy().into_owned(),
        pinned_ca_sha256: None,
        ca_pin_path: Some(pin_path.to_string_lossy().into_owned()),
    })
    .expect("configure tls should persist explicit pin path");

    let persisted_pin = std::fs::read_to_string(&pin_path).expect("read explicit pin file");
    assert_eq!(persisted_pin.trim().len(), 64);

    let _ = std::fs::remove_dir_all(base);
}

#[test]
// AC-GRP-097
fn configure_tls_rejects_missing_files() {
    let mut c = Client::new("10.0.0.1:50052".to_string());
    let err = c
        .configure_tls(TlsConfig {
            cert_path: "/tmp/definitely-missing-cert.pem".to_string(),
            key_path: "/tmp/definitely-missing-key.pem".to_string(),
            ca_path: "/tmp/definitely-missing-ca.pem".to_string(),
            pinned_ca_sha256: None,
            ca_pin_path: None,
        })
        .expect_err("missing tls files must fail");
    assert!(err.to_string().contains("TLS file does not exist"));
}

#[test]
fn configure_tls_rejects_invalid_http_tls_material() {
    let base = std::env::temp_dir().join(format!(
        "eguard-agent-tls-invalid-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let _ = std::fs::create_dir_all(&base);

    let cert = base.join("agent.crt");
    let key = base.join("agent.key");
    let ca = base.join("ca.crt");
    let _ = std::fs::write(&cert, b"invalid-cert");
    let _ = std::fs::write(&key, b"invalid-key");
    let _ = std::fs::write(&ca, b"invalid-ca");

    let mut c = Client::new("10.0.0.1:50052".to_string());
    let err = c
        .configure_tls(TlsConfig {
            cert_path: cert.to_string_lossy().into_owned(),
            key_path: key.to_string_lossy().into_owned(),
            ca_path: ca.to_string_lossy().into_owned(),
            pinned_ca_sha256: None,
            ca_pin_path: Some(base.join("ca.pin.sha256").to_string_lossy().into_owned()),
        })
        .expect_err("invalid tls material should fail http client construction");
    assert!(
        err.to_string().contains("invalid HTTP TLS"),
        "unexpected error: {}",
        err
    );

    let _ = std::fs::remove_dir_all(base);
}

#[test]
// AC-GRP-090 AC-GRP-096
fn grpc_base_url_adds_default_scheme() {
    let c = Client::new("127.0.0.1:50052".to_string());
    assert_eq!(c.grpc_base_url(), "http://127.0.0.1:50052");
}

#[test]
// AC-GRP-090
fn grpc_base_url_preserves_existing_scheme() {
    let c = Client::new("https://agent.example:50052".to_string());
    assert_eq!(c.grpc_base_url(), "https://agent.example:50052");
}

#[test]
// AC-PKG-027
fn client_agent_version_can_be_updated_for_subsequent_heartbeat_reporting() {
    let mut c = Client::new("127.0.0.1:50052".to_string());
    assert_eq!(c.agent_version(), env!("CARGO_PKG_VERSION"));

    c.set_agent_version("1.2.3");
    assert_eq!(c.agent_version(), "1.2.3");

    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let grpc_src = std::fs::read_to_string(root.join("src/client/client_grpc.rs"))
        .expect("read client_grpc.rs");
    let http_src = std::fs::read_to_string(root.join("src/client/client_http.rs"))
        .expect("read client_http.rs");
    assert!(grpc_src.contains("agent_version: self.agent_version.clone()"));
    assert!(http_src.contains("\"agent_version\": self.agent_version.clone()"));
}

#[test]
// AC-GRP-095
fn grpc_max_receive_message_size_matches_contract() {
    assert_eq!(MAX_GRPC_RECV_MSG_SIZE_BYTES, 16 << 20);
}

#[test]
// AC-EBP-071 AC-EBP-072 AC-EBP-085 AC-EBP-091
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
    let avg_bytes_per_sec = compressed.len() as f64 / 30.0;
    assert!(avg_bytes_per_sec <= 500.0);
}

#[test]
// AC-GRP-080 AC-GRP-081
fn ensure_online_returns_error_when_offline() {
    let mut c = Client::new("10.0.0.1:50052".to_string());
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
            severity: String::new(),
            rule_name: String::new(),
            payload_json: "{}".to_string(),
            created_at_unix: 1,
        }])
        .await
        .expect_err("offline send should fail");
    assert!(err.to_string().contains("server unreachable"));
    assert!(started.elapsed() < std::time::Duration::from_millis(20));
}

#[test]
// AC-GRP-029 AC-EBP-070 AC-RES-024
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
// AC-BSL-031 AC-BSL-032 AC-BSL-033
async fn fetch_fleet_baselines_http_returns_seed_rows() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fleet baseline mock server");
    let addr = listener.local_addr().expect("local addr");

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept client");
        let mut request_buf = vec![0u8; 4096];
        let _ = stream.read(&mut request_buf).await;

        let body = r#"{
  "status":"ok",
  "seeded":true,
  "fleet_baselines":[
    {
      "process_key":"bash:sshd",
      "median_distribution":{
        "process_exec":0.55,
        "dns_query":0.45
      },
      "agent_count":12,
      "stddev_kl":0.07,
      "source":"fleet_aggregated"
    }
  ]
}"#;

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body,
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write mock response");
    });

    let client = Client::new(addr.to_string());
    let baselines = client
        .fetch_fleet_baselines(32)
        .await
        .expect("fetch fleet baselines");

    assert_eq!(baselines.len(), 1);
    assert_eq!(baselines[0].process_key, "bash:sshd");
    assert_eq!(baselines[0].agent_count, 12);
    assert!(baselines[0]
        .median_distribution
        .contains_key("process_exec"));

    server.await.expect("mock server join");
}

#[tokio::test]
// AC-REM-002 AC-REM-004
async fn fetch_policy_http_returns_certificate_policy_payload() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind policy mock server");
    let addr = listener.local_addr().expect("local addr");

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept client");
        let mut request_buf = vec![0u8; 4096];
        let _ = stream.read(&mut request_buf).await;

        let body = r#"{
  "policy_id":"policy-7",
  "config_version":"cfg-9",
  "policy_json":"{\"firewall_required\":true}",
  "certificate_policy":{
    "pinned_ca_sha256":"abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
    "rotate_before_expiry_days":21,
    "seamless_rotation":true,
    "require_client_cert_for_all_rpcs_except_enroll":true,
    "grpc_max_recv_msg_size_bytes":16777216,
    "grpc_port":50052
  }
}"#;

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body,
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write mock response");
    });

    let client = Client::new(addr.to_string());
    let policy = client
        .fetch_policy("agent-1")
        .await
        .expect("fetch policy")
        .expect("expected policy payload");

    assert_eq!(policy.policy_id, "policy-7");
    assert_eq!(policy.config_version, "cfg-9");
    assert!(policy.policy_json.contains("firewall_required"));
    let cert_policy = policy
        .certificate_policy
        .expect("certificate policy should be present");
    assert_eq!(cert_policy.rotate_before_expiry_days, 21);
    assert_eq!(cert_policy.grpc_port, 50052);

    server.await.expect("mock server join");
}

#[tokio::test]
// AC-GRP-042
async fn ack_command_http_includes_agent_id_for_collector_contract() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ack mock server");
    let addr = listener.local_addr().expect("local addr");

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept client");
        let mut request_buf = vec![0u8; 4096];
        let read_len = stream.read(&mut request_buf).await.expect("read request");
        let request = std::str::from_utf8(&request_buf[..read_len]).expect("utf8 request");
        assert!(request.starts_with("POST /api/v1/endpoint/command/ack "));

        let body = request
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .expect("split request body");
        let payload: serde_json::Value = serde_json::from_str(body).expect("parse request json");
        assert_eq!(payload["agent_id"], "agent-http-1");
        assert_eq!(payload["command_id"], "cmd-http-1");
        assert_eq!(payload["status"], "completed");

        let response_body = r#"{"status":"ack_saved"}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response_body.len(),
            response_body,
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write mock response");
    });

    let client = Client::new(addr.to_string());
    client
        .ack_command("agent-http-1", "cmd-http-1", "completed")
        .await
        .expect("ack command should succeed");

    server.await.expect("mock server join");
}

#[tokio::test]
// AC-GRP-020
async fn send_events_http_maps_payload_json_into_event_data_object() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind telemetry mock server");
    let addr = listener.local_addr().expect("local addr");

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept client");
        let mut request_buf = vec![0u8; 8192];
        let read_len = stream.read(&mut request_buf).await.expect("read request");
        let request = std::str::from_utf8(&request_buf[..read_len]).expect("utf8 request");
        assert!(request.starts_with("POST /api/v1/endpoint/telemetry "));

        let body = request
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .expect("split request body");
        let payload: serde_json::Value = serde_json::from_str(body).expect("parse request json");
        assert_eq!(payload["agent_id"], "agent-http-telemetry");
        assert_eq!(payload["event_type"], "process_exec");
        assert_eq!(payload["event_data"]["pid"], 4242);
        assert_eq!(payload["event_data"]["exe"], "/bin/sh");

        let response_body = r#"{"status":"telemetry_accepted"}"#;
        let response = format!(
            "HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response_body.len(),
            response_body,
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write mock response");
    });

    let client = Client::new(addr.to_string());
    client
        .send_events(&[EventEnvelope {
            agent_id: "agent-http-telemetry".to_string(),
            event_type: "process_exec".to_string(),
            severity: String::new(),
            rule_name: String::new(),
            payload_json: "{\"pid\":4242,\"exe\":\"/bin/sh\"}".to_string(),
            created_at_unix: 1_700_000_000,
        }])
        .await
        .expect("send events should succeed");

    server.await.expect("mock server join");
}

#[tokio::test]
// AC-GRP-020
async fn send_events_grpc_falls_back_to_http_when_grpc_stream_is_unavailable() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind telemetry fallback mock server");
    let addr = listener.local_addr().expect("local addr");

    let server = tokio::spawn(async move {
        let result = tokio::time::timeout(std::time::Duration::from_secs(12), async move {
            for _ in 0..8 {
                let (mut stream, _) = listener.accept().await.expect("accept client");
                let mut request_buf = vec![0u8; 8192];
                let read_len = stream.read(&mut request_buf).await.expect("read request");
                if read_len == 0 {
                    continue;
                }

                let request = String::from_utf8_lossy(&request_buf[..read_len]);
                if !request.starts_with("POST /api/v1/endpoint/telemetry ") {
                    continue;
                }

                let body = request
                    .split_once("\r\n\r\n")
                    .map(|(_, body)| body)
                    .expect("split request body");
                let payload: serde_json::Value =
                    serde_json::from_str(body).expect("parse request json");
                assert_eq!(payload["agent_id"], "agent-grpc-fallback");
                assert_eq!(payload["event_type"], "process_exec");

                let response_body = r#"{"status":"telemetry_accepted"}"#;
                let response = format!(
                    "HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body,
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write mock response");
                return;
            }
            panic!("did not observe HTTP telemetry fallback request");
        })
        .await;

        if let Err(err) = result {
            panic!("timeout waiting for HTTP telemetry fallback request: {err}");
        }
    });

    let client = Client::with_mode(addr.to_string(), TransportMode::Grpc);
    client
        .send_events(&[EventEnvelope {
            agent_id: "agent-grpc-fallback".to_string(),
            event_type: "process_exec".to_string(),
            severity: String::new(),
            rule_name: String::new(),
            payload_json: "{\"pid\":7}".to_string(),
            created_at_unix: 1_700_000_123,
        }])
        .await
        .expect("telemetry send should fall back to HTTP");

    server.await.expect("mock server join");
}

#[tokio::test]
async fn send_events_grpc_clears_forced_http_fallback_after_successful_grpc_retry() {
    let state = Arc::new(Mutex::new(TelemetryMockState::default()));
    let server = spawn_mock_telemetry_service(state.clone()).await;

    let mut client = Client::with_mode("inproc-telemetry".to_string(), TransportMode::Grpc);
    client.set_test_channel_override(server.channel());
    client
        .grpc_reporting_force_http
        .store(true, Ordering::Relaxed);

    client
        .send_events(&[EventEnvelope {
            agent_id: "agent-grpc-recovery".to_string(),
            event_type: "process_exec".to_string(),
            severity: String::new(),
            rule_name: String::new(),
            payload_json: "{\"pid\":42}".to_string(),
            created_at_unix: 1_700_000_777,
        }])
        .await
        .expect("forced fallback mode should recover when gRPC succeeds");

    assert!(
        !client.grpc_reporting_force_http.load(Ordering::Relaxed),
        "expected forced HTTP fallback flag to clear after successful gRPC send"
    );
    let guard = state.lock().expect("telemetry state lock");
    assert_eq!(guard.batches.len(), 1);

    server.shutdown().await;
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
            policy_version: String::new(),
            policy_hash: String::new(),
            schema_version: String::new(),
            checked_at_unix: 0,
            overall_status: String::new(),
            checks: Vec::new(),
            check_type: "firewall_enabled".to_string(),
            status: "non_compliant".to_string(),
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
// AC-REM-002 AC-REM-004
async fn fetch_policy_offline_returns_error() {
    let mut c = Client::new("127.0.0.1:1".to_string());
    c.set_online(false);
    let err = c
        .fetch_policy("agent-1")
        .await
        .expect_err("offline policy query should fail");
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
        .ack_command("agent-1", "cmd-1", "completed")
        .await
        .expect_err("offline ack should fail");
    assert!(err.to_string().contains("server unreachable"));
}

#[test]
// AC-GRP-061
fn resolve_bundle_download_url_accepts_absolute_url() {
    let c = Client::new("10.0.0.1:50052".to_string());
    let resolved = c
        .resolve_bundle_download_url("https://downloads.example/rules.tar.zst")
        .expect("resolve absolute url");
    assert_eq!(resolved, "https://downloads.example/rules.tar.zst");
}

#[test]
// AC-GRP-061
fn resolve_bundle_download_url_expands_api_relative_path() {
    let c = Client::new("10.0.0.1:50052".to_string());
    let resolved = c
        .resolve_bundle_download_url("/api/v1/endpoint/threat-intel/bundle/rules-v1")
        .expect("resolve relative api path");
    assert_eq!(
        resolved,
        "http://10.0.0.1:50052/api/v1/endpoint/threat-intel/bundle/rules-v1"
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
    heartbeats: Vec<pb::HeartbeatRequest>,
    threat_intel_requests: Vec<pb::ThreatIntelRequest>,
    threat_intel_response: Option<pb::ThreatIntelVersion>,
}

#[derive(Default)]
struct ComplianceMockState {
    reports: Vec<pb::ComplianceReport>,
}

#[derive(Default)]
struct ResponseMockState {
    reports: Vec<pb::ResponseReport>,
}

#[derive(Default)]
struct TelemetryMockState {
    batches: Vec<pb::TelemetryBatch>,
}

#[derive(Clone)]
struct MockAgentControlService {
    state: Arc<Mutex<EnrollmentMockState>>,
}

#[derive(Clone)]
struct MockResponseService {
    state: Arc<Mutex<ResponseMockState>>,
}

#[derive(Clone)]
struct MockComplianceService {
    state: Arc<Mutex<ComplianceMockState>>,
}

#[derive(Clone)]
struct MockCommandService {
    state: Arc<Mutex<CommandMockState>>,
}

#[derive(Default)]
struct CommandMockState {
    command_channel_should_fail: bool,
    channel_commands: Vec<pb::ServerCommand>,
    poll_commands: Vec<pb::AgentCommand>,
    channel_requests: Vec<pb::CommandPollRequest>,
    poll_requests: Vec<pb::PollCommandsRequest>,
    ack_requests: Vec<pb::AckCommandRequest>,
}

#[derive(Clone)]
struct MockTelemetryService {
    state: Arc<Mutex<TelemetryMockState>>,
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
        request: Request<pb::HeartbeatRequest>,
    ) -> Result<Response<pb::HeartbeatResponse>, Status> {
        self.state
            .lock()
            .expect("state lock")
            .heartbeats
            .push(request.into_inner());
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
        request: Request<pb::ThreatIntelRequest>,
    ) -> Result<Response<pb::ThreatIntelVersion>, Status> {
        let mut guard = self.state.lock().expect("state lock");
        guard.threat_intel_requests.push(request.into_inner());
        Ok(Response::new(
            guard
                .threat_intel_response
                .clone()
                .unwrap_or(pb::ThreatIntelVersion {
                    version: String::new(),
                    bundle_path: String::new(),
                    sigma_count: 0,
                    yara_count: 0,
                    ioc_count: 0,
                    cve_count: 0,
                    published_at_unix: 0,
                    custom_rule_count: 0,
                    custom_rule_version_hash: String::new(),
                    bundle_signature_path: String::new(),
                    bundle_sha256: String::new(),
                }),
        ))
    }
}

#[tonic::async_trait]
impl pb::response_service_server::ResponseService for MockResponseService {
    async fn report_response(
        &self,
        request: Request<pb::ResponseReport>,
    ) -> Result<Response<pb::ResponseAck>, Status> {
        let mut guard = self.state.lock().expect("state lock");
        guard.reports.push(request.into_inner());
        Ok(Response::new(pb::ResponseAck {
            accepted: true,
            incident_id: "inc-1".to_string(),
            status: "ok".to_string(),
        }))
    }
}

#[tonic::async_trait]
impl pb::compliance_service_server::ComplianceService for MockComplianceService {
    async fn report_compliance(
        &self,
        request: Request<pb::ComplianceReport>,
    ) -> Result<Response<pb::ComplianceAck>, Status> {
        let mut guard = self.state.lock().expect("state lock");
        guard.reports.push(request.into_inner());
        Ok(Response::new(pb::ComplianceAck {
            accepted: true,
            next_check_override_secs: 0,
            status: "ok".to_string(),
        }))
    }
}

#[tonic::async_trait]
impl pb::command_service_server::CommandService for MockCommandService {
    type CommandChannelStream = ReceiverStream<Result<pb::ServerCommand, Status>>;

    async fn command_channel(
        &self,
        request: Request<pb::CommandPollRequest>,
    ) -> Result<Response<Self::CommandChannelStream>, Status> {
        let (commands, should_fail) = {
            let mut guard = self.state.lock().expect("state lock");
            guard.channel_requests.push(request.into_inner());
            (
                guard.channel_commands.clone(),
                guard.command_channel_should_fail,
            )
        };

        if should_fail {
            return Err(Status::unavailable("command channel disabled for test"));
        }

        let (tx, rx) = tokio::sync::mpsc::channel(commands.len().max(1));
        for command in commands {
            tx.send(Ok(command))
                .await
                .map_err(|_| Status::internal("failed to send command stream item"))?;
        }
        drop(tx);
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn poll_commands(
        &self,
        request: Request<pb::PollCommandsRequest>,
    ) -> Result<Response<pb::PollCommandsResponse>, Status> {
        let mut guard = self.state.lock().expect("state lock");
        guard.poll_requests.push(request.into_inner());
        Ok(Response::new(pb::PollCommandsResponse {
            commands: guard.poll_commands.clone(),
        }))
    }

    async fn ack_command(
        &self,
        request: Request<pb::AckCommandRequest>,
    ) -> Result<Response<pb::AckCommandResponse>, Status> {
        let ack = request.into_inner();
        let status = ack.status.clone();
        self.state
            .lock()
            .expect("state lock")
            .ack_requests
            .push(ack);
        Ok(Response::new(pb::AckCommandResponse { status }))
    }

    async fn enqueue_command(
        &self,
        _request: Request<pb::EnqueueCommandRequest>,
    ) -> Result<Response<pb::EnqueueCommandResponse>, Status> {
        Ok(Response::new(pb::EnqueueCommandResponse {
            status: "ok".to_string(),
        }))
    }
}

#[tonic::async_trait]
impl pb::telemetry_service_server::TelemetryService for MockTelemetryService {
    async fn send_event(
        &self,
        request: Request<pb::TelemetryEvent>,
    ) -> Result<Response<pb::TelemetryAck>, Status> {
        let event = request.into_inner();
        let mut guard = self.state.lock().expect("state lock");
        guard.batches.push(pb::TelemetryBatch {
            agent_id: event.agent_id.clone(),
            events: vec![event],
            compressed: false,
            events_compressed: Vec::new(),
        });
        Ok(Response::new(pb::TelemetryAck {
            status: "ok".to_string(),
        }))
    }

    type StreamEventsStream = ReceiverStream<Result<pb::EventAck, Status>>;

    async fn stream_events(
        &self,
        request: Request<tonic::Streaming<pb::TelemetryBatch>>,
    ) -> Result<Response<Self::StreamEventsStream>, Status> {
        let mut stream = request.into_inner();
        let mut accepted = 0i64;
        while let Some(batch) = stream.message().await? {
            accepted += batch.events.len() as i64;
            self.state.lock().expect("state lock").batches.push(batch);
        }

        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tx.send(Ok(pb::EventAck {
            last_event_offset: accepted,
            events_accepted: accepted,
        }))
        .await
        .map_err(|_| Status::internal("failed to send telemetry ack"))?;
        drop(tx);
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn report_inventory(
        &self,
        _request: Request<pb::InventoryReport>,
    ) -> Result<Response<pb::InventoryAck>, Status> {
        Ok(Response::new(pb::InventoryAck {
            status: "ok".to_string(),
            next_report_override_secs: 0,
        }))
    }
}

struct MockServerHandle {
    channel: tonic::transport::Channel,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

impl MockServerHandle {
    fn channel(&self) -> tonic::transport::Channel {
        self.channel.clone()
    }

    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

#[derive(Clone)]
struct InMemoryConnector {
    incoming_tx: tokio::sync::mpsc::Sender<InMemoryIo>,
}

impl InMemoryConnector {
    fn new(incoming_tx: tokio::sync::mpsc::Sender<InMemoryIo>) -> Self {
        Self { incoming_tx }
    }
}

impl tonic::codegen::Service<tonic::codegen::http::Uri> for InMemoryConnector {
    type Response = TokioIo<tokio::io::DuplexStream>;
    type Error = std::io::Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: tonic::codegen::http::Uri) -> Self::Future {
        let incoming_tx = self.incoming_tx.clone();
        Box::pin(async move {
            let (client_side, server_side) = tokio::io::duplex(64 * 1024);
            incoming_tx
                .send(InMemoryIo::new(server_side))
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "in-memory server channel closed",
                    )
                })?;
            Ok(TokioIo::new(client_side))
        })
    }
}

struct InMemoryIo {
    inner: tokio::io::DuplexStream,
}

impl InMemoryIo {
    fn new(inner: tokio::io::DuplexStream) -> Self {
        Self { inner }
    }
}

impl AsyncRead for InMemoryIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for InMemoryIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl tonic::transport::server::Connected for InMemoryIo {
    type ConnectInfo = ();

    fn connect_info(&self) -> Self::ConnectInfo {}
}

async fn connect_in_memory_channel(
    incoming_tx: tokio::sync::mpsc::Sender<InMemoryIo>,
) -> tonic::transport::Channel {
    tonic::transport::Endpoint::from_static("http://[::]:50052")
        .connect_with_connector(InMemoryConnector::new(incoming_tx))
        .await
        .expect("connect mock in-memory gRPC channel")
}

async fn spawn_mock_agent_control(state: Arc<Mutex<EnrollmentMockState>>) -> MockServerHandle {
    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel::<InMemoryIo>(8);
    let incoming = ReceiverStream::new(incoming_rx).map(Ok::<InMemoryIo, std::io::Error>);
    let svc = MockAgentControlService { state };
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(pb::agent_control_service_server::AgentControlServiceServer::new(svc))
            .serve_with_incoming_shutdown(incoming, async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("serve mock agent-control");
    });
    let channel = connect_in_memory_channel(incoming_tx).await;
    MockServerHandle {
        channel,
        shutdown_tx,
    }
}

async fn spawn_mock_response_service(state: Arc<Mutex<ResponseMockState>>) -> MockServerHandle {
    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel::<InMemoryIo>(8);
    let incoming = ReceiverStream::new(incoming_rx).map(Ok::<InMemoryIo, std::io::Error>);
    let svc = MockResponseService { state };
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(pb::response_service_server::ResponseServiceServer::new(svc))
            .serve_with_incoming_shutdown(incoming, async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("serve mock response");
    });
    let channel = connect_in_memory_channel(incoming_tx).await;
    MockServerHandle {
        channel,
        shutdown_tx,
    }
}

async fn spawn_mock_compliance_service(state: Arc<Mutex<ComplianceMockState>>) -> MockServerHandle {
    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel::<InMemoryIo>(8);
    let incoming = ReceiverStream::new(incoming_rx).map(Ok::<InMemoryIo, std::io::Error>);
    let svc = MockComplianceService { state };
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(pb::compliance_service_server::ComplianceServiceServer::new(
                svc,
            ))
            .serve_with_incoming_shutdown(incoming, async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("serve mock compliance");
    });
    let channel = connect_in_memory_channel(incoming_tx).await;
    MockServerHandle {
        channel,
        shutdown_tx,
    }
}

async fn spawn_mock_command_service(state: Arc<Mutex<CommandMockState>>) -> MockServerHandle {
    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel::<InMemoryIo>(8);
    let incoming = ReceiverStream::new(incoming_rx).map(Ok::<InMemoryIo, std::io::Error>);
    let svc = MockCommandService { state };
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(pb::command_service_server::CommandServiceServer::new(svc))
            .serve_with_incoming_shutdown(incoming, async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("serve mock command");
    });
    let channel = connect_in_memory_channel(incoming_tx).await;
    MockServerHandle {
        channel,
        shutdown_tx,
    }
}

async fn spawn_mock_telemetry_service(state: Arc<Mutex<TelemetryMockState>>) -> MockServerHandle {
    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel::<InMemoryIo>(8);
    let incoming = ReceiverStream::new(incoming_rx).map(Ok::<InMemoryIo, std::io::Error>);
    let svc = MockTelemetryService { state };
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(pb::telemetry_service_server::TelemetryServiceServer::new(
                svc,
            ))
            .serve_with_incoming_shutdown(incoming, async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("serve mock telemetry");
    });
    let channel = connect_in_memory_channel(incoming_tx).await;
    MockServerHandle {
        channel,
        shutdown_tx,
    }
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

    let server = spawn_mock_agent_control(state.clone()).await;
    let mut client = Client::with_mode("inproc-agent-control".to_string(), TransportMode::Grpc);
    client.set_test_channel_override(server.channel());
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

    {
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
    }

    server.shutdown().await;
}

#[tokio::test]
// AC-GRP-004
async fn enroll_with_material_returns_certificate_payloads() {
    let state = Arc::new(Mutex::new(EnrollmentMockState::default()));
    state.lock().expect("state lock").token_table.insert(
        "tok-valid-material".to_string(),
        EnrollmentTokenRecord {
            expires_at_unix: i64::MAX,
            max_uses: 1,
            used: 0,
        },
    );

    let server = spawn_mock_agent_control(state).await;
    let mut client = Client::with_mode("inproc-agent-control".to_string(), TransportMode::Grpc);
    client.set_test_channel_override(server.channel());
    let material = client
        .enroll_with_material(&EnrollmentEnvelope {
            agent_id: "agent-material".to_string(),
            mac: "00:11:22:33:44:11".to_string(),
            hostname: "host-material".to_string(),
            enrollment_token: Some("tok-valid-material".to_string()),
            tenant_id: None,
        })
        .await
        .expect("enroll_with_material should succeed")
        .expect("grpc enroll should return material");

    assert!(material.agent_id.starts_with("agent-created-"));
    assert_eq!(material.signed_certificate, b"signed-by-scep-ca".to_vec());
    assert_eq!(material.ca_certificate, b"ca-cert".to_vec());

    server.shutdown().await;
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

    let server = spawn_mock_agent_control(state.clone()).await;
    let mut client = Client::with_mode("inproc-agent-control".to_string(), TransportMode::Grpc);
    client.set_test_channel_override(server.channel());

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

    {
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
    }

    server.shutdown().await;
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

    let server = spawn_mock_agent_control(state.clone()).await;
    let mut client = Client::with_mode("inproc-agent-control".to_string(), TransportMode::Grpc);
    client.set_test_channel_override(server.channel());
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

    {
        let guard = state.lock().expect("state lock");
        let token = guard
            .token_table
            .get("tok-unlimited")
            .expect("unlimited token");
        assert_eq!(token.used, 3);
    }

    server.shutdown().await;
}

#[tokio::test]
// AC-VER-029 AC-ENR-006
async fn enrollment_rejects_expired_or_wrong_ca_certificates() {
    let state = Arc::new(Mutex::new(EnrollmentMockState::default()));
    state.lock().expect("state lock").token_table.insert(
        "tok-expired".to_string(),
        EnrollmentTokenRecord {
            expires_at_unix: 1,
            max_uses: 1,
            used: 0,
        },
    );

    let server = spawn_mock_agent_control(state.clone()).await;
    let mut grpc_client =
        Client::with_mode("inproc-agent-control".to_string(), TransportMode::Grpc);
    grpc_client.set_test_channel_override(server.channel());

    let enrollment_err = grpc_client
        .enroll(&EnrollmentEnvelope {
            agent_id: "agent-expired-cert".to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            hostname: "host-expired-cert".to_string(),
            enrollment_token: Some("tok-expired".to_string()),
            tenant_id: None,
        })
        .await
        .expect_err("expired enrollment token must fail");
    assert!(enrollment_err
        .to_string()
        .contains("operation enroll_grpc failed"));

    let mut tls_client = Client::new("127.0.0.1:50052".to_string());
    let ca_err = tls_client
        .configure_tls(TlsConfig {
            cert_path: "/tmp/eguard-cert-missing.pem".to_string(),
            key_path: "/tmp/eguard-key-missing.pem".to_string(),
            ca_path: "/tmp/eguard-ca-wrong.pem".to_string(),
            pinned_ca_sha256: None,
            ca_pin_path: None,
        })
        .expect_err("wrong CA path must fail TLS configuration");
    assert!(ca_err.to_string().contains("TLS file does not exist"));

    server.shutdown().await;
}

#[tokio::test]
// AC-GRP-050
async fn send_response_grpc_reports_payload_to_server() {
    let state = Arc::new(Mutex::new(ResponseMockState::default()));
    let server = spawn_mock_response_service(state.clone()).await;
    let mut client = Client::with_mode("inproc-response".to_string(), TransportMode::Grpc);
    client.set_test_channel_override(server.channel());

    client
        .send_response(&ResponseEnvelope {
            agent_id: "agent-1".to_string(),
            action_type: "kill_tree".to_string(),
            confidence: "very_high".to_string(),
            success: false,
            error_message: "access denied".to_string(),
        })
        .await
        .expect("send_response should succeed");

    {
        let guard = state.lock().expect("state lock");
        assert_eq!(guard.reports.len(), 1);
        let report = &guard.reports[0];
        assert_eq!(report.agent_id, "agent-1");
        assert_eq!(report.action, pb::ResponseAction::KillTree as i32);
        assert_eq!(report.confidence, pb::ResponseConfidence::VeryHigh as i32);
        assert!(!report.success);
        assert_eq!(report.error_message, "access denied");
        assert!(report.created_at_unix > 0);
    }

    server.shutdown().await;
}

#[tokio::test]
// AC-GRP-028
async fn send_events_grpc_streams_batch_to_server_with_expected_fields() {
    let state = Arc::new(Mutex::new(TelemetryMockState::default()));
    let server = spawn_mock_telemetry_service(state.clone()).await;
    let mut client = Client::with_mode("inproc-telemetry".to_string(), TransportMode::Grpc);
    client.set_test_channel_override(server.channel());

    client
        .send_events(&[EventEnvelope {
            agent_id: "agent-telemetry".to_string(),
            event_type: "alert".to_string(),
            severity: "high".to_string(),
            rule_name: "unit-test-rule".to_string(),
            payload_json: "{\"reason\":\"unit-test\"}".to_string(),
            created_at_unix: 4242,
        }])
        .await
        .expect("send_events should succeed");

    {
        let guard = state.lock().expect("state lock");
        assert_eq!(guard.batches.len(), 1);
        let batch = &guard.batches[0];
        assert_eq!(batch.agent_id, "agent-telemetry");
        assert_eq!(batch.events.len(), 1);
        assert!(!batch.compressed);
        assert!(batch.events_compressed.is_empty());
        let event = &batch.events[0];
        assert_eq!(event.agent_id, "agent-telemetry");
        assert_eq!(event.event_type, pb::EventType::Alert as i32);
        assert_eq!(event.severity, pb::Severity::High as i32);
        assert_eq!(event.rule_name, "unit-test-rule");
        assert_eq!(event.payload_json, "{\"reason\":\"unit-test\"}");
        assert_eq!(event.created_at_unix, 4242);
    }

    server.shutdown().await;
}

#[tokio::test]
// AC-GRP-010
async fn send_heartbeat_grpc_captures_agent_and_compliance_and_config_version() {
    let state = Arc::new(Mutex::new(EnrollmentMockState::default()));
    let server = spawn_mock_agent_control(state.clone()).await;
    let mut client = Client::with_mode("inproc-agent-control".to_string(), TransportMode::Grpc);
    client.set_test_channel_override(server.channel());

    client
        .send_heartbeat_with_config("agent-heartbeat-1", "compliant", "cfg-v7")
        .await
        .expect("send_heartbeat should succeed");

    {
        let guard = state.lock().expect("state lock");
        assert_eq!(guard.heartbeats.len(), 1);
        let heartbeat = &guard.heartbeats[0];
        assert_eq!(heartbeat.agent_id, "agent-heartbeat-1");
        assert_eq!(heartbeat.compliance_status, "compliant");
        assert_eq!(heartbeat.config_version, "cfg-v7");
    }

    server.shutdown().await;
}

#[tokio::test]
// AC-GRP-030 AC-CMP-032
async fn send_compliance_grpc_captures_report_fields() {
    let state = Arc::new(Mutex::new(ComplianceMockState::default()));
    let server = spawn_mock_compliance_service(state.clone()).await;
    let mut client = Client::with_mode("inproc-compliance".to_string(), TransportMode::Grpc);
    client.set_test_channel_override(server.channel());

    client
        .send_compliance(&ComplianceEnvelope {
            agent_id: "agent-comp-1".to_string(),
            policy_id: "policy-xyz".to_string(),
            policy_version: "v2".to_string(),
            policy_hash: "hash-1".to_string(),
            schema_version: "v2".to_string(),
            checked_at_unix: 4242,
            overall_status: "non_compliant".to_string(),
            checks: vec![ComplianceCheckEnvelope {
                check_id: "firewall_enabled".to_string(),
                check_type: "firewall_enabled".to_string(),
                status: "non_compliant".to_string(),
                severity: "high".to_string(),
                actual_value: "false".to_string(),
                expected_value: "true".to_string(),
                detail: "firewall disabled".to_string(),
                evidence_json: "{\"actual\":\"false\"}".to_string(),
                evidence_source: "legacy".to_string(),
                collected_at_unix: 4242,
                grace_expires_at_unix: 0,
                remediation_action_id: String::new(),
                auto_remediated: false,
                remediation_detail: String::new(),
            }],
            check_type: "firewall_enabled".to_string(),
            status: "non_compliant".to_string(),
            detail: "firewall disabled".to_string(),
            expected_value: "true".to_string(),
            actual_value: "false".to_string(),
        })
        .await
        .expect("send_compliance should succeed");

    {
        let guard = state.lock().expect("state lock");
        assert_eq!(guard.reports.len(), 1);
        let report = &guard.reports[0];
        assert_eq!(report.agent_id, "agent-comp-1");
        assert_eq!(report.policy_id, "policy-xyz");
        assert_eq!(report.policy_version, "v2");
        assert_eq!(report.policy_hash, "hash-1");
        assert_eq!(report.schema_version, "v2");
        assert_eq!(report.checked_at, 4242);
        assert_eq!(report.check_type, "firewall_enabled");
        assert_eq!(report.status, "non_compliant");
        assert_eq!(report.detail, "firewall disabled");
        assert_eq!(report.expected_value, "true");
        assert_eq!(report.actual_value, "false");
        assert_eq!(
            report.overall_status,
            pb::ComplianceStatus::NonCompliant as i32
        );
        assert_eq!(report.checks.len(), 1);
        let check = &report.checks[0];
        assert_eq!(check.check_id, "firewall_enabled");
        assert_eq!(check.check_type, "firewall_enabled");
        assert_eq!(check.status, pb::CheckStatus::Fail as i32);
        assert_eq!(check.severity, "high");
        assert_eq!(check.actual_value, "false");
        assert_eq!(check.expected_value, "true");
        assert_eq!(check.detail, "firewall disabled");
        assert_eq!(check.evidence_source, "legacy");
    }

    server.shutdown().await;
}

#[tokio::test]
// AC-GRP-040
async fn fetch_commands_grpc_uses_poll_commands_path_for_collector_compat() {
    let state = Arc::new(Mutex::new(CommandMockState {
        command_channel_should_fail: true,
        channel_commands: Vec::new(),
        poll_commands: vec![
            pb::AgentCommand {
                command_id: "cmd-poll-1".to_string(),
                command_type: "run_scan".to_string(),
                payload_json: "{\"scope\":\"quick\"}".to_string(),
                status: "pending".to_string(),
                issued_by: "control".to_string(),
            },
            pb::AgentCommand {
                command_id: "cmd-poll-2".to_string(),
                command_type: "update_rules".to_string(),
                payload_json: "{\"target\":\"v2\"}".to_string(),
                status: "pending".to_string(),
                issued_by: "control".to_string(),
            },
        ],
        channel_requests: Vec::new(),
        poll_requests: Vec::new(),
        ack_requests: Vec::new(),
    }));
    let server = spawn_mock_command_service(state.clone()).await;
    let mut client = Client::with_mode("inproc-command".to_string(), TransportMode::Grpc);
    client.set_test_channel_override(server.channel());

    let commands = client
        .fetch_commands("agent-cmd-1", &["cmd-done-1".to_string()], 2)
        .await
        .expect("fetch_commands should succeed");

    assert_eq!(commands.len(), 2);
    assert_eq!(commands[0].command_id, "cmd-poll-1");
    assert_eq!(commands[0].command_type, "run_scan");
    assert_eq!(commands[0].payload_json, "{\"scope\":\"quick\"}");
    assert_eq!(commands[1].command_id, "cmd-poll-2");
    assert_eq!(commands[1].command_type, "update_rules");
    assert_eq!(commands[1].payload_json, "{\"target\":\"v2\"}");

    {
        let guard = state.lock().expect("state lock");
        assert!(guard.channel_requests.is_empty());
        assert_eq!(guard.poll_requests.len(), 1);
        let poll_req = &guard.poll_requests[0];
        assert_eq!(poll_req.agent_id, "agent-cmd-1");
        assert_eq!(poll_req.limit, 2);
    }

    server.shutdown().await;
}

#[tokio::test]
// AC-GRP-041
async fn stream_command_channel_grpc_streams_commands_from_command_channel() {
    let state = Arc::new(Mutex::new(CommandMockState {
        command_channel_should_fail: false,
        channel_commands: vec![
            pb::ServerCommand {
                command_id: "cmd-stream-1".to_string(),
                command_type: pb::CommandType::UpdateRules as i32,
                issued_at: 1_700_000_001,
                issued_by: "control".to_string(),
                params: None,
            },
            pb::ServerCommand {
                command_id: "cmd-stream-2".to_string(),
                command_type: pb::CommandType::Uninstall as i32,
                issued_at: 1_700_000_002,
                issued_by: "control".to_string(),
                params: None,
            },
        ],
        poll_commands: Vec::new(),
        channel_requests: Vec::new(),
        poll_requests: Vec::new(),
        ack_requests: Vec::new(),
    }));
    let server = spawn_mock_command_service(state.clone()).await;
    let mut client = Client::with_mode("inproc-command".to_string(), TransportMode::Grpc);
    client.set_test_channel_override(server.channel());

    let commands = client
        .stream_command_channel(
            "agent-stream-1",
            &["cmd-completed-1".to_string(), "cmd-completed-2".to_string()],
            2,
        )
        .await
        .expect("stream_command_channel should succeed");

    assert_eq!(commands.len(), 2);
    assert_eq!(commands[0].command_id, "cmd-stream-1");
    assert_eq!(commands[0].command_type, "update_rules");
    assert_eq!(commands[0].payload_json, "");
    assert_eq!(commands[1].command_id, "cmd-stream-2");
    assert_eq!(commands[1].command_type, "uninstall");
    assert_eq!(commands[1].payload_json, "");

    {
        let guard = state.lock().expect("state lock");
        assert_eq!(guard.channel_requests.len(), 1);
        let req = &guard.channel_requests[0];
        assert_eq!(req.agent_id, "agent-stream-1");
        assert_eq!(
            req.completed_command_ids,
            vec!["cmd-completed-1", "cmd-completed-2"]
        );
        assert!(guard.poll_requests.is_empty());
    }

    server.shutdown().await;
}

#[tokio::test]
// AC-GRP-042
async fn ack_command_grpc_captures_command_id_and_status() {
    let state = Arc::new(Mutex::new(CommandMockState::default()));
    let server = spawn_mock_command_service(state.clone()).await;
    let mut client = Client::with_mode("inproc-command".to_string(), TransportMode::Grpc);
    client.set_test_channel_override(server.channel());

    client
        .ack_command("agent-ack-77", "cmd-ack-77", "completed")
        .await
        .expect("ack_command should succeed");

    {
        let guard = state.lock().expect("state lock");
        assert_eq!(guard.ack_requests.len(), 1);
        let ack = &guard.ack_requests[0];
        assert_eq!(ack.agent_id, "agent-ack-77");
        assert_eq!(ack.command_id, "cmd-ack-77");
        assert_eq!(ack.status, "completed");
    }

    server.shutdown().await;
}

#[tokio::test]
// AC-GRP-060
async fn fetch_latest_threat_intel_grpc_returns_some_with_expected_fields() {
    let state = Arc::new(Mutex::new(EnrollmentMockState {
        threat_intel_response: Some(pb::ThreatIntelVersion {
            version: "2026.02.13".to_string(),
            bundle_path: "/api/v1/endpoint/threat-intel/bundle/rules-2026.02.13.tar.zst"
                .to_string(),
            sigma_count: 11,
            yara_count: 7,
            ioc_count: 3,
            cve_count: 5,
            published_at_unix: 1_700_000_999,
            custom_rule_count: 2,
            custom_rule_version_hash: "hash-rules-v2026-02-13".to_string(),
            bundle_signature_path:
                "/api/v1/endpoint/threat-intel/bundle/rules-2026.02.13.tar.zst.sig".to_string(),
            bundle_sha256: "7f8e2ec8d80f12d8a9ef89f0f14bd06f26f8b4fcaef48ec6f7ccf4ec3d88f571"
                .to_string(),
        }),
        ..EnrollmentMockState::default()
    }));
    let server = spawn_mock_agent_control(state.clone()).await;
    let mut client = Client::with_mode("inproc-agent-control".to_string(), TransportMode::Grpc);
    client.set_test_channel_override(server.channel());

    let intel = client
        .fetch_latest_threat_intel()
        .await
        .expect("fetch_latest_threat_intel should succeed")
        .expect("threat intel response should be Some");

    assert_eq!(intel.version, "2026.02.13");
    assert_eq!(
        intel.bundle_path,
        "/api/v1/endpoint/threat-intel/bundle/rules-2026.02.13.tar.zst"
    );
    assert_eq!(intel.sigma_count, 11);
    assert_eq!(intel.yara_count, 7);
    assert_eq!(intel.ioc_count, 3);
    assert_eq!(intel.cve_count, 5);
    assert_eq!(intel.published_at_unix, 1_700_000_999);
    assert_eq!(intel.custom_rule_count, 2);
    assert_eq!(intel.custom_rule_version_hash, "hash-rules-v2026-02-13");
    assert_eq!(
        intel.bundle_signature_path,
        "/api/v1/endpoint/threat-intel/bundle/rules-2026.02.13.tar.zst.sig"
    );
    assert_eq!(
        intel.bundle_sha256,
        "7f8e2ec8d80f12d8a9ef89f0f14bd06f26f8b4fcaef48ec6f7ccf4ec3d88f571"
    );

    {
        let guard = state.lock().expect("state lock");
        assert_eq!(guard.threat_intel_requests.len(), 1);
        assert_eq!(guard.threat_intel_requests[0].agent_id, "");
    }

    server.shutdown().await;
}
