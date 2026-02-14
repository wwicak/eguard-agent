use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use nac::{apply_network_profile_config_change, NetworkSecurity};

fn temp_dir(prefix: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("{}-{}-{}", prefix, std::process::id(), ts));
    fs::create_dir_all(&path).expect("create temp dir");
    path
}

#[test]
// AC-NAC-PROFILE-004
fn config_change_network_profile_push_writes_nmconnection_file() {
    let root = temp_dir("nac-profile-psk");

    let payload = serde_json::json!({
        "config_json": {
            "config_type": "network_profile",
            "profile": {
                "profile_id": "corp-main",
                "ssid": "CorpWiFi",
                "security": "wpa2_psk",
                "psk": "Sup3rSecret!",
                "priority": 20,
                "auto_connect": true
            }
        }
    })
    .to_string();

    let report = apply_network_profile_config_change(&payload, &root)
        .expect("apply config_change")
        .expect("network profile report");

    assert_eq!(report.profile_id, "corp-main");
    assert!(report.connection_path.exists());
    assert!(report.ca_cert_path.is_none());

    let content = fs::read_to_string(&report.connection_path).expect("read nmconnection");
    assert!(content.contains("id=corp-main"));
    assert!(content.contains("ssid=CorpWiFi"));
    assert!(content.contains("key-mgmt=wpa-psk"));
    assert!(content.contains("psk=Sup3rSecret!"));

    #[cfg(unix)]
    {
        let mode = fs::metadata(&report.connection_path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    let _ = fs::remove_dir_all(root);
}

#[test]
// AC-NAC-PROFILE-004
fn enterprise_profile_writes_connection_and_ca_certificate() {
    let root = temp_dir("nac-profile-eap");
    let pem = "-----BEGIN CERTIFICATE-----\nMIIBjzCCATWgAwIBAgIUQ2VydGlmaWNhdGU=\n-----END CERTIFICATE-----";

    let payload = serde_json::json!({
        "config_json": {
            "config_type": "network_profile",
            "profile": {
                "profile_id": "corp-eap",
                "ssid": "CorpEAP",
                "security": "wpa2_enterprise",
                "identity": "employee@example.com",
                "password": "P@ssword1!",
                "eap_method": "peap",
                "phase2_auth": "mschapv2",
                "ca_cert_pem": pem
            }
        }
    })
    .to_string();

    let report = apply_network_profile_config_change(&payload, &root)
        .expect("apply config_change")
        .expect("network profile report");

    assert_eq!(report.profile_id, "corp-eap");
    let ca_path = report.ca_cert_path.clone().expect("ca cert path");
    assert!(ca_path.exists());

    let content = fs::read_to_string(&report.connection_path).expect("read nmconnection");
    assert!(content.contains("key-mgmt=wpa-eap"));
    assert!(content.contains("identity=employee@example.com"));
    assert!(content.contains("phase2-auth=mschapv2"));
    assert!(content.contains(&format!("ca-cert=file://{}", ca_path.display())));

    #[cfg(unix)]
    {
        let ca_mode = fs::metadata(&ca_path)
            .expect("ca metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(ca_mode, 0o600);
    }

    let _ = fs::remove_dir_all(root);
}

#[test]
// AC-NAC-PROFILE-005
fn invalid_profile_payload_returns_error() {
    let root = temp_dir("nac-profile-invalid");

    let payload = serde_json::json!({
        "config_json": {
            "config_type": "network_profile",
            "profile": {
                "profile_id": "corp-bad",
                "ssid": "CorpBad",
                "security": "wpa2_psk",
                "psk": "short"
            }
        }
    })
    .to_string();

    let err =
        apply_network_profile_config_change(&payload, &root).expect_err("invalid psk should fail");
    assert!(err.contains("8-63"));

    let _ = fs::remove_dir_all(root);
}

#[test]
// AC-NAC-PROFILE-006
fn non_network_config_change_payload_is_ignored() {
    let root = temp_dir("nac-profile-ignore");

    let payload = serde_json::json!({
        "config_json": {
            "config_type": "response_policy",
            "kill_rate": 2
        }
    })
    .to_string();

    let result = apply_network_profile_config_change(&payload, &root).expect("parse payload");
    assert!(result.is_none());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn network_security_enum_serialization_contract() {
    let as_json = serde_json::to_string(&NetworkSecurity::Wpa2Enterprise).expect("serialize enum");
    assert_eq!(as_json, "\"wpa2_enterprise\"");
}
