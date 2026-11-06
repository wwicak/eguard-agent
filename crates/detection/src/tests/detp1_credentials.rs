use super::*;

fn credential_exfil(path: &str) -> bool {
    let mut engine = TemporalEngine::with_default_rules();
    let mut read = event(1, EventClass::FileOpen, "curl", "bash", 0);
    read.file_path = Some(path.into());
    engine.observe(&read);
    let mut network = read.clone();
    network.ts_unix = 2;
    network.event_class = EventClass::NetworkConnect;
    network.dst_ip = Some("198.51.100.20".into());
    network.dst_port = Some(50053);
    engine
        .observe(&network)
        .iter()
        .any(|hit| hit == "phi_credential_exfil")
}

#[test]
fn detp1_credentials_passwd_is_not_a_secret_but_shadow_still_alerts() {
    assert!(!credential_exfil("/etc/passwd"));
    assert!(credential_exfil("/etc/shadow"));
}

#[test]
fn detp1_credentials_public_ssh_material_is_not_a_private_key() {
    for path in [
        "/home/user/.ssh/authorized_keys",
        "/home/user/.ssh/id_rsa.pub",
    ] {
        assert!(!credential_exfil(path), "not a secret: {path}");
    }
    assert!(credential_exfil("/home/user/.ssh/id_rsa"));
}

#[test]
fn detp1_credentials_real_cloud_browser_and_group_secrets_alert() {
    for path in [
        "/etc/gshadow",
        "/home/user/.aws/credentials",
        "/home/user/.config/gcloud/credentials.db",
        "/home/user/.config/chromium/Default/Login Data",
        "/home/user/.mozilla/firefox/profile/logins.json",
    ] {
        assert!(credential_exfil(path), "credential source: {path}");
    }
}
