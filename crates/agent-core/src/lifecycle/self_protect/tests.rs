use super::*;
use crate::config::AgentConfig;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("eguard-f26-{}-{suffix}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        Self(root)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct EnvRestore(Vec<(&'static str, Option<std::ffi::OsString>)>);

impl EnvRestore {
    fn set(values: &[(&'static str, &Path)]) -> Self {
        let old = values
            .iter()
            .map(|(key, _)| (*key, std::env::var_os(key)))
            .collect();
        for (key, path) in values {
            std::env::set_var(key, path);
        }
        Self(old)
    }
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        for (key, value) in &self.0 {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn write_with_mode(path: &Path, contents: &str, mode: u32) {
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn legacy_state() -> Vec<Option<(u32, std::time::SystemTime)>> {
    [
        "/etc/eguard-agent/agent.conf",
        "/etc/eguard-agent/bootstrap.conf",
        "/etc/eguard-agent/certs/agent.crt",
        "/etc/eguard-agent/certs/agent.key",
        "/etc/eguard-agent/certs/ca.crt",
    ]
    .into_iter()
    .map(|path| {
        std::fs::symlink_metadata(path)
            .ok()
            .map(|m| (m.permissions().mode(), m.modified().unwrap()))
    })
    .collect()
}

#[test]
fn configured_paths_are_enforced_without_touching_legacy_etc() {
    let _lock = crate::test_support::env_lock().lock().unwrap();
    let fixture = Fixture::new();
    let root = &fixture.0;
    let agent = root.join("custom-agent.toml");
    let bootstrap = root.join("custom-bootstrap.conf");
    let cert = root.join("custom-client.pem");
    let key = root.join("custom-private.pem");
    let ca = root.join("custom-authority.pem");
    let last_good = root.join("last-good.toml");
    write_with_mode(&agent, "[storage]\nbackend = 'memory'\n", 0o644);
    write_with_mode(
        &bootstrap,
        "[server]\naddress = '127.0.0.1'\nenrollment_token = 'test-token'\nschema_version = 1\n",
        0o664,
    );
    write_with_mode(&cert, "test cert", 0o644);
    write_with_mode(&key, "test key", 0o640);
    write_with_mode(&ca, "test ca", 0o444);
    let _env = EnvRestore::set(&[
        ("EGUARD_AGENT_CONFIG", &agent),
        ("EGUARD_BOOTSTRAP_CONFIG", &bootstrap),
        ("EGUARD_LAST_KNOWN_AGENT_CONFIG", &last_good),
        ("EGUARD_TLS_CERT", &cert),
        ("EGUARD_TLS_KEY", &key),
        ("EGUARD_TLS_CA", &ca),
    ]);
    let config = AgentConfig::load().unwrap();
    // Initialize without fake TLS material; enforce against the loaded effective
    // config, not a reimplementation of the loader's resolution.
    let mut runtime = AgentRuntime::new(AgentConfig {
        offline_buffer_backend: "memory".into(),
        server_addr: "127.0.0.1:1".into(),
        ..Default::default()
    })
    .unwrap();
    runtime.config = config;
    let legacy_before = legacy_state();
    let root_mode = mode(root);
    runtime.enforce_config_permissions_if_due(1000);
    for path in [&agent, &bootstrap, &cert, &key, &ca] {
        assert_eq!(mode(path), 0o600, "configured path {}", path.display());
    }
    assert_eq!(
        legacy_state(),
        legacy_before,
        "must not touch /etc/eguard-agent"
    );
    assert_eq!(mode(root), root_mode, "must not chmod the parent");

    // Preserve the five-minute cadence, and leave already restrictive modes alone.
    std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o400)).unwrap();
    runtime.enforce_config_permissions_if_due(1299);
    assert_eq!(mode(&agent), 0o644);
    runtime.enforce_config_permissions_if_due(1300);
    assert_eq!(mode(&agent), 0o600);
    assert_eq!(mode(&key), 0o400);
    assert_eq!(mode(&ca), 0o600);
    std::fs::remove_file(&ca).unwrap();
    runtime.enforce_config_permissions_if_due(1600);
    assert!(!ca.exists(), "missing files must not be created");
    assert_eq!(legacy_state(), legacy_before);
}

#[test]
fn permission_enforcement_skips_symlinks_directories_and_missing_files() {
    let fixture = Fixture::new();
    let target = fixture.0.join("attacker-target");
    let link = fixture.0.join("client.key");
    let missing = fixture.0.join("missing");
    write_with_mode(&target, "attacker controlled", 0o666);
    symlink(&target, &link).unwrap();
    let parent_mode = mode(&fixture.0);
    let tmp_mode = mode(&std::env::temp_dir());
    let root_mode = mode(Path::new("/"));
    enforce_private_file_permissions(&link).unwrap();
    enforce_private_file_permissions(&fixture.0).unwrap();
    enforce_private_file_permissions(&missing).unwrap();
    // Explicit misconfiguration must not modify even pre-existing shared dirs.
    enforce_private_file_permissions(&std::env::temp_dir()).unwrap();
    enforce_private_file_permissions(Path::new("/")).unwrap();
    assert_eq!(mode(&target), 0o666);
    assert_eq!(mode(&fixture.0), parent_mode);
    assert_eq!(mode(&std::env::temp_dir()), tmp_mode);
    assert_eq!(mode(Path::new("/")), root_mode);
    assert!(!missing.exists());
    std::fs::remove_file(&target).unwrap();
    enforce_private_file_permissions(&link).unwrap();
    assert!(std::fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());
}
