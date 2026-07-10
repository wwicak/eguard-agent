use std::path::{Path, PathBuf};

use super::types::AgentMode;

pub(super) fn non_empty(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.trim().is_empty())
}

pub(super) fn env_non_empty(name: &str) -> Option<String> {
    std::env::var(name).ok().and_then(|v| non_empty(Some(v)))
}

pub(super) fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
}

pub(super) fn split_csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
        .collect()
}

pub(crate) fn preferred_hostname_env() -> Option<String> {
    env_non_empty("HOSTNAME")
        .or_else(|| env_non_empty("COMPUTERNAME"))
        .or_else(read_macos_hostname)
}

pub(super) fn default_agent_id() -> String {
    default_agent_id_with_sources(preferred_hostname_env, Path::new("/etc/hostname"))
}

fn default_agent_id_with_sources(
    preferred_hostname: impl FnOnce() -> Option<String>,
    hostname_path: &Path,
) -> String {
    let identity_path = resolve_agent_id_path();
    if let Some(agent_id) = read_non_empty_file(&identity_path) {
        return agent_id;
    }

    let agent_id = if let Some(hostname) = preferred_hostname() {
        hostname
    } else if let Some(machine_id) = read_machine_id_for_agent_id() {
        let suffix = machine_id
            .chars()
            .filter(|ch| ch.is_ascii_hexdigit())
            .take(12)
            .collect::<String>();
        if suffix.is_empty() {
            read_non_empty_file(hostname_path).unwrap_or_else(generate_agent_id)
        } else {
            format!("agent-{}", suffix.to_ascii_lowercase())
        }
    } else {
        read_non_empty_file(hostname_path).unwrap_or_else(generate_agent_id)
    };

    if let Err(error) = persist_agent_id(&identity_path, &agent_id) {
        tracing::warn!(
            path = %identity_path.display(),
            error = %error,
            "failed persisting agent identity"
        );
    }
    agent_id
}

fn resolve_agent_id_path() -> PathBuf {
    if let Some(path) = env_non_empty("EGUARD_AGENT_ID_PATH") {
        return PathBuf::from(path.trim());
    }

    resolve_agent_data_dir().join("agent-id")
}

fn resolve_agent_data_dir() -> PathBuf {
    if let Some(path) = env_non_empty("EGUARD_AGENT_DATA_DIR") {
        return PathBuf::from(path.trim());
    }

    #[cfg(target_os = "windows")]
    {
        return PathBuf::from(r"C:\ProgramData\eGuard");
    }

    #[cfg(target_os = "macos")]
    {
        return PathBuf::from("/Library/Application Support/eGuard");
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        PathBuf::from("/var/lib/eguard-agent")
    }
}

fn read_non_empty_file(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn persist_agent_id(path: &Path, agent_id: &str) -> std::io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, agent_id)
}

fn generate_agent_id() -> String {
    let mut bytes = [0u8; 6];

    #[cfg(unix)]
    {
        use std::io::Read;

        if std::fs::File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut bytes))
            .is_ok()
        {
            let value = u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], 0, 0,
            ]);
            return format!("agent-{value:012x}");
        }
    }

    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut hasher = Sha256::new();
    hasher.update(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos().to_le_bytes())
            .unwrap_or_default(),
    );
    hasher.update(COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    bytes.copy_from_slice(&hasher.finalize()[..6]);
    let value = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], 0, 0,
    ]);
    format!("agent-{value:012x}")
}

fn read_machine_id_for_agent_id() -> Option<String> {
    let path = std::env::var("EGUARD_MACHINE_ID_PATH")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "/etc/machine-id".to_string());

    std::fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(target_os = "macos")]
fn read_macos_hostname() -> Option<String> {
    for key in ["HostName", "LocalHostName", "ComputerName"] {
        let output = std::process::Command::new("/usr/sbin/scutil")
            .args(["--get", key])
            .output()
            .ok()?;
        if !output.status.success() {
            continue;
        }
        let value = String::from_utf8(output.stdout).ok()?;
        let value = value.trim();
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

#[cfg(not(target_os = "macos"))]
fn read_macos_hostname() -> Option<String> {
    None
}

pub(super) fn parse_mode(raw: &str) -> AgentMode {
    match raw.trim().to_ascii_lowercase().as_str() {
        "active" => AgentMode::Active,
        "degraded" => AgentMode::Degraded,
        _ => AgentMode::Learning,
    }
}

pub(super) fn parse_bool(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "enabled" | "on"
    )
}

pub(super) fn parse_cap_mb(raw: &str) -> Option<usize> {
    let mb = raw.trim().parse::<usize>().ok()?;
    Some(mb.saturating_mul(1024 * 1024))
}

pub(super) fn format_server_addr(address: &str, grpc_port: Option<u16>) -> String {
    let address = address.trim();
    let Some(port) = grpc_port else {
        return address.to_string();
    };
    if has_explicit_port(address) {
        return address.to_string();
    }

    if address.contains(':') && !address.starts_with('[') {
        format!("[{}]:{}", address, port)
    } else {
        format!("{}:{}", address, port)
    }
}

pub(super) fn has_explicit_port(address: &str) -> bool {
    if address.starts_with('[') {
        return address.contains("]:");
    }

    if address.matches(':').count() == 1 {
        return address
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse::<u16>().ok())
            .is_some();
    }

    false
}

#[cfg(test)]
mod tests {
    use super::{default_agent_id, default_agent_id_with_sources};

    fn env_lock() -> &'static std::sync::Mutex<()> {
        crate::test_support::env_lock()
    }

    fn temp_dir(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "eguard-agent-id-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or_default()
        ))
    }

    fn set_agent_id_path(root: &std::path::Path) -> std::path::PathBuf {
        let path = root.join("agent-id");
        std::env::set_var("EGUARD_AGENT_ID_PATH", &path);
        path
    }

    fn clear_identity_env() {
        for name in [
            "EGUARD_AGENT_ID_PATH",
            "EGUARD_MACHINE_ID_PATH",
            "HOSTNAME",
            "COMPUTERNAME",
        ] {
            std::env::remove_var(name);
        }
    }

    #[test]
    fn default_agent_id_uses_hostname_env_and_persists_it() {
        let _guard = env_lock().lock().expect("env lock");
        clear_identity_env();
        let root = temp_dir("hostname");
        let identity_path = set_agent_id_path(&root);
        std::env::set_var("HOSTNAME", "agent-host-a");
        std::env::set_var("COMPUTERNAME", "WIN-HOST-A");

        let id = default_agent_id();

        assert_eq!(id, "agent-host-a");
        assert_eq!(
            std::fs::read_to_string(&identity_path).expect("read persisted agent id"),
            "agent-host-a"
        );
        clear_identity_env();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn default_agent_id_prefers_persisted_id_over_hostname_env() {
        let _guard = env_lock().lock().expect("env lock");
        clear_identity_env();
        let root = temp_dir("persisted");
        let identity_path = set_agent_id_path(&root);
        std::fs::create_dir_all(&root).expect("create identity dir");
        std::fs::write(&identity_path, "persisted-agent\n").expect("write persisted agent id");
        std::env::set_var("HOSTNAME", "different-hostname");

        assert_eq!(default_agent_id(), "persisted-agent");

        clear_identity_env();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn default_agent_id_uses_windows_computername_when_hostname_missing() {
        let _guard = env_lock().lock().expect("env lock");
        clear_identity_env();
        let root = temp_dir("computername");
        set_agent_id_path(&root);
        std::env::set_var("COMPUTERNAME", "WIN-4209A3FD-104E-4");

        let id = default_agent_id();
        assert_eq!(id, "WIN-4209A3FD-104E-4");

        clear_identity_env();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn default_agent_id_uses_machine_id_when_hostname_missing() {
        let _guard = env_lock().lock().expect("env lock");
        clear_identity_env();
        let root = temp_dir("machine-id");
        set_agent_id_path(&root);
        std::fs::create_dir_all(&root).expect("create identity dir");
        let machine_id_path = root.join("machine-id");
        std::fs::write(&machine_id_path, "AABBCCDDEEFF00112233\n").expect("write machine id");
        std::env::set_var("EGUARD_MACHINE_ID_PATH", &machine_id_path);

        let id = default_agent_id();
        assert_eq!(id, "agent-aabbccddeeff");

        clear_identity_env();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn generated_agent_id_is_random_format_and_persists() {
        let _guard = env_lock().lock().expect("env lock");
        clear_identity_env();
        let root = temp_dir("generated");
        let identity_path = set_agent_id_path(&root);
        std::env::set_var("EGUARD_MACHINE_ID_PATH", root.join("missing-machine-id"));
        let missing_hostname = root.join("missing-hostname");

        let id = default_agent_id_with_sources(|| None, &missing_hostname);
        let suffix = id.strip_prefix("agent-").expect("agent id prefix");
        assert_eq!(suffix.len(), 12);
        assert!(
            suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "generated agent id must contain only lowercase hexadecimal characters"
        );
        assert_ne!(id, format!("agent-{}", std::process::id()));
        assert_eq!(
            default_agent_id_with_sources(|| None, &missing_hostname),
            id
        );
        assert_eq!(
            std::fs::read_to_string(&identity_path).expect("read persisted agent id"),
            id
        );

        clear_identity_env();
        let _ = std::fs::remove_dir_all(root);
    }
}
