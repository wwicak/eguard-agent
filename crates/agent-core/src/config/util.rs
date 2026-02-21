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

pub(super) fn default_agent_id() -> String {
    if let Some(hostname) = std::env::var("HOSTNAME")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return hostname;
    }

    if let Some(machine_id) = read_machine_id_for_agent_id() {
        let suffix = machine_id
            .chars()
            .filter(|ch| ch.is_ascii_hexdigit())
            .take(12)
            .collect::<String>();
        if !suffix.is_empty() {
            return format!("agent-{}", suffix.to_ascii_lowercase());
        }
    }

    if let Some(hostname) = std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return hostname;
    }

    format!("agent-{}", std::process::id())
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
    use super::default_agent_id;

    fn env_lock() -> &'static std::sync::Mutex<()> {
        crate::test_support::env_lock()
    }

    #[test]
    fn default_agent_id_prefers_hostname_env() {
        let _guard = env_lock().lock().expect("env lock");
        std::env::set_var("HOSTNAME", "agent-host-a");
        let id = default_agent_id();
        assert_eq!(id, "agent-host-a");
        std::env::remove_var("HOSTNAME");
    }

    #[test]
    fn default_agent_id_uses_machine_id_when_hostname_missing() {
        let _guard = env_lock().lock().expect("env lock");
        std::env::remove_var("HOSTNAME");

        let path = std::env::temp_dir().join(format!(
            "eguard-default-agent-id-machine-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::write(&path, "AABBCCDDEEFF00112233\n").expect("write machine id");
        std::env::set_var("EGUARD_MACHINE_ID_PATH", &path);

        let id = default_agent_id();
        assert_eq!(id, "agent-aabbccddeeff");

        std::env::remove_var("EGUARD_MACHINE_ID_PATH");
        let _ = std::fs::remove_file(path);
    }
}
