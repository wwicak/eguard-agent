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
    std::env::var("HOSTNAME")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "agent-dev-1".to_string())
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
