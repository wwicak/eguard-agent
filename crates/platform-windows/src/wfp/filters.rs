//! WFP network filtering rules.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

#[cfg(target_os = "windows")]
use std::process::Command;

#[cfg(target_os = "windows")]
use crate::windows_cmd::NETSH_EXE;

static NEXT_FILTER_ID: AtomicU64 = AtomicU64::new(1);
static FILTER_REGISTRY: OnceLock<Mutex<HashMap<u64, String>>> = OnceLock::new();

#[cfg(any(test, target_os = "windows"))]
const MAX_RULE_DESCRIPTION_LEN: usize = 240;

fn filter_registry() -> &'static Mutex<HashMap<u64, String>> {
    FILTER_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// A WFP filter definition.
#[derive(Debug, Clone)]
pub struct WfpFilter {
    pub name: String,
    pub description: String,
    pub layer: WfpLayer,
    pub action: WfpAction,
    pub remote_ip: Option<String>,
}

/// WFP filtering layers.
#[derive(Debug, Clone, Copy)]
pub enum WfpLayer {
    InboundTransportV4,
    OutboundTransportV4,
    InboundTransportV6,
    OutboundTransportV6,
}

/// Filter action (permit or block).
#[derive(Debug, Clone, Copy)]
pub enum WfpAction {
    Permit,
    Block,
}

/// Add a filter to the WFP engine.
pub fn add_filter(engine: &super::WfpEngine, filter: &WfpFilter) -> Result<u64, super::WfpError> {
    #[cfg(target_os = "windows")]
    if engine.handle() == 0 {
        return Err(super::WfpError::EngineOpen(
            "cannot add filter on a closed engine".to_string(),
        ));
    }

    let normalized_remote_ip = normalize_remote_ip(filter.remote_ip.as_deref()).map_err(|err| {
        super::WfpError::FilterAdd(format!(
            "invalid filter remote_ip for '{}': {err}",
            filter.name
        ))
    })?;
    #[cfg(not(target_os = "windows"))]
    let _ = &normalized_remote_ip;

    let filter_id = NEXT_FILTER_ID.fetch_add(1, Ordering::Relaxed);
    let rule_name = format!(
        "eGuard-Wfp-{filter_id}-{}",
        sanitize_rule_name(&filter.name)
    );

    #[cfg(target_os = "windows")]
    {
        apply_netsh_rule(&rule_name, filter, normalized_remote_ip.as_deref())
            .map_err(super::WfpError::FilterAdd)?;
    }

    let mut registry = filter_registry().lock().map_err(|err| {
        super::WfpError::FilterAdd(format!("filter registry lock poisoned: {err}"))
    })?;
    registry.insert(filter_id, rule_name);

    let _ = engine;
    Ok(filter_id)
}

/// Remove a filter by its ID.
pub fn remove_filter(engine: &super::WfpEngine, filter_id: u64) -> Result<(), super::WfpError> {
    #[cfg(target_os = "windows")]
    if engine.handle() == 0 {
        return Err(super::WfpError::EngineOpen(
            "cannot remove filter on a closed engine".to_string(),
        ));
    }

    let removed_rule_name = {
        let mut registry = filter_registry().lock().map_err(|err| {
            super::WfpError::FilterRemove(format!("filter registry lock poisoned: {err}"))
        })?;
        registry.remove(&filter_id).ok_or_else(|| {
            super::WfpError::FilterRemove(format!("unknown filter id {filter_id}"))
        })?
    };

    #[cfg(target_os = "windows")]
    {
        remove_netsh_rule(&removed_rule_name).map_err(super::WfpError::FilterRemove)?;
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = removed_rule_name;
    }

    let _ = engine;
    Ok(())
}

fn sanitize_rule_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "unnamed".to_string()
    } else {
        out
    }
}

#[cfg(any(test, target_os = "windows"))]
fn sanitize_rule_description(raw: &str) -> String {
    let mut normalized = raw
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>();
    normalized = normalized.split_whitespace().collect::<Vec<_>>().join(" ");

    let bounded = normalized
        .chars()
        .take(MAX_RULE_DESCRIPTION_LEN)
        .collect::<String>();

    if bounded.trim().is_empty() {
        "eGuard WFP policy".to_string()
    } else {
        bounded
    }
}

fn normalize_remote_ip(remote_ip: Option<&str>) -> Result<Option<String>, String> {
    let Some(raw) = remote_ip else {
        return Ok(None);
    };

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("remote_ip cannot be empty".to_string());
    }

    if trimmed.eq_ignore_ascii_case("any") {
        return Ok(None);
    }

    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(Some(ip.to_string()));
    }

    let (ip_raw, prefix_raw) = trimmed
        .split_once('/')
        .ok_or_else(|| format!("'{trimmed}' is not a valid IP or CIDR"))?;

    let ip = ip_raw
        .trim()
        .parse::<IpAddr>()
        .map_err(|_| format!("'{trimmed}' has invalid CIDR base IP"))?;
    let prefix = prefix_raw
        .trim()
        .parse::<u8>()
        .map_err(|_| format!("'{trimmed}' has invalid CIDR prefix"))?;

    let max_prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max_prefix {
        return Err(format!("'{trimmed}' CIDR prefix exceeds {max_prefix}"));
    }

    Ok(Some(format!("{ip}/{prefix}")))
}

#[cfg(any(test, target_os = "windows"))]
fn netsh_direction(layer: WfpLayer) -> &'static str {
    match layer {
        WfpLayer::InboundTransportV4 | WfpLayer::InboundTransportV6 => "in",
        WfpLayer::OutboundTransportV4 | WfpLayer::OutboundTransportV6 => "out",
    }
}

#[cfg(target_os = "windows")]
fn netsh_action(action: WfpAction) -> &'static str {
    match action {
        WfpAction::Permit => "allow",
        WfpAction::Block => "block",
    }
}

#[cfg(target_os = "windows")]
fn apply_netsh_rule(
    rule_name: &str,
    filter: &WfpFilter,
    normalized_remote_ip: Option<&str>,
) -> Result<(), String> {
    let remote_ip = normalized_remote_ip.unwrap_or("any");
    let description = sanitize_rule_description(&filter.description);
    let args = [
        "advfirewall",
        "firewall",
        "add",
        "rule",
        &format!("name={rule_name}"),
        &format!("description={description}"),
        &format!("dir={}", netsh_direction(filter.layer)),
        &format!("action={}", netsh_action(filter.action)),
        &format!("remoteip={remote_ip}"),
        "profile=any",
    ];

    let output = Command::new(NETSH_EXE)
        .args(args)
        .output()
        .map_err(|err| format!("failed spawning netsh for add rule: {err}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = if stderr.trim().is_empty() {
        stdout.trim().to_string()
    } else {
        stderr.trim().to_string()
    };

    Err(format!("netsh add rule failed for {rule_name}: {detail}"))
}

#[cfg(target_os = "windows")]
fn remove_netsh_rule(rule_name: &str) -> Result<(), String> {
    let args = [
        "advfirewall",
        "firewall",
        "delete",
        "rule",
        &format!("name={rule_name}"),
    ];

    let output = Command::new(NETSH_EXE)
        .args(args)
        .output()
        .map_err(|err| format!("failed spawning netsh for delete rule: {err}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = if stderr.trim().is_empty() {
        stdout.trim().to_string()
    } else {
        stderr.trim().to_string()
    };

    Err(format!(
        "netsh delete rule failed for {rule_name}: {detail}"
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        add_filter, netsh_direction, normalize_remote_ip, remove_filter, sanitize_rule_description,
        WfpAction, WfpFilter, WfpLayer,
    };

    #[test]
    fn direction_mapping_matches_layer() {
        assert_eq!(netsh_direction(WfpLayer::InboundTransportV4), "in");
        assert_eq!(netsh_direction(WfpLayer::OutboundTransportV6), "out");
    }

    #[test]
    fn normalize_remote_ip_supports_ip_and_cidr() {
        assert_eq!(
            normalize_remote_ip(Some("203.0.113.10")).expect("valid ipv4"),
            Some("203.0.113.10".to_string())
        );
        assert_eq!(
            normalize_remote_ip(Some("2001:db8::1/128")).expect("valid ipv6 cidr"),
            Some("2001:db8::1/128".to_string())
        );
        assert_eq!(normalize_remote_ip(Some("any")).expect("valid any"), None);
    }

    #[test]
    fn normalize_remote_ip_rejects_invalid_values() {
        assert!(normalize_remote_ip(Some("")).is_err());
        assert!(normalize_remote_ip(Some("not-an-ip")).is_err());
        assert!(normalize_remote_ip(Some("203.0.113.10/48")).is_err());
    }

    #[test]
    fn sanitize_rule_description_strips_control_chars_and_bounds_length() {
        let description = sanitize_rule_description("line1\nline2\tline3");
        assert_eq!(description, "line1 line2 line3");

        let very_long = "x".repeat(1_000);
        let bounded = sanitize_rule_description(&very_long);
        assert!(bounded.len() <= 240);
    }

    #[test]
    fn add_and_remove_filter_round_trip() {
        let engine = crate::wfp::WfpEngine::open().expect("engine open");
        let filter = WfpFilter {
            name: "test-filter".to_string(),
            description: "test".to_string(),
            layer: WfpLayer::OutboundTransportV4,
            action: WfpAction::Block,
            remote_ip: None,
        };

        let id = add_filter(&engine, &filter).expect("add filter");
        assert!(id > 0);
        remove_filter(&engine, id).expect("remove filter");
    }
}
