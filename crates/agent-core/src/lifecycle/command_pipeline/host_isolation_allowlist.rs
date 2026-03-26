use super::command_utils::{extract_server_host, resolve_allowed_server_ips};

pub(super) fn resolve_host_isolation_allowlist(
    server_addr: &str,
    allow_server_connection: bool,
    payload_ips: &[String],
) -> Vec<String> {
    let base_allowlist =
        resolve_allowed_server_ips(server_addr, payload_ips, allow_server_connection);
    let mut effective =
        merge_isolation_allowlist(&base_allowlist, &collect_active_management_peer_ips());

    // SAFETY: Always include the configured server_addr IP in the allow-list.
    // Without this, the agent cannot receive unisolate commands and the user
    // is permanently locked out.  This is the primary CrowdStrike prevention
    // measure — the agent must ALWAYS be able to reach its server.
    let host = extract_server_host(server_addr);
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        let value = ip.to_string();
        if !effective.iter().any(|entry| entry == &value) {
            effective.push(value);
        }
    }

    effective
}

fn merge_isolation_allowlist(
    base_allowlist: &[String],
    discovered_peers: &[String],
) -> Vec<String> {
    let mut effective = dedupe_ip_literals(base_allowlist);
    for peer_ip in dedupe_ip_literals(discovered_peers) {
        if !effective.iter().any(|entry| entry == &peer_ip) {
            effective.push(peer_ip);
        }
    }
    effective
}

fn dedupe_ip_literals(values: &[String]) -> Vec<String> {
    let mut deduped = Vec::new();
    for raw in values {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.parse::<std::net::IpAddr>().is_err() {
            continue;
        }
        if !deduped.iter().any(|entry| entry == trimmed) {
            deduped.push(trimmed.to_string());
        }
    }
    deduped
}

#[cfg(target_os = "windows")]
fn collect_active_management_peer_ips() -> Vec<String> {
    platform_windows::response::collect_active_management_peer_ips()
}

#[cfg(target_os = "macos")]
fn collect_active_management_peer_ips() -> Vec<String> {
    platform_macos::response::collect_active_management_peer_ips()
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn collect_active_management_peer_ips() -> Vec<String> {
    super::host_isolation_linux::collect_active_management_peer_ips()
}

#[cfg(test)]
mod tests {
    use super::{dedupe_ip_literals, merge_isolation_allowlist};

    #[test]
    fn dedupe_ip_literals_filters_invalid_entries() {
        assert_eq!(
            dedupe_ip_literals(&[
                "203.0.113.10".to_string(),
                "203.0.113.10".to_string(),
                "2001:db8::1".to_string(),
                "not-an-ip".to_string(),
                String::new(),
            ]),
            vec!["203.0.113.10".to_string(), "2001:db8::1".to_string()]
        );
    }

    #[test]
    fn merge_isolation_allowlist_appends_discovered_management_peers() {
        let merged = merge_isolation_allowlist(
            &["203.0.113.10".to_string()],
            &[
                "198.51.100.44".to_string(),
                "203.0.113.10".to_string(),
                "invalid".to_string(),
            ],
        );

        assert_eq!(
            merged,
            vec!["203.0.113.10".to_string(), "198.51.100.44".to_string()]
        );
    }
}
