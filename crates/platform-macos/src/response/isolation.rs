//! Network isolation response action via macOS pf (packet filter).

#[cfg(target_os = "macos")]
use std::fs;
#[cfg(any(test, target_os = "macos"))]
use std::net::IpAddr;
#[cfg(target_os = "macos")]
use std::process::Command;

#[cfg(target_os = "macos")]
const PF_ANCHOR_PATH: &str = "/etc/pf.anchors/com.eguard";
#[cfg(target_os = "macos")]
const PF_ANCHOR_NAME: &str = "com.eguard";
#[cfg(any(test, target_os = "macos"))]
const MANAGEMENT_PORTS: &[u16] = &[22, 5900, 3283];

/// Isolate a host from the network, allowing only the specified server IPs.
pub fn isolate_host(allowed_server_ips: &[&str]) -> Result<(), super::ResponseError> {
    #[cfg(target_os = "macos")]
    {
        // Clean old rules first to make operation idempotent.
        remove_isolation()?;

        // Build pf rules: allow specified IPs, block everything else.
        let mut rules = String::new();
        for ip_str in allowed_server_ips {
            // Validate IP to prevent pf rule injection.
            let addr: std::net::IpAddr = ip_str.parse().map_err(|_| {
                super::ResponseError::OperationFailed(format!("invalid IP address: {ip_str}"))
            })?;
            rules.push_str(&format!("pass out quick proto tcp to {addr}\n"));
            rules.push_str(&format!("pass in quick proto tcp from {addr}\n"));
        }
        // Allow loopback.
        rules.push_str("pass quick on lo0 all\n");
        // Block everything else.
        rules.push_str("block all\n");

        fs::write(PF_ANCHOR_PATH, &rules).map_err(|err| {
            super::ResponseError::OperationFailed(format!(
                "failed writing pf anchor {PF_ANCHOR_PATH}: {err}"
            ))
        })?;

        // Load the anchor into pf.
        run_pfctl(&["-a", PF_ANCHOR_NAME, "-f", PF_ANCHOR_PATH])?;
        // Enable pf if not already enabled.
        let _ = run_pfctl(&["-e"]);

        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = allowed_server_ips;
        tracing::warn!("isolate_host is a stub on non-macOS");
        Ok(())
    }
}

pub fn collect_active_management_peer_ips() -> Vec<String> {
    #[cfg(target_os = "macos")]
    {
        let output = match Command::new("lsof")
            .args(["-n", "-P", "-iTCP", "-sTCP:ESTABLISHED"])
            .output()
        {
            Ok(output) if output.status.success() => output,
            _ => return Vec::new(),
        };
        parse_established_management_peer_ips(&String::from_utf8_lossy(&output.stdout))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Vec::new()
    }
}

/// Remove host network isolation.
pub fn remove_isolation() -> Result<(), super::ResponseError> {
    #[cfg(target_os = "macos")]
    {
        // Flush the anchor rules.
        let _ = run_pfctl(&["-a", PF_ANCHOR_NAME, "-F", "all"]);
        // Remove anchor file.
        let _ = fs::remove_file(PF_ANCHOR_PATH);
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        tracing::warn!("remove_isolation is a stub on non-macOS");
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn run_pfctl(args: &[&str]) -> Result<(), super::ResponseError> {
    let output = Command::new("pfctl").args(args).output().map_err(|err| {
        super::ResponseError::OperationFailed(format!("failed spawning pfctl {:?}: {err}", args))
    })?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let detail = if stderr.trim().is_empty() {
        stdout
    } else {
        stderr
    };
    Err(super::ResponseError::OperationFailed(detail))
}

#[cfg(any(test, target_os = "macos"))]
fn parse_established_management_peer_ips(raw: &str) -> Vec<String> {
    let mut peers = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("COMMAND") {
            continue;
        }

        if let Some(peer) = parse_established_management_peer_ip(trimmed) {
            if !peers.iter().any(|entry| entry == &peer) {
                peers.push(peer);
            }
        }
    }
    peers
}

#[cfg(any(test, target_os = "macos"))]
fn parse_established_management_peer_ip(line: &str) -> Option<String> {
    let token = line
        .split_whitespace()
        .find(|segment| segment.contains("->") && segment.contains(':'))?;
    let (local_raw, remote_raw) = token.split_once("->")?;
    let (_, local_port) = split_endpoint(local_raw)?;
    if !MANAGEMENT_PORTS.contains(&local_port) {
        return None;
    }

    let (remote_addr, _) = split_endpoint(remote_raw)?;
    let ip = remote_addr.parse::<IpAddr>().ok()?;
    if ip.is_loopback() || ip.is_unspecified() {
        return None;
    }
    Some(ip.to_string())
}

#[cfg(any(test, target_os = "macos"))]
fn split_endpoint(raw: &str) -> Option<(String, u16)> {
    let endpoint = raw.trim().trim_matches('[').trim_matches(']');
    if endpoint.is_empty() {
        return None;
    }

    let (host, port) = endpoint.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;

    let host = host.trim_matches('[').trim_matches(']').to_string();
    if host.is_empty() {
        return None;
    }

    Some((host, port))
}

#[cfg(test)]
mod tests {
    use super::parse_established_management_peer_ips;

    #[test]
    fn parse_established_management_peer_ips_collects_management_sessions() {
        let raw = r#"COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
sshd     1001 dimas    7u  IPv4 0x123456      0t0  TCP 10.0.0.5:22->203.0.113.10:52341 (ESTABLISHED)
sharingd 1002 dimas    7u  IPv4 0x123456      0t0  TCP 10.0.0.5:5900->198.51.100.44:60123 (ESTABLISHED)
launchd  1003 dimas    7u  IPv4 0x123456      0t0  TCP 10.0.0.5:443->192.0.2.1:44321 (ESTABLISHED)
sshd     1004 dimas    7u  IPv6 0x123456      0t0  TCP [2001:db8::10]:22->[2001:db8::55]:61234 (ESTABLISHED)
"#;

        assert_eq!(
            parse_established_management_peer_ips(raw),
            vec![
                "203.0.113.10".to_string(),
                "198.51.100.44".to_string(),
                "2001:db8::55".to_string(),
            ]
        );
    }

    #[test]
    fn parse_established_management_peer_ips_ignores_invalid_or_local_peers() {
        let raw = r#"COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
sshd     1001 dimas    7u  IPv4 0x123456      0t0  TCP 10.0.0.5:22->127.0.0.1:52341 (ESTABLISHED)
sshd     1002 dimas    7u  IPv4 0x123456      0t0  TCP 10.0.0.5:22->not-an-ip:52341 (ESTABLISHED)
"#;

        assert!(parse_established_management_peer_ips(raw).is_empty());
    }
}
