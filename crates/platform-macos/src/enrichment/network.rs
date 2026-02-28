//! Network connection enrichment.
//!
//! On macOS this resolves PID-scoped TCP connection context via `lsof`.

#[cfg(target_os = "macos")]
use std::process::Command;

/// Resolved network connection context.
#[derive(Debug, Clone)]
pub struct NetworkContext {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
}

/// Look up the network context for a given PID.
pub fn resolve_network_context(pid: u32) -> Option<NetworkContext> {
    #[cfg(target_os = "macos")]
    {
        resolve_network_context_macos(pid)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        None
    }
}

#[cfg(target_os = "macos")]
fn resolve_network_context_macos(pid: u32) -> Option<NetworkContext> {
    if pid == 0 {
        return None;
    }

    let output = Command::new("lsof")
        .args(["-n", "-P", "-a", "-p", &pid.to_string(), "-iTCP"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_lsof_output(&stdout)
}

#[cfg(any(test, target_os = "macos"))]
fn parse_lsof_output(raw: &str) -> Option<NetworkContext> {
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("COMMAND") {
            continue;
        }

        if let Some(ctx) = parse_lsof_connection_line(trimmed) {
            return Some(ctx);
        }
    }

    None
}

#[cfg(any(test, target_os = "macos"))]
fn parse_lsof_connection_line(line: &str) -> Option<NetworkContext> {
    // Typical lsof token near end:
    // TCP 127.0.0.1:56120->203.0.113.7:443 (ESTABLISHED)
    // We locate the first token containing "->" and then split local/remote endpoints.
    let token = line
        .split_whitespace()
        .find(|segment| segment.contains("->") && segment.contains(':'))?;

    let (local_raw, remote_raw) = token.split_once("->")?;
    let (local_addr, local_port) = split_endpoint(local_raw)?;
    let (remote_addr, remote_port) = split_endpoint(remote_raw)?;

    Some(NetworkContext {
        local_addr,
        local_port,
        remote_addr,
        remote_port,
    })
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
    use super::{parse_lsof_connection_line, parse_lsof_output};

    #[test]
    fn parse_lsof_connection_line_extracts_endpoints() {
        let line = "ssh      1001 dimas    7u  IPv4 0x123456      0t0  TCP 127.0.0.1:56120->203.0.113.7:443 (ESTABLISHED)";
        let ctx = parse_lsof_connection_line(line).expect("context parsed");

        assert_eq!(ctx.local_addr, "127.0.0.1");
        assert_eq!(ctx.local_port, 56120);
        assert_eq!(ctx.remote_addr, "203.0.113.7");
        assert_eq!(ctx.remote_port, 443);
    }

    #[test]
    fn parse_lsof_output_skips_header_lines() {
        let output = r#"COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
ssh      1001 dimas    7u  IPv4 0x123456      0t0  TCP 127.0.0.1:56120->203.0.113.7:443 (ESTABLISHED)
"#;
        let ctx = parse_lsof_output(output).expect("context parsed");
        assert_eq!(ctx.remote_addr, "203.0.113.7");
    }
}
