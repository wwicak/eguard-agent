use super::command_utils::{mark_internal_command, run_command};
use std::process::Command;
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FirewallCommand {
    pub(super) bin: &'static str,
    pub(super) args: Vec<String>,
}

const IPV4_INPUT_CHAIN: &str = "EGUARD-ISOLATE-IN";
const IPV4_OUTPUT_CHAIN: &str = "EGUARD-ISOLATE-OUT";
const IPV6_INPUT_CHAIN: &str = "EGUARD-ISOLATE6-IN";
const IPV6_OUTPUT_CHAIN: &str = "EGUARD-ISOLATE6-OUT";
const NFT_TABLE_NAME: &str = "eguard_isolate";
const MANAGEMENT_PORTS: &[u16] = &[22];
const XTABLES_WAIT_SECS: &str = "5";

/// Detected firewall backend: iptables (legacy) or nftables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirewallBackend {
    Iptables,
    Nftables,
}

static DETECTED_BACKEND: OnceLock<FirewallBackend> = OnceLock::new();

fn detect_firewall_backend() -> FirewallBackend {
    *DETECTED_BACKEND.get_or_init(|| {
        // Try iptables first — attempt to list filter rules. If iptables
        // fails for ANY reason (SELinux, missing module, permission denied,
        // missing binary), fall back to nftables.
        if let Ok(output) = mark_internal_command(Command::new("iptables").args(["-w", "2", "-L", "-n"])).output() {
            if output.status.success() {
                return FirewallBackend::Iptables;
            }
        }

        // Try to ensure nf_tables kernel module is loaded (required on some
        // distros like Fedora where iptables-legacy fails under SELinux).
        // This may fail if the process lacks CAP_SYS_MODULE — that's fine,
        // the module might already be loaded.
        let _ = mark_internal_command(Command::new("modprobe").arg("nf_tables")).output();

        // Check if nft can list tables (requires root + nf_tables module).
        if let Ok(output) = mark_internal_command(Command::new("nft").args(["list", "tables"])).output() {
            if output.status.success() {
                return FirewallBackend::Nftables;
            }
        }
        // Default to iptables and let it fail with a clear error.
        FirewallBackend::Iptables
    })
}

pub(super) fn apply_linux_host_isolation(allowed_server_ips: &[String]) -> Result<(), String> {
    if allowed_server_ips.is_empty() {
        return Err("isolation rejected: no routable server IPs provided".to_string());
    }

    remove_linux_host_isolation().ok();

    match detect_firewall_backend() {
        FirewallBackend::Iptables => {
            for command in build_ipv4_apply_commands(allowed_server_ips) {
                run_command(command.bin, &command.args)?;
            }
            if firewall_filter_table_available("ip6tables") {
                for command in build_ipv6_apply_commands(allowed_server_ips) {
                    run_command(command.bin, &command.args)?;
                }
            }
        }
        FirewallBackend::Nftables => {
            for command in build_nft_apply_commands(allowed_server_ips) {
                run_command(command.bin, &command.args)?;
            }
        }
    }
    Ok(())
}

pub(super) fn remove_linux_host_isolation() -> Result<(), String> {
    let mut last_err = None;

    // Always try both backends for cleanup — isolation may have been applied
    // with either backend in a previous run.
    for command in build_remove_commands() {
        if let Err(err) = run_command(command.bin, &command.args) {
            if !is_nonfatal_firewall_cleanup_error(&err) {
                last_err = Some(err);
            }
        }
    }
    for command in build_nft_remove_commands() {
        if let Err(err) = run_command(command.bin, &command.args) {
            if !is_nonfatal_firewall_cleanup_error(&err)
                && !err.contains("No such file or directory")
            {
                last_err = Some(err);
            }
        }
    }

    match last_err {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

fn build_ipv4_apply_commands(allowed_server_ips: &[String]) -> Vec<FirewallCommand> {
    let allowed = allowed_server_ips
        .iter()
        .filter(|value| value.parse::<std::net::Ipv4Addr>().is_ok())
        .cloned()
        .collect::<Vec<_>>();
    build_apply_commands("iptables", IPV4_INPUT_CHAIN, IPV4_OUTPUT_CHAIN, &allowed)
}

fn build_ipv6_apply_commands(allowed_server_ips: &[String]) -> Vec<FirewallCommand> {
    let allowed = allowed_server_ips
        .iter()
        .filter(|value| value.parse::<std::net::Ipv6Addr>().is_ok())
        .cloned()
        .collect::<Vec<_>>();
    build_apply_commands("ip6tables", IPV6_INPUT_CHAIN, IPV6_OUTPUT_CHAIN, &allowed)
}

pub(super) fn collect_active_management_peer_ips() -> Vec<String> {
    let mut command = Command::new("ss");
    let output =
        match mark_internal_command(command.args(["-H", "-tn", "state", "established"])).output() {
            Ok(output) if output.status.success() => output,
            _ => return Vec::new(),
        };

    parse_established_management_peer_ips(&String::from_utf8_lossy(&output.stdout))
}

fn parse_established_management_peer_ips(raw: &str) -> Vec<String> {
    let mut peers = Vec::new();
    for line in raw.lines() {
        if let Some(peer_ip) = parse_established_management_peer_ip(line) {
            if !peers.iter().any(|entry| entry == &peer_ip) {
                peers.push(peer_ip);
            }
        }
    }
    peers
}

fn parse_established_management_peer_ip(line: &str) -> Option<String> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    if fields.len() < 2 {
        return None;
    }

    let local = fields.get(fields.len().saturating_sub(2))?;
    let peer = fields.last()?;
    let (_, local_port) = parse_socket_endpoint(local)?;
    if !MANAGEMENT_PORTS.contains(&local_port) {
        return None;
    }

    let (peer_ip, _) = parse_socket_endpoint(peer)?;
    Some(peer_ip)
}

fn parse_socket_endpoint(raw: &str) -> Option<(String, u16)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(stripped) = trimmed.strip_prefix('[') {
        let (host, rest) = stripped.split_once("]:")?;
        let port = rest.parse::<u16>().ok()?;
        return Some((host.to_string(), port));
    }

    let (host, port) = trimmed.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    Some((host.to_string(), port))
}

fn firewall_filter_table_available(bin: &str) -> bool {
    let mut command = Command::new(bin);
    match mark_internal_command(command.arg("-S")).output() {
        Ok(output) if output.status.success() => true,
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            !stderr.contains("Table does not exist")
        }
        Err(_) => false,
    }
}

fn is_nonfatal_firewall_cleanup_error(err: &str) -> bool {
    err.contains("No chain/target/match")
        || err.contains("Bad rule")
        || err.contains("Table does not exist")
        || err.contains("Chain already exists")
}

fn build_apply_commands(
    bin: &'static str,
    input_chain: &'static str,
    output_chain: &'static str,
    allowed_server_ips: &[String],
) -> Vec<FirewallCommand> {
    let mut commands = vec![
        fw(bin, ["-N", input_chain]),
        fw(bin, ["-N", output_chain]),
        fw(bin, ["-A", input_chain, "-i", "lo", "-j", "ACCEPT"]),
        fw(bin, ["-A", output_chain, "-o", "lo", "-j", "ACCEPT"]),
    ];

    for ip in allowed_server_ips {
        commands.push(FirewallCommand {
            bin,
            args: vec![
                "-w".into(),
                XTABLES_WAIT_SECS.into(),
                "-A".into(),
                input_chain.into(),
                "-s".into(),
                ip.clone(),
                "-j".into(),
                "ACCEPT".into(),
            ],
        });
        commands.push(FirewallCommand {
            bin,
            args: vec![
                "-w".into(),
                XTABLES_WAIT_SECS.into(),
                "-A".into(),
                output_chain.into(),
                "-d".into(),
                ip.clone(),
                "-j".into(),
                "ACCEPT".into(),
            ],
        });
    }

    commands.extend([
        fw(bin, ["-A", input_chain, "-j", "DROP"]),
        fw(bin, ["-A", output_chain, "-j", "DROP"]),
        fw(bin, ["-I", "INPUT", "1", "-j", input_chain]),
        fw(bin, ["-I", "OUTPUT", "1", "-j", output_chain]),
    ]);
    commands
}

fn build_remove_commands() -> Vec<FirewallCommand> {
    vec![
        fw("iptables", ["-D", "INPUT", "-j", IPV4_INPUT_CHAIN]),
        fw("iptables", ["-D", "OUTPUT", "-j", IPV4_OUTPUT_CHAIN]),
        fw("iptables", ["-F", IPV4_INPUT_CHAIN]),
        fw("iptables", ["-F", IPV4_OUTPUT_CHAIN]),
        fw("iptables", ["-X", IPV4_INPUT_CHAIN]),
        fw("iptables", ["-X", IPV4_OUTPUT_CHAIN]),
        fw("ip6tables", ["-D", "INPUT", "-j", IPV6_INPUT_CHAIN]),
        fw("ip6tables", ["-D", "OUTPUT", "-j", IPV6_OUTPUT_CHAIN]),
        fw("ip6tables", ["-F", IPV6_INPUT_CHAIN]),
        fw("ip6tables", ["-F", IPV6_OUTPUT_CHAIN]),
        fw("ip6tables", ["-X", IPV6_INPUT_CHAIN]),
        fw("ip6tables", ["-X", IPV6_OUTPUT_CHAIN]),
    ]
}

fn fw<const N: usize>(bin: &'static str, args: [&str; N]) -> FirewallCommand {
    let mut all_args = vec!["-w".to_string(), XTABLES_WAIT_SECS.to_string()];
    all_args.extend(args.into_iter().map(|value| value.to_string()));
    FirewallCommand {
        bin,
        args: all_args,
    }
}

// ── nftables backend ─────────────────────────────────────────────────────

fn nft(args: &[&str]) -> FirewallCommand {
    FirewallCommand {
        bin: "nft",
        args: args.iter().map(|s| s.to_string()).collect(),
    }
}

fn build_nft_apply_commands(allowed_server_ips: &[String]) -> Vec<FirewallCommand> {
    let mut commands = Vec::new();

    // Create table (idempotent via "add" which is create-if-not-exists).
    commands.push(nft(&["add", "table", "inet", NFT_TABLE_NAME]));

    // Create chains with hook priority. The chain definition must be
    // a single brace-enclosed argument for nft.
    commands.push(nft(&[
        "add", "chain", "inet", NFT_TABLE_NAME, "input",
        "{ type filter hook input priority -200 ; }",
    ]));
    commands.push(nft(&[
        "add", "chain", "inet", NFT_TABLE_NAME, "output",
        "{ type filter hook output priority -200 ; }",
    ]));

    // Allow loopback
    commands.push(nft(&["add", "rule", "inet", NFT_TABLE_NAME, "input", "iif", "lo", "accept"]));
    commands.push(nft(&["add", "rule", "inet", NFT_TABLE_NAME, "output", "oif", "lo", "accept"]));

    // Allow management server IPs
    for ip in allowed_server_ips {
        let family = if ip.contains(':') { "ip6" } else { "ip" };
        commands.push(nft(&[
            "add", "rule", "inet", NFT_TABLE_NAME, "input",
            family, "saddr", ip, "accept",
        ]));
        commands.push(nft(&[
            "add", "rule", "inet", NFT_TABLE_NAME, "output",
            family, "daddr", ip, "accept",
        ]));
    }

    // Drop everything else
    commands.push(nft(&["add", "rule", "inet", NFT_TABLE_NAME, "input", "drop"]));
    commands.push(nft(&["add", "rule", "inet", NFT_TABLE_NAME, "output", "drop"]));

    commands
}

fn build_nft_remove_commands() -> Vec<FirewallCommand> {
    vec![
        // Deleting the table removes all its chains and rules atomically.
        nft(&["delete", "table", "inet", NFT_TABLE_NAME]),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_ipv4_apply_commands_allows_management_server_and_drops_rest() {
        let commands = build_ipv4_apply_commands(&["203.0.113.10".to_string()]);
        assert!(commands.iter().any(|cmd| cmd.args
            == vec![
                "-w",
                XTABLES_WAIT_SECS,
                "-A",
                IPV4_INPUT_CHAIN,
                "-s",
                "203.0.113.10",
                "-j",
                "ACCEPT"
            ]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()));
        assert!(commands.iter().any(|cmd| cmd.args
            == vec![
                "-w",
                XTABLES_WAIT_SECS,
                "-A",
                IPV4_OUTPUT_CHAIN,
                "-d",
                "203.0.113.10",
                "-j",
                "ACCEPT"
            ]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()));
        assert!(commands
            .iter()
            .any(|cmd| cmd.args.ends_with(&["DROP".to_string()])));
    }

    #[test]
    fn parse_established_management_peer_ips_collects_ipv4_and_ipv6_clients() {
        let output = "\
ESTAB 0 0 10.0.2.15:22 198.51.100.44:54422
ESTAB 0 0 [2001:db8::10]:22 [2001:db8::55]:61234
ESTAB 0 0 10.0.2.15:443 198.51.100.44:60000
";
        assert_eq!(
            parse_established_management_peer_ips(output),
            vec!["198.51.100.44".to_string(), "2001:db8::55".to_string()]
        );
    }

    #[test]
    fn cleanup_error_classifier_treats_missing_ipv6_filter_table_as_nonfatal() {
        assert!(is_nonfatal_firewall_cleanup_error(
            "Table does not exist (do you need to insmod?)"
        ));
        assert!(!is_nonfatal_firewall_cleanup_error("Permission denied"));
    }

    #[test]
    fn build_remove_commands_cleans_up_ipv4_and_ipv6_chains() {
        let commands = build_remove_commands();
        assert!(commands.iter().any(|cmd| cmd.bin == "iptables"
            && cmd.args
                == vec!["-w", XTABLES_WAIT_SECS, "-X", IPV4_INPUT_CHAIN]
                    .into_iter()
                    .map(str::to_string)
                    .collect::<Vec<_>>()));
        assert!(commands.iter().any(|cmd| cmd.bin == "ip6tables"
            && cmd.args
                == vec!["-w", XTABLES_WAIT_SECS, "-X", IPV6_OUTPUT_CHAIN]
                    .into_iter()
                    .map(str::to_string)
                    .collect::<Vec<_>>()));
    }
}
