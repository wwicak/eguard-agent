use super::command_utils::run_command;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FirewallCommand {
    pub(super) bin: &'static str,
    pub(super) args: Vec<String>,
}

const IPV4_INPUT_CHAIN: &str = "EGUARD-ISOLATE-IN";
const IPV4_OUTPUT_CHAIN: &str = "EGUARD-ISOLATE-OUT";
const IPV6_INPUT_CHAIN: &str = "EGUARD-ISOLATE6-IN";
const IPV6_OUTPUT_CHAIN: &str = "EGUARD-ISOLATE6-OUT";

pub(super) fn apply_linux_host_isolation(allowed_server_ips: &[String]) -> Result<(), String> {
    if allowed_server_ips.is_empty() {
        return Err("isolation rejected: no routable server IPs provided".to_string());
    }

    remove_linux_host_isolation().ok();

    for command in build_ipv4_apply_commands(allowed_server_ips) {
        run_command(command.bin, &command.args)?;
    }
    if firewall_filter_table_available("ip6tables") {
        for command in build_ipv6_apply_commands(allowed_server_ips) {
            run_command(command.bin, &command.args)?;
        }
    }
    Ok(())
}

pub(super) fn remove_linux_host_isolation() -> Result<(), String> {
    let mut last_err = None;
    for command in build_remove_commands() {
        if let Err(err) = run_command(command.bin, &command.args) {
            if !is_nonfatal_firewall_cleanup_error(&err) {
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

fn firewall_filter_table_available(bin: &str) -> bool {
    match Command::new(bin).arg("-S").output() {
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
    FirewallCommand {
        bin,
        args: args.into_iter().map(|value| value.to_string()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_ipv4_apply_commands_allows_management_server_and_drops_rest() {
        let commands = build_ipv4_apply_commands(&["203.0.113.10".to_string()]);
        assert!(commands.iter().any(|cmd| cmd.args
            == vec!["-A", IPV4_INPUT_CHAIN, "-s", "203.0.113.10", "-j", "ACCEPT"]
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()));
        assert!(commands.iter().any(|cmd| cmd.args
            == vec![
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
                == vec!["-X", IPV4_INPUT_CHAIN]
                    .into_iter()
                    .map(str::to_string)
                    .collect::<Vec<_>>()));
        assert!(commands.iter().any(|cmd| cmd.bin == "ip6tables"
            && cmd.args
                == vec!["-X", IPV6_OUTPUT_CHAIN]
                    .into_iter()
                    .map(str::to_string)
                    .collect::<Vec<_>>()));
    }
}
