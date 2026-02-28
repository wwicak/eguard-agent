use std::net::IpAddr;
use std::path::Path;
use std::process::Command;

use anyhow::Result;

pub(super) fn resolve_allowed_server_ips(server_addr: &str, payload_ips: &[String]) -> Vec<String> {
    let mut ips = Vec::new();

    for raw in payload_ips {
        let ip = raw.trim();
        if ip.is_empty() {
            continue;
        }
        if parse_ip_literal(ip).is_some() && !ips.iter().any(|entry| entry == ip) {
            ips.push(ip.to_string());
        }
    }

    let host = extract_server_host(server_addr);
    if let Some(ip) = parse_ip_literal(&host) {
        let value = ip.to_string();
        if !ips.iter().any(|entry| entry == &value) {
            ips.push(value);
        }
    }

    ips
}

pub(super) fn extract_server_host(server_addr: &str) -> String {
    let raw = server_addr.trim();
    if raw.is_empty() {
        return String::new();
    }

    if let Some(stripped) = raw.strip_prefix('[') {
        if let Some((host, _rest)) = stripped.split_once(']') {
            return host.to_string();
        }
    }

    if let Some((host, port)) = raw.rsplit_once(':') {
        if !host.contains(':') && port.parse::<u16>().is_ok() {
            return host.to_string();
        }
    }

    raw.to_string()
}

fn parse_ip_literal(raw: &str) -> Option<IpAddr> {
    raw.trim().parse::<IpAddr>().ok()
}

pub(super) fn mdm_action_allowed(action: &str) -> bool {
    let normalized = action.trim().to_ascii_lowercase();
    if normalized == "lock" || normalized == "locate" || normalized == "lost_mode" {
        return true;
    }

    if std::env::var("EGUARD_MDM_ALLOW_ALL")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return true;
    }

    let allow_env = format!("EGUARD_MDM_ALLOW_{}", normalized.to_ascii_uppercase());
    if std::env::var(allow_env)
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return true;
    }

    if matches!(normalized.as_str(), "wipe" | "retire" | "restart") {
        return std::env::var("EGUARD_MDM_ALLOW_DESTRUCTIVE")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
    }

    if normalized.starts_with("app_") || normalized == "app" {
        return std::env::var("EGUARD_MDM_ALLOW_APP_MANAGEMENT")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
    }

    false
}

pub(super) fn run_command_sequence(commands: &[(&str, &[&str])]) -> Result<(), String> {
    let mut last_error = String::new();

    for (cmd, args) in commands {
        let owned = args
            .iter()
            .map(|arg| (*arg).to_string())
            .collect::<Vec<_>>();
        match run_command(cmd, &owned) {
            Ok(()) => return Ok(()),
            Err(err) => {
                last_error = format!("{}: {}", cmd, err);
            }
        }
    }

    if last_error.is_empty() {
        Err("all command attempts failed".to_string())
    } else {
        Err(last_error)
    }
}

pub(super) fn run_command(cmd: &str, args: &[String]) -> Result<(), String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|err| format!("spawn failed: {err}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if stderr.is_empty() { stdout } else { stderr };

    if detail.is_empty() {
        Err(format!("command exited with status {}", output.status))
    } else {
        Err(detail)
    }
}

pub(super) fn remove_path(path: &str) -> Result<(), String> {
    let path = Path::new(path);
    if !path.exists() {
        return Ok(());
    }
    if path.is_dir() {
        std::fs::remove_dir_all(path)
            .map_err(|err| format!("remove dir {}: {}", path.display(), err))
    } else {
        std::fs::remove_file(path).map_err(|err| format!("remove file {}: {}", path.display(), err))
    }
}

pub(super) fn write_marker(path: &str) -> Result<(), String> {
    let marker_path = Path::new(path);
    let content = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string());

    if let Some(parent) = marker_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("create marker dir {}: {}", parent.display(), err))?;
    }

    std::fs::write(marker_path, content.as_bytes())
        .map_err(|err| format!("write marker {}: {}", marker_path.display(), err))
}
