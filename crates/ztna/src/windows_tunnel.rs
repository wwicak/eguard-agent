#[cfg(target_os = "windows")]
use std::fs;
#[cfg(target_os = "windows")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "windows")]
use std::process::Command;
#[cfg(target_os = "windows")]
use std::thread;
#[cfg(target_os = "windows")]
use std::time::Duration;

#[cfg(target_os = "windows")]
use anyhow::{anyhow, Context, Result};

#[cfg(target_os = "windows")]
use crate::{TunnelGrant, WireguardIdentity};

#[cfg(target_os = "windows")]
const ZTNA_TUNNEL_NAME: &str = "eguard-ztna";

#[cfg(target_os = "windows")]
pub fn apply_windows_tunnel_grant(
    data_dir: &Path,
    identity: &WireguardIdentity,
    grant: &TunnelGrant,
) -> Result<()> {
    let config_path = config_path(data_dir);
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create ztna tunnel dir {}", parent.display()))?;
    }

    let allowed_ips = effective_allowed_ips(grant);
    let rendered = render_config(identity, grant, &allowed_ips);
    fs::write(&config_path, rendered)
        .with_context(|| format!("write ztna tunnel config {}", config_path.display()))?;

    let wireguard = wireguard_exe()?;
    if windows_tunnel_service_exists()? {
        run_wireguard_command(&wireguard, &["/uninstalltunnelservice", ZTNA_TUNNEL_NAME])
            .context("uninstall existing ztna tunnel service")?;
        wait_for_windows_tunnel_service_state(false, Duration::from_secs(10))?;
    }

    let config_arg = config_path.to_string_lossy().into_owned();
    run_wireguard_command(&wireguard, &["/installtunnelservice", &config_arg])
        .with_context(|| format!("install ztna tunnel service from {}", config_path.display()))?;
    wait_for_windows_tunnel_service_state(true, Duration::from_secs(10))?;

    // Give the Windows WireGuard service a moment to bring the interface up.
    thread::sleep(Duration::from_millis(750));
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn remove_windows_tunnel(data_dir: &Path) -> Result<()> {
    let wireguard = wireguard_exe()?;
    if !windows_tunnel_service_exists()? {
        let config_path = config_path(data_dir);
        let _ = fs::remove_file(&config_path);
        return Ok(());
    }
    run_wireguard_command(&wireguard, &["/uninstalltunnelservice", ZTNA_TUNNEL_NAME])
        .context("uninstall ztna tunnel service")?;
    wait_for_windows_tunnel_service_state(false, Duration::from_secs(10))?;
    let config_path = config_path(data_dir);
    let _ = fs::remove_file(&config_path);
    Ok(())
}

#[cfg(target_os = "windows")]
fn config_path(data_dir: &Path) -> PathBuf {
    data_dir.join("ztna").join(format!("{}.conf", ZTNA_TUNNEL_NAME))
}

#[cfg(target_os = "windows")]
fn wireguard_exe() -> Result<PathBuf> {
    let candidates = [
        std::env::var_os("ProgramFiles")
            .map(PathBuf::from)
            .map(|root| root.join("WireGuard").join("wireguard.exe")),
        std::env::var_os("ProgramFiles(x86)")
            .map(PathBuf::from)
            .map(|root| root.join("WireGuard").join("wireguard.exe")),
    ];
    for candidate in candidates.into_iter().flatten() {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    if let Some(path) = find_in_path("wireguard.exe") {
        return Ok(path);
    }
    Err(anyhow!("wireguard.exe not found"))
}

#[cfg(target_os = "windows")]
fn windows_tunnel_service_exists() -> Result<bool> {
    let service_name = format!("WireGuardTunnel${}", ZTNA_TUNNEL_NAME);
    let status = Command::new("sc.exe")
        .arg("query")
        .arg(&service_name)
        .status()
        .with_context(|| format!("query windows service {}", service_name))?;
    Ok(status.success())
}

#[cfg(target_os = "windows")]
fn wait_for_windows_tunnel_service_state(expected_exists: bool, timeout: Duration) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if windows_tunnel_service_exists()? == expected_exists {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    Err(anyhow!(
        "wireguard tunnel service did not reach expected exists={} within {:?}",
        expected_exists,
        timeout
    ))
}

#[cfg(target_os = "windows")]
fn run_wireguard_command(wireguard: &Path, args: &[&str]) -> Result<()> {
    let status = Command::new(wireguard)
        .args(args)
        .status()
        .with_context(|| format!("run {} {}", wireguard.display(), args.join(" ")))?;
    if !status.success() {
        return Err(anyhow!(
            "wireguard command failed: {} {} (status={})",
            wireguard.display(),
            args.join(" "),
            status
        ));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let full = dir.join(name);
        if full.is_file() {
            return Some(full);
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn effective_allowed_ips(grant: &TunnelGrant) -> Vec<String> {
    let mut allowed = Vec::new();
    for cidr in &grant.allowed_ips {
        let trimmed = cidr.trim();
        if trimmed.is_empty() || trimmed == "0.0.0.0/0" || trimmed == "::/0" {
            continue;
        }
        if !allowed.iter().any(|existing| existing == trimmed) {
            allowed.push(trimmed.to_string());
        }
    }
    allowed
}

#[cfg(target_os = "windows")]
fn render_config(
    identity: &WireguardIdentity,
    grant: &TunnelGrant,
    allowed_ips: &[String],
) -> String {
    format!(
        "[Interface]\nPrivateKey = {}\nAddress = {}/32\n\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = {}\nPersistentKeepalive = 25\n",
        identity.private_key_b64.trim(),
        grant.tunnel_ip.trim(),
        grant.server_wg_public_key.trim(),
        grant.server_endpoint.trim(),
        allowed_ips.join(", ")
    )
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::{effective_allowed_ips, render_config};
    use crate::{TunnelGrant, WireguardIdentity};

    fn sample_identity() -> WireguardIdentity {
        WireguardIdentity {
            private_key_b64: "private-key".to_string(),
            public_key_b64: "public-key".to_string(),
            storage_backend: "file".to_string(),
            storage_path: None,
        }
    }

    fn sample_grant() -> TunnelGrant {
        TunnelGrant {
            session_id: "session-1".to_string(),
            session_token: "token-1".to_string(),
            server_wg_public_key: "server-pub".to_string(),
            server_endpoint: "138.252.193.169:51820".to_string(),
            tunnel_ip: "100.64.0.13".to_string(),
            service_ip: String::new(),
            allowed_ips: vec!["0.0.0.0/0".to_string(), "172.16.10.11/32".to_string()],
            ttl_seconds: 300,
            transport: "wireguard".to_string(),
        }
    }

    #[test]
    fn allowed_ips_keep_tunnel_route_and_drop_default_route() {
        let grant = sample_grant();
        let allowed = effective_allowed_ips(&grant);
        assert_eq!(allowed, vec!["172.16.10.11/32".to_string()]);
    }

    #[test]
    fn render_config_includes_tunnel_address_and_peer() {
        let grant = sample_grant();
        let config = render_config(&sample_identity(), &grant, &effective_allowed_ips(&grant));
        assert!(config.contains("Address = 100.64.0.13/32"));
        assert!(config.contains("Endpoint = 138.252.193.169:51820"));
        assert!(config.contains("AllowedIPs = 172.16.10.11/32"));
    }
}
