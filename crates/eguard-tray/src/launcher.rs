use std::process::Command;

use anyhow::{anyhow, Context, Result};

use crate::app::open_external_url;
use crate::protocol::LaunchRequest;
use crate::state::BookmarkEntry;

pub fn launch_bookmark(bookmark: &BookmarkEntry) -> Result<()> {
    let request = LaunchRequest::parse(&bookmark.launch_uri)
        .with_context(|| format!("parse launch uri for {}", bookmark.app_id))?;
    launch_launch_request(&request)
}

pub fn launch_launch_request(request: &LaunchRequest) -> Result<()> {
    match normalized_app_type(&request.app_type).as_str() {
        "ssh" => launch_ssh(request),
        "rdp" => launch_rdp(request),
        "vnc" => launch_vnc(request),
        "web" | "https" | "http" => open_external_url(&request.target),
        other => Err(anyhow!("unsupported launch target `{other}`")),
    }
}

fn normalized_app_type(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn launch_ssh(request: &LaunchRequest) -> Result<()> {
    let ssh_exe = find_in_path(&["ssh.exe"])
        .ok_or_else(|| anyhow!("OpenSSH client `ssh.exe` not found in PATH"))?;

    let target = match request.user.as_deref() {
        Some(user) if !user.trim().is_empty() => format!("{}@{}", user.trim(), request.target),
        _ => request.target.clone(),
    };

    let mut cmd = Command::new(ssh_exe);
    if let Some(port) = request.port {
        cmd.arg("-p").arg(port.to_string());
    }
    cmd.arg(target);
    spawn_detached(cmd, "ssh")
}

fn launch_rdp(request: &LaunchRequest) -> Result<()> {
    let mstsc = find_in_path(&["mstsc.exe"])
        .or_else(|| Some(String::from(r"C:\Windows\System32\mstsc.exe")))
        .ok_or_else(|| anyhow!("`mstsc.exe` not available"))?;

    let mut cmd = Command::new(mstsc);
    cmd.arg(format!(
        "/v:{}:{}",
        request.target,
        request.port.unwrap_or(3389)
    ));
    if let Some(display) = request.display.as_deref() {
        let parts: Vec<_> = display.split('x').collect();
        if parts.len() == 2 {
            cmd.arg(format!("/w:{}", parts[0]));
            cmd.arg(format!("/h:{}", parts[1]));
        }
    }
    spawn_detached(cmd, "rdp")
}

fn launch_vnc(request: &LaunchRequest) -> Result<()> {
    let viewer = find_in_path(&["vncviewer.exe", "tvnviewer.exe"]).ok_or_else(|| {
        anyhow!("no supported VNC viewer found (`vncviewer.exe`/`tvnviewer.exe`)")
    })?;
    let mut cmd = Command::new(viewer);
    cmd.arg(format!(
        "{}:{}",
        request.target,
        request.port.unwrap_or(5900)
    ));
    spawn_detached(cmd, "vnc")
}

fn find_in_path(candidates: &[&str]) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        for candidate in candidates {
            let full = dir.join(candidate);
            if full.is_file() {
                return Some(full.to_string_lossy().into_owned());
            }
        }
    }
    None
}

fn spawn_detached(mut cmd: Command, label: &str) -> Result<()> {
    cmd.spawn()
        .with_context(|| format!("launch {label} client"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::normalized_app_type;

    #[test]
    fn normalizes_app_type() {
        assert_eq!(normalized_app_type(" RDP "), "rdp");
    }
}
