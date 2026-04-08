use std::process::Command;

use anyhow::{anyhow, Result};

use crate::discovery::discover_launchers;
use crate::types::{LaunchRequest, LaunchTargetKind};
use crate::uri::parse_launch_uri;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchOutcome {
    pub launcher: String,
    pub target: String,
}

pub fn launch_uri(raw: &str) -> Result<LaunchOutcome> {
    let request = parse_launch_uri(raw)?;
    launch_request(&request)
}

pub fn launch_request(request: &LaunchRequest) -> Result<LaunchOutcome> {
    let launchers = discover_launchers();
    match request.kind {
        LaunchTargetKind::Ssh => launch_ssh(request, &launchers),
        LaunchTargetKind::Rdp => launch_rdp(request, &launchers),
        LaunchTargetKind::Vnc => launch_vnc(request, &launchers),
        LaunchTargetKind::Web => launch_web(request, &launchers),
        LaunchTargetKind::Tcp => Err(anyhow!("tcp_launcher_not_supported")),
    }
}

fn launch_ssh(
    request: &LaunchRequest,
    launchers: &crate::discovery::DiscoveredLaunchers,
) -> Result<LaunchOutcome> {
    let launcher = launchers
        .ssh
        .as_ref()
        .ok_or_else(|| anyhow!("ssh_launcher_not_found"))?;
    let mut command = Command::new(launcher);
    if let Some(port) = request.port {
        command.arg("-p").arg(port.to_string());
    }
    let target = match request.username.as_deref() {
        Some(username) if !username.trim().is_empty() => format!("{}@{}", username, request.host),
        _ => request.host.clone(),
    };
    command.arg(&target);
    command.spawn()?;
    Ok(LaunchOutcome {
        launcher: launcher.display().to_string(),
        target,
    })
}

fn launch_rdp(
    request: &LaunchRequest,
    launchers: &crate::discovery::DiscoveredLaunchers,
) -> Result<LaunchOutcome> {
    let launcher = launchers
        .rdp
        .as_ref()
        .ok_or_else(|| anyhow!("rdp_launcher_not_found"))?;
    let target = format!("{}:{}", request.host, request.port.unwrap_or(3389));
    let mut command = Command::new(launcher);
    #[cfg(target_os = "windows")]
    {
        command.arg(format!("/v:{}", target));
    }
    #[cfg(target_os = "macos")]
    {
        command.arg(format!("rdp://full%20address=s:{}", target));
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        let launcher_name = launcher
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if launcher_name.contains("remmina") {
            command.arg("-c").arg(format!("rdp://{}", target));
        } else {
            command.arg(format!("/v:{}", target));
        }
    }
    command.spawn()?;
    Ok(LaunchOutcome {
        launcher: launcher.display().to_string(),
        target,
    })
}

fn launch_vnc(
    request: &LaunchRequest,
    launchers: &crate::discovery::DiscoveredLaunchers,
) -> Result<LaunchOutcome> {
    let launcher = launchers
        .vnc
        .as_ref()
        .ok_or_else(|| anyhow!("vnc_launcher_not_found"))?;
    let target = format!("{}:{}", request.host, request.port.unwrap_or(5900));
    let mut command = Command::new(launcher);
    #[cfg(target_os = "macos")]
    {
        command.arg(format!("vnc://{}", target));
    }
    #[cfg(not(target_os = "macos"))]
    {
        command.arg(&target);
    }
    command.spawn()?;
    Ok(LaunchOutcome {
        launcher: launcher.display().to_string(),
        target,
    })
}

fn launch_web(
    request: &LaunchRequest,
    launchers: &crate::discovery::DiscoveredLaunchers,
) -> Result<LaunchOutcome> {
    let launcher = launchers
        .web
        .as_ref()
        .ok_or_else(|| anyhow!("web_launcher_not_found"))?;
    let target = if let Some(url) = request.url.as_ref() {
        url.clone()
    } else {
        let scheme = if request.port == Some(443) {
            "https"
        } else {
            "http"
        };
        let path = request.path.clone().unwrap_or_default();
        format!(
            "{}://{}:{}{}",
            scheme,
            request.host,
            request
                .port
                .unwrap_or(if scheme == "https" { 443 } else { 80 }),
            path
        )
    };
    let mut command = Command::new(launcher);
    #[cfg(target_os = "windows")]
    {
        command.arg("/C").arg("start").arg("").arg(&target);
    }
    #[cfg(not(target_os = "windows"))]
    {
        command.arg(&target);
    }
    command.spawn()?;
    Ok(LaunchOutcome {
        launcher: launcher.display().to_string(),
        target,
    })
}
