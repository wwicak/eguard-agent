use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};

use crate::types::SshLaunchRequest;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshLaunchMode {
    BrowserHtml5,
    Putty,
    NativeSsh,
}

#[derive(Debug)]
pub struct SshLaunchOutcome {
    pub mode: SshLaunchMode,
    pub child: Option<Child>,
    pub cleanup_paths: Vec<PathBuf>,
}

pub fn launch_ssh_request(request: &SshLaunchRequest) -> Result<SshLaunchOutcome> {
    let mode = resolve_ssh_launch_mode(request);
    match mode {
        SshLaunchMode::BrowserHtml5 => {
            open_external_url(&request.target)?;
            Ok(SshLaunchOutcome { mode: SshLaunchMode::BrowserHtml5, child: None, cleanup_paths: Vec::new() })
        }
        SshLaunchMode::Putty => {
            let child = launch_putty(request)?;
            Ok(SshLaunchOutcome { mode: SshLaunchMode::Putty, child: Some(child), cleanup_paths: Vec::new() })
        }
        SshLaunchMode::NativeSsh => {
            let (child, cleanup_paths) = launch_native_ssh(request)?;
            Ok(SshLaunchOutcome { mode: SshLaunchMode::NativeSsh, child: Some(child), cleanup_paths })
        }
    }
}

pub fn resolve_ssh_launch_mode(request: &SshLaunchRequest) -> SshLaunchMode {
    let preferred = request
        .launcher
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if preferred == "browser" || preferred == "html5" || preferred == "web" {
        return SshLaunchMode::BrowserHtml5;
    }
    if request.private_key_pem.as_deref().is_some_and(|v| !v.trim().is_empty()) {
        return SshLaunchMode::NativeSsh;
    }
    if preferred == "putty" {
        return SshLaunchMode::Putty;
    }
    if preferred == "ssh" || preferred == "openssh" {
        return SshLaunchMode::NativeSsh;
    }
    if target_is_web_url(&request.target) {
        return SshLaunchMode::BrowserHtml5;
    }
    if find_putty().is_some() {
        return SshLaunchMode::Putty;
    }
    SshLaunchMode::NativeSsh
}

fn target_is_web_url(target: &str) -> bool {
    let lower = target.trim().to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

fn launch_putty(request: &SshLaunchRequest) -> Result<Child> {
    let putty = find_putty().ok_or_else(|| anyhow!("PuTTY client `putty.exe` not found"))?;
    let mut cmd = Command::new(putty);
    cmd.arg("-ssh");
    cmd.arg(request.target.trim());
    if let Some(port) = request.port {
        cmd.arg("-P").arg(port.to_string());
    }
    if let Some(user) = request.user.as_deref().filter(|v| !v.trim().is_empty()) {
        cmd.arg("-l").arg(user.trim());
    }
    if let Some(password) = request.password.as_deref().filter(|v| !v.trim().is_empty()) {
        cmd.arg("-pw").arg(password);
    }
    spawn_detached(cmd, "putty")
}

fn launch_native_ssh(request: &SshLaunchRequest) -> Result<(Child, Vec<PathBuf>)> {
    let ssh_exe = find_in_path(&["ssh.exe"])
        .ok_or_else(|| anyhow!("OpenSSH client `ssh.exe` not found in PATH"))?;
    let target = match request.user.as_deref() {
        Some(user) if !user.trim().is_empty() => format!("{}@{}", user.trim(), request.target),
        _ => request.target.clone(),
    };
    let mut cmd = Command::new(ssh_exe);
    let mut cleanup_paths = Vec::new();
    if let Some(port) = request.port {
        cmd.arg("-p").arg(port.to_string());
    }
    if let Some(key_pem) = request
        .private_key_pem
        .as_deref()
        .filter(|v| !v.trim().is_empty())
    {
        let key_path = write_temp_key_file(key_pem)?;
        cmd.arg("-i").arg(&key_path);
        cleanup_paths.push(key_path);
    }
    cmd.arg(target);
    let child = spawn_detached(cmd, "ssh")?;
    Ok((child, cleanup_paths))
}

fn spawn_detached(mut cmd: Command, label: &str) -> Result<Child> {
    cmd.spawn()
        .with_context(|| format!("launch {label} client"))
}

fn write_temp_key_file(private_key_pem: &str) -> Result<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let path = std::env::temp_dir().join(format!("eguard-pam-ssh-{stamp}.pem"));
    fs::write(&path, private_key_pem).with_context(|| format!("write temp ssh key {}", path.display()))?;
    apply_restrictive_key_file_permissions(&path)
        .with_context(|| format!("restrict temp ssh key permissions {}", path.display()))?;
    Ok(path)
}

fn apply_restrictive_key_file_permissions(path: &PathBuf) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        restrict_windows_file_acl(path)?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn restrict_windows_file_acl(path: &PathBuf) -> Result<()> {
    let user = current_windows_account_name()?;
    let status = Command::new("icacls")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("{user}:R"))
        .arg("/grant:r")
        .arg("SYSTEM:F")
        .arg("/grant:r")
        .arg("Administrators:F")
        .status()
        .context("apply restrictive ACL with icacls")?;
    if !status.success() {
        return Err(anyhow!("icacls failed while restricting SSH key temp file ACL"));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn current_windows_account_name() -> Result<String> {
    if let Ok(value) = std::env::var("USERNAME") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    let output = Command::new("whoami")
        .output()
        .context("resolve current Windows account with whoami")?;
    if !output.status.success() {
        return Err(anyhow!("whoami failed while resolving current Windows account"));
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() {
        return Err(anyhow!("current Windows account is empty"));
    }
    Ok(value)
}

fn find_putty() -> Option<String> {
    find_in_path(&["putty.exe"]).or_else(|| {
        let candidates = [
            r"C:\Program Files\PuTTY\putty.exe",
            r"C:\Program Files (x86)\PuTTY\putty.exe",
        ];
        candidates
            .iter()
            .find(|path| std::path::Path::new(path).is_file())
            .map(|path| (*path).to_string())
    })
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

fn open_external_url(target: &str) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use windows::core::PCWSTR;
        use windows::Win32::UI::Shell::ShellExecuteW;
        use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

        let operation: Vec<u16> = "open".encode_utf16().chain(std::iter::once(0)).collect();
        let wide_target: Vec<u16> = target.encode_utf16().chain(std::iter::once(0)).collect();
        let result = unsafe {
            ShellExecuteW(
                None,
                PCWSTR(operation.as_ptr()),
                PCWSTR(wide_target.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            )
        };
        let code = result.0 as isize;
        if code <= 32 {
            return Err(anyhow!("failed to open external URL (ShellExecuteW={code})"));
        }
        return Ok(());
    }

    #[allow(unreachable_code)]
    Err(anyhow!("opening external URLs is only implemented for Windows"))
}

#[cfg(test)]
mod tests {
    use super::{resolve_ssh_launch_mode, SshLaunchMode};
    use crate::types::SshLaunchRequest;

    #[test]
    fn prefers_browser_mode_for_http_targets() {
        let req = SshLaunchRequest {
            target: "https://ssh.internal.example/terminal".to_string(),
            ..Default::default()
        };
        assert_eq!(resolve_ssh_launch_mode(&req), SshLaunchMode::BrowserHtml5);
    }

    #[test]
    fn honors_explicit_putty_launcher() {
        let req = SshLaunchRequest {
            target: "127.0.0.1".to_string(),
            launcher: Some("putty".to_string()),
            ..Default::default()
        };
        assert_eq!(resolve_ssh_launch_mode(&req), SshLaunchMode::Putty);
    }
}
