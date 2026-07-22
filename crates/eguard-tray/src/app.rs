use anyhow::{anyhow, Result};
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(target_os = "windows")]
use windows::core::PCWSTR;
#[cfg(target_os = "windows")]
use windows::Win32::UI::Shell::ShellExecuteW;
#[cfg(target_os = "windows")]
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

pub fn open_admin_ui() -> Result<()> {
    open_external_url(&admin_ui_url())
}

pub fn uninstall_agent_with_token(token: &str) -> Result<()> {
    let token = token.trim();
    if token.is_empty() {
        return Err(anyhow!("uninstall token is required"));
    }
    if token.contains('\0') || token.contains('\r') || token.contains('\n') {
        return Err(anyhow!("uninstall token contains invalid characters"));
    }

    let script = Path::new(r"C:\Program Files\eGuard\uninstall.ps1");
    if !script.is_file() {
        return Err(anyhow!("installed uninstall script not found: {}", script.display()));
    }
    let server_host = resolve_server_host()
        .ok_or_else(|| anyhow!("agent server address is not configured"))?;
    let parameters = format!(
        "-NoProfile -ExecutionPolicy Bypass -Command \"$env:EGUARD_SERVER_HOST='{}'; & '{}' -UninstallToken '{}'\"",
        powershell_quote(&server_host),
        powershell_quote(&script.display().to_string()),
        powershell_quote(token),
    );
    launch_elevated("powershell.exe", &parameters)
}

fn resolve_server_host() -> Option<String> {
    let value = std::env::var("EGUARD_SERVER_HOST")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| read_agent_config_value("server_addr"))?;
    let value = value.trim().trim_start_matches("https://").trim_start_matches("http://");
    let value = value.trim_matches('[').trim_matches(']');
    let host = value.rsplit_once(':').map(|(host, _)| host).unwrap_or(value).trim();
    (!host.is_empty()).then(|| host.to_string())
}

fn read_agent_config_value(key: &str) -> Option<String> {
    let raw = fs::read_to_string(r"C:\ProgramData\eGuard\agent.conf").ok()?;
    raw.lines().find_map(|line| {
        let (candidate, value) = line.trim().split_once('=')?;
        candidate.trim().eq_ignore_ascii_case(key).then(|| value.trim().trim_matches(['\"', '\'']).to_string())
    })
}

fn powershell_quote(value: &str) -> String {
    value.replace('\'', "''")
}

fn launch_elevated(executable: &str, parameters: &str) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        let operation = wide("runas");
        let executable = wide(executable);
        let parameters = wide(parameters);
        let result = unsafe {
            ShellExecuteW(
                None,
                PCWSTR(operation.as_ptr()),
                PCWSTR(executable.as_ptr()),
                PCWSTR(parameters.as_ptr()),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            )
        };
        if result.0 as isize <= 32 {
            return Err(anyhow!("uninstall elevation was cancelled or could not start"));
        }
        return Ok(());
    }
    #[allow(unreachable_code)]
    Err(anyhow!("elevated uninstall is only implemented for Windows"))
}

fn admin_ui_url() -> String {
    std::env::var("EGUARD_ADMIN_UI_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(resolve_admin_ui_url_from_config)
        .unwrap_or_else(|| "https://127.0.0.1:1443/admin".to_string())
}

fn resolve_admin_ui_url_from_config() -> Option<String> {
    let path = PathBuf::from(r"C:\ProgramData\eGuard\bootstrap.conf");
    let raw = fs::read_to_string(path).ok()?;
    let mut address = None;
    for line in raw.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("address = ") {
            address = Some(value.trim().trim_matches('"').to_string());
            break;
        }
    }
    let address = address?
        .trim()
        .trim_matches('[')
        .trim_matches(']')
        .to_string();
    if address.is_empty() {
        return None;
    }
    Some(format!("https://{}:1443/admin", address))
}

pub fn open_local_path(path: &Path) -> Result<()> {
    open_shell_target(path.to_string_lossy().as_ref())
}

pub fn open_external_url(target: &str) -> Result<()> {
    open_shell_target(target)
}

fn open_shell_target(target: &str) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        let operation = wide("open");
        let target = wide(target);
        let result = unsafe {
            ShellExecuteW(
                None,
                PCWSTR(operation.as_ptr()),
                PCWSTR(target.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            )
        };
        let code = result.0 as isize;
        if code <= 32 {
            return Err(anyhow!(
                "failed to open external URL (ShellExecuteW={code})"
            ));
        }
        return Ok(());
    }

    #[allow(unreachable_code)]
    Err(anyhow!(
        "opening shell targets is only implemented for Windows in this crate"
    ))
}

#[cfg(target_os = "windows")]
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
